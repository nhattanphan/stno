"""Scan sDrive › 02_Measurements through a read-only share link and write the encrypted
device→files index used by the hub (scan.enc.json). Runs in GitHub Actions.
Secrets: SDRIVE_SHARE_URL (the share link), SDRIVE_SHARE_PASSWORD, HUB_PASSWORD."""
import os, re, json, base64, hashlib, datetime, sys, xml.etree.ElementTree as ET
from urllib.parse import unquote
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

URL = os.environ["SDRIVE_SHARE_URL"].strip()
SPW = os.environ.get("SDRIVE_SHARE_PASSWORD", "")
HPW = os.environ["HUB_PASSWORD"]
m = re.match(r"(https://[^/]+)/(?:index\.php/)?s/([A-Za-z0-9]+)", URL)
if not m: sys.exit("SDRIVE_SHARE_URL is not a share link")
HOST, TOKEN = m.groups()
BASE = f"{HOST}/public.php/dav/files/{TOKEN}/"

# --- key from the hub data file (same salt) and a check that HUB_PASSWORD is right
D = json.load(open("data.enc.json"))
KEY = hashlib.pbkdf2_hmac("sha256", HPW.encode(), base64.b64decode(D["kdf"]["salt"]), D["kdf"]["iter"], 32)
A = AESGCM(KEY)
def dec(x): return json.loads(A.decrypt(base64.b64decode(x["iv"]), base64.b64decode(x["ct"]), None))
def enc(o):
    iv = os.urandom(12)
    return {"v": 1, "iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(A.encrypt(iv, json.dumps(o, ensure_ascii=False, separators=(",", ":")).encode(), None)).decode()}
try: dec(D)
except Exception: sys.exit("HUB_PASSWORD does not open data.enc.json")

# --- crawl
S = requests.Session()
if SPW: S.auth = ("anonymous", SPW)
BODY = '<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/><d:resourcetype/></d:prop></d:propfind>'
NS = {"d": "DAV:", "oc": "http://owncloud.org/ns"}
def ls(path):
    r = S.request("PROPFIND", BASE + requests.utils.quote(path), data=BODY, headers={"Depth": "1", "Content-Type": "application/xml"}, timeout=60)
    if r.status_code == 401 and SPW and S.auth[0] == "anonymous":
        S.auth = (TOKEN, SPW); r = S.request("PROPFIND", BASE + requests.utils.quote(path), data=BODY, headers={"Depth": "1", "Content-Type": "application/xml"}, timeout=60)
    r.raise_for_status()
    out = []
    for resp in ET.fromstring(r.content).findall("d:response", NS)[1:]:
        href = unquote(resp.find("d:href", NS).text)
        rel = href.split(f"/files/{TOKEN}/", 1)[1]
        fid = resp.find(".//oc:fileid", NS)
        out.append({"p": rel, "id": int(fid.text) if fid is not None else 0, "dir": resp.find(".//d:collection", NS) is not None})
    return out
tree, q = [], [""]
while q:
    for x in ls(q.pop(0)):
        tree.append(x)
        if x["dir"]: q.append(x["p"])
print("entries:", len(tree))

# --- device matching (same rules as the hub)
MAP = {"VB01-23-EN": "vb-en", "VB01-23-DM": "vb-dm", "INL-VPW32-TJ7917_MaskD-CoFeSi-wedge": "inl-vpw32-tj7917", "INL-SMWEH08-TJ7377": "inl-smweh08-tj7377",
       "SPINTEC-RFHR1111-D41": "spintec-rfhr1111-d41", "SPINTEC-AZ96-13-HI": "spintec-az96-13-hi", "INL-VPW43": "inl-vpw43", "SPINTEC-RFL693-D65": "spintec-rfl693-d65",
       "INL-VPW41-TJ8929": "inl-vpw41-tj8929", "SPINTEC-AZ96-13-DI": "spintec-az96-13-di", "SPINTEC-RFL655-HG": "spintec-rfl655-hg"}
def key(sid, n):
    m = re.search(r"(?:^|[^A-Z])([A-I])\s*([1-6])\s*_?\s*J\s*([1-4])", n, re.I)
    if m: return m.group(1).upper() + m.group(2) + "_J" + m.group(3)
    m = re.search(r"P\s*(\d+)\s*[-_]\s*(\d+)", n, re.I)
    if m: return f"P{m.group(1)}-{m.group(2)}"
    m = re.match(r"^([A-E])\s*([1-6])(\b|\s|$)", n, re.I)
    if m and re.search("rfhr|rfl693", sid): return m.group(1).upper() + m.group(2)
    return None
def cat(p):
    if re.search(r"\.(pptx?|pdf)$", p, re.I): return 1
    if re.search(r"\.(nc|csv|txt|dat|h5|hdf5|npy|xlsx?|ini|json|mat)$", p, re.I): return 0
    if re.search(r"\.(png|jpe?g|gif|tiff?|svg)$", p, re.I): return 2
    return 3
files = {}
for d in [x for x in tree if x["dir"] and x["p"].startswith("Spin-diode/")]:
    parts = d["p"].rstrip("/").split("/")
    if len(parts) < 3: continue
    sid = MAP.get(parts[1])
    if not sid: continue
    k = key(sid, parts[-1])
    if not k or any(key(sid, a) == k for a in parts[2:-1]): continue
    c, sl = [0, 0, 0, 0], []
    for f in tree:
        if not f["dir"] and f["p"].startswith(d["p"]):
            t = cat(f["p"]); c[t] += 1
            if t == 1: sl.append([f["p"].split("/")[-1], f["id"]])
    e = {"n": "/".join(parts[2:]), "id": d["id"], "c": c}
    if sl: e["sl"] = sl[:8]
    files.setdefault(sid, {}).setdefault(k, []).append(e)
for f in tree:
    if f["dir"] or not re.match(r"(STVO-array_Tristan|EP)/", f["p"]): continue
    nm = f["p"].split("/")[-1]
    m = re.search(r"_S([1-4])_((?:[A-O]\d{1,2}_?)+)", nm)
    if m:
        for dv in filter(None, m.group(2).split("_")):
            files.setdefault("stvo-s" + m.group(1), {}).setdefault(dv, []).append({"n": nm, "id": f["id"], "file": 1, "c": [0, 1, 0, 0], "sl": [[nm, f["id"]]]})

# --- write only when something changed
old = None
if os.path.exists("scan.enc.json"):
    try: old = dec(json.load(open("scan.enc.json")))
    except Exception: pass
if old and old.get("files") == files:
    print("no change"); sys.exit(0)
out = {"files": files, "scanned": datetime.date.today().isoformat(), "entries": len(tree)}
json.dump(enc(out), open("scan.enc.json", "w"))
print("updated:", sum(len(v) for v in files.values()), "devices with files")
