"""Scan sDrive › 01_Samples (one folder per die, one sub-folder per device) and 02_Projects through a read-only share link
(of the Tan_STNO_LAF root folder) and write the encrypted
device→files index used by the hub (scan.enc.json). Runs in GitHub Actions.
Secrets: SDRIVE_SHARE_URL (the share link), SDRIVE_SHARE_PASSWORD, HUB_PASSWORD."""
import os, re, json, base64, hashlib, datetime, sys, email.utils, xml.etree.ElementTree as ET
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
BODY = '<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/><d:resourcetype/><d:getlastmodified/></d:prop></d:propfind>'
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
        lm = resp.find(".//d:getlastmodified", NS)
        try: lmd = email.utils.parsedate_to_datetime(lm.text).date().isoformat() if lm is not None and lm.text else ""
        except Exception: lmd = ""
        out.append({"p": rel, "id": int(fid.text) if fid is not None else 0, "dir": resp.find(".//d:collection", NS) is not None, "lm": lmd})
    return out
# The share link may point at the hub root folder (Tan_STNO_LAF) or at 01_Samples / 02_Projects themselves.
top = [x["p"] for x in ls("")]
if any(t.rstrip("/") == "01_Samples" for t in top): roots = {"s": "01_Samples/", "p": "02_Projects/"}
else: roots = {"s": "", "p": ""}
tree, q = [], [roots["s"]] + ([roots["p"]] if roots["p"] else [])
seen = set()
while q:
    p = q.pop(0)
    if p in seen: continue
    seen.add(p)
    for x in ls(p):
        tree.append(x)
        if x["dir"]: q.append(x["p"])
print("entries:", len(tree))
samples = [dict(x, p=x["p"][len(roots["s"]):]) for x in tree if x["p"].startswith(roots["s"]) and (not roots["p"] or not x["p"].startswith(roots["p"]))]
proj = [dict(x, p=x["p"][len(roots["p"]):]) for x in tree if roots["p"] and x["p"].startswith(roots["p"])] or samples

# --- device matching (same rules as the hub): 01_Samples/<die>/<device folder>/...
MAP = {"VB01-23-EN": "vb-en", "VB01-23-DM": "vb-dm", "INL-VPW32-TJ7917": "inl-vpw32-tj7917", "INL-SMWEH08-TJ7377": "inl-smweh08-tj7377",
       "SPINTEC-RFHR1111-D41": "spintec-rfhr1111-d41", "SPINTEC-AZ96-13-HI": "spintec-az96-13-hi", "SPINTEC-AZ96-13-HM": "spintec-az96-13-hm", "INL-VPW43": "inl-vpw43",
       "SPINTEC-RFL693-D65": "spintec-rfl693-d65", "INL-VPW41-TJ8929": "inl-vpw41-tj8929", "SPINTEC-AZ96-13-DI": "spintec-az96-13-di", "SPINTEC-RFL655-HG": "spintec-rfl655-hg"}
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
def fdate(name, lm):
    m = re.search(r"(20[12]\d)[-_.]?(0[1-9]|1[0-2])[-_.]?(0[1-9]|[12]\d|3[01])", name)
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else lm
nm = lambda p: p.rstrip("/").split("/")[-1]
files, days, pdays = {}, {}, {}
def addday(sid, k, d, n=1):
    if d: dd = days.setdefault(sid, {}).setdefault(k, {}); dd[d] = dd.get(d, 0) + n
def entry(sid, k, d, fs):
    fs = [f for f in fs if not nm(f["p"]).startswith("~$")]
    c, sl = [0, 0, 0, 0], []
    for f in fs:
        t = cat(f["p"]); c[t] += 1; addday(sid, k, fdate(nm(f["p"]), f["lm"]))
        if t == 1: sl.append([nm(f["p"]), f["id"]])
    e = {"n": "/".join(d["p"].rstrip("/").split("/")[1:]), "id": d["id"], "c": c}
    if sl: e["sl"] = sl[:5]
    files.setdefault(sid, {}).setdefault(k, []).append(e)
for d in [x for x in samples if x["dir"]]:
    parts = d["p"].rstrip("/").split("/")
    if len(parts) < 2: continue
    sid = MAP.get(parts[0])
    if not sid: continue
    k = key(sid, parts[-1])
    if not k or any(key(sid, a) == k for a in parts[1:-1]): continue
    entry(sid, k, d, [f for f in samples if not f["dir"] and f["p"].startswith(d["p"])])
ST = "STVO-array_S1-S4/"
dev_dirs = [x for x in samples if x["dir"] and re.match(r"^S[1-4]/[A-O]\d{1,2}/$", x["p"][len(ST):]) and x["p"].startswith(ST)]
for d in dev_dirs:
    s, dv = d["p"][len(ST):].split("/")[:2]
    entry("stvo-s" + s[1], dv, d, [f for f in samples if not f["dir"] and f["p"].startswith(d["p"])])
loose = {}
for f in samples:
    if f["dir"] or not f["p"].startswith(ST) or any(f["p"].startswith(d["p"]) for d in dev_dirs) or nm(f["p"]).startswith("~$"): continue
    m = re.search(r"(?:^|_)S([1-4])_((?:[A-O]\d{1,2}_?)+)", nm(f["p"]))
    if not m: continue
    par = f["p"][:f["p"].rfind("/") + 1]
    for dv in filter(None, m.group(2).split("_")):
        loose.setdefault(("stvo-s" + m.group(1), dv, par), []).append(f)
for (sid, dv, par), fs in loose.items():
    if par == ST:
        for f in fs:
            files.setdefault(sid, {}).setdefault(dv, []).append({"n": nm(f["p"]), "id": f["id"], "file": 1, "c": [0, 1, 0, 0], "sl": [[nm(f["p"]), f["id"]]]})
            addday(sid, dv, fdate(nm(f["p"]), f["lm"]))
    else:
        pd = next((x for x in samples if x["dir"] and x["p"] == par), {"p": par, "id": 0})
        entry(sid, dv, pd, fs)
projfiles = []
for f in proj:
    if f["dir"] or nm(f["p"]).startswith("~$") or not re.match(r"(Floquet|EP|EP-encirclement_PRB|Spin-diode)/", f["p"]): continue
    pj = "floq" if f["p"].startswith("Floquet") else "sd" if f["p"].startswith("Spin-diode") else "ep"; d = fdate(nm(f["p"]), f["lm"])
    projfiles.append({"p": f["p"], "id": f["id"], "d": d})
    if d: pdays.setdefault(pj, {})[d] = pdays.setdefault(pj, {}).get(d, 0) + 1

# --- write only when something changed
old = None
if os.path.exists("scan.enc.json"):
    try: old = dec(json.load(open("scan.enc.json")))
    except Exception: pass
if old and old.get("files") == files and old.get("days") == days and old.get("pdays") == pdays and old.get("proj") == projfiles:
    print("no change"); sys.exit(0)
out = {"files": files, "days": days, "pdays": pdays, "proj": projfiles, "scanned": datetime.date.today().isoformat(), "entries": len(tree)}
json.dump(enc(out), open("scan.enc.json", "w"))
print("updated:", sum(len(v) for v in files.values()), "devices with files")
