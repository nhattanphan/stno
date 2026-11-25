import json, os, re, sys
body = os.environ.get("ISSUE_BODY", "")
m = re.search(r"```json\s*(\{.*?\})\s*```", body, re.S)
if not m:
    sys.exit("No JSON block found in the issue body")
blob = json.loads(m.group(1))
b64 = re.compile(r"^[A-Za-z0-9+/=]+$")
if set(blob) != {"iv", "ct"} or not all(isinstance(blob[k], str) and b64.match(blob[k]) for k in blob) or len(blob["ct"]) > 20000:
    sys.exit("Expected an encrypted entry {iv, ct}")
d = json.load(open("data.enc.json"))
d.setdefault("extra", []).append(blob)
json.dump(d, open("data.enc.json", "w"), indent=1)
print("Appended encrypted meeting; extras:", len(d["extra"]))
