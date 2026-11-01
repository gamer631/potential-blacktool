"""Offline dependency manifest inventory; does not claim CVE coverage."""
import json,re
from pathlib import Path

def audit_dependencies(root):
 root=Path(root); findings=[]; inventory=[]
 candidates=[root/"requirements.txt",root/"pyproject.toml",root/"package.json",root/"go.mod"]
 for path in candidates:
  if not path.is_file(): continue
  try: text=path.read_text(encoding="utf-8")
  except OSError: continue
  if path.name=="requirements.txt":
   for raw in text.splitlines():
    line=raw.strip()
    if not line or line.startswith(("#","-")): continue
    m=re.match(r"([A-Za-z0-9_.-]+)\s*(==|~=|>=|<=|!=|>|<)?\s*([A-Za-z0-9_.!*+-]+)?",line)
    if m: inventory.append({"ecosystem":"pypi","name":m.group(1),"constraint":(m.group(2) or "")+(m.group(3) or ""),"manifest":str(path)})
  elif path.name=="pyproject.toml":
   # Keep this dependency inventory parser dependency-free and intentionally conservative.
   section=""
   for raw in text.splitlines():
    line=raw.strip()
    if line.startswith("["): section=line
    if section=="[project]" and line.startswith("dependencies") and "=" in line:
     values=re.findall(r"['\"]([^'\"]+)['\"]",line.split("=",1)[1])
     for value in values:
      m=re.match(r"([A-Za-z0-9_.-]+)\s*(.*)",value)
      if m: inventory.append({"ecosystem":"pypi","name":m.group(1),"constraint":m.group(2),"manifest":str(path)})
  elif path.name=="package.json":
   try: data=json.loads(text)
   except json.JSONDecodeError:
    findings.append({"area":"dependencies","severity":"medium","title":"Invalid package.json","detail":str(path),"recommendation":"Fix the JSON manifest."});continue
   for section in ("dependencies","devDependencies","optionalDependencies"):
    for name,version in data.get(section,{}).items():
     inventory.append({"ecosystem":"npm","name":name,"constraint":str(version),"manifest":str(path)})
  elif path.name=="go.mod":
   for raw in text.splitlines():
    line=raw.strip()
    if line.startswith("require "):
     parts=line.split()
     if len(parts)>=3: inventory.append({"ecosystem":"go","name":parts[1],"constraint":parts[2],"manifest":str(path)})
    elif line and not line.startswith(("module ","go ","toolchain ","//","require","replace","exclude",")")):
     parts=line.split()
     if len(parts)>=2 and re.match(r"v\d",parts[1]):
      inventory.append({"ecosystem":"go","name":parts[0],"constraint":parts[1],"manifest":str(path)})
 for item in inventory:
  constraint=str(item.get("constraint", "")).strip()
  version=None
  if item.get("ecosystem")=="pypi":
   match=re.fullmatch(r"==\\s*([A-Za-z0-9_.+!-]+)",constraint)
   if match: version=match.group(1)
  elif item.get("ecosystem") in ("npm", "go"):
   candidate=constraint[1:] if constraint.startswith("=") else constraint
   if re.fullmatch(r"v?\\d+\\.\\d+\\.\\d+[^\\s]*",candidate): version=candidate
  item["version"]=version
 if not inventory and not findings:
  findings.append({"area":"dependencies","severity":"info","title":"No supported dependency manifest found",
   "detail":"Looked for requirements.txt, pyproject.toml, package.json and go.mod at the selected root.",
   "recommendation":"Provide a supported manifest or lockfile for inventory."})
 return inventory,findings
