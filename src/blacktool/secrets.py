"""Local secret-pattern scanner. Values are never copied into findings."""
import re
from pathlib import Path
RULES=[
 ("SEC001","critical","Private key material",re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
 ("SEC002","high","AWS access key identifier",re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
 ("SEC003","high","GitHub token-like value",re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
 ("SEC004","high","Slack token-like value",re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
 ("SEC005","high","Generic credential assignment",re.compile(r"""(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*['"][^'"\s]{8,}['"]""")),
 ("SEC006","medium","Possible high-entropy credential",re.compile(r"""(?i)\b(?:token|secret|key)\b\s*[:=]\s*['"][A-Za-z0-9_+/=-]{24,}['"]""")),
]
SKIP={".git","node_modules",".venv","venv","dist","build",".next","vendor","__pycache__"}
def scan_secrets(path):
 root=Path(path); files=root.rglob("*") if root.is_dir() else [root]; findings=[]
 for file in files:
  if not file.is_file() or any(part in SKIP for part in file.parts): continue
  try:
   if file.stat().st_size>2_000_000: continue
   lines=file.read_text(encoding="utf-8",errors="replace").splitlines()
  except OSError: continue
  for n,line in enumerate(lines,1):
   for rule,severity,title,pattern in RULES:
    if pattern.search(line):
     findings.append({"area":"secrets","rule_id":rule,"severity":severity,"title":title,"file":str(file),"line":n,
      "detail":"A secret-like pattern was detected. The matched value is intentionally redacted.",
      "recommendation":"Remove it from source, rotate it if exposed, and use a secret manager."})
 return findings
