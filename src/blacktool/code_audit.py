"""Defensive, read-only source-code pattern review."""
import re
from pathlib import Path

RULES=[
 ("PY001","high",re.compile(r"\beval\s*\("),"Dynamic eval call","Avoid evaluating untrusted strings as code."),
 ("PY002","high",re.compile(r"\bexec\s*\("),"Dynamic exec call","Avoid dynamic execution; use explicit, typed operations."),
 ("PY003","high",re.compile(r"subprocess\.(?:run|Popen|call|check_output)\([^\n]*shell\s*=\s*True"),"Shell execution enabled","Pass argument arrays and keep shell=False."),
 ("PY004","medium",re.compile(r"\bdebug\s*=\s*True"),"Debug mode enabled","Disable debug mode in production."),
 ("PY005","high",re.compile(r"verify\s*=\s*False"),"TLS verification disabled","Keep certificate verification enabled."),
 ("GEN001","high",re.compile(r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),"Possible hard-coded secret","Move secrets to a managed secret store and rotate exposed values."),
 ("GEN002","medium",re.compile(r"(?i)md5\s*\(|sha1\s*\("),"Weak hash primitive reference","Use modern cryptographic primitives; use Argon2id/bcrypt/scrypt for passwords."),
 ("JS001","high",re.compile(r"\beval\s*\("),"JavaScript eval call","Avoid evaluating untrusted strings as code."),
 ("JS002","high",re.compile(r"innerHTML\s*="),"HTML injection sink","Prefer textContent or sanitize untrusted HTML with a vetted library."),
 ("JS003","medium",re.compile(r"(?i)\bhttp://"),"Insecure HTTP URL literal","Use HTTPS for production service endpoints."),
 ("GO001","medium",re.compile(r"InsecureSkipVerify\s*:\s*true"),"TLS verification disabled","Do not disable certificate verification."),
]
EXTS={".py",".js",".jsx",".ts",".tsx",".go",".java",".php",".rb",".cs",".vue",".mjs",".cjs"}
def scan_source(path):
 root=Path(path); findings=[]; files=list(root.rglob("*")) if root.is_dir() else [root]
 for file in files:
  if not file.is_file() or file.suffix.lower() not in EXTS or any(x in file.parts for x in (".git","node_modules",".venv","venv","dist","build")):continue
  try: lines=file.read_text(encoding="utf-8",errors="replace").splitlines()
  except OSError: continue
  for number,line in enumerate(lines,1):
   if len(line)>2000: continue
   for rule,severity,pattern,title,recommendation in RULES:
    if pattern.search(line):
     findings.append({"area":"source","rule_id":rule,"severity":severity,"title":title,
      "file":str(file),"line":number,"detail":"Potentially risky code pattern detected; manual review required.",
      "recommendation":recommendation})
 return findings
