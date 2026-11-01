"""Read-only pattern review of deployment and infrastructure configuration."""
import re
from pathlib import Path
SKIP={".git","node_modules",".venv","venv","dist","build","vendor"}
RULES=[
 ("CFG001","high",re.compile(r"(?i)\bprivileged\s*:\s*true"),"Privileged container enabled","Avoid privileged containers; grant only required capabilities."),
 ("CFG002","high",re.compile(r"(?i)\bnetwork_mode\s*:\s*host"),"Host networking enabled","Use an isolated container network unless host networking is essential."),
 ("CFG003","high",re.compile(r"(?i)\b(?:debug|flask_debug)\s*[:=]\s*(?:true|1|['\"]true['\"])"),"Debug mode enabled","Disable debug mode in production."),
 ("CFG004","high",re.compile(r"\b0\.0\.0\.0/0\b"),"Public IPv4 ingress range","Restrict ingress to trusted source ranges."),
 ("CFG005","high",re.compile(r"\b::/0\b"),"Public IPv6 ingress range","Restrict IPv6 ingress to trusted source ranges."),
 ("CFG006","medium",re.compile(r"(?i)\blatest\s*(?:#.*)?$"),"Floating latest image tag","Pin production images to reviewed immutable versions or digests."),
 ("CFG007","medium",re.compile(r"(?i)\bssl_protocols\s+[^;]*\bTLSv1(?:\s|;|$)"),"Legacy TLS protocol enabled","Disable obsolete TLS versions."),
 ("CFG008","medium",re.compile(r"(?i)\ballow\s+all\s*;"),"Broad allow-all access rule","Replace broad access with least-privilege rules."),
]
EXTS={".yml",".yaml",".toml",".ini",".conf",".cfg",".tf",".tfvars",".json",".env",".properties"}
def audit_config(path):
 root=Path(path); files=root.rglob("*") if root.is_dir() else [root]; findings=[]
 for file in files:
  if not file.is_file() or any(part in SKIP for part in file.parts):continue
  if file.suffix.lower() not in EXTS and not file.name.startswith(("Dockerfile","docker-compose","compose")):continue
  try:
   if file.stat().st_size>2_000_000:continue
   lines=file.read_text(encoding="utf-8",errors="replace").splitlines()
  except OSError:continue
  for n,line in enumerate(lines,1):
   stripped=line.strip()
   if not stripped or stripped.startswith(("#","//")):continue
   for rule,severity,pattern,title,recommendation in RULES:
    if pattern.search(line):
     findings.append({"area":"configuration","rule_id":rule,"severity":severity,"title":title,"file":str(file),"line":n,
      "detail":"Potentially unsafe configuration pattern; validate the effective configuration.","recommendation":recommendation})
 return findings
