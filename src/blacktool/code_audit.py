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
 ("DJ001","high",re.compile(r"ALLOWED_HOSTS\\s*=\\s*\\[\\s*['\\\"]\\*['\\\"]"),"Django allows every host","Set ALLOWED_HOSTS to exact production hostnames."),
 ("DJ002","high",re.compile(r"CSRF_COOKIE_SECURE\\s*=\\s*False|SESSION_COOKIE_SECURE\\s*=\\s*False"),"Django cookie secure flag disabled","Enable secure cookie flags in HTTPS production deployments."),
 ("DJ003","medium",re.compile(r"\\bmark_safe\\s*\\("),"Django mark_safe usage","Ensure values are trusted or escaped before marking safe."),
 ("FL001","high",re.compile(r"app\\.run\\([^)]*debug\\s*=\\s*True"),"Flask debug server enabled","Disable the interactive debugger outside local development."),
 ("EX001","medium",re.compile(r"(?i)cors\\s*\\(\\s*\\{[^}]*origin\\s*:\\s*['\\\"]\\*"),"Express CORS wildcard origin","Restrict CORS to trusted origins."),
 ("NX001","high",re.compile(r"dangerouslySetInnerHTML\\s*="),"Next.js/React raw HTML sink","Sanitize untrusted HTML or render it as text."),
 ("SP001","high",re.compile(r"requestMatchers?\\([^)]*\\)\\.permitAll\\s*\\("),"Spring Security permitAll rule","Review whether the matched route is intentionally public."),
 ("LV001","high",re.compile(r"(?i)APP_DEBUG\\s*=\\s*true"),"Laravel debug enabled","Set APP_DEBUG=false in production."),
 ("RA001","medium",re.compile(r"config\\.force_ssl\\s*=\\s*false"),"Rails force_ssl disabled","Enable force_ssl in production."),
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
