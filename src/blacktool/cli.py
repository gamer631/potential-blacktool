"""CLI for authorized passive assessment and local defensive analysis."""
import argparse,json
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urlsplit
from . import __version__
from .api_audit import audit_openapi
from .checks import dns_check,http_check,tls_check
from .code_audit import scan_source
from .report import write_json,write_html
from .scope import Scope

def stamp():return datetime.now(timezone.utc).isoformat()
def main():
 p=argparse.ArgumentParser(prog="blacktool",description="Scoped defensive security assessment toolkit")
 sub=p.add_subparsers(dest="command",required=True)
 init=sub.add_parser("init-scope",help="Create a scope template");init.add_argument("url");init.add_argument("--output",default="scope.json")
 scan=sub.add_parser("scan",help="Passive HTTPS checks for one allowlisted host");scan.add_argument("url");scan.add_argument("--scope",required=True);scan.add_argument("--acknowledge-authorization",action="store_true");scan.add_argument("--output",default="reports/latest.json")
 code=sub.add_parser("scan-code",help="Read-only source-code pattern review");code.add_argument("path");code.add_argument("--output",default="reports/code.json")
 api=sub.add_parser("audit-api",help="Offline OpenAPI/Swagger JSON lint");api.add_argument("schema");api.add_argument("--output",default="reports/api.json")
 htmlp=sub.add_parser("report-html",help="Convert a JSON report to standalone HTML");htmlp.add_argument("report");htmlp.add_argument("--output",default="reports/report.html")
 a=p.parse_args()
 if a.command=="init-scope":
  u=urlsplit(a.url)
  if u.scheme!="https" or not u.hostname:p.error("Provide an absolute HTTPS URL")
  Path(a.output).write_text(json.dumps({"allowed_hosts":[u.hostname],"max_requests":10,"timeout_seconds":8},indent=2)+"\n",encoding="utf-8")
  print(f"Created {a.output}; review the allowlist before use.");return
 if a.command=="scan":
  if not a.acknowledge_authorization:p.error("Confirm ownership or written permission with --acknowledge-authorization")
  scope=Scope.load(a.scope);host=scope.validate_url(a.url)
  meta,findings=http_check(a.url,scope);findings.extend(tls_check(host,scope.timeout_seconds))
  report={"tool":"Potential BlackTool","version":__version__,"generated_at":stamp(),"target":a.url,"dns":dns_check(host),"http":meta,"findings":findings,"notice":"Passive observations only; manually validate findings."}
 elif a.command=="scan-code":
  findings=scan_source(a.path)
  report={"tool":"Potential BlackTool","version":__version__,"generated_at":stamp(),"target":str(Path(a.path).resolve()),"findings":findings,"notice":"Static pattern matches are heuristic; inspect context before treating as vulnerabilities."}
 elif a.command=="audit-api":
  findings=audit_openapi(a.schema)
  report={"tool":"Potential BlackTool","version":__version__,"generated_at":stamp(),"target":str(Path(a.schema).resolve()),"findings":findings,"notice":"Offline schema lint only; this does not test a running API."}
 else:
  source=json.loads(Path(a.report).read_text(encoding="utf-8"));write_html(source,a.output);print(f"HTML report: {a.output}");return
 write_json(report,a.output);print(f"Completed: {len(report['findings'])} finding(s). JSON report: {a.output}")
if __name__=="__main__":main()
