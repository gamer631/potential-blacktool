"""CLI for authorized passive assessment and local defensive analysis."""
import argparse,json,sys
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urlsplit
from . import __version__
from .api_audit import audit_openapi
from .checks import dns_check,http_check,tls_check
from .code_audit import scan_source
from .config_audit import audit_config
from .dashboard import serve
from .dependencies import audit_dependencies
from .policy import violations
from .report import write_json,write_html
from .sarif import write_sarif
from .scope import Scope
from .secrets import scan_secrets

def stamp():return datetime.now(timezone.utc).isoformat()
def make_report(target,findings,**extra):
 return {"tool":"Potential BlackTool","version":__version__,"generated_at":stamp(),"target":str(target),"findings":findings,**extra}
def save(report,output,fmt="json"):
 {"json":write_json,"html":write_html,"sarif":write_sarif}[fmt](report,output)
 print(f"Completed: {len(report.get('findings',[]))} finding(s). Report: {output}")
def main():
 p=argparse.ArgumentParser(prog="blacktool",description="Scoped defensive security assessment toolkit")
 sub=p.add_subparsers(dest="command",required=True)
 init=sub.add_parser("init-scope");init.add_argument("url");init.add_argument("--output",default="scope.json")
 scan=sub.add_parser("scan");scan.add_argument("url");scan.add_argument("--scope",required=True);scan.add_argument("--acknowledge-authorization",action="store_true");scan.add_argument("--output",default="reports/web.json")
 code=sub.add_parser("scan-code");code.add_argument("path");code.add_argument("--output",default="reports/code.json");code.add_argument("--format",choices=["json","html","sarif"],default="json")
 api=sub.add_parser("audit-api");api.add_argument("schema");api.add_argument("--output",default="reports/api.json");api.add_argument("--format",choices=["json","html","sarif"],default="json")
 dep=sub.add_parser("audit-deps");dep.add_argument("path",nargs="?",default=".");dep.add_argument("--output",default="reports/dependencies.json")
 sec=sub.add_parser("scan-secrets");sec.add_argument("path");sec.add_argument("--output",default="reports/secrets.json");sec.add_argument("--format",choices=["json","html","sarif"],default="json")
 cfg=sub.add_parser("audit-config");cfg.add_argument("path");cfg.add_argument("--output",default="reports/config.json");cfg.add_argument("--format",choices=["json","html","sarif"],default="json")
 htmlp=sub.add_parser("report-html");htmlp.add_argument("report");htmlp.add_argument("--output",default="reports/report.html")
 sarifp=sub.add_parser("report-sarif");sarifp.add_argument("report");sarifp.add_argument("--output",default="reports/report.sarif")
 policy=sub.add_parser("policy");policy.add_argument("report");policy.add_argument("--fail-on",choices=["low","medium","high","critical"],default="high")
 dash=sub.add_parser("dashboard");dash.add_argument("--host",default="127.0.0.1");dash.add_argument("--port",type=int,default=8765)
 a=p.parse_args()
 if a.command=="dashboard":
  try:serve(a.host,a.port)
  except ValueError as exc:p.error(str(exc))
  return
 if a.command=="init-scope":
  u=urlsplit(a.url)
  if u.scheme!="https" or not u.hostname:p.error("Provide an absolute HTTPS URL")
  Path(a.output).write_text(json.dumps({"allowed_hosts":[u.hostname],"max_requests":10,"timeout_seconds":8},indent=2)+"\n",encoding="utf-8")
  print(f"Created {a.output}; review the allowlist before use.");return
 if a.command=="scan":
  if not a.acknowledge_authorization:p.error("Confirm ownership or written permission with --acknowledge-authorization")
  scope=Scope.load(a.scope);host=scope.validate_url(a.url)
  meta,findings=http_check(a.url,scope);findings.extend(tls_check(host,scope.timeout_seconds))
  save(make_report(a.url,findings,dns=dns_check(host),http=meta,notice="Passive observations only."),a.output);return
 if a.command=="scan-code":save(make_report(Path(a.path).resolve(),scan_source(a.path)),a.output,a.format);return
 if a.command=="audit-api":save(make_report(Path(a.schema).resolve(),audit_openapi(a.schema)),a.output,a.format);return
 if a.command=="audit-deps":
  inventory,findings=audit_dependencies(a.path)
  save(make_report(Path(a.path).resolve(),findings,dependencies=inventory,notice="Inventory only; no CVE lookup."),a.output);return
 if a.command=="scan-secrets":save(make_report(Path(a.path).resolve(),scan_secrets(a.path)),a.output,a.format);return
 if a.command=="audit-config":save(make_report(Path(a.path).resolve(),audit_config(a.path)),a.output,a.format);return
 if a.command in ("report-html","report-sarif"):
  report=json.loads(Path(a.report).read_text(encoding="utf-8"))
  (write_html if a.command=="report-html" else write_sarif)(report,a.output);print(f"Report written: {a.output}");return
 report=json.loads(Path(a.report).read_text(encoding="utf-8"));failed=violations(report,a.fail_on)
 print(f"Policy threshold: {a.fail_on}; matching findings: {len(failed)}")
 if failed:
  for item in failed:print(f"- {item.get('severity','info')}: {item.get('title','Finding')}")
  sys.exit(1)
if __name__=="__main__":main()
