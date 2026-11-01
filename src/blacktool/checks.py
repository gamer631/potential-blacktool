"""Low-impact network checks. Redirects are not followed."""
import socket, ssl
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler

HEADERS={
 "content-security-policy":("medium","Define a restrictive Content-Security-Policy suited to the application."),
 "strict-transport-security":("medium","Enable HSTS after confirming HTTPS is consistently available."),
 "x-content-type-options":("low","Set X-Content-Type-Options: nosniff."),
 "referrer-policy":("low","Set a privacy-conscious Referrer-Policy."),
 "permissions-policy":("info","Review browser features that should be restricted."),
}
def finding(area,severity,title,detail,recommendation):
 return {"area":area,"severity":severity,"title":title,"detail":detail,"recommendation":recommendation}
def check_headers(headers):
 observed={k.lower():v for k,v in headers.items()}
 out=[finding("headers",sev,f"Missing {name}","Response did not include this header.",fix)
      for name,(sev,fix) in HEADERS.items() if name not in observed]
 if "x-frame-options" not in observed and "content-security-policy" not in observed:
  out.append(finding("headers","medium","No visible framing protection",
   "Neither X-Frame-Options nor Content-Security-Policy was observed.",
   "Configure CSP frame-ancestors; consider X-Frame-Options for legacy clients."))
 if observed.get("server"):
  out.append(finding("information","info","Server header exposed",
   "The response includes a Server header; its value is intentionally omitted.",
   "Consider minimizing unnecessary version and platform disclosure."))
 return out
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl): return None
def http_check(url,scope):
 scope.validate_url(url)
 req=Request(url,headers={"User-Agent":scope.user_agent,"Accept":"text/html,application/json;q=0.9,*/*;q=0.1"},method="GET")
 opener=build_opener(NoRedirect)
 try:
  with opener.open(req,timeout=scope.timeout_seconds) as response:
   return {"status":response.status,"final_url":url,"content_type":response.headers.get("Content-Type","")},check_headers(response.headers)
 except HTTPError as exc:
  if exc.code in (301,302,303,307,308):
   return {"status":exc.code,"final_url":url,"redirect_not_followed":True},[
    finding("http","info","Redirect not followed","A redirect was returned; the scanner deliberately did not follow it.",
     "Review the Location destination manually and add its exact hostname to scope only if authorized.")]
  return {"status":exc.code,"final_url":url},[finding("http","info","HTTP error response",
    f"Server returned HTTP {exc.code}.","Review whether this response is expected.")]
 except (URLError,TimeoutError,OSError,ValueError) as exc:
  return {"error":str(exc)},[finding("http","info","Request failed",str(exc),
    "Verify DNS, network access, TLS and the authorized URL.")]
def tls_check(host,timeout):
 try:
  with socket.create_connection((host,443),timeout=timeout) as raw:
   with ssl.create_default_context().wrap_socket(raw,server_hostname=host) as conn:
    cert=conn.getpeercert(); raw_expiry=cert.get("notAfter")
    if not raw_expiry:return []
    expiry=datetime.strptime(raw_expiry,"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days=(expiry-datetime.now(timezone.utc)).days
    if days<0:return [finding("tls","high","Certificate expired",f"Expired {abs(days)} days ago.","Renew and deploy a valid certificate.")]
    if days<=30:return [finding("tls","medium","Certificate expires soon",f"Expires in {days} days.","Renew before expiry.")]
    return []
 except (OSError,ssl.SSLError,ValueError) as exc:
  return [finding("tls","high","TLS validation failed",str(exc),"Review certificate chain, hostname, expiry and listener configuration.")]
def dns_check(host):
 try:return {"host":host,"addresses":sorted({x[4][0] for x in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)})}
 except socket.gaierror as exc:return {"host":host,"error":str(exc)}
