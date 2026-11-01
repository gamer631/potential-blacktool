"""Loopback-only local dashboard. No remote bind and no cross-origin API access."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime, timezone
from . import __version__
from .api_audit import audit_openapi
from .checks import dns_check, http_check, tls_check
from .code_audit import scan_source
from .scope import Scope

PAGE=r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Potential BlackTool</title><style>
:root{color-scheme:dark;font:15px system-ui;background:#10151d;color:#e8edf5}body{max-width:1000px;margin:36px auto;padding:0 18px}
header{border-bottom:1px solid #344052;padding-bottom:18px}.muted{color:#9eacc0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;margin-top:22px}
section{background:#192230;border:1px solid #344052;border-radius:12px;padding:18px}input{box-sizing:border-box;width:100%;padding:10px;background:#0d131c;color:#fff;border:1px solid #48576c;border-radius:7px;margin:8px 0 14px}
button{background:#8bb8ff;color:#081321;border:0;border-radius:7px;padding:10px 15px;font-weight:700;cursor:pointer}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1119;padding:16px;border-radius:9px;min-height:100px}
.notice{border-left:4px solid #e2b45f;padding:10px 14px;background:#24251f}.hidden{display:none}
</style></head><body><header><h1>Potential BlackTool</h1><p class="muted">Local defensive assessment dashboard · v""" + __version__ + r"""</p></header>
<p class="notice">Only assess assets you own or are explicitly authorized to test. Network checks are passive and require an exact-host scope file. This dashboard listens on localhost only.</p>
<div class="grid">
<section><h2>Website posture</h2><label>HTTPS URL<input id="url" placeholder="https://your-domain.example"></label>
<label>Scope JSON file path<input id="scope" placeholder="./scope.json"></label>
<button onclick="run('web')">Run passive checks</button></section>
<section><h2>Source code review</h2><label>Local project directory<input id="code" placeholder="./src"></label>
<button onclick="run('code')">Analyze source</button></section>
<section><h2>API schema review</h2><label>OpenAPI / Swagger JSON path<input id="api" placeholder="./openapi.json"></label>
<button onclick="run('api')">Audit schema</button></section></div>
<h2>Assessment output</h2><p id="status" class="muted">Ready. Reports are displayed locally and are not uploaded.</p><pre id="output">No scan has been run.</pre>
<script>
async function run(kind){
 const status=document.getElementById('status'),out=document.getElementById('output');
 const values={web:{url:document.getElementById('url').value,scope:document.getElementById('scope').value,authorized:true},
 code:{path:document.getElementById('code').value},api:{path:document.getElementById('api').value}};
 status.textContent='Running…';out.textContent='';
 try{const r=await fetch('/api/'+kind,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(values[kind])});
 const data=await r.json();if(!r.ok)throw new Error(data.error||'Request failed');
 out.textContent=JSON.stringify(data,null,2);status.textContent='Finished · '+(data.findings||[]).length+' finding(s).';
 }catch(e){status.textContent='Could not complete request.';out.textContent=String(e);}
}
</script></body></html>"""

def build_handler():
 class Handler(BaseHTTPRequestHandler):
  server_version="PotentialBlackTool"
  def log_message(self,*args): pass
  def _json(self,status,obj):
   raw=json.dumps(obj).encode()
   self.send_response(status);self.send_header("Content-Type","application/json; charset=utf-8")
   self.send_header("Content-Length",str(len(raw)));self.send_header("Cache-Control","no-store")
   self.end_headers();self.wfile.write(raw)
  def _allowed(self):
   host=self.headers.get("Host","").split(":")[0].lower()
   return host in ("127.0.0.1","localhost","[::1]")
  def do_GET(self):
   if not self._allowed(): return self._json(403,{"error":"Local requests only"})
   if urlparse(self.path).path!="/": return self._json(404,{"error":"Not found"})
   raw=PAGE.encode();self.send_response(200);self.send_header("Content-Type","text/html; charset=utf-8")
   self.send_header("Content-Length",str(len(raw)));self.send_header("Cache-Control","no-store")
   self.end_headers();self.wfile.write(raw)
  def do_POST(self):
   if not self._allowed(): return self._json(403,{"error":"Local requests only"})
   if self.headers.get("Origin") not in (None,"http://127.0.0.1:8765","http://localhost:8765"):
    return self._json(403,{"error":"Cross-origin requests are not allowed"})
   try:
    length=int(self.headers.get("Content-Length","0"))
    if length<1 or length>65536: return self._json(413,{"error":"Request body size must be 1-65536 bytes"})
    data=json.loads(self.rfile.read(length))
    route=urlparse(self.path).path
    if route=="/api/code":
     findings=scan_source(data["path"]);target=str(Path(data["path"]).resolve())
    elif route=="/api/api":
     findings=audit_openapi(data["path"]);target=str(Path(data["path"]).resolve())
    elif route=="/api/web":
     if data.get("authorized") is not True: return self._json(400,{"error":"Authorization acknowledgement required"})
     scope=Scope.load(data["scope"]);host=scope.validate_url(data["url"])
     meta,findings=http_check(data["url"],scope);findings.extend(tls_check(host,scope.timeout_seconds))
     report={"http":meta,"dns":dns_check(host)}
     return self._json(200,{"tool":"Potential BlackTool","target":data["url"],"generated_at":datetime.now(timezone.utc).isoformat(),"findings":findings,"metadata":report})
    else:return self._json(404,{"error":"Unknown endpoint"})
    return self._json(200,{"tool":"Potential BlackTool","target":target,"generated_at":datetime.now(timezone.utc).isoformat(),"findings":findings})
   except (KeyError,ValueError,OSError,json.JSONDecodeError) as exc:
    return self._json(400,{"error":str(exc)})
 return Handler

def serve(host="127.0.0.1",port=8765):
 if host not in ("127.0.0.1","localhost","::1"):
  raise ValueError("Dashboard may only bind to loopback")
 server=ThreadingHTTPServer((host,port),build_handler())
 print(f"Potential BlackTool dashboard: http://127.0.0.1:{port} (Ctrl+C to stop)")
 try:server.serve_forever()
 except KeyboardInterrupt:pass
 finally:server.server_close()
