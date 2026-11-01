"""Offline OpenAPI JSON document linting; never sends requests to API endpoints."""
import json
from pathlib import Path
from .checks import finding

def audit_openapi(path):
 data=json.loads(Path(path).read_text(encoding="utf-8"))
 out=[]
 if not isinstance(data,dict) or not (str(data.get("openapi","")).startswith("3.") or str(data.get("swagger",""))=="2.0"):
  return [finding("api","high","Unrecognized API schema","Document does not declare OpenAPI 3.x or Swagger 2.0.","Provide a valid OpenAPI document.")]
 servers=data.get("servers",[])
 if not servers and "host" not in data:
  out.append(finding("api","info","No server URL declared","The schema does not declare a server base URL.","Document the intended API servers."))
 for server in servers:
  url=str(server.get("url",""))
  if url.startswith("http://"):
   out.append(finding("api","high","HTTP API server URL","A server URL uses unencrypted HTTP.","Use HTTPS outside isolated local development."))
 paths=data.get("paths",{})
 if not isinstance(paths,dict): paths={}
 for route,methods in paths.items():
  if not isinstance(methods,dict):continue
  for method,operation in methods.items():
   if method.lower() not in {"get","post","put","patch","delete","options","head","trace"} or not isinstance(operation,dict):continue
   security=operation.get("security",data.get("security"))
   if security==[]:
    out.append(finding("api","medium","Operation explicitly disables security",
      f"{method.upper()} {route} has an empty security requirement.",
      "Confirm this endpoint is intentionally public; otherwise define an authentication requirement."))
   if method.lower() in {"put","patch","delete"} and security is None:
    out.append(finding("api","medium","Mutation operation has no declared security",
      f"{method.upper()} {route} has no operation or global security declaration.",
      "Document and enforce authorization at the API implementation layer."))
 return out
