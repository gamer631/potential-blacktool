"""Safe JSON and standalone HTML report writers."""
import html,json
from pathlib import Path
def write_json(report,path):
 p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(report,indent=2),encoding="utf-8");return p
def write_html(report,path):
 rows=[]
 for item in report.get("findings",[]):
  cells=[item.get("severity","info"),item.get("title","Finding"),item.get("file",""),str(item.get("line","")),item.get("detail",""),item.get("recommendation","")]
  rows.append("<tr>"+"".join("<td>"+html.escape(str(v))+"</td>" for v in cells)+"</tr>")
 table="<table><thead><tr><th>Severity</th><th>Finding</th><th>File</th><th>Line</th><th>Details</th><th>Recommendation</th></tr></thead><tbody>"+"".join(rows)+"</tbody></table>"
 page="<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width'><title>Potential BlackTool report</title><style>body{font:15px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#20242a}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:.6rem;text-align:left;vertical-align:top}th{background:#f2f4f7}td{overflow-wrap:anywhere} .notice{padding:1rem;background:#fff4d6}</style><h1>Potential BlackTool report</h1><p class='notice'>Authorized defensive assessment only. Findings are heuristic and require manual validation.</p><p>Target: "+html.escape(str(report.get("target","local source")))+"</p><p>Generated: "+html.escape(str(report.get("generated_at","")))+"</p>"+table+"</html>"
 p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(page,encoding="utf-8");return p
