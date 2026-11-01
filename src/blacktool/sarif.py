"""SARIF 2.1.0 export for code and configuration findings."""
import json
from pathlib import Path
SEVERITY={"critical":"error","high":"error","medium":"warning","low":"note","info":"note"}
def to_sarif(report):
 results=[]; rules={}
 for index,item in enumerate(report.get("findings",[])):
  rule_id=item.get("rule_id") or ("PBT-"+str(item.get("area","GEN")).upper())
  level=SEVERITY.get(str(item.get("severity","info")).lower(),"note")
  rules[rule_id]={"id":rule_id,"shortDescription":{"text":str(item.get("title","Potential issue"))}}
  result={"ruleId":rule_id,"level":level,"message":{"text":str(item.get("detail","Finding requires review."))},
          "properties":{"severity":item.get("severity","info"),"recommendation":item.get("recommendation","")}}
  if item.get("file"):
   location={"physicalLocation":{"artifactLocation":{"uri":str(item["file"]).replace("\\","/")}}}
   if item.get("line"): location["physicalLocation"]["region"]={"startLine":int(item["line"])}
   result["locations"]=[location]
  results.append(result)
 return {"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json",
  "runs":[{"tool":{"driver":{"name":"Potential BlackTool","rules":list(rules.values())}},
           "results":results}]}
def write_sarif(report,path):
 p=Path(path);p.parent.mkdir(parents=True,exist_ok=True)
 p.write_text(json.dumps(to_sarif(report),indent=2),encoding="utf-8")
 return p
