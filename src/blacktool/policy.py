"""Simple severity threshold gate for CI."""
ORDER={"info":0,"low":1,"medium":2,"high":3,"critical":4}
def violations(report,fail_on="high"):
 threshold=ORDER[fail_on]
 return [x for x in report.get("findings",[]) if ORDER.get(str(x.get("severity","info")).lower(),0)>=threshold]
