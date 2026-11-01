#!/usr/bin/env node
// Read-only JavaScript/TypeScript pattern checker. Usage: node audit.mjs <file-or-directory>
import fs from "node:fs";
import path from "node:path";
const rules=[
 ["JS001","high",/\beval\s*\(/,"Avoid eval; use explicit parsing and dispatch."],
 ["JS002","high",/innerHTML\s*=/,"Avoid inserting untrusted data with innerHTML; prefer textContent or vetted sanitization."],
 ["JS003","medium",/\bhttp:\/\//i,"Use HTTPS for production service endpoints."],
 ["JS004","medium",/Math\.random\s*\(/,"Do not use Math.random for security-sensitive tokens; use crypto APIs."]
];
const ignored=new Set(["node_modules",".git","dist","build",".next"]);
function walk(p){const s=fs.statSync(p);if(s.isFile())return [p];return fs.readdirSync(p).filter(n=>!ignored.has(n)).flatMap(n=>walk(path.join(p,n)));}
const target=process.argv[2];if(!target){console.error("Usage: node audit.mjs <file-or-directory>");process.exit(2);}
const findings=[];
for(const file of walk(target)){if(!/\.(mjs|cjs|js|jsx|ts|tsx|vue)$/.test(file))continue;
 const lines=fs.readFileSync(file,"utf8").split(/\r?\n/);
 lines.forEach((line,i)=>{for(const [id,severity,recommendation] of rules)if(recommendation.test(line))findings.push({rule_id:id,severity,file,line:i+1,recommendation});});
}
console.log(JSON.stringify({tool:"Potential BlackTool JS audit",findings},null,2));
