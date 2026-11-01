// Minimal local Go source pattern audit. No network operations.
package main

import (
 "bufio"
 "encoding/json"
 "flag"
 "fmt"
 "os"
 "path/filepath"
 "strings"
)
type Finding struct { File string `json:"file"`; Line int `json:"line"`; Rule string `json:"rule"`; Detail string `json:"detail"` }
func main() {
 root:=flag.String("path",".","Source file or directory"); flag.Parse()
 var out []Finding
 _=filepath.Walk(*root,func(path string,info os.FileInfo,err error)error{
  if err!=nil{return nil};if info.IsDir(){if info.Name()==".git"||info.Name()=="vendor"{return filepath.SkipDir};return nil}
  if filepath.Ext(path)!=".go"{return nil}
  f,e:=os.Open(path);if e!=nil{return nil};defer f.Close()
  s:=bufio.NewScanner(f);line:=0
  for s.Scan(){line++;v:=s.Text()
   if strings.Contains(v,"InsecureSkipVerify: true"){out=append(out,Finding{path,line,"GO001","TLS certificate verification disabled"})}
   if strings.Contains(v,"http://"){out=append(out,Finding{path,line,"GO002","Plain HTTP URL literal; verify whether HTTPS is required"})}
  };return nil
 })
 b,_:=json.MarshalIndent(map[string]any{"tool":"Potential BlackTool Go audit","findings":out},"","  ");fmt.Println(string(b))
}
