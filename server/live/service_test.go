package live

import (
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "vulns-news/server/model"
 "vulns-news/src/processor"
 "vulns-news/src/reposcan"
 "vulns-news/src/scananalyze"
 "vulns-news/src/scanjob"
)

const fixture="../../cmd/repo-analyze/testdata/pre-citation-fix"
func openTest(t *testing.T,cfg Config)*Service {
 t.Helper(); if cfg.DataDir=="" { cfg.DataDir=t.TempDir() }; cfg.Workers=1; cfg.Capacity=4
 s,err:=Open(context.Background(),cfg); if err!=nil { t.Fatal(err) }; t.Cleanup(s.Close); return s
}
func request(t *testing.T,s *Service,method,path,body string,status int)[]byte {
 t.Helper(); r:=httptest.NewRequest(method,path,strings.NewReader(body)); if body!="" { r.Header.Set("Content-Type","application/json") }
 w:=httptest.NewRecorder(); s.Handler().ServeHTTP(w,r)
 if w.Code!=status { t.Fatalf("%s %s: %d %s",method,path,w.Code,w.Body.String()) }; return w.Body.Bytes()
}
func decode[T any](t *testing.T,data []byte)T { t.Helper(); var out T; if err:=json.Unmarshal(data,&out); err!=nil {t.Fatal(err)}; return out }
func TestOfflineImportRestartAndAPI(t *testing.T){
 dir:=t.TempDir(); s:=openTest(t,Config{DataDir:dir})
 job,err:=s.Import(filepath.Join(fixture,"scan.json"),filepath.Join(fixture,"analysis.json")); if err!=nil {t.Fatal(err)}
 if job.Stage!="failed" || job.ConfirmedCount==nil || *job.ConfirmedCount!=1 {t.Fatalf("partial report must not appear complete: %+v",job)}
 url:="/api/repositories/"+job.RepositoryID+"/feed"
 result:=decode[model.FeedResult](t,request(t,s,"GET",url,"",200)); if len(result.Items)!=1 {t.Fatalf("items=%d",len(result.Items))}
 item:=result.Items[0]
 if item.Exploitation!="unknown" || item.Analysis.Confidence!="unknown" || item.Relevance.Score!=nil || item.RepositoryAnalysis!="analyzed" {t.Fatalf("invented assessment: %+v",item)}
 detail:=decode[model.FeedItem](t,request(t,s,"GET",url+"/"+item.ID,"",200)); if detail.Summary!=item.Summary {t.Fatal("detail differs")}
 request(t,s,"GET",url+"/missing","",404)
 request(t,s,"GET","/api/repositories/missing/feed","",404)
 request(t,s,"GET","/api/cves?limit=0","",400)
 request(t,s,"GET","/api/cves?offset=-1","",400)
 empty:=decode[model.FeedResult](t,request(t,s,"GET",url+"?search=definitely-absent","",200)); if empty.Items==nil || len(empty.Items)!=0 {t.Fatal("empty feed is not []")}
 global:=decode[model.FeedResult](t,request(t,s,"GET","/api/cves","",200)); if global.Items[0].Relevance!=nil || global.Items[0].RepositoryAnalysis!="" {t.Fatal("global feed asserts scoped relevance")}
 s.Close(); reopened:=openTest(t,Config{DataDir:dir})
 restored:=decode[model.FeedResult](t,request(t,reopened,"GET",url,"",200)); if restored.Items[0].Summary!=item.Summary {t.Fatal("restart lost saved analysis")}
 ids:=decode[model.CreateRepositoryResponse](t,request(t,reopened,"POST","/api/repositories",`{"url":"https://github.com/example/archive-app","ref":"main"}`,202))
 if ids.JobID!=job.JobID {t.Fatal("registration did not reuse imported results")}
 request(t,reopened,"POST","/api/repositories",`{"url":"https://github.com/example/new"}`,503)
}
func TestSavedAnalysisCatalogReadOnly(t *testing.T) {
 s:=openTest(t,Config{})
 type catalog struct { ReadOnly bool `json:"readOnly"`; Items []struct { URL string `json:"url"`; Job model.JobResponse `json:"job"`; ItemCount int `json:"itemCount"`; Commit string `json:"commit"` } `json:"items"` }
 empty:=decode[catalog](t,request(t,s,"GET","/api/analyses","",200))
 if !empty.ReadOnly || empty.Items==nil || len(empty.Items)!=0 { t.Fatalf("empty catalog: %+v",empty) }
 job,err:=s.Import(filepath.Join(fixture,"scan.json"),filepath.Join(fixture,"analysis.json")); if err!=nil { t.Fatal(err) }
 before:=len(s.jobs)
 got:=decode[catalog](t,request(t,s,"GET","/api/analyses","",200))
 if len(got.Items)!=1 || got.Items[0].Job.JobID!=job.JobID || got.Items[0].ItemCount!=1 || got.Items[0].Commit=="" || got.Items[0].Job.Stage!="failed" { t.Fatalf("catalog lost partial results: %+v",got) }
 request(t,s,"GET","/api/repositories/"+got.Items[0].Job.RepositoryID+"/feed","",200)
 if len(s.jobs)!=before { t.Fatal("catalog read scheduled work") }
 enabled:=openTest(t,Config{Model:"test",Analyzer:fakeAnalyzer{}})
 if decode[catalog](t,request(t,enabled,"GET","/api/analyses","",200)).ReadOnly { t.Fatal("wrong service mode") }
}
func TestRestoreRejectsCorruptionAndRebuildsFeed(t *testing.T){
 state,err:=reposcan.Load(filepath.Join(fixture,"scan.json")); if err!=nil {t.Fatal(err)}
 data,err:=os.ReadFile(filepath.Join(fixture,"analysis.json")); if err!=nil {t.Fatal(err)}
 saved:=decode[scananalyze.Report](t,data)
 saved.Entries[0].Feed.Severity="fabricated"
 restored,err:=Restore(state,saved); if err!=nil {t.Fatal(err)}
 if restored.Entries[0].Feed.Severity=="fabricated" {t.Fatal("trusted serialized feed")}
 saved.Entries[0].Analysis.Analysis.Summary.Text="changed output"
 if _,err=Restore(state,saved); err==nil {t.Fatal("accepted corrupted output")}
}

type fakeAnalyzer struct{}
func (fakeAnalyzer) Screen(_ context.Context,input processor.Input)(processor.ScreeningOutput,error){
 ids:=[]string{}; for _,e:=range input.Evidence {if e.Kind==processor.EvidenceAdvisory || e.Kind==processor.EvidenceRepositoryDependency {ids=append(ids,e.ID)}}
 return processor.ScreeningOutput{Result:processor.ScreeningResult{Relevance:processor.RelevanceRelated,Reason:"Dependency match; runtime impact unverified",EvidenceIDs:ids},Generation:processor.Generation{Model:"test",DoneReason:"stop"}},nil
}
func (a fakeAnalyzer) Analyze(ctx context.Context,input processor.Input)(processor.AnalysisOutput,error){
 screen,_:=a.Screen(ctx,input); claim:=processor.SupportedClaim{Text:"Dependency evidence only; runtime impact unknown",EvidenceIDs:screen.Result.EvidenceIDs}
 return processor.AnalysisOutput{Analysis:processor.DeepAnalysis{Summary:claim,RepositoryImpact:claim,MissingInformation:[]string{"Runtime reachability"},RecommendedActions:[]string{"Review advisory"}},Generation:processor.Generation{Model:"test",DoneReason:"stop"}},nil
}
func TestQueuedScanAnalysisPersistenceFeed(t *testing.T){
 state,err:=reposcan.Load(filepath.Join(fixture,"scan.json")); if err!=nil {t.Fatal(err)}
 started,release:=make(chan struct{}),make(chan struct{})
 s:=openTest(t,Config{Model:"test",Analyzer:fakeAnalyzer{},Discover:func(ctx context.Context,r scanjob.Request)(reposcan.State,error){close(started); select {case <-release:return state,nil;case <-ctx.Done():return reposcan.State{},ctx.Err()}}})
 ids:=decode[model.CreateRepositoryResponse](t,request(t,s,"POST","/api/repositories",`{"url":"https://github.com/example/archive-app","ref":"main"}`,202))
 <-started
 duplicate:=decode[model.CreateRepositoryResponse](t,request(t,s,"POST","/api/repositories",`{"url":"https://github.com/example/archive-app","ref":"main"}`,202))
 if duplicate!=ids {t.Fatal("duplicate work scheduled")}
 close(release)
 deadline:=time.Now().Add(5*time.Second)
 for {
  job:=decode[model.JobResponse](t,request(t,s,"GET","/api/jobs/"+ids.JobID,"",200))
  if job.Stage=="completed" {if *job.ConfirmedCount!=3 {t.Fatalf("job=%+v",job)};break}
  if job.Stage=="failed" || time.Now().After(deadline){t.Fatalf("job did not complete: %+v",job)}
  time.Sleep(time.Millisecond)
 }
 path:="/api/repositories/"+ids.RepositoryID+"/feed"
 page:=decode[model.FeedResult](t,request(t,s,"GET",path+"?limit=2","",200)); if page.Total!=3 || page.NextOffset==nil || *page.NextOffset!=2 {t.Fatalf("page=%+v",page)}
 last:=decode[model.FeedResult](t,request(t,s,"GET",path+"?limit=2&offset=2","",200)); if len(last.Items)!=1 || last.NextOffset!=nil {t.Fatal("bad final page")}
 s.Close(); reopened:=openTest(t,Config{DataDir:s.cfg.DataDir})
 final:=decode[model.FeedResult](t,request(t,reopened,"GET",path,"",200)); if len(final.Items)!=3 {t.Fatal("scan->analysis->disk->feed lost items")}
}
func TestInvalidRegistration(t *testing.T){
 s:=openTest(t,Config{})
 for _,body:=range []string{`{}`,`{"url":null}`,`{"URL":"https://github.com/a/b"}`,`{"url":"https://github.com/a/b","url":"https://github.com/a/c"}`,`{"url":"http://127.0.0.1/private"}`,`{"url":"https://github.com/a/b","ref":"--help"}`,`{"url":"https://github.com/a/b"} {}`} {
  request(t,s,http.MethodPost,"/api/repositories",body,400)
 }
}

// Opt-in validation of operator-provided saved results; no model/network calls.
func TestSavedAnalysisIntegration(t *testing.T){
 scan,analysis:=os.Getenv("NEWS_TEST_SCAN"),os.Getenv("NEWS_TEST_ANALYSIS")
 if scan=="" || analysis=="" {t.Skip("set NEWS_TEST_SCAN and NEWS_TEST_ANALYSIS to validate existing analysis")}
 s:=openTest(t,Config{})
 job,err:=s.Import(scan,analysis); if err!=nil {t.Fatal(err)}
 body:=request(t,s,"GET","/api/repositories/"+job.RepositoryID+"/feed","",200)
 result:=decode[model.FeedResult](t,body)
 if len(result.Items)==0 {t.Fatal("no validated feed items")}
 for _,item:=range result.Items {
  seen:=map[string]bool{}
  for _,source:=range item.Sources {
   if seen[source.URL] {t.Fatalf("%s has duplicate source URL %q",item.ID,source.URL)}
   seen[source.URL]=true
  }
 }
 t.Logf("imported %d items; confirmed=%d pending=%d",result.Total,*job.ConfirmedCount,*job.PendingCount)
 if output:=os.Getenv("NEWS_TEST_FEED"); output!="" {if err:=os.WriteFile(output,body,0600);err!=nil {t.Fatal(err)}}
}
