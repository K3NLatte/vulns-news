package live

import (
 "net/url"
 "sort"
 "strings"
 "time"

 "vulns-news/server/model"
 "vulns-news/src/scananalyze"
  "vulns-news/src/reposcan"
)

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
func nonempty(s, fallback string) string { if strings.TrimSpace(s) == "" { return fallback }; return s }

// Items deliberately leaves unknown severity, exploitation and confidence unknown.
// A dependency match is not proof of reachability or an exploitable deployment.
func Items(report scananalyze.Report, prepared []scananalyze.Prepared, records map[string]reposcan.SourceRecord) []model.FeedItem {
 inputs := make(map[string]scananalyze.Prepared, len(prepared))
 for _, p := range prepared { inputs[p.ID] = p }
 items := []model.FeedItem{}
 for _, entry := range report.Entries {
  f := entry.Feed
  p, ok := inputs[entry.ID]
  if f == nil || !ok || p.Error != "" { continue }
  v := p.Input.Vulnerability
  item := model.FeedItem{
   ID: entry.ID, AdvisoryID: entry.ID, Title: nonempty(v.Description, entry.ID),
   Product: "未確認", AffectedComponent: "未確認", AffectedVersions: "未確認", FixedVersion: "参照情報で確認してください",
   Severity: strings.ToLower(f.Severity), CVSS: f.CVSS,
   PublishedAt: stamp(f.PublishedAt), UpdatedAt: stamp(f.VulnerabilityRevision),
   Summary: nonempty(f.ScreeningReason, "スクリーニング結果を確認してください。"),
   Exploitation: "unknown", RepositoryAnalysis: "pending",
   Remediation: append([]string{}, f.Actions...), Sources: []model.FeedSource{},
   Analysis: model.FeedAnalysis{Summary: "深掘り解析は未実施です。", Evidence: "実行時の到達可能性・悪用条件は未確認です。", Confidence: "unknown"},
   Relevance: &model.FeedRelevance{Kind: "review", Priority: "review", Reason: nonempty(f.ScreeningReason, "要確認"), PackageName: "未確認", InstalledVersion: "未確認"},
  }
  switch item.Severity { case "critical", "high", "medium", "low", "none": default: item.Severity = "unknown" }
    var scoreEvidence string
    if item.CVSS==nil {
     if score:=osvCVSS(entry.RecordKeys,records); score!=nil {
      item.CVSS=&score.score; item.Severity=cvssSeverity(score.score); item.CVSSSource=score.source
      scoreEvidence="CVSS出典: "+score.source+"\nベクトル: "+score.vector+"\n複数出典はv4.0 > v3.1 > v3.0、同一版では最大の基本値を表示。リポジトリ固有のリスク評価ではありません。"
     }
    }
  // Source descriptions may be long; the full source remains in the saved scan.
  titleText := item.Title
    // Prepare prefixes each source description with its record key, not a headline.
    for _, key := range entry.RecordKeys { titleText = strings.TrimPrefix(titleText, key+":\n") }
    title := []rune(strings.Split(strings.TrimSpace(titleText), "\n")[0]); if len(title)>160 { title=title[:160] }; item.Title=string(title)
  packages, versions, installed, paths := []string{}, []string{}, []string{}, []string{}
  for _, c := range p.Input.Repository.Components {
   packages=append(packages,c.Name); versions=append(versions,c.Name+"@"+nonempty(c.Version,"未確認")); installed=append(installed,nonempty(c.Version,"未確認")); paths=append(paths,c.SourcePath)
  }
  if len(packages)>0 {
   item.Product=strings.Join(unique(packages),", "); item.AffectedComponent=strings.Join(unique(paths),", ")
   item.AffectedVersions="OSV照合済み: "+strings.Join(unique(versions),", ")
   item.Relevance.PackageName=item.Product; item.Relevance.InstalledVersion=strings.Join(unique(installed),", ")
  }
  if f.Summary != nil { item.Summary=f.Summary.Text }
  if f.RepositoryImpact != nil { item.Analysis.Summary=f.RepositoryImpact.Text; item.RepositoryAnalysis="analyzed" }
  evidence:=[]string{"repository: "+report.Repository.CanonicalURL, "commit: "+report.Repository.CommitSHA, "実行時の到達可能性・悪用条件は未確認です。"}
    if report.ScanStatus!="complete" { evidence=append(evidence,"スキャン範囲に未確認の項目があります。") }
  if f.Summary!=nil { evidence=append(evidence, "summary citations: "+strings.Join(f.Summary.EvidenceIDs,", ")) }
  if f.RepositoryImpact!=nil { evidence=append(evidence, "impact citations: "+strings.Join(f.RepositoryImpact.EvidenceIDs,", ")) }
  if scoreEvidence!="" { evidence=append(evidence,scoreEvidence) }
    evidence=append(evidence,f.MissingInfo...)
  item.Analysis.Evidence=strings.Join(evidence,"\n")
  seenURLs:=map[string]bool{}
  for _, ref:=range v.References {
   u,err:=url.Parse(ref.URL); if err!=nil || u.Scheme!="https" || u.Hostname()=="" || u.User!=nil { continue }
   // Deduplicate display links only; retain the first occurrence and raw provenance.
   if seenURLs[ref.URL] { continue }
   seenURLs[ref.URL]=true
   // Label the linked resource, not the OSV record that supplied the reference.
   _,label,_:=strings.Cut(ref.URL,"://")
   item.Sources=append(item.Sources,model.FeedSource{Name:label,URL:ref.URL,Kind:"reference"})
   if len(item.Sources)==100 { break }
  }
  items=append(items,item)
 }
 sort.Slice(items,func(i,j int)bool { if items[i].PublishedAt==items[j].PublishedAt { return items[i].ID<items[j].ID }; return items[i].PublishedAt>items[j].PublishedAt })
 return items
}
func unique(values []string) []string {
 seen:=map[string]bool{}; out:=[]string{}
 for _,v:=range values { if v!="" && !seen[v] { seen[v]=true; out=append(out,v) } }
 return out
}
