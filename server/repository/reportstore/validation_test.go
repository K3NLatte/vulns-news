package reportstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validationFixture() Input {
	return Input{
		ContextKey: ContextKey{
			RepositoryID: "example/repo", RepositoryCommit: "abc123",
			VulnerabilityID: "GHSA-example", VulnerabilityRevision: "2026-09-29T00:00:00.123456789Z",
		},
		PublishedAt: "2026-09-28T00:00:00Z", Status: Analyzed, Relevance: Related,
		Body: json.RawMessage(`{
			"matches":[{"reason":"exact","extension":{"counter":9007199254740993}}],
			"screening_reason":"対象と一致",
			"summary":{"text":"Summary","evidence_ids":["E1"]},
			"repository_impact":{"text":"Impact","evidence_ids":["E1"]},
			"missing_information":["Usage"],"recommended_actions":["Review"],
			"applicability":{"package_presence":{"level":1,"status":"confirmed","sources":[],"evidence_ids":[],"missing_reasons":[]},"extension":{"evidence_ids":["E1"]}},
			"evidence":[{"id":"E1","kind":"advisory","source":"OSV","uri":"https://example.test/a","content":"Evidence"}]
		}`),
	}
}

func requireInvalid(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

func editValidationBody(t *testing.T, input *Input, edit func(map[string]any)) {
	t.Helper()
	var body map[string]any
	decoder := json.NewDecoder(bytes.NewReader(input.Body))
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		t.Fatal(err)
	}
	edit(body)
	var err error
	input.Body, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
}

func TestInputMetadataValidation(t *testing.T) {
	if err := validateInput(validationFixture()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Input){
		"repository": func(i *Input) { i.RepositoryID = " \t" },
		"commit":     func(i *Input) { i.RepositoryCommit = "" },
		"canonical ID": func(i *Input) {
			i.VulnerabilityID = ""
			i.CVEID = "CVE-2026-1"
			i.CVERevision = i.VulnerabilityRevision
		},
		"invalid UTF8":         func(i *Input) { i.RepositoryID = string([]byte{0xff}) },
		"zero revision":        func(i *Input) { i.VulnerabilityRevision = "0001-01-01T00:00:00Z" },
		"invalid day":          func(i *Input) { i.VulnerabilityRevision = "2026-02-30T00:00:00Z" },
		"offset":               func(i *Input) { i.VulnerabilityRevision = "2026-09-29T00:00:00+00:00" },
		"fraction precision":   func(i *Input) { i.PublishedAt = "2026-09-29T00:00:00.1234567890Z" },
		"comma fraction":       func(i *Input) { i.PublishedAt = "2026-09-29T00:00:00,1Z" },
		"zero published":       func(i *Input) { i.PublishedAt = "0001-01-01T00:00:00Z" },
		"blank CVE":            func(i *Input) { i.CVEID = " " },
		"revision without CVE": func(i *Input) { i.CVERevision = i.VulnerabilityRevision },
		"CVE zero revision":    func(i *Input) { i.CVEID = "CVE-2026-1"; i.CVERevision = "0001-01-01T00:00:00Z" },
		"blank severity":       func(i *Input) { i.Severity = "　" },
		"screened related":     func(i *Input) { i.Status = Screened },
		"analyzed unknown":     func(i *Input) { i.Relevance = Unknown },
		"pending":              func(i *Input) { i.Status = "pending" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			input := validationFixture()
			edit(&input)
			requireInvalid(t, validateInput(input))
		})
	}
	for _, score := range []float64{-1, 10.1, math.NaN(), math.Inf(1)} {
		input := validationFixture()
		input.CVSS = &score
		requireInvalid(t, validateInput(input))
	}
	for _, score := range []float64{0, 8.1, 10} {
		input := validationFixture()
		input.CVSS = &score
		if err := validateInput(input); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOptionalInputDates(t *testing.T) {
	for _, published := range []string{"", "2026-09-28T00:00:00Z"} {
		for _, revision := range []string{"", "2026-09-29T00:00:00.123456789Z"} {
			for _, cveRevision := range []string{"", "2026-09-29T00:00:00Z"} {
				input := validationFixture()
				input.PublishedAt, input.VulnerabilityRevision = published, revision
				input.CVEID, input.CVERevision = "CVE-2026-1", cveRevision
				if err := validateInput(input); err != nil {
					t.Fatalf("published=%q revision=%q cve_revision=%q: %v", published, revision, cveRevision, err)
				}
				data, err := ToFeedJSON(Report{Input: input})
				if err != nil {
					t.Fatal(err)
				}
				converted, err := FromFeedJSON(data, nil)
				if err != nil {
					t.Fatal(err)
				}
				if converted.ContextKey != input.ContextKey || converted.PublishedAt != published || converted.CVEID != input.CVEID || converted.CVERevision != cveRevision {
					t.Fatal("independent CVE and canonical revision states changed")
				}
			}
		}
	}
}

func setUnknownFeedDate(object map[string]any, key, representation string) {
	switch representation {
	case "missing":
		delete(object, key)
	case "null":
		object[key] = nil
	case "empty":
		object[key] = ""
	case "zero":
		object[key] = "0001-01-01T00:00:00Z"
	case "zero fraction":
		object[key] = "0001-01-01T00:00:00.000000000Z"
	}
}

func TestFeedOptionalDatesRoundTrip(t *testing.T) {
	for _, source := range []string{"GHSA", "CVE", "GHSA with CVE"} {
		for _, publishedKnown := range []bool{false, true} {
			for _, revisionKnown := range []bool{false, true} {
				for _, representation := range []string{"missing", "null", "empty", "zero", "zero fraction"} {
					name := fmt.Sprintf("%s/published=%t/revision=%t/%s", source, publishedKnown, revisionKnown, representation)
					t.Run(name, func(t *testing.T) {
						input := validationFixture()
						if source != "GHSA" {
							input.CVEID, input.CVERevision = "CVE-2026-1", input.VulnerabilityRevision
						}
						if source == "CVE" {
							input.VulnerabilityID = input.CVEID
						}
						data, err := ToFeedJSON(Report{Input: input})
						if err != nil {
							t.Fatal(err)
						}
						feed, err := readObject(data)
						if err != nil {
							t.Fatal(err)
						}
						if !publishedKnown {
							setUnknownFeedDate(feed, "published_at", representation)
							input.PublishedAt = ""
						}
						if !revisionKnown {
							setUnknownFeedDate(feed, "vulnerability_revision", representation)
							setUnknownFeedDate(feed["applicability"].(map[string]any), "vulnerability_revision", representation)
							setUnknownFeedDate(feed, "cve_revision", representation)
							input.VulnerabilityRevision, input.CVERevision = "", ""
						}
						data, err = json.Marshal(feed)
						if err != nil {
							t.Fatal(err)
						}
						converted, err := FromFeedJSON(data, nil)
						if err != nil {
							t.Fatal(err)
						}
						if converted.ContextKey != input.ContextKey || converted.PublishedAt != input.PublishedAt || converted.CVEID != input.CVEID || converted.CVERevision != input.CVERevision {
							t.Fatalf("date or identity changed: %+v", converted)
						}
						roundtrip, err := ToFeedJSON(Report{Input: converted})
						if err != nil {
							t.Fatal(err)
						}
						output, err := readObject(roundtrip)
						if err != nil {
							t.Fatal(err)
						}
						for key, want := range map[string]string{"published_at": input.PublishedAt, "vulnerability_revision": input.VulnerabilityRevision, "cve_revision": input.CVERevision} {
							got, exists := output[key]
							if (want == "" && exists) || (want != "" && got != want) {
								t.Fatalf("%s=%v exists=%t, want %q or omission if unknown", key, got, exists, want)
							}
						}
						if _, exists := output["applicability"].(map[string]any)["vulnerability_revision"]; exists != revisionKnown {
							t.Fatal("applicability revision presence differs from authoritative column")
						}
						// バックエンドのフィードでは time.Time 型のフィールドを使うため、JSON の空文字列は受け付けない。
						var typed struct {
							PublishedAt           time.Time `json:"published_at"`
							VulnerabilityRevision time.Time `json:"vulnerability_revision"`
							CVERevision           time.Time `json:"cve_revision"`
							Applicability         struct {
								VulnerabilityRevision time.Time `json:"vulnerability_revision"`
							} `json:"applicability"`
						}
						if err := json.Unmarshal(roundtrip, &typed); err != nil {
							t.Fatalf("backend time.Time compatibility: %v", err)
						}
						if typed.PublishedAt.IsZero() == publishedKnown || typed.VulnerabilityRevision.IsZero() == revisionKnown || typed.CVERevision.IsZero() != (input.CVERevision == "") || typed.Applicability.VulnerabilityRevision != typed.VulnerabilityRevision {
							t.Fatal("backend timestamps changed known/unknown state")
						}
						again, err := FromFeedJSON(roundtrip, nil)
						if err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(again, converted) {
							t.Fatal("feed roundtrip changed report data")
						}
					})
				}
			}
		}
	}
}

func TestFeedUnknownRevisionIdentity(t *testing.T) {
	input := validationFixture()
	input.VulnerabilityRevision = ""
	data, err := ToFeedJSON(Report{Input: input})
	if err != nil {
		t.Fatal(err)
	}
	for _, top := range []string{"missing", "null", "empty", "zero", "zero fraction"} {
		for _, nested := range []string{"missing", "null", "empty", "zero", "zero fraction", "known", "malformed", "wrong type"} {
			t.Run(top+"/"+nested, func(t *testing.T) {
				feed, err := readObject(data)
				if err != nil {
					t.Fatal(err)
				}
				setUnknownFeedDate(feed, "vulnerability_revision", top)
				app := feed["applicability"].(map[string]any)
				setUnknownFeedDate(app, "vulnerability_revision", nested)
				switch nested {
				case "known":
					app["vulnerability_revision"] = "2026-09-29T00:00:00Z"
				case "malformed":
					app["vulnerability_revision"] = "invalid"
				case "wrong type":
					app["vulnerability_revision"] = false
				}
				raw, err := json.Marshal(feed)
				if err != nil {
					t.Fatal(err)
				}
				converted, err := FromFeedJSON(raw, nil)
				if nested == "known" || nested == "malformed" || nested == "wrong type" {
					requireInvalid(t, err)
				} else if err != nil || converted.VulnerabilityRevision != "" {
					t.Fatalf("unknown revisions did not match: %+v, %v", converted, err)
				}
			})
		}
	}
}

func TestFeedInvalidDates(t *testing.T) {
	input := validationFixture()
	input.CVEID, input.CVERevision = "CVE-2026-1", input.VulnerabilityRevision
	data, err := ToFeedJSON(Report{Input: input})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"published_at", "vulnerability_revision", "cve_revision"} {
		for _, bad := range []any{" ", "invalid", "2026-02-30T00:00:00Z", "2026-09-29T00:00:00+00:00", false, 42} {
			t.Run(fmt.Sprintf("%s/%v", field, bad), func(t *testing.T) {
				feed, err := readObject(data)
				if err != nil {
					t.Fatal(err)
				}
				feed[field] = bad
				if field == "vulnerability_revision" {
					feed["applicability"].(map[string]any)[field] = bad
				}
				raw, err := json.Marshal(feed)
				if err != nil {
					t.Fatal(err)
				}
				_, err = FromFeedJSON(raw, nil)
				requireInvalid(t, err)
			})
		}
	}
	feed, err := readObject(data)
	if err != nil {
		t.Fatal(err)
	}
	delete(feed, "cve_id")
	raw, err := json.Marshal(feed)
	if err != nil {
		t.Fatal(err)
	}
	_, err = FromFeedJSON(raw, nil)
	requireInvalid(t, err)
}

func TestInputBodyContract(t *testing.T) {
	cases := map[string]func(map[string]any){
		"unknown top field":           func(b map[string]any) { b["new_field"] = true },
		"metadata null":               func(b map[string]any) { b["repository_id"] = nil },
		"generation null":             func(b map[string]any) { b["generation"] = nil },
		"missing reason":              func(b map[string]any) { delete(b, "screening_reason") },
		"blank reason":                func(b map[string]any) { b["screening_reason"] = " " },
		"null matches":                func(b map[string]any) { b["matches"] = nil },
		"scalar match":                func(b map[string]any) { b["matches"] = []any{"x"} },
		"wrong match field":           func(b map[string]any) { b["matches"] = []any{map[string]any{"reason": 2}} },
		"missing applicability":       func(b map[string]any) { delete(b, "applicability") },
		"null applicability":          func(b map[string]any) { b["applicability"] = nil },
		"duplicated nested ID":        func(b map[string]any) { b["applicability"].(map[string]any)["repository_commit"] = nil },
		"wrong stage":                 func(b map[string]any) { b["applicability"].(map[string]any)["feature_usage"] = []any{} },
		"wrong applicability matches": func(b map[string]any) { b["applicability"].(map[string]any)["matches"] = []any{nil} },
		"missing claim":               func(b map[string]any) { delete(b, "summary") },
		"blank claim":                 func(b map[string]any) { b["summary"].(map[string]any)["text"] = " " },
		"empty claim refs":            func(b map[string]any) { b["summary"].(map[string]any)["evidence_ids"] = []any{} },
		"unknown ref":                 func(b map[string]any) { b["summary"].(map[string]any)["evidence_ids"] = []any{"missing"} },
		"duplicate refs":              func(b map[string]any) { b["summary"].(map[string]any)["evidence_ids"] = []any{"E1", "E1"} },
		"nested ref": func(b map[string]any) {
			b["applicability"].(map[string]any)["extension"] = map[string]any{"evidence_ids": []any{"missing"}}
		},
		"null nested refs": func(b map[string]any) {
			b["applicability"].(map[string]any)["extension"] = map[string]any{"evidence_ids": nil}
		},
		"empty screening refs":     func(b map[string]any) { b["screening_evidence_ids"] = []any{} },
		"wrong actions":            func(b map[string]any) { b["recommended_actions"] = []any{false} },
		"empty evidence":           func(b map[string]any) { b["evidence"] = []any{} },
		"scalar evidence":          func(b map[string]any) { b["evidence"] = []any{"x"} },
		"duplicate evidence":       func(b map[string]any) { e := b["evidence"].([]any); b["evidence"] = append(e, e[0]) },
		"missing evidence content": func(b map[string]any) { delete(b["evidence"].([]any)[0].(map[string]any), "content") },
		"nontext uri":              func(b map[string]any) { b["evidence"].([]any)[0].(map[string]any)["uri"] = false },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			input := validationFixture()
			editValidationBody(t, &input, edit)
			requireInvalid(t, validateInput(input))
		})
	}
	for _, relevance := range []Relevance{PossiblyRelated, Unknown, Unrelated} {
		input := validationFixture()
		input.Status, input.Relevance = Screened, relevance
		requireInvalid(t, validateInput(input))
		editValidationBody(t, &input, func(b map[string]any) {
			b["summary"], b["repository_impact"] = nil, nil
			b["missing_information"], b["recommended_actions"] = nil, nil
			b["screening_evidence_ids"] = []any{"E1"}
			if relevance == Unrelated {
				delete(b, "applicability")
			}
		})
		if err := validateInput(input); err != nil {
			t.Fatalf("%s: %v", relevance, err)
		}
	}
}

func TestStrictJSONBoundary(t *testing.T) {
	cases := []string{
		`[]`, `null`, `true`, `{broken`, `{}`, `{} {}`, `{} garbage`,
		`{"screening_reason":"a","screening_reason":"b"}`,
		`{"matches":[{"reason":"a","reason":"b"}]}`,
		`{"matches":[{"reason":"a","rea\u0073on":"b"}]}`,
		`{"extension":` + strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66) + "}",
		`{"content":"` + string([]byte{0xff}) + `"}`,
		strings.Repeat(" ", MaxBodyBytes+1),
	}
	for _, body := range cases {
		input := validationFixture()
		input.Body = json.RawMessage(body)
		requireInvalid(t, validateInput(input))
		_, err := FromFeedJSON([]byte(body), nil)
		requireInvalid(t, err)
	}
}

func TestFeedConversionPreservesSelectedData(t *testing.T) {
	input := validationFixture()
	editValidationBody(t, &input, func(b map[string]any) {
		b["summary"].(map[string]any)["text"] = "'); DROP TABLE reports; -- <script>text</script>"
	})
	data, err := ToFeedJSON(Report{ID: 12, Input: input, StoredAt: "2026-09-29T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	var source map[string]json.RawMessage
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	source["cve_revision"] = json.RawMessage(`"0001-01-01T00:00:00Z"`)
	source["generation"] = json.RawMessage(`[{"model":"fixture","tokens":123}]`)
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), raw...)
	converted, err := FromFeedJSON(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("source was mutated")
	}
	if converted.CVEID != "" || converted.CVERevision != "" {
		t.Fatal("absent CVE was not normalized")
	}
	if converted.VulnerabilityRevision != input.VulnerabilityRevision {
		t.Fatal("revision precision changed")
	}
	if !bytes.Contains(converted.Body, []byte("9007199254740993")) {
		t.Fatal("nested integer lost precision")
	}
	roundtrip, err := ToFeedJSON(Report{Input: converted})
	if err != nil {
		t.Fatal(err)
	}
	var actual, expected any
	if err := json.Unmarshal(roundtrip, &actual); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatal("selected feed data changed after roundtrip")
	}
	for _, key := range []string{"generation", "report_id", "stored_at", "cve_revision"} {
		if _, exists := actual.(map[string]any)[key]; exists {
			t.Fatalf("unexpected %s in feed", key)
		}
	}
	converted.Body = json.RawMessage(`{}`)
	_, err = ToFeedJSON(Report{Input: converted})
	requireInvalid(t, err)
}

func TestFeedIdentityAndScreeningValidation(t *testing.T) {
	data, err := ToFeedJSON(Report{Input: validationFixture()})
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(t *testing.T, edit func(map[string]any)) []byte {
		t.Helper()
		var feed map[string]any
		if err := json.Unmarshal(data, &feed); err != nil {
			t.Fatal(err)
		}
		edit(feed)
		result, err := json.Marshal(feed)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	for _, key := range contextFields {
		for _, mode := range []string{"missing", "null", "different"} {
			t.Run(key+"/"+mode, func(t *testing.T) {
				bad := mutate(t, func(f map[string]any) {
					app := f["applicability"].(map[string]any)
					switch mode {
					case "missing":
						delete(app, key)
					case "null":
						app[key] = nil
					default:
						app[key] = "different"
					}
				})
				_, err := FromFeedJSON(bad, nil)
				requireInvalid(t, err)
			})
		}
	}
	bad := mutate(t, func(f map[string]any) { f["new_runtime_field"] = nil })
	_, err = FromFeedJSON(bad, nil)
	requireInvalid(t, err)
	for _, score := range []any{true, "8.1", map[string]any{}, []any{}} {
		bad := mutate(t, func(f map[string]any) { f["cvss"] = score })
		_, err := FromFeedJSON(bad, nil)
		requireInvalid(t, err)
	}
	decision := Screening{Relevance: Related, Reason: "対象と一致", EvidenceIDs: []string{"E1"}}
	converted, err := FromFeedJSON(data, &decision)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(converted.Body, []byte(`"screening_evidence_ids":["E1"]`)) {
		t.Fatal("screening refs missing")
	}
	for _, badDecision := range []Screening{
		{Relevance: Unrelated, Reason: decision.Reason, EvidenceIDs: []string{"E1"}},
		{Relevance: Related, Reason: "different", EvidenceIDs: []string{"E1"}},
		{Relevance: Related, Reason: decision.Reason},
		{Relevance: Related, Reason: decision.Reason, EvidenceIDs: []string{"missing"}},
		{Relevance: Related, Reason: decision.Reason, EvidenceIDs: []string{"E1", "E1"}},
	} {
		_, err := FromFeedJSON(data, &badDecision)
		requireInvalid(t, err)
	}
	bad = mutate(t, func(f map[string]any) { f["screening_evidence_ids"] = []any{"different"} })
	_, err = FromFeedJSON(bad, &decision)
	requireInvalid(t, err)
}

func TestUnrelatedInputRequiresScreeningEvidence(t *testing.T) {
	input := validationFixture()
	input.Status, input.Relevance = Screened, Unrelated
	var body map[string]json.RawMessage
	if err := json.Unmarshal(input.Body, &body); err != nil {
		t.Fatal(err)
	}
	delete(body, "summary")
	delete(body, "repository_impact")
	delete(body, "applicability")
	body["screening_evidence_ids"] = json.RawMessage(`["E1"]`)
	input.Body, _ = json.Marshal(body)
	if err := validateInput(input); err != nil {
		t.Fatal(err)
	}
	delete(body, "screening_evidence_ids")
	input.Body, _ = json.Marshal(body)
	requireInvalid(t, validateInput(input))
}
