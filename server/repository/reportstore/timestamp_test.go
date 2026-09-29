package reportstore

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestCanonicalTimestamp(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"", ""},
		{"2026-09-24T12:00:00Z", "2026-09-24T12:00:00Z"},
		{"2026-09-24T12:00:00.000Z", "2026-09-24T12:00:00Z"},
		{"2026-09-24T12:00:00.000000000Z", "2026-09-24T12:00:00Z"},
		{"2026-09-24T12:00:00.123450000Z", "2026-09-24T12:00:00.12345Z"},
		{"2026-09-24T12:00:00.000000001Z", "2026-09-24T12:00:00.000000001Z"},
		{"2026-09-24T12:00:00.123456789Z", "2026-09-24T12:00:00.123456789Z"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := canonicalTimestamp(tc.input)
			if err != nil || got != tc.want {
				t.Fatalf("canonicalTimestamp(%q) = %q, %v; want %q", tc.input, got, err, tc.want)
			}
			again, err := canonicalTimestamp(got)
			if err != nil || again != got {
				t.Fatalf("normalization is not idempotent: %q, %v", again, err)
			}
		})
	}
	for _, bad := range []string{
		" ", "invalid", "2026-02-30T12:00:00Z", "2026-09-24T12:00:60Z",
		"2026-09-24T12:00:00+00:00", "2026-09-24T21:00:00+09:00",
		"2026-09-24T12:00:00.1234567890Z", "2026-09-24T12:00:00,1Z",
		"0001-01-01T00:00:00Z", "0001-01-01T00:00:00.000Z",
		"0001-01-01T00:00:00.000000001Z", "0000-01-01T00:00:00Z",
	} {
		t.Run(bad, func(t *testing.T) {
			_, err := canonicalTimestamp(bad)
			requireInvalid(t, err)
		})
	}
}

func TestCanonicalizeInputTimesPreservesOtherData(t *testing.T) {
	input := validationFixture()
	input.VulnerabilityRevision = "2026-09-24T12:00:00.000Z"
	input.PublishedAt = "2026-09-24T11:00:00.123450000Z"
	input.CVEID, input.CVERevision = "CVE-2026-1", "2026-09-24T12:00:00.123456789Z"
	body := append([]byte(nil), input.Body...)
	got, err := canonicalizeInputTimes(input)
	if err != nil {
		t.Fatal(err)
	}
	want := input
	want.VulnerabilityRevision = "2026-09-24T12:00:00Z"
	want.PublishedAt = "2026-09-24T11:00:00.12345Z"
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalization changed data or precision: got %+v, want %+v", got, want)
	}
	if input.VulnerabilityRevision != "2026-09-24T12:00:00.000Z" || !bytes.Equal(input.Body, body) {
		t.Fatal("normalization mutated the caller's input")
	}
	key, err := canonicalizeContextKey(input.ContextKey)
	if err != nil || key != want.ContextKey {
		t.Fatalf("context normalization = %+v, %v; want %+v", key, err, want.ContextKey)
	}
	input.PublishedAt, input.VulnerabilityRevision, input.CVERevision = "", "", ""
	got, err = canonicalizeInputTimes(input)
	if err != nil || !reflect.DeepEqual(got, input) {
		t.Fatalf("unknown dates changed: %+v, %v", got, err)
	}
	for _, field := range []string{"published_at", "vulnerability_revision", "cve_revision"} {
		t.Run(field, func(t *testing.T) {
			invalidInput := input
			switch field {
			case "published_at":
				invalidInput.PublishedAt = "0001-01-01T00:00:00.000Z"
			case "vulnerability_revision":
				invalidInput.VulnerabilityRevision = "0001-01-01T00:00:00.000Z"
			case "cve_revision":
				invalidInput.CVERevision = "0001-01-01T00:00:00.000Z"
			}
			_, err := canonicalizeInputTimes(invalidInput)
			requireInvalid(t, err)
			_, err = ToFeedJSON(Report{Input: invalidInput})
			requireInvalid(t, err)
		})
	}
}

func TestFeedRevisionUsesTimestampIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, top, nested, want string
		invalid                 bool
	}{
		{"fractional zeros", "2026-09-24T12:00:00.000Z", "2026-09-24T12:00:00Z", "2026-09-24T12:00:00Z", false},
		{"nested fractional zeros", "2026-09-24T12:00:00Z", "2026-09-24T12:00:00.000000000Z", "2026-09-24T12:00:00Z", false},
		{"significant fraction", "2026-09-24T12:00:00.123000000Z", "2026-09-24T12:00:00.1230Z", "2026-09-24T12:00:00.123Z", false},
		{"nanosecond precision", "2026-09-24T12:00:00.123456789Z", "2026-09-24T12:00:00.123456789Z", "2026-09-24T12:00:00.123456789Z", false},
		{"one nanosecond different", "2026-09-24T12:00:00.123000000Z", "2026-09-24T12:00:00.123000001Z", "", true},
		{"unknown remains distinct", "", "2026-09-24T12:00:00Z", "", true},
		{"malformed nested revision", "", "invalid", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := ToFeedJSON(Report{Input: validationFixture()})
			if err != nil {
				t.Fatal(err)
			}
			feed, err := readObject(data)
			if err != nil {
				t.Fatal(err)
			}
			feed["vulnerability_revision"] = tc.top
			feed["applicability"].(map[string]any)["vulnerability_revision"] = tc.nested
			feed["published_at"] = "2026-09-24T11:00:00.000Z"
			feed["cve_id"], feed["cve_revision"] = "CVE-2026-1", "2026-09-24T12:00:00.123450000Z"
			data, err = json.Marshal(feed)
			if err != nil {
				t.Fatal(err)
			}
			converted, err := FromFeedJSON(data, nil)
			if tc.invalid {
				requireInvalid(t, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if converted.VulnerabilityRevision != tc.want || converted.PublishedAt != "2026-09-24T11:00:00Z" || converted.CVERevision != "2026-09-24T12:00:00.12345Z" {
				t.Fatalf("feed dates were not canonicalized: %+v", converted)
			}
			roundtrip, err := ToFeedJSON(Report{Input: converted})
			if err != nil {
				t.Fatal(err)
			}
			output, err := readObject(roundtrip)
			if err != nil {
				t.Fatal(err)
			}
			if output["vulnerability_revision"] != tc.want || output["applicability"].(map[string]any)["vulnerability_revision"] != tc.want {
				t.Fatal("exported revision spellings differ")
			}
			again, err := FromFeedJSON(roundtrip, nil)
			if err != nil || !reflect.DeepEqual(again, converted) {
				t.Fatalf("roundtrip changed input: %+v, %v", again, err)
			}
		})
	}
}

func TestFeedExportCanonicalizesTimestampColumns(t *testing.T) {
	input := validationFixture()
	input.VulnerabilityRevision = "2026-09-24T12:00:00.000Z"
	input.PublishedAt = "2026-09-24T11:00:00.123450000Z"
	input.CVEID, input.CVERevision = "CVE-2026-1", "2026-09-24T12:00:00.123456789Z"
	data, err := ToFeedJSON(Report{Input: input})
	if err != nil {
		t.Fatal(err)
	}
	feed, err := readObject(data)
	if err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]string{
		"vulnerability_revision": "2026-09-24T12:00:00Z",
		"published_at":           "2026-09-24T11:00:00.12345Z",
		"cve_revision":           "2026-09-24T12:00:00.123456789Z",
	} {
		if feed[field] != want {
			t.Fatalf("%s = %v; want %q", field, feed[field], want)
		}
	}
	if feed["applicability"].(map[string]any)["vulnerability_revision"] != feed["vulnerability_revision"] {
		t.Fatal("exported applicability revision differs from top-level revision")
	}
	if input.VulnerabilityRevision != "2026-09-24T12:00:00.000Z" {
		t.Fatal("export mutated the caller's input")
	}
}
