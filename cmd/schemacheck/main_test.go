package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func diffJSON(t *testing.T, old, cur string) []string {
	t.Helper()
	var o, n any
	if err := json.Unmarshal([]byte(old), &o); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(cur), &n); err != nil {
		t.Fatal(err)
	}
	return Diff("s", o, n)
}

func TestDiffFindsBreakingChanges(t *testing.T) {
	cases := map[string][2]string{
		"enum value b removed":    {`{"enum":["a","b"]}`, `{"enum":["a"]}`},
		"became required":         {`{"required":[]}`, `{"required":["x"]}`},
		"closed":                  {`{"type":"object"}`, `{"type":"object","additionalProperties":false}`},
		"minimum raised":          {`{"minimum":0}`, `{"minimum":1}`},
		"type null no longer":     {`{"type":["string","null"]}`, `{"type":"string"}`},
		"a: enum value y removed": {`{"properties":{"a":{"enum":["x","y"]}}}`, `{"properties":{"a":{"enum":["x"]}}}`},
		"property a removed":      {`{"additionalProperties":false,"properties":{"a":{}}}`, `{"additionalProperties":false,"properties":{}}`},
		"pattern changed":         {`{"pattern":"^a"}`, `{"pattern":"^b"}`},
		"const v1 became v2":      {`{"const":"v1"}`, `{"const":"v2"}`},
		// A condition on a value the old schema already allowed narrows it.
		"allOf changed length": {`{"properties":{"t":{"enum":["a","b"]}},"allOf":[]}`, `{"properties":{"t":{"enum":["a","b"]}},"allOf":[{"if":{"properties":{"t":{"const":"b"}}},"then":{"required":["x"]}}]}`},
	}
	for want, c := range cases {
		got := strings.Join(diffJSON(t, c[0], c[1]), "\n")
		if !strings.Contains(got, want) {
			t.Errorf("%s: got %q", want, got)
		}
	}
}

func TestDiffAllowsWidening(t *testing.T) {
	cases := [][2]string{
		{`{"enum":["a"]}`, `{"enum":["a","b"]}`},
		{`{"additionalProperties":false,"properties":{}}`, `{"additionalProperties":false,"properties":{"new":{}}}`},
		{`{"required":["x"]}`, `{"required":[]}`},
		{`{"minimum":1}`, `{"minimum":0}`},
		{`{"type":"string"}`, `{"type":["string","null"]}`},
		{`{"$ref":"https://h/v1.0.0/common.schema.json#/a"}`, `{"$ref":"https://h/v1.1.0/common.schema.json#/a"}`},
		{`{"description":"old"}`, `{"description":"new"}`},
		// A condition gated on a newly added enum value only constrains
		// documents the old schema refused.
		{`{"properties":{"t":{"enum":["a"]}},"allOf":[{"x":1}]}`, `{"properties":{"t":{"enum":["a","b"]}},"allOf":[{"if":{"properties":{"t":{"const":"b"}}},"then":{"required":["x"]}},{"x":1}]}`},
	}
	for _, c := range cases {
		if got := diffJSON(t, c[0], c[1]); len(got) != 0 {
			t.Errorf("%s -> %s: %v", c[0], c[1], got)
		}
	}
}
