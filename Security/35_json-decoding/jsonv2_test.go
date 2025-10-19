//go:build goexperiment.jsonv2 && !go1.26

// These tests only build with a Go 1.25 toolchain and GOEXPERIMENT=jsonv2,
// which adds the experimental encoding/json/v2 and encoding/json/jsontext
// packages. The !go1.26 constraint pins them to the API as shipped in 1.25:
//
//	GOEXPERIMENT=jsonv2 go test -run V2 -v ./Security/35_json-decoding/

package jsondecode

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"testing"
)

func TestV2StricterDefaults(t *testing.T) {
	tests := []struct {
		name string
		body string
		ok   bool
	}{
		{"case-sensitive names", `{"ISADMIN":true}`, true}, // accepted, but does not set IsAdmin
		{"duplicate names rejected", `{"name":"a","name":"b"}`, false},
		{"invalid UTF-8 rejected", "{\"name\":\"ad\xffmin\"}", false},
		{"lone surrogate rejected", `{"name":"\ud800"}`, false},
		{"trailing data rejected", `{"name":"a"} x`, false},
		{"unknown members still ignored", `{"extra":1}`, true},
	}
	for _, tt := range tests {
		var u User
		err := jsonv2.Unmarshal([]byte(tt.body), &u)
		if (err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want ok=%v", tt.name, err, tt.ok)
		}
		if u.IsAdmin {
			t.Errorf("%s: IsAdmin set", tt.name)
		}
	}
}

func TestV2OptionsRestoreV1Behaviour(t *testing.T) {
	var u User
	if err := jsonv2.Unmarshal([]byte(`{"ISADMIN":true}`), &u, jsonv2.MatchCaseInsensitiveNames(true)); err != nil || !u.IsAdmin {
		t.Errorf("MatchCaseInsensitiveNames: %+v %v", u, err)
	}
	if err := jsonv2.Unmarshal([]byte(`{"name":"a","name":"b"}`), &u, jsontext.AllowDuplicateNames(true)); err != nil || u.Name != "b" {
		t.Errorf("AllowDuplicateNames: %+v %v", u, err)
	}
	if err := jsonv2.Unmarshal([]byte(`{"extra":1}`), &u, jsonv2.RejectUnknownMembers(true)); err == nil {
		t.Error("RejectUnknownMembers accepted an unknown member")
	}
}
