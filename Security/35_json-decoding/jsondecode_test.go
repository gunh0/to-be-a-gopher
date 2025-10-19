package jsondecode

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// The first group of tests pins down encoding/json v1 defaults. They are
// written as assertions so that a change in the standard library (for
// example v1 being reimplemented on top of v2) is noticed.

func TestV1CaseInsensitiveFieldMatch(t *testing.T) {
	tests := []struct {
		body string
		want bool
	}{
		{`{"isAdmin":true}`, true},
		{`{"ISADMIN":true}`, true},
		{`{"isadmin":true}`, true},
		{"{\"isAdm\u0131n\":true}", false}, // U+0131 dotless i does not fold to "i"
	}
	for _, tt := range tests {
		var u User
		if err := json.Unmarshal([]byte(tt.body), &u); err != nil {
			t.Fatal(err)
		}
		if u.IsAdmin != tt.want {
			t.Errorf("%s: IsAdmin = %v, want %v", tt.body, u.IsAdmin, tt.want)
		}
	}
}

func TestV1UnicodeFolding(t *testing.T) {
	var v struct {
		Key  string `json:"key"`
		Pass string `json:"pass"`
	}
	// U+212A KELVIN SIGN and U+017F LONG S fold to ASCII "k" and "s".
	if err := json.Unmarshal([]byte("{\"\u212aey\":\"k\",\"pa\u017f\u017f\":\"s\"}"), &v); err != nil {
		t.Fatal(err)
	}
	if v.Key != "k" || v.Pass != "s" {
		t.Fatalf("got %+v, want both fields set through non-ASCII keys", v)
	}
}

func TestV1DuplicateKeysLastWins(t *testing.T) {
	var u User
	// A validator that reads the first "isAdmin" sees false; Go sees true.
	if err := json.Unmarshal([]byte(`{"isAdmin":false,"ISADMIN":true}`), &u); err != nil {
		t.Fatal(err)
	}
	if !u.IsAdmin {
		t.Fatal("want the last duplicate to win")
	}
}

func TestV1UnknownFieldsIgnored(t *testing.T) {
	var p ProfileUpdate
	if err := json.Unmarshal([]byte(`{"name":"a","isAdmin":true}`), &p); err != nil {
		t.Fatalf("v1 default rejected an unknown field: %v", err)
	}
	dec := json.NewDecoder(strings.NewReader(`{"name":"a","isAdmin":true}`))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err == nil {
		t.Fatal("DisallowUnknownFields accepted an unknown field")
	}
}

func TestV1InvalidUTF8Replaced(t *testing.T) {
	var u User
	for _, body := range []string{"{\"name\":\"ad\xffmin\"}", `{"name":"ad\ud800min"}`} {
		if err := json.Unmarshal([]byte(body), &u); err != nil {
			t.Fatal(err)
		}
		if u.Name != "ad\ufffdmin" {
			t.Errorf("%q decoded to %q, want silent U+FFFD substitution", body, u.Name)
		}
	}
}

func TestV1DashCommaTagIsAField(t *testing.T) {
	var v struct {
		Hidden bool `json:"-"`
		Dash   bool `json:"-,"` // looks hidden, is the field named "-"
	}
	if err := json.Unmarshal([]byte(`{"Hidden":true,"-":true}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.Hidden || !v.Dash {
		t.Fatalf("got %+v, want Hidden=false Dash=true", v)
	}
}

func TestV1LargeIntegerLosesPrecision(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal([]byte(`{"id":9007199254740993}`), &m); err != nil {
		t.Fatal(err)
	}
	if m["id"] != float64(9007199254740992) {
		t.Fatalf("id = %v, want the float64-rounded value", m["id"])
	}
	dec := json.NewDecoder(strings.NewReader(`{"id":9007199254740993}`))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil || m["id"] != json.Number("9007199254740993") {
		t.Fatalf("UseNumber: %v %v", m["id"], err)
	}
}

func TestDecodeLenientTrailingData(t *testing.T) {
	var p ProfileUpdate
	for _, body := range []string{
		`{"name":"a"} garbage`,
		`{"name":"a"}{"name":"b"}`,
		`{"name":"a"}]`,
	} {
		if err := DecodeLenient(strings.NewReader(body), &p); err != nil {
			t.Errorf("%s: lenient decode err = %v, want accepted", body, err)
		}
	}
	// More() misses a trailing closing delimiter.
	dec := json.NewDecoder(strings.NewReader(`{"name":"a"}]`))
	if err := dec.Decode(&p); err != nil {
		t.Fatal(err)
	}
	if dec.More() {
		t.Fatal("More() = true; the documented gap no longer exists")
	}
	if err := dec.Decode(&struct{}{}); err == io.EOF {
		t.Fatal("second Decode returned io.EOF despite trailing data")
	}
}

func TestUpdateProfileUnsafeMassAssignment(t *testing.T) {
	for _, body := range []string{
		`{"name":"mallory","isAdmin":true}`,
		`{"name":"mallory","ISADMIN":true}`, // bypasses a case-sensitive gateway filter
		`{"name":"mallory","id":1}`,
	} {
		u := User{ID: 42, Name: "alice"}
		if err := UpdateProfileUnsafe(&u, []byte(body)); err != nil {
			t.Fatal(err)
		}
		if !u.IsAdmin && u.ID == 42 {
			t.Errorf("%s: no privileged field changed", body)
		}
	}
}

func TestUpdateProfile(t *testing.T) {
	u := User{ID: 42, Name: "alice", Email: "a@example.com"}
	if err := UpdateProfile(&u, []byte(`{"name":"bob"}`)); err != nil {
		t.Fatal(err)
	}
	if u != (User{ID: 42, Name: "bob", Email: "a@example.com"}) {
		t.Fatalf("u = %+v", u)
	}

	tests := []struct {
		body string
		want error // nil: any non-nil error is acceptable
	}{
		{`{"name":"x","isAdmin":true}`, nil},
		{`{"name":"x","ISADMIN":true}`, nil},
		{`{"name":"x","id":1}`, nil},
		{`{"name":"x","NAME":"y"}`, ErrDuplicateKey},
		{`{"name":"x","name":"y"}`, ErrDuplicateKey},
		{"{\"name\":\"ad\xffmin\"}", ErrInvalidUTF8},
		{`{"name":"x"} {"isAdmin":true}`, ErrTrailingData},
		{`{"name":"x"}]`, nil}, // rejected by the token walk already
		{`{"name":""}`, ErrInvalidProfile},
		{`{"email":"nope"}`, ErrInvalidProfile},
		{`{"name":"` + strings.Repeat("a", MaxBody) + `"}`, ErrTooLarge},
	}
	for _, tt := range tests {
		before := u
		err := UpdateProfile(&u, []byte(tt.body))
		if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) {
			name := tt.body
			if len(name) > 40 {
				name = name[:40] + "..."
			}
			t.Errorf("%s: err = %v, want %v", name, err, tt.want)
		}
		if u != before {
			t.Errorf("%.40s: record changed despite error: %+v", tt.body, u)
		}
	}
}

func TestCheckKeys(t *testing.T) {
	tests := []struct {
		body string
		want error
	}{
		{`{"a":1,"b":{"a":2},"c":[{"a":1},{"a":2}]}`, nil}, // same key in different objects
		{`[1,"a","a",{"a":"a"}]`, nil},                     // strings that are values, not keys
		{`{"a":{"b":1,"b":2}}`, ErrDuplicateKey},
		{`{"c":[{"d":1,"D":2}]}`, ErrDuplicateKey},
		{"{\"k\":1,\"\u212a\":2}", ErrDuplicateKey}, // KELVIN SIGN
		{"{\"s\":1,\"\u017f\":2}", ErrDuplicateKey}, // LONG S
		{strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1), ErrTooDeep},
	}
	for _, tt := range tests {
		if err := CheckKeys([]byte(tt.body)); !errors.Is(err, tt.want) {
			t.Errorf("CheckKeys(%.40s) = %v, want %v", tt.body, err, tt.want)
		}
	}
	if err := CheckKeys([]byte(strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth))); err != nil {
		t.Errorf("depth MaxDepth rejected: %v", err)
	}
}

func ExampleUpdateProfileUnsafe() {
	body := []byte(`{"name":"mallory","ISADMIN":true}`)

	u := User{ID: 42, Name: "alice"}
	_ = UpdateProfileUnsafe(&u, body)
	fmt.Printf("%+v\n", u)

	v := User{ID: 42, Name: "alice"}
	err := UpdateProfile(&v, body)
	fmt.Printf("%+v rejected=%v\n", v, err != nil)
	// Output:
	// {ID:42 Name:mallory Email: IsAdmin:true}
	// {ID:42 Name:alice Email: IsAdmin:false} rejected=true
}
