package strictjson

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

var testShape = Object{
	"values": Map{Elem: Object{"real": nil, "hosts": nil}},
	"exp":    nil,
}

func TestCheckAccepts(t *testing.T) {
	for name, doc := range map[string]string{
		"as written":              `{"values": {"tok_a": {"real": "r", "hosts": ["a.test"]}}, "exp": 1}`,
		"unknown members":         `{"values": {}, "jti": "j", "nested": {"a": 1, "A": 2}, "list": [{"a": 1}, {"a": 2}]}`,
		"map keys by case":        `{"values": {"tok_a": {"real": "r"}, "TOK_A": {"real": "s"}}}`,
		"another type than shape": `{"values": {"tok_a": "r"}, "exp": null}`,
		"not an object":           `["a", 1, null]`,
		"a huge number":           `{"exp": 1e400}`,
		"surrounding space":       " \n{\"exp\": 1}\n",
		"a scalar":                `"x"`,
	} {
		if err := Check([]byte(doc), testShape); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCheckRefuses(t *testing.T) {
	for name, doc := range map[string]string{
		"a known member in another case":   `{"values": {}, "EXP": 1}`,
		"with a long s":                    `{"values": {"tok_a": {"real": "r", "hoſts": []}}}`,
		"escaped in another case":          `{"values": {"tok_a": {"real": "r", "\u0048OSTS": []}}}`,
		"a nested known member by case":    `{"values": {"tok_a": {"Real": "secret-value"}}}`,
		"a member twice":                   `{"exp": 1, "exp": 2}`,
		"a map key twice":                  `{"values": {"tok_a": {"real": "secret-value"}, "tok_a": {"real": "s"}}}`,
		"an unknown member's member twice": `{"nested": {"a": 1, "a": 2}}`,
		"inside an array":                  `{"list": [{"a": 1, "a": 2}]}`,
		"twice once escaped":               `{"exp": 1, "\u0065xp": 2}`,
		"trailing data":                    `{"exp": 1} {"exp": 2}`,
		"truncated":                        `{"values": {"tok_a": {"real": "secret-value"`,
		"empty":                            ``,
	} {
		err := Check([]byte(doc), testShape)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), "tok_") {
			t.Errorf("%s: the error quotes the document: %v", name, err)
		}
	}
	if err := Check([]byte(`{"a": 1, "a": 2}`), nil); !errors.Is(err, ErrRepeated) {
		t.Fatalf("err = %v, want ErrRepeated", err)
	}
}

// What Check accepts, encoding/json decodes as written: no member is lost
// to a later duplicate or to another spelling.
func TestCheckedDocumentsDecodeAsWritten(t *testing.T) {
	var v struct {
		Hosts []string `json:"hosts"`
	}
	const doc = `{"hosts": ["a.test"], "HOSTS": []}`
	if err := json.Unmarshal([]byte(doc), &v); err != nil || len(v.Hosts) != 0 {
		t.Fatalf("encoding/json read %q, err %v: the premise of this package changed", v.Hosts, err)
	}
	if Check([]byte(doc), Object{"hosts": nil}) == nil {
		t.Fatal("accepted a document encoding/json reads another way than written")
	}
}
