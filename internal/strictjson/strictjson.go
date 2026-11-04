// Package strictjson checks that a JSON document names its members one way
// before encoding/json decodes it. encoding/json matches a member to a
// struct field in any case and keeps the last of two members with the same
// name, so {"hosts": ["a.test"], "HOSTS": []} decodes as an empty host list,
// while another reader of the same document sees one host.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Shape is what a JSON object is expected to hold: an Object or a Map. A nil
// Shape is any value, checked for repeated members only.
type Shape interface {
	// member returns the shape of the member called name, or an error when
	// the name must not appear.
	member(name string) (Shape, error)
}

// Object is a JSON object whose known members are the keys, spelled as
// their json tags spell them, each holding a value of its Shape. A member
// that spells a known name in another case is refused; other members are
// allowed and checked for repeated members only.
type Object map[string]Shape

func (o Object) member(name string) (Shape, error) {
	if shape, ok := o[name]; ok {
		return shape, nil
	}
	for known := range o {
		if strings.EqualFold(name, known) {
			return nil, fmt.Errorf("a member spells %q in another case", known)
		}
	}
	return nil, nil
}

// Map is a JSON object of any member names, a Go map, whose values each
// hold a value of Elem's shape. Its names are not compared by case: two
// keys that differ in case are two entries.
type Map struct{ Elem Shape }

func (m Map) member(string) (Shape, error) { return m.Elem, nil }

// ErrRepeated is returned for an object that names a member twice.
var ErrRepeated = errors.New("an object names a member twice")

// errMalformed is returned for data that is not one JSON value. Its
// message never quotes the data.
var errMalformed = errors.New("not one JSON value")

// Check reports whether data is one JSON value in which no object, at any
// depth, names a member twice, and shape's known members are spelled
// exactly as their names. A shape applies only where the value is an
// object: a value of another type is left to the decoder. Array elements
// are checked for repeated members only. Errors never quote data, only the
// known names of shape.
func Check(data []byte, shape Shape) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // a number is not parsed, so its size cannot fail the check
	if err := check(dec, shape); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errMalformed
	}
	return nil
}

func check(dec *json.Decoder, shape Shape) error {
	tok, err := dec.Token()
	if err != nil {
		return errMalformed
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return errMalformed
			}
			name, _ := tok.(string)
			if seen[name] {
				return ErrRepeated
			}
			seen[name] = true
			var child Shape
			if shape != nil {
				if child, err = shape.member(name); err != nil {
					return err
				}
			}
			if err := check(dec, child); err != nil {
				return err
			}
		}
	case json.Delim('['):
		for dec.More() {
			if err := check(dec, nil); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	if _, err := dec.Token(); err != nil { // the closing delimiter
		return errMalformed
	}
	return nil
}
