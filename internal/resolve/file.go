package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync/atomic"
)

// File resolves stand-ins from a JSON file mapping each stand-in to its real
// value. Its stand-ins are known in advance, so no pattern is needed.
type File struct {
	path    string
	current atomic.Pointer[fileSnapshot]
}

type fileSnapshot struct {
	values   map[string]Value
	standIns []string // sorted keys of values
}

// LoadFile reads the file once.
func LoadFile(path string) (*File, error) {
	snapshot, err := readFile(path)
	if err != nil {
		return nil, err
	}
	f := &File{path: path}
	f.current.Store(snapshot)
	return f, nil
}

// NewStatic is a File resolver over values held in memory.
func NewStatic(values map[string]string) (*File, error) {
	snapshot, err := newSnapshot(values)
	if err != nil {
		return nil, err
	}
	f := &File{}
	f.current.Store(snapshot)
	return f, nil
}

func readFile(path string) (*fileSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var values map[string]string
	if err := json.Unmarshal(data, &values); err != nil {
		// The error never quotes the file: it holds real values.
		return nil, fmt.Errorf("%s: want a JSON object of stand-in to real value", path)
	}
	snapshot, err := newSnapshot(values)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return snapshot, nil
}

func newSnapshot(values map[string]string) (*fileSnapshot, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("no stand-in values")
	}
	s := &fileSnapshot{values: make(map[string]Value, len(values))}
	for standIn, real := range values {
		if standIn == "" {
			return nil, fmt.Errorf("empty stand-in")
		}
		s.values[standIn] = Value{Real: real}
		s.standIns = append(s.standIns, standIn)
	}
	sort.Strings(s.standIns)
	return s, nil
}

// Resolve answers every requested stand-in the file holds.
func (f *File) Resolve(_ context.Context, req Request) (Result, error) {
	snapshot := f.current.Load()
	out := Result{Values: make(map[string]Value, len(req.StandIns))}
	for _, standIn := range req.StandIns {
		if v, ok := snapshot.values[standIn]; ok {
			out.Values[standIn] = v
		}
	}
	return out, nil
}

// StandIns returns the file's stand-ins, whoever asks.
func (f *File) StandIns(Principal) []string { return f.current.Load().standIns }

// Count is the number of stand-ins currently loaded.
func (f *File) Count() int { return len(f.current.Load().standIns) }
