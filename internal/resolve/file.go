package resolve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// File resolves stand-ins from a JSON file mapping each stand-in to its real
// value. Its stand-ins are known in advance, so no pattern is needed.
//
// Watch reloads the file when its content changes, so a secret manager can
// rewrite it in place (Vault Agent, the Kubernetes Secrets Store CSI driver
// and Secret volumes all replace the file or the symlink to it). A new
// content that does not load keeps the previous map.
type File struct {
	path    string
	current atomic.Pointer[fileSnapshot]

	mu          sync.Mutex        // serializes reloads, guards the fields below
	loaded      [sha256.Size]byte // hash of the content in current
	lastFailure string            // the previous attempt's failure, logged once
}

type fileSnapshot struct {
	values   map[string]Value
	standIns []string // sorted keys of values
}

// LoadFile reads the file. Call Watch to follow later changes.
func LoadFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	snapshot, err := parseFile(path, data)
	if err != nil {
		return nil, err
	}
	f := &File{path: path, loaded: sha256.Sum256(data)}
	f.current.Store(snapshot)
	return f, nil
}

// Reload reads the file again and, when its content changed and loads,
// replaces the map in one step: a request sees either the old map or the new
// one. It reports whether the map changed. On an error the previous map
// stays in use.
func (f *File) Reload() (bool, error) {
	changed, _, err := f.reload()
	return changed, err
}

// reload is Reload, also reporting whether an error is new: a content (or a
// read error) that did not fail at the previous attempt.
func (f *File) reload() (changed, newFailure bool, err error) {
	if f.path == "" {
		return false, false, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := os.ReadFile(f.path)
	if err != nil {
		newFailure = err.Error() != f.lastFailure
		f.lastFailure = err.Error()
		return false, newFailure, err
	}
	sum := sha256.Sum256(data)
	if sum == f.loaded {
		f.lastFailure = ""
		return false, false, nil
	}
	snapshot, err := parseFile(f.path, data)
	if err != nil {
		failure := "content " + hex.EncodeToString(sum[:])
		newFailure = failure != f.lastFailure
		f.lastFailure = failure
		return false, newFailure, err
	}
	f.current.Store(snapshot)
	f.loaded = sum
	f.lastFailure = ""
	return true, false, nil
}

// Watch reloads the file every interval until ctx ends. It logs each change,
// and each failure once until the file changes again. Real values are never
// logged.
func (f *File) Watch(ctx context.Context, interval time.Duration, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		changed, newFailure, err := f.reload()
		switch {
		case err != nil && newFailure:
			log.Error("keeping the previous stand-ins: the swaps file does not load", "path", f.path, "error", err)
		case changed:
			log.Info("reloaded the swaps file", "path", f.path, "stand_ins", f.Count())
		}
	}
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

func parseFile(path string, data []byte) (*fileSnapshot, error) {
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
func (f *File) Resolve(ctx context.Context, req Request) (Result, error) {
	return f.current.Load().Resolve(ctx, req)
}

// Snapshot returns the file's current version, whose StandIns and Resolve
// stay the same whatever is loaded afterwards.
func (f *File) Snapshot(Principal) (Snapshot, error) { return f.current.Load(), nil }

// Resolve answers every requested stand-in the snapshot holds.
func (snapshot *fileSnapshot) Resolve(_ context.Context, req Request) (Result, error) {
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

// StandIns returns the snapshot's stand-ins, whoever asks.
func (snapshot *fileSnapshot) StandIns(Principal) []string { return snapshot.standIns }

// Local marks the file as answering from memory.
func (f *File) Local() {}

// Local marks a file snapshot as answering from memory.
func (snapshot *fileSnapshot) Local() {}

// Count is the number of stand-ins currently loaded.
func (f *File) Count() int { return len(f.current.Load().standIns) }
