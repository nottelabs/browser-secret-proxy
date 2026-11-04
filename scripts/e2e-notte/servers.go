package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// detokenizer is the detokenize service of the http resolver run. It
// answers fixed values and one TOTP stand-in, whose real value is the code
// of the moment it is asked for, and allows every value only to host.
type detokenizer struct {
	host        string
	static      map[string]string
	totpStandIn string
	totpSecret  []byte
	now         func() time.Time

	mu      sync.Mutex
	lookups []lookup
}

// lookup is one call the proxy made: the host it asked for and the
// stand-ins it sent. Real values are not kept.
type lookup struct {
	Host     string
	StandIns []string
}

func (d *detokenizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		StandIns    []string `json:"stand_ins"`
		Host        string   `json:"host"`
		PrincipalID string   `json:"principal_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "want {stand_ins, host, principal_id}", http.StatusBadRequest)
		return
	}
	type value struct {
		Real  string   `json:"real"`
		Hosts []string `json:"hosts"`
	}
	values := map[string]value{}
	for _, s := range req.StandIns {
		switch real, ok := d.static[s]; {
		case ok:
			values[s] = value{real, []string{d.host}}
		case s == d.totpStandIn:
			values[s] = value{totp(d.totpSecret, d.now()), []string{d.host}}
		}
	}
	d.mu.Lock()
	d.lookups = append(d.lookups, lookup{Host: req.Host, StandIns: req.StandIns})
	d.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"values": values})
}

// asked reports whether the proxy looked standIn up for host.
func (d *detokenizer) asked(host, standIn string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, l := range d.lookups {
		if l.Host != host {
			continue
		}
		for _, s := range l.StandIns {
			if s == standIn {
				return true
			}
		}
	}
	return false
}

// capturePrefix is the path under which captureServer records requests.
const capturePrefix = "/capture/"

// captureServer is the destination this test controls, reached through an
// ngrok HTTPS endpoint. It records the body of every POST to
// /capture/<name>, so the test reads exactly what arrived upstream without
// going through the browser. For names in echo it answers the body back,
// to give the proxy something to mask.
type captureServer struct {
	echo map[string]bool

	mu  sync.Mutex
	got map[string][]byte
}

func newCaptureServer(echo ...string) *captureServer {
	c := &captureServer{echo: map[string]bool{}, got: map[string][]byte{}}
	for _, name := range echo {
		c.echo[name] = true
	}
	return c
}

func (c *captureServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, ok := strings.CutPrefix(r.URL.Path, capturePrefix)
	if !ok || r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "browser-secret-proxy e2e capture server\n")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	c.mu.Lock()
	c.got[name] = body
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if c.echo[name] {
		_ = json.NewEncoder(w).Encode(map[string]string{"received": string(body)})
		return
	}
	_, _ = io.WriteString(w, `{"ok":true}`)
}

// received returns the body of the last POST to /capture/<name>.
func (c *captureServer) received(name string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	body, ok := c.got[name]
	return body, ok
}
