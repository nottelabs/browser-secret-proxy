package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// notteAPI calls the Notte API. Every call has its own time limit, so a
// stalled API cannot hold up the test or its cleanup.
type notteAPI struct {
	baseURL string
	key     string
	client  *http.Client
}

// apiTimeout bounds one call of the test; stopTimeout the session stop in
// cleanup.
const (
	apiTimeout  = 120 * time.Second
	stopTimeout = 30 * time.Second
)

// call sends in as JSON (when not nil) and decodes a 2xx answer into out
// (when not nil).
func (n *notteAPI) call(ctx context.Context, timeout time.Duration, method, path string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, n.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+n.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("%s %s: reading the answer: %w", method, path, err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s returned %d: %s", method, path, resp.StatusCode, truncate(string(data), 500))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: decoding the answer: %w", method, path, err)
	}
	return nil
}

// secretProxy is the session's "secret" proxy entry.
type secretProxy struct {
	Type          string   `json:"type"`
	Server        string   `json:"server"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	CACertificate string   `json:"ca_certificate"`
	Hosts         []string `json:"hosts"`
}

// startSession starts a session that sends hosts through proxy and returns
// its ID.
func (n *notteAPI) startSession(ctx context.Context, proxy secretProxy) (string, error) {
	proxy.Type = "secret"
	var out struct {
		SessionID   string `json:"session_id"`
		SecretProxy *struct {
			Hosts []string `json:"hosts"`
		} `json:"secret_proxy"`
	}
	in := map[string]any{"max_duration_minutes": 5, "idle_timeout_minutes": 3, "proxies": []any{proxy}}
	if err := n.call(ctx, apiTimeout, http.MethodPost, "/sessions/start", in, &out); err != nil {
		return "", err
	}
	if out.SessionID == "" {
		return "", fmt.Errorf("the session start answer has no session_id")
	}
	if out.SecretProxy == nil || !slices.Equal(out.SecretProxy.Hosts, proxy.Hosts) {
		return out.SessionID, fmt.Errorf("session %s does not report the secret proxy for %v", out.SessionID, proxy.Hosts)
	}
	return out.SessionID, nil
}

// stopSession stops a session, with the short cleanup time limit.
func (n *notteAPI) stopSession(ctx context.Context, id string) error {
	return n.call(ctx, stopTimeout, http.MethodDelete, "/sessions/"+id+"/stop", nil, nil)
}

// execute runs one page action and returns the text of its data, which is
// where evaluate_js puts the script's result.
func (n *notteAPI) execute(ctx context.Context, sessionID string, action map[string]any) (string, error) {
	var out struct {
		Success   bool    `json:"success"`
		Message   string  `json:"message"`
		Exception *string `json:"exception"`
		Data      *struct {
			Markdown string `json:"markdown"`
		} `json:"data"`
	}
	if err := n.call(ctx, apiTimeout, http.MethodPost, "/sessions/"+sessionID+"/page/execute", action, &out); err != nil {
		return "", err
	}
	if !out.Success {
		detail := out.Message
		if out.Exception != nil {
			detail += ": " + *out.Exception
		}
		return "", fmt.Errorf("%s action failed: %s", action["type"], truncate(detail, 500))
	}
	if out.Data == nil {
		return "", nil
	}
	return out.Data.Markdown, nil
}

func (n *notteAPI) gotoURL(ctx context.Context, sessionID, url string) error {
	_, err := n.execute(ctx, sessionID, map[string]any{"type": "goto", "url": url})
	return err
}

// fetchRequest is a request the page sends with fetch(). Form, when set,
// is the body as URLSearchParams (the browser encodes it and sets the
// form Content-Type); otherwise Body is sent as is.
type fetchRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers,omitempty"`
	Form    map[string]string `json:"form,omitempty"`
	Body    *string           `json:"body,omitempty"`
}

// fetchScript runs the request in the page and returns its status and text.
const fetchScript = `(async () => {
  const a = %s;
  const init = {method: a.method, headers: a.headers || {}};
  if (a.form) init.body = new URLSearchParams(a.form);
  else if (a.body !== undefined) init.body = a.body;
  const r = await fetch(a.url, init);
  return JSON.stringify({status: r.status, body: await r.text()});
})()`

// fetch sends req from the current page of the session and returns the
// response status and body the page saw.
func (n *notteAPI) fetch(ctx context.Context, sessionID string, req fetchRequest) (int, string, error) {
	args, err := json.Marshal(req)
	if err != nil {
		return 0, "", err
	}
	text, err := n.execute(ctx, sessionID, map[string]any{"type": "evaluate_js", "code": fmt.Sprintf(fetchScript, args)})
	if err != nil {
		return 0, "", err
	}
	var res struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	if err := json.Unmarshal([]byte(text), &res); err != nil {
		return 0, "", fmt.Errorf("the page script returned %q, not a fetch result", truncate(text, 200))
	}
	return res.Status, res.Body, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
