package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// proxyRun is one proxy container: its arguments, files and where it
// listens on the host network.
type proxyRun struct {
	role      string            // swap or mask
	name      string            // container name
	port      int               // listens on 127.0.0.1:port
	mounts    map[string]string // host path to container path
	args      []string          // proxy flags after -listen
	username  string
	password  string
	publicURL string // the ngrok TCP address, http://host:port
	started   bool   // docker run was attempted, so cleanup removes the container
}

// startProxy starts the container on the host network, so the proxy and an
// http resolver on 127.0.0.1 see each other on Linux and Docker Desktop or
// OrbStack alike. The proxy credentials go through the environment, not the
// command line.
func startProxy(ctx context.Context, image string, p *proxyRun) error {
	args := []string{"run", "-d", "--name", p.name, "--network", "host",
		"-e", "SECRET_PROXY_USERNAME", "-e", "SECRET_PROXY_PASSWORD"}
	for host, container := range p.mounts {
		args = append(args, "-v", host+":"+container+":ro")
	}
	args = append(args, image, "-listen", fmt.Sprintf("127.0.0.1:%d", p.port))
	args = append(args, p.args...)
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // arguments this program built
	cmd.Env = append(os.Environ(), "SECRET_PROXY_USERNAME="+p.username, "SECRET_PROXY_PASSWORD="+p.password)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker run %s: %w: %s", p.name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// proxyLogs returns the container's log. The proxy never logs real values.
func proxyLogs(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "docker", "logs", name).CombinedOutput() //nolint:gosec // a container this program named
	return string(out)
}

func removeContainer(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", name).Run() //nolint:gosec // a container this program named
}

// waitHTTP waits until url answers any HTTP response (the proxy answers
// 407 or 400 to a plain GET), for at most limit.
func waitHTTP(ctx context.Context, rawURL string, header http.Header, limit time.Duration) (int, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	deadline := time.Now().Add(limit)
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return 0, err
		}
		if header != nil {
			req.Header = header
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return resp.StatusCode, nil
		}
		if time.Now().After(deadline) {
			return 0, err
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// freePort returns a TCP port free on 127.0.0.1 right now.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// ngrokAgent is the ngrok agent that makes the proxies and the capture
// server public.
type ngrokAgent struct {
	cmd     *exec.Cmd
	logPath string
	exited  chan struct{}
}

// ngrokTunnel is one tunnel of the agent's configuration.
type ngrokTunnel struct {
	name  string
	proto string // tcp or http
	port  int
}

var startedTunnel = regexp.MustCompile(`msg="started tunnel".* name=(\S+) .*url=(\S+)`)

// startNgrok starts one agent for every tunnel and returns their public
// URLs by name. The configuration is its own, so a local ngrok setup is not
// used; the authtoken stays in the environment (NGROK_AUTHTOKEN), and the
// agent's local web interface is off.
func startNgrok(ctx context.Context, bin, dir string, tunnels []ngrokTunnel) (*ngrokAgent, map[string]string, error) {
	var conf strings.Builder
	conf.WriteString("version: \"3\"\nagent:\n  web_addr: false\ntunnels:\n")
	for _, t := range tunnels {
		fmt.Fprintf(&conf, "  %s:\n    proto: %s\n    addr: 127.0.0.1:%d\n", t.name, t.proto, t.port)
	}
	confPath := filepath.Join(dir, "ngrok.yml")
	if err := os.WriteFile(confPath, []byte(conf.String()), 0o600); err != nil {
		return nil, nil, err
	}
	a := &ngrokAgent{logPath: filepath.Join(dir, "ngrok.log"), exited: make(chan struct{})}
	logFile, err := os.Create(a.logPath)
	if err != nil {
		return nil, nil, err
	}
	defer logFile.Close()
	// Not CommandContext: cleanup stops the agent, after the sessions.
	a.cmd = exec.Command(bin, "start", "--all", "--config", confPath, "--log", "stdout", "--log-format", "logfmt") //nolint:gosec // the ngrok binary the caller chose
	a.cmd.Stdout, a.cmd.Stderr = logFile, logFile
	if err := a.cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("starting ngrok: %w", err)
	}
	go func() { _ = a.cmd.Wait(); close(a.exited) }()

	deadline := time.Now().Add(30 * time.Second)
	for {
		urls := a.tunnelURLs()
		if len(urls) == len(tunnels) {
			return a, urls, nil
		}
		select {
		case <-a.exited:
			return a, nil, errors.New("ngrok exited before its tunnels started")
		case <-ctx.Done():
			return a, nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return a, nil, fmt.Errorf("ngrok started %d of %d tunnels in 30 s", len(urls), len(tunnels))
		}
	}
}

func (a *ngrokAgent) tunnelURLs() map[string]string {
	urls := map[string]string{}
	f, err := os.Open(a.logPath)
	if err != nil {
		return urls
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if m := startedTunnel.FindStringSubmatch(scanner.Text()); m != nil {
			urls[m[1]] = m[2]
		}
	}
	return urls
}

// stop ends the agent and returns the end of its log.
func (a *ngrokAgent) stop() string {
	if a.cmd.Process != nil {
		_ = a.cmd.Process.Kill()
		<-a.exited
	}
	data, _ := os.ReadFile(a.logPath)
	return lastLines(string(data), 20)
}

// tcpToHTTP turns ngrok's tcp://host:port into the proxy URL a session
// uses.
func tcpToHTTP(tcpURL string) (string, error) {
	u, err := url.Parse(tcpURL)
	if err != nil || u.Scheme != "tcp" || u.Port() == "" {
		return "", fmt.Errorf("unexpected ngrok TCP address %q", tcpURL)
	}
	return "http://" + u.Host, nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
