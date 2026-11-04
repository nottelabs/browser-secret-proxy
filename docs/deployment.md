# Deployment

How to run browser-secret-proxy in production: getting the binary or
image, the CA, credentials, TLS in front of the proxy port, systemd and
Kubernetes, logs, health checks and sizing. Hardening choices are in
[security.md](security.md).

- [Get the proxy](#get-the-proxy)
- [Create the CA](#create-the-ca)
- [Rotate the CA](#rotate-the-ca)
- [Proxy credentials](#proxy-credentials)
- [TLS on the proxy port](#tls-on-the-proxy-port)
- [Docker](#docker)
- [systemd](#systemd)
- [Kubernetes](#kubernetes)
- [Outbound traffic through a parent proxy](#outbound-traffic-through-a-parent-proxy)
- [Logs](#logs)
- [Health checks](#health-checks)
- [Shutdown and restarts](#shutdown-and-restarts)
- [Sizing](#sizing)

## Get the proxy

Each release publishes static binaries for linux and darwin (amd64 and
arm64), a signed `checksums.txt`, an SPDX SBOM per archive and a signed
multi-arch image, `ghcr.io/nottelabs/browser-secret-proxy:<version>`.
Verify what you download as described in
[Verifying a release](../README.md#verifying-a-release), and pin the image
by digest in production.

To build from source (Go 1.26 or later):

```sh
git clone https://github.com/nottelabs/browser-secret-proxy
cd browser-secret-proxy
make build     # bin/browser-secret-proxy, static (CGO_ENABLED=0)
make docker    # image browser-secret-proxy:dev
```

The image is distroless, has no shell, and runs as UID 65532. Its
entrypoint already passes `-listen :8080`; a later `-listen` wins.

## Create the CA

The proxy issues a certificate for each allowlisted host from a CA you
create. The browser trusts that CA. Whoever holds its key can impersonate
any host to a browser that trusts it, so:

- create it where the proxy runs, or in your PKI, never on the automation
  vendor's side;
- give clients the certificate only (`ca.pem`), never the key;
- give it a short lifetime and rotate it.

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj "/CN=browser-secret-proxy CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" -keyout ca.key -out ca.pem
chmod 600 ca.key
```

Optionally, add X.509 name constraints so the CA can only vouch for your
allowlisted domains. A client that enforces them then rejects any other
certificate from this CA, even one made with a stolen key. Check that your
browser enforces constraints on the roots you add before relying on it;
the proxy itself works either way.

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj "/CN=browser-secret-proxy CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" \
  -addext "nameConstraints=critical,permitted;DNS:payments.example,permitted;DNS:login.example.com" \
  -keyout ca.key -out ca.pem
chmod 600 ca.key
```

`permitted;DNS:payments.example` covers `payments.example` and every name
below it.

The proxy accepts the key as PKCS #8, PKCS #1 or SEC 1 PEM, and checks
that it matches the certificate and that the certificate is a CA. It
generates one P-256 key for all leaf certificates at start. Each leaf is
valid for 7 days, never past the CA's own expiry, is kept in memory per
host and renewed an hour before it ends.

## Rotate the CA

The CA is read once at start, and the proxy does not warn when it is
close to expiry or expired. Leaf certificates never outlive the CA, so an
expired CA breaks every intercepted connection. Monitor it:

```sh
# Exit status 1 when ca.pem expires within 7 days.
openssl x509 -in ca.pem -noout -checkend 604800
```

To rotate without breaking running sessions:

1. Create the new CA (`ca-new.pem`, `ca-new.key`).
2. Give clients a bundle of both certificates, so new sessions trust
   either: `cat ca.pem ca-new.pem > ca-bundle.pem`. For a Notte session,
   put the bundle in the `secret` entry's `ca_certificate`.
3. Wait until every session started before step 2 has ended. They trust
   only the old CA, so the proxy must keep using it until then.
4. Restart the proxy with `-ca-cert ca-new.pem -ca-key ca-new.key`.
   Sessions from step 2 trust both, so they keep working.
5. Give new sessions only `ca-new.pem`. Once the sessions that got the
   bundle have ended, delete `ca.key`.

If you cannot wait in step 3, run a second proxy with the new CA on
another address, point new sessions at it, and stop the old proxy once its
sessions have ended. Restarting the proxy with the new CA while
old-CA-only sessions still run makes their next TLS handshake fail; those
sessions must then be restarted.

## Proxy credentials

Set `SECRET_PROXY_USERNAME` and `SECRET_PROXY_PASSWORD` whenever the
proxy is reachable from another host. Without them, anyone who can reach
the port can send your real values to the allowlisted hosts.

```sh
export SECRET_PROXY_USERNAME=proxy-user
export SECRET_PROXY_PASSWORD="$(openssl rand -hex 32)"
```

- Every `CONNECT` must carry them as `Proxy-Authorization: Basic`; others
  get `407`. The comparison is constant-time.
- A password without a username refuses to start.
- The proxy accepts one credential. To rotate it without a gap, start a
  second proxy with the new credential, move clients to it, then stop the
  first.
- In `sealed` mode, do not set them: each client's sealed token is its
  credential.

Pass them through the environment from a secret store, never on the
command line, where `ps` shows them.

## TLS on the proxy port

The proxy listens in plain HTTP. The `CONNECT` line and its
`Proxy-Authorization` header (the proxy password, or a sealed token)
travel in clear text to the proxy, while the traffic inside the tunnel
stays TLS. Over any network you do not fully control, put a TLS terminator
in front of the port and give clients the `https://` address. The proxy
has no TLS listener of its own.

Any TCP-mode terminator works: a cloud load balancer with a TLS listener,
stunnel, or HAProxy. An HAProxy example (`proxy.pem` holds the
certificate followed by its key):

```text
global
  log stdout format raw local0

defaults
  mode tcp
  log global
  timeout connect 5s
  timeout client 1h
  timeout server 1h

frontend proxy_tls
  bind :8443 ssl crt /usr/local/etc/haproxy/proxy.pem ssl-min-ver TLSv1.2
  default_backend browser_secret_proxy

backend browser_secret_proxy
  server proxy1 127.0.0.1:8080
```

Keep the proxy itself on `127.0.0.1` or a private network, so the
terminator is the only way in. Check the path with curl (`--proxy-cacert`
is the CA of the terminator's certificate):

```sh
curl --proxy https://proxy.internal.example:8443 --proxy-cacert front-ca.pem \
  --proxy-user "proxy-user:$SECRET_PROXY_PASSWORD" --cacert ca.pem \
  "https://api.example.com/echo?token=tok_standin_123"
```

curl built with OpenSSL is refused by the interception step (see
[Allowlisted hosts and interception](concepts.md#allowlisted-hosts-and-interception));
curl on macOS and Chromium-based browsers work.

Behind a terminator, the proxy logs the terminator's address as `client`.
A terminator closes connections that stay idle past its timeouts, which
cuts long-lived tunnels: set `timeout client` and `timeout server` above
the longest idle time you expect in a session.

## Docker

```sh
docker run -d --name browser-secret-proxy --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8080:8080 \
  -v /etc/browser-secret-proxy:/etc/browser-secret-proxy:ro \
  --env-file /etc/browser-secret-proxy.env \
  ghcr.io/nottelabs/browser-secret-proxy:<version> \
  -ca-cert /etc/browser-secret-proxy/ca.pem \
  -ca-key /etc/browser-secret-proxy/ca.key \
  -hosts 'pay.psp.example,login.example.com' \
  -swaps /etc/browser-secret-proxy/swaps.json
```

- `/etc/browser-secret-proxy.env` holds `SECRET_PROXY_USERNAME=...` and
  `SECRET_PROXY_PASSWORD=...`, mode 600, root-owned. Docker reads it on the
  host; it stays outside the mounted directory.
- Mounted files must be readable by UID 65532:
  `chown 65532 /etc/browser-secret-proxy/ca.key /etc/browser-secret-proxy/swaps.json`
  and keep them mode 600.
- Mount the directory rather than single files when the swaps file is
  rewritten by a secret manager: a single-file bind mount keeps the old
  file after a symlink swap.

## systemd

A unit for the binary, with the CA key passed as a systemd credential and
the usual sandboxing. Create the user and directory first:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin browser-secret-proxy
sudo install -d -m 750 -o root -g browser-secret-proxy /etc/browser-secret-proxy
# ca.pem: 644. ca.key and env: 600, root. swaps.json: 640, root:browser-secret-proxy.
```

`/etc/systemd/system/browser-secret-proxy.service`:

```ini
[Unit]
Description=browser-secret-proxy
Wants=network-online.target
After=network-online.target

[Service]
User=browser-secret-proxy
Group=browser-secret-proxy
EnvironmentFile=/etc/browser-secret-proxy/env
# Copied to a private, memory-backed directory readable by this service only.
LoadCredential=ca.key:/etc/browser-secret-proxy/ca.key
ExecStart=/usr/local/bin/browser-secret-proxy \
  -listen 127.0.0.1:8080 \
  -ca-cert /etc/browser-secret-proxy/ca.pem \
  -ca-key %d/ca.key \
  -hosts pay.psp.example,login.example.com \
  -swaps /etc/browser-secret-proxy/swaps.json
Restart=on-failure
RestartSec=2s
# The proxy waits at most 10 s for open connections after SIGTERM.
TimeoutStopSec=20s

NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
UMask=0077

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now browser-secret-proxy
journalctl -u browser-secret-proxy -f
```

The swaps file stays a plain path, not a credential: credentials are
copied once at start, so a rewritten file would not be reloaded.

## Kubernetes

The CA, the swaps file and the proxy credential as Secrets, the proxy as
a Deployment that cannot write to its file system or gain privileges, and
a ClusterIP Service for the TLS terminator in front of it.

```sh
kubectl create namespace browser-secret-proxy
kubectl -n browser-secret-proxy create secret generic proxy-ca \
  --from-file=ca.pem --from-file=ca.key
kubectl -n browser-secret-proxy create secret generic proxy-swaps \
  --from-file=swaps.json
kubectl -n browser-secret-proxy create secret generic proxy-auth \
  --from-literal=username=proxy-user \
  --from-literal=password="$(openssl rand -hex 32)"
```

In production, have your secret manager (External Secrets, the Secrets
Store CSI driver, Vault Agent) create these Secrets instead.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: browser-secret-proxy
  namespace: browser-secret-proxy
spec:
  replicas: 2
  selector:
    matchLabels:
      app: browser-secret-proxy
  template:
    metadata:
      labels:
        app: browser-secret-proxy
    spec:
      automountServiceAccountToken: false
      terminationGracePeriodSeconds: 20
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: proxy
          image: ghcr.io/nottelabs/browser-secret-proxy:<version>
          args:
            - -ca-cert=/etc/browser-secret-proxy/ca/ca.pem
            - -ca-key=/etc/browser-secret-proxy/ca/ca.key
            - -hosts=pay.psp.example,login.example.com
            - -swaps=/etc/browser-secret-proxy/swaps/swaps.json
          env:
            - name: SECRET_PROXY_USERNAME
              valueFrom:
                secretKeyRef:
                  name: proxy-auth
                  key: username
            - name: SECRET_PROXY_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: proxy-auth
                  key: password
          ports:
            - name: proxy
              containerPort: 8080
          readinessProbe:
            tcpSocket:
              port: proxy
            periodSeconds: 5
          livenessProbe:
            tcpSocket:
              port: proxy
            periodSeconds: 10
            failureThreshold: 3
          resources:
            requests:
              cpu: 100m
              memory: 64Mi
            limits:
              memory: 1Gi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: ca
              mountPath: /etc/browser-secret-proxy/ca
              readOnly: true
            - name: swaps
              mountPath: /etc/browser-secret-proxy/swaps
              readOnly: true
      volumes:
        - name: ca
          secret:
            secretName: proxy-ca
            defaultMode: 0440
        - name: swaps
          secret:
            secretName: proxy-swaps
            defaultMode: 0440
---
apiVersion: v1
kind: Service
metadata:
  name: browser-secret-proxy
  namespace: browser-secret-proxy
spec:
  selector:
    app: browser-secret-proxy
  ports:
    - name: proxy
      port: 8080
      targetPort: proxy
```

- Secret volumes are memory-backed, and an updated `proxy-swaps` Secret
  reaches the pod as a symlink swap, which the proxy reloads (allow up to
  a minute or two for the kubelet to sync it). The CA is read once: roll
  the Deployment after changing `proxy-ca`.
- Expose the Service only through your TLS terminator (a load balancer
  with a TLS listener, or a TCP-mode ingress), and restrict who can reach
  it with a NetworkPolicy.
- Restrict egress to the allowlisted hosts' addresses, your DNS, and your
  detokenize service or parent proxy, where your network plugin allows it.
- Use the [`http` resolver](resolvers.md#http) instead of `proxy-swaps`
  when values live in a vault: drop the `swaps` volume, mount the client
  certificate the same way, and pass the `-resolver` flags.

## Outbound traffic through a parent proxy

`-upstream-proxy` (or `SECRET_PROXY_UPSTREAM`) sends every outgoing
connection, tunneled or intercepted, through a parent proxy: `http://`,
`https://` or `socks5://`, with a port and with credentials in the URL.

```sh
SECRET_PROXY_UPSTREAM='http://egress-user:egress-pass@egress.internal:3128' \
  browser-secret-proxy -ca-cert ca.pem -ca-key ca.key -hosts api.example.com -swaps swaps.json
```

Use it to send all destination traffic through your egress gateway, or to
keep one exit IP address for the whole browser session (for a Notte
session, a Notte proxy gateway URL from your account). The parent sees
only encrypted traffic: the proxy opens its TLS connection to the
destination through the parent's tunnel. Credentials in the URL are never
logged. Calls to an `http` resolver do not use the parent.

A `CONNECT` to an internal address (loopback, private, link-local such as
`169.254.169.254`, `100.64.0.0/10`) is refused with `403`, so a browser
cannot use the proxy to reach your network. Through `-upstream-proxy`,
only destinations given as IP addresses are checked.
`-allow-private-destinations` turns the check off, for tests against a
local destination.

## Logs

The proxy logs to stderr in `key=value` text, one line per event. `-v`
adds debug lines (tunneled hosts, refused credentials, clients that closed
early).

Each line names at most the client address, the `CONNECT` host and port,
the principal (the proxy username, or a sealed token's `sub`), and counts
or reasons. Useful lines:

| Message | Meaning |
| --- | --- |
| `listening` | Start: address, hosts, resolver mode and settings, whether auth and masking are on. |
| `intercepting` | An allowlisted connection, its protocol and principal. |
| `swapped stand-ins in a request` (HTTP/1.1), `swapped stand-ins in request headers`, `swapped stand-ins in a request body` (HTTP/2) | A swap happened; counts only. |
| `refusing a request` | A request was answered `502`, with the reason. |
| `resolver failed`, `resolver refused the principal` | A lookup failed: `timeout`, `canceled`, `credential refused` or `error`. |
| `refusing connection: ClientHello cannot be replayed exactly` | A client whose TLS the proxy cannot reproduce. |
| `refusing a response that cannot be masked` | A response replaced by `502` (see [masking](cookbook/masking.md)). |
| `reloaded the swaps file`, `keeping the previous stand-ins: the swaps file does not load` | File mode reloads. |

What it never logs, at any level: real values, the swaps file's content,
the CA key, the proxy password or sealed tokens, resolver answers or
error bodies, parent proxy credentials, request paths, query strings and
bodies.

For an audit trail of who used which value where, log releases in your
`http` resolver (stand-in, host, principal, time), and keep the proxy's
`swapped` and `refusing` lines.

## Health checks

The proxy has no health endpoint and no metrics endpoint.

- Check that the port accepts TCP connections (the Kubernetes probes
  above).
- An HTTP check works too if it expects `405`: the proxy answers any
  non-`CONNECT` request with `405 Method Not Allowed`, before
  authentication. `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/`
  prints `405`.
- For an end-to-end check, send a stand-in to an allowlisted echo endpoint
  you control and look for the `swapped` log line.

The distroless image has no shell or curl, so a Docker `HEALTHCHECK`
cannot run inside it; check from outside.

## Shutdown and restarts

On `SIGINT` or `SIGTERM` the proxy stops accepting connections, closes the
open ones, and waits at most 10 seconds for their handlers. Requests in
flight are cut, and browsers retry or fail them. Roll replicas one at a
time.

The CA, the `http` client certificate and the `sealed` keys are read once
at start: restart to change them. The swaps file reloads on its own.

## Sizing

The proxy keeps little state. Measured locally, an idle proxy uses about
17 MB of resident memory. What grows it:

- **Request bodies on allowlisted hosts are buffered** so stand-ins can be
  swapped: up to 32 MiB per body and 64 MiB per HTTP/2 connection, with at
  most 256 open streams per connection. Requests over a limit are refused
  rather than buffered.
- **Response masking streams**: memory is bounded per stream, and
  compressed bodies are decoded on the fly (capped at 64 MiB per decoded
  body).
- **Caches** are capped: 10,000 `http` values, 256 sealed tokens, 1,024
  masked values per principal and 4,096 principals.
- **Connections** are capped at `-max-conns` (default `1024`); past it a
  new one is answered `503`. A connection idle for `-idle-timeout`
  (default `5m`) is closed, and each request head must arrive within
  `-header-timeout` (default `10s`). Raise `-max-conns` for many browsers
  per replica.
- **CPU** goes to TLS: every intercepted connection does a full handshake
  with the destination and one with the client (no session resumption).
  Tunneled hosts cost a TCP copy only.

There are no published benchmarks. Load test with your own traffic and
set the memory limit from what you see under your peak concurrency.

Replicas are independent and keep no shared state, so you can run several
behind one Service. Caches and the masking record are per process,
though: a value looked up through one replica is masked only in responses
through that replica. If a browser's connections can land on different
replicas, prefer client-IP affinity on your load balancer, or accept that
masking covers only the connection's own replica.
