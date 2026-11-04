# secret-proxy

A forward proxy that fills in secrets on the way out. A browser, or an agent
driving it, only ever handles stand-in values; the proxy swaps each stand-in
for its real value in requests to the hosts you list, and nowhere else.

It is built so that the destination cannot tell the proxy is there. It works
with any Chromium-based browser (and other clients) and copies, on every
connection:

- the TLS ClientHello: the client's own cipher suites, extensions and their
  order, supported groups, signature algorithms and ALPN, with fresh randoms
  and key shares (via [uTLS](https://github.com/refraction-networking/utls));
- the HTTP/2 connection: SETTINGS values and order, the connection
  WINDOW_UPDATE, PRIORITY frames, request priorities, and pseudo-header and
  header order. HTTP/2 stays HTTP/2 and no header is added.

When a ClientHello cannot be copied exactly, the proxy refuses the connection,
logs why and answers the client with an error. It never falls back to a
built-in fingerprint.

Hosts that are not on the list are tunneled untouched: plain CONNECT, no
decryption.

## How it works

1. The client sends `CONNECT host:443`. If `host` is not allowlisted, the proxy
   opens a tunnel and copies bytes both ways.
2. For an allowlisted host, the proxy reads the client's ClientHello, rebuilds
   it with uTLS, checks field by field that the rebuilt hello matches (only
   randoms, session ID, key shares and GREASE values may differ), and performs
   that handshake with the destination. An extension uTLS does not model is
   copied byte for byte only if it is on a short reviewed list of data-only
   extensions (`verbatimExtensions` in `internal/proxy`, today TLS Trust
   Anchor IDs); any other one fails the connection.
3. It then completes the client's handshake with a certificate for `host`
   issued on the fly by your CA, offering the application protocol the
   destination chose.
4. Requests are relayed:
   - **HTTP/2** frame by frame. The client's connection-level frames go
     upstream unchanged and in order; responses come back byte for byte. Each
     request header block is decoded, stand-ins are swapped in header values
     and in the `:path` query string, and the block is encoded again in the
     same order. A request body is buffered until the client ends it, swapped,
     and sent with a corrected `content-length`.
   - **HTTP/1.1** with the client's request line, header order, casing and
     spacing kept as sent.

Swaps happen only when the request's authority is on the allowlist.

## Running it

Create a CA. The browser must trust it; keep the key private.

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj "/CN=secret-proxy CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" -keyout ca.key -out ca.pem
```

List the stand-ins and their real values:

```json
{
  "4242424242424242": "<real card number>",
  "tok_standin_123": "<real API token>"
}
```

Start the proxy:

```sh
go run ./cmd/secret-proxy \
  -listen 127.0.0.1:8080 \
  -ca-cert ca.pem -ca-key ca.key \
  -hosts 'api.example.com,*.payments.example' \
  -swaps swaps.json
```

Point the browser at it, for example
`chromium --proxy-server=http://127.0.0.1:8080`, and make it trust `ca.pem`
(on Linux, add it to the NSS database with
`certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n secret-proxy -i ca.pem`).

### Options

| Flag or variable | Meaning |
| --- | --- |
| `-listen` | Address to listen on (default `127.0.0.1:8080`). |
| `-ca-cert`, `-ca-key` | PEM CA certificate and key (PKCS #8, PKCS #1 or SEC 1). |
| `-hosts` | Comma-separated hosts to decrypt: exact names, or `*.domain` for every name below `domain` (not `domain` itself). |
| `-swaps` | JSON object of stand-in to real value. Each real value is inserted in the form its place needs: query-escaped in query strings and form bodies (whether the stand-in was raw or percent-encoded), JSON-escaped inside JSON strings (`application/json`, `text/json`, `+json` types), as is in other bodies. In headers it is inserted as is, and a value with a line break or NUL is refused there. |
| `-upstream-proxy`, `SECRET_PROXY_UPSTREAM` | Parent proxy for all outgoing connections: `http://`, `https://` or `socks5://`, with credentials in the URL. |
| `SECRET_PROXY_USERNAME`, `SECRET_PROXY_PASSWORD` | Require these Basic credentials on every CONNECT. |
| `-v` | Debug logging. |

Real values are never logged; log lines name the host and how many fields were
swapped.

## Limitations of this version

- CONNECT only; plain `http://` proxy requests get `405`. The CONNECT request
  head is capped at 64 KiB (`431` beyond it), before any authentication.
- **TLS session resumption is not mirrored (fingerprint gap).** The proxy
  issues no session tickets to the client, so the client never resumes and
  every upstream handshake is a full one. A browser connecting directly would
  resume on repeat visits (a `pre_shared_key` in its ClientHello), so repeat
  visits look different to the destination. The fix is a per-client,
  per-host cache of upstream tickets: resume upstream exactly when the client
  resumes with the proxy, do a full handshake exactly when it does not, and
  fail the connection when the client resumes but no upstream ticket is
  held. A ClientHello that offers `pre_shared_key` or early data is refused
  today.
- HTTP/2 request header blocks are re-encoded with a standard HPACK encoder:
  order, values and never-indexed fields are kept, but the encoder's indexing
  choices are its own.
- Request bodies on allowlisted hosts are buffered: 32 MiB per body and
  64 MiB per HTTP/2 connection, with at most 256 open streams and 1 MiB per
  header block. An HTTP/2 stream over a limit is refused with
  `REFUSED_STREAM`, so the browser can retry it. HTTP/1.1 heads are capped at
  1 MiB and chunked trailers at 16 KiB. `Expect: 100-continue` is answered by
  the proxy, which needs the body before forwarding the request. Extended
  CONNECT (WebSockets over HTTP/2) and HTTP/1.1 upgrades are streamed without
  swapping.
- When the destination sends GOAWAY, requests it will not process are
  refused with `REFUSED_STREAM` and no new request is sent upstream.
- HTTP/2 clients must respect flow control: a client that sends past its
  window ends the connection with `FLOW_CONTROL_ERROR`, and a streamed upload
  that would pass the connection's buffer limit is reset. The client is told
  a header table size of at most 64 KiB (the relay's request decoder); this
  only bounds the client's own HPACK encoder, whose output the proxy encodes
  again, so the destination sees no difference.
- A swap cannot grow a request past its limits (1 MiB of headers, the body
  and connection buffer limits): over a limit, an HTTP/2 stream is refused
  and an HTTP/1.1 connection is closed, before anything is sent. The same
  happens when a real value with a line break would go into a header.
- Other text formats (XML, multipart) get real values as is; a value that
  needs escaping in such a body is not escaped.
- An HTTP/1.1 `Upgrade` (or `CONNECT`) request turns the connection into a
  raw stream only after the destination accepts it (`101`, or `2xx` for
  `CONNECT`); after a refusal, later requests are still swapped.
- Stopping the proxy closes open connections, then waits at most 10 seconds
  for them to finish.
- Server push is not supported.
- Responses are not masked.

## Development

```sh
go vet ./...
go test -race ./...
```

The tests run a local TLS destination that records the ClientHello it
receives and compare it with what a Chrome client (uTLS's Chrome profile) sent,
check HTTP/2 SETTINGS, priority and header order end to end, and check that
non-allowlisted hosts are tunneled without decryption.

## License

Apache License 2.0, see [LICENSE](LICENSE).
