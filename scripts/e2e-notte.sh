#!/usr/bin/env bash
# End-to-end check against a real Notte environment.
#
# Starts the proxy image with a throwaway CA and swaps file, exposes it on a
# public address through a bore tunnel, starts a Notte session that sends one
# host through it, and checks that:
#   - the allowlisted host receives the real value instead of the stand-in;
#   - another host still receives the stand-in.
#
# Needs: docker, curl, jq, openssl, bore (https://github.com/ekzhang/bore).
#
# Environment:
#   NOTTE_API_KEY    API key for the Notte environment (required)
#   NOTTE_API_URL    default https://us-staging.notte.cc
#   IMAGE            proxy image to test, default browser-secret-proxy:dev
#   BORE_SERVER      default bore.pub
#   SWAP_HOST        allowlisted echo host, default postman-echo.com
#   CONTROL_HOST     echo host outside the allowlist, default httpbingo.org
set -euo pipefail

: "${NOTTE_API_KEY:?set NOTTE_API_KEY}"
NOTTE_API_URL="${NOTTE_API_URL:-https://us-staging.notte.cc}"
IMAGE="${IMAGE:-browser-secret-proxy:dev}"
BORE_SERVER="${BORE_SERVER:-bore.pub}"
SWAP_HOST="${SWAP_HOST:-postman-echo.com}"
CONTROL_HOST="${CONTROL_HOST:-httpbingo.org}"
LOCAL_PORT="${LOCAL_PORT:-18080}"

log() { printf '[e2e] %s\n' "$*" >&2; }
fail() { printf '[e2e] FAIL: %s\n' "$*" >&2; exit 1; }

work="$(mktemp -d)"
container="bsp-e2e-$$"
bore_pid=""
session_id=""

cleanup() {
  set +e
  if [ -n "$session_id" ]; then
    log "stopping session $session_id"
    curl -sS -o /dev/null --connect-timeout 10 --max-time 30 -X DELETE \
      -H "Authorization: Bearer $NOTTE_API_KEY" \
      "$NOTTE_API_URL/sessions/$session_id/stop"
  fi
  [ -n "$bore_pid" ] && kill "$bore_pid" 2>/dev/null
  if docker inspect "$container" >/dev/null 2>&1; then
    log "proxy logs:"
    docker logs "$container" 2>&1 | tail -n 40 >&2
    docker rm -f "$container" >/dev/null
  fi
  rm -rf "$work"
}
trap cleanup EXIT

api() {
  # api METHOD PATH [JSON]: prints the body, fails on a non-2xx status.
  local method="$1" path="$2" body="${3:-}" out status
  out="$work/response.json"
  status="$(curl -sS -o "$out" -w '%{http_code}' --connect-timeout 10 --max-time 120 -X "$method" \
    -H "Authorization: Bearer $NOTTE_API_KEY" -H 'Content-Type: application/json' \
    ${body:+--data "$body"} "$NOTTE_API_URL$path")"
  if [ "${status:0:1}" != 2 ]; then
    cat "$out" >&2
    fail "$method $path returned $status"
  fi
  cat "$out"
}

rand() { openssl rand -hex 12; }

# Throwaway CA, credentials and values, new on every run.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=browser-secret-proxy e2e CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" -keyout "$work/ca.key" -out "$work/ca.pem" 2>/dev/null
standin="tok_e2e_$(rand)"
real="real_e2e_$(rand)"
proxy_user="e2e-$(rand)"
proxy_pass="$(rand)$(rand)"
jq -n --arg s "$standin" --arg r "$real" '{($s): $r}' >"$work/swaps.json"
# The image runs as UID 65532; the files are throwaway.
chmod 644 "$work/ca.key" "$work/ca.pem" "$work/swaps.json"

log "starting $IMAGE for $SWAP_HOST"
docker run -d --name "$container" -p "127.0.0.1:$LOCAL_PORT:8080" \
  -v "$work/ca.pem:/etc/bsp/ca.pem:ro" -v "$work/ca.key:/etc/bsp/ca.key:ro" \
  -v "$work/swaps.json:/etc/bsp/swaps.json:ro" \
  -e SECRET_PROXY_USERNAME="$proxy_user" -e SECRET_PROXY_PASSWORD="$proxy_pass" \
  "$IMAGE" -ca-cert /etc/bsp/ca.pem -ca-key /etc/bsp/ca.key \
  -swaps /etc/bsp/swaps.json -hosts "$SWAP_HOST" -mask-responses=false >/dev/null

# Wait until the proxy answers. There is no local swap check: the proxy
# refuses TLS clients whose ClientHello it cannot replay exactly, which
# includes OpenSSL's curl, so only the browser below tests the swap.
ready=""
for _ in $(seq 1 20); do
  if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$LOCAL_PORT"; then ready=1; break; fi
  sleep 0.5
done
[ -n "$ready" ] || fail "the proxy did not start"

log "opening a tunnel through $BORE_SERVER"
bore local "$LOCAL_PORT" --to "$BORE_SERVER" >"$work/bore.log" 2>&1 &
bore_pid=$!
public=""
for _ in $(seq 1 30); do
  public="$(grep -o "listening at [^ ]*" "$work/bore.log" | awk '{print $3}' | head -n1 || true)"
  [ -n "$public" ] && break
  kill -0 "$bore_pid" 2>/dev/null || { cat "$work/bore.log" >&2; fail "bore exited"; }
  sleep 1
done
[ -n "$public" ] || { cat "$work/bore.log" >&2; fail "no tunnel address"; }
log "proxy is public at $public"

start_body="$(jq -n --arg server "http://$public" --arg user "$proxy_user" --arg pass "$proxy_pass" \
  --rawfile ca "$work/ca.pem" --arg host "$SWAP_HOST" \
  '{max_duration_minutes: 5, idle_timeout_minutes: 3,
    proxies: [{type: "secret", server: $server, username: $user, password: $pass,
               ca_certificate: $ca, hosts: [$host]}]}')"
log "starting a session on $NOTTE_API_URL"
session="$(api POST /sessions/start "$start_body")"
session_id="$(jq -r .session_id <<<"$session")"
log "session $session_id"
jq -e --arg host "$SWAP_HOST" '.secret_proxy.hosts == [$host]' <<<"$session" >/dev/null \
  || fail "the session does not report the secret proxy: $(jq -c .secret_proxy <<<"$session")"

page_text() {
  # page_text URL: opens URL in the session and prints the page as markdown.
  local url="$1" result
  result="$(api POST "/sessions/$session_id/page/execute" "$(jq -n --arg url "$url" '{type: "goto", url: $url}')")"
  jq -e '.success == true' <<<"$result" >/dev/null \
    || fail "goto $url failed: $(jq -c '{message, exception}' <<<"$result")"
  api POST "/sessions/$session_id/page/scrape" '{"scrape_links": false}' | jq -r '.markdown // ""'
}

swapped="$(page_text "https://$SWAP_HOST/get?card=$standin")"
grep -q "$real" <<<"$swapped" || { printf '%s\n' "$swapped" | head -n 40 >&2; fail "$SWAP_HOST did not receive the real value"; }
grep -q "$standin" <<<"$swapped" && fail "$SWAP_HOST still saw the stand-in"
log "$SWAP_HOST received the real value"

control="$(page_text "https://$CONTROL_HOST/get?card=$standin")"
grep -q "$standin" <<<"$control" || { printf '%s\n' "$control" | head -n 40 >&2; fail "$CONTROL_HOST page did not echo the stand-in"; }
grep -q "$real" <<<"$control" && fail "$CONTROL_HOST received the real value"
log "$CONTROL_HOST received the stand-in"

log "PASS"
