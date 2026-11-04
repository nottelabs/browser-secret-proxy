#!/usr/bin/env bash
# Temporary pre-submit shopping compatibility run; source proxy is unchanged.
set -euo pipefail
: "${NOTTE_API_KEY:?required}"
: "${NGROK_AUTHTOKEN:?required}"
export NOTTE_API_URL="${NOTTE_API_URL:-https://us-staging.notte.cc}"
work=$(mktemp -d)
container="bsp-shopping-$$"
tunnel_pid=""
cleanup() {
  if [ -n "$tunnel_pid" ]; then kill "$tunnel_pid" 2>/dev/null || true; fi
  docker logs "$container" 2>&1 | tail -n 80 || true
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
export SECRET_PROXY_USERNAME="shopping-$(openssl rand -hex 12)"
export SECRET_PROXY_PASSWORD="$(openssl rand -hex 24)"
echo "::add-mask::$SECRET_PROXY_USERNAME"
echo "::add-mask::$SECRET_PROXY_PASSWORD"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj '/CN=BSP synthetic shopping test CA' -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign' -keyout "$work/ca.key" -out "$work/ca.pem" 2>/dev/null
cat > "$work/swaps.json" <<'JSON'
{"/status/299":"/status/200","tok_bsp_shopping_probe":"dummy_bsp_shopping_replacement","4111111111111111":"4242424242424242"}
JSON
chmod 644 "$work/ca.key" "$work/ca.pem" "$work/swaps.json"
docker run -d --name "$container" -p 127.0.0.1:18380:8080 \
  -v "$work/ca.pem:/etc/bsp/ca.pem:ro" -v "$work/ca.key:/etc/bsp/ca.key:ro" \
  -v "$work/swaps.json:/etc/bsp/swaps.json:ro" \
  -e SECRET_PROXY_USERNAME -e SECRET_PROXY_PASSWORD \
  browser-secret-proxy:dev -ca-cert /etc/bsp/ca.pem -ca-key /etc/bsp/ca.key \
  -swaps /etc/bsp/swaps.json -hosts 'postman-echo.com,www.birkenstock.com,checkoutshopper-live.adyen.com,live.adyen.com,www.booking.com,secure.booking.com' >/dev/null
ready=""
for _ in $(seq 1 20); do
  status=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 1 --max-time 2 http://127.0.0.1:18380/ || true)
  if [ "$status" = 407 ]; then ready=1; break; fi
  if [ "$(docker inspect -f '{{.State.Running}}' "$container")" != true ]; then
    echo 'Proxy exited before readiness; no browser will be allocated' >&2
    exit 1
  fi
  sleep 0.5
done
test -n "$ready"
printf 'version: "3"\nagent:\n  web_addr: false\n' > "$work/ngrok.yml"
ngrok tcp 18380 --config "$work/ngrok.yml" --log stdout --log-format logfmt > "$work/ngrok.log" 2>&1 &
tunnel_pid=$!
public=""
for _ in $(seq 1 30); do
  public=$(sed -n 's/.*url=tcp:\/\/\([^ ]*\).*/\1/p' "$work/ngrok.log" | head -n 1)
  [ -n "$public" ] && break
  if ! kill -0 "$tunnel_pid" 2>/dev/null; then
    sed -E 's/(authtoken|token)=[^ ]+/\1=[redacted]/g' "$work/ngrok.log" >&2
    exit 1
  fi
  sleep 1
done
test -n "$public"
export BSP_PROXY_SERVER="http://$public"
export BSP_CA_FILE="$work/ca.pem"
echo "BSP public tunnel ready; synthetic values only; masks enabled; private destinations refused"
cd scripts/shopping-proxy
npm ci --ignore-scripts --no-audit --no-fund >/dev/null
npx --no-install tsx run.ts birkenstock-us
