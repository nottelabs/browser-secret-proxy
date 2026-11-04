#!/usr/bin/env bash
# End-to-end check against a real Notte environment: runs the scenarios of
# scripts/e2e-notte (see its package comment and CONTRIBUTING.md) against the
# proxy image, through Notte sessions and ngrok tunnels.
#
# Needs: Go, docker (with host networking: Linux, OrbStack, or Docker Desktop
# 4.34 or later with host networking turned on) and ngrok v3.
#
# Environment:
#   NOTTE_API_KEY    API key for the Notte environment (required)
#   NGROK_AUTHTOKEN  ngrok agent authtoken; TCP tunnels need a verified account (required)
#   NOTTE_API_URL    default https://us-staging.notte.cc
#   IMAGE            proxy image to test, default browser-secret-proxy:dev
#   NGROK            ngrok binary, default ngrok
#   SWAP_HOST        allowlisted echo host, default postman-echo.com
#   CONTROL_HOST     echo host outside the allowlist, default httpbingo.org
set -euo pipefail

cd "$(dirname "$0")/.."
exec go run ./scripts/e2e-notte
