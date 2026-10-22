#!/usr/bin/env bash
# Start the traffic analyzer (backend + frontend) and verify that both are healthy.
#
#   ./scripts/dev.sh            start both, wait for the health checks, follow the logs
#   ./scripts/dev.sh backend    start only the API
#   ./scripts/dev.sh frontend   start only the UI
#
# The API must be reachable before the UI is useful: when the backend is down, the
# dev proxy answers every /api request with HTTP 500, which looks like a broken
# application. This script fails loudly instead.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="${ROOT}/backend"
FRONTEND_DIR="${ROOT}/frontend"
LOG_DIR="${ROOT}/.run"
VENV="${ROOT}/backend/.venv"
API_HOST="127.0.0.1"
API_PORT="8000"
UI_PORT="5174"

mkdir -p "${LOG_DIR}"

pick_python() {
  if [ -x "${VENV}/bin/python" ]; then
    echo "${VENV}/bin/python"
  elif [ -x "/home/abhaysawant/.venvs/traffic-analyzer/bin/python" ]; then
    echo "/home/abhaysawant/.venvs/traffic-analyzer/bin/python"
  else
    echo "python3"
  fi
}

PYTHON="$(pick_python)"

wait_for_api() {
  echo "==> waiting for the API on http://${API_HOST}:${API_PORT}"
  for _ in $(seq 1 40); do
    if curl -fsS "http://${API_HOST}:${API_PORT}/api/health" >/dev/null 2>&1; then
      echo "    API is up: $(curl -fsS "http://${API_HOST}:${API_PORT}/api/health" | head -c 120)"
      return 0
    fi
    sleep 0.5
  done
  echo "!!! The API did not come up. See ${LOG_DIR}/backend.log" >&2
  tail -20 "${LOG_DIR}/backend.log" >&2 || true
  return 1
}

start_backend() {
  if curl -fsS "http://${API_HOST}:${API_PORT}/api/health" >/dev/null 2>&1; then
    echo "==> the API is already running on port ${API_PORT}"
    return 0
  fi
  echo "==> starting the API"
  # setsid fully detaches the process, so the API keeps running even when the
  # shell that started it exits. Without this the API silently dies and every
  # /api request from the dev proxy answers HTTP 500.
  ( cd "${BACKEND_DIR}" && setsid nohup "${PYTHON}" -m uvicorn app.main:app \
      --host "${API_HOST}" --port "${API_PORT}" >"${LOG_DIR}/backend.log" 2>&1 < /dev/null & )
  wait_for_api
}

start_frontend() {
  echo "==> starting the UI on http://localhost:${UI_PORT}"
  ( cd "${FRONTEND_DIR}" && setsid nohup npm run dev >"${LOG_DIR}/frontend.log" 2>&1 < /dev/null & )
  for _ in $(seq 1 40); do
    if curl -fsS "http://localhost:${UI_PORT}/" >/dev/null 2>&1; then
      echo "    UI is up: http://localhost:${UI_PORT}"
      return 0
    fi
    sleep 0.5
  done
  echo "!!! The UI did not come up. See ${LOG_DIR}/frontend.log" >&2
  tail -20 "${LOG_DIR}/frontend.log" >&2 || true
  return 1
}

case "${1:-all}" in
  backend)  start_backend ;;
  frontend) start_frontend ;;
  all)
    start_backend
    start_frontend
    echo
    echo "Traffic analyzer is running:"
    echo "  UI  -> http://localhost:${UI_PORT}"
    echo "  API -> http://${API_HOST}:${API_PORT}/api/health"
    echo "  logs: ${LOG_DIR}/backend.log, ${LOG_DIR}/frontend.log"
    ;;
  *)
    echo "usage: $0 [all|backend|frontend]" >&2
    exit 2
    ;;
esac
