#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
state_dir="$project_dir/.qa-sync"
pid_file="$state_dir/server.pid"
log_file="$state_dir/server.log"
url="http://127.0.0.1:8787/"
mkdir -p "$state_dir"

is_ready() {
  command -v curl >/dev/null 2>&1 && curl -fsS --max-time 2 "$url/api/status" >/dev/null 2>&1
}

open_app() {
  if command -v open >/dev/null 2>&1; then
    open "$url"
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url"
  else
    printf 'QA Sync is available at %s\n' "$url"
  fi
}

wait_for_server() {
  watched_pid=$1
  attempt=0
  while [ "$attempt" -lt 100 ]; do
    if is_ready; then
      return 0
    fi
    if ! kill -0 "$watched_pid" 2>/dev/null; then
      return 1
    fi
    attempt=$((attempt + 1))
    sleep 0.2
  done
  return 1
}

if is_ready; then
  if [ "$(uname -s)" = "Darwin" ]; then
    (cd "$project_dir" && python3 -m qasync.launcher start)
  fi
  open_app
  exit 0
fi

if [ "$(uname -s)" = "Darwin" ]; then
  (cd "$project_dir" && python3 -m qasync.launcher start)
  open_app
  exit 0
fi

if [ -f "$pid_file" ]; then
  old_pid=$(sed -n '1p' "$pid_file")
  case "$old_pid" in (*[!0-9]*|'') old_pid=0;; esac
  if [ "$old_pid" -gt 1 ] && kill -0 "$old_pid" 2>/dev/null; then
    old_command=$(ps -p "$old_pid" -o command= 2>/dev/null || true)
    case "$old_command" in
      *qasync*)
        if wait_for_server "$old_pid"; then
          open_app
          exit 0
        fi
        printf 'QA Sync PID %s is alive but did not become ready. Check %s\n' "$old_pid" "$log_file" >&2
        exit 1
        ;;
    esac
  fi
fi

nohup sh "$project_dir/run.sh" >"$log_file" 2>&1 &
server_pid=$!
printf '%s\n' "$server_pid" >"$pid_file"
chmod 600 "$pid_file" "$log_file"

if wait_for_server "$server_pid"; then
  open_app
  exit 0
fi
printf 'QA Sync did not become ready. Check %s\n' "$log_file" >&2
exit 1
