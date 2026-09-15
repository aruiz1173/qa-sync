#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
state_dir="$project_dir/.qa-sync"
pid_file="$state_dir/server.pid"
log_file="$state_dir/server.log"
url="http://127.0.0.1:8787/"
mkdir -p "$state_dir"

if command -v curl >/dev/null 2>&1 && curl -fsS "$url/api/status" >/dev/null 2>&1; then
  open "$url"
  exit 0
fi

if [ -f "$pid_file" ]; then
  old_pid=$(sed -n '1p' "$pid_file")
  case "$old_pid" in (*[!0-9]*|'') old_pid=0;; esac
  if [ "$old_pid" -gt 1 ] && kill -0 "$old_pid" 2>/dev/null; then
    open "$url"
    exit 0
  fi
fi

nohup "$project_dir/run.sh" >"$log_file" 2>&1 &
server_pid=$!
printf '%s\n' "$server_pid" >"$pid_file"
chmod 600 "$pid_file" "$log_file"

attempt=0
while [ "$attempt" -lt 30 ]; do
  if command -v curl >/dev/null 2>&1 && curl -fsS "$url/api/status" >/dev/null 2>&1; then
    open "$url"
    exit 0
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    open "$log_file"
    exit 1
  fi
  attempt=$((attempt + 1))
  sleep 0.2
done
open "$log_file"
exit 1
