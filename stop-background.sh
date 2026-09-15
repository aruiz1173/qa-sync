#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
pid_file="$project_dir/.qa-sync/server.pid"
[ -f "$pid_file" ] || exit 0
server_pid=$(sed -n '1p' "$pid_file")
case "$server_pid" in (*[!0-9]*|'') exit 1;; esac
if [ "$server_pid" -gt 1 ] && kill -0 "$server_pid" 2>/dev/null; then
  kill "$server_pid"
fi
# El servidor también borra su PID al salir limpio, así que puede no estar.
rm -f "$pid_file"
