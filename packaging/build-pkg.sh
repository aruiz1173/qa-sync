#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir="$project_dir/.qa-sync/package-build"
payload_dir="$build_dir/payload/Applications/QA Sync"
output_dir="$project_dir/dist"
unsigned_pkg="$build_dir/QA-Sync-unsigned.pkg"
final_pkg="$output_dir/QA-Sync.pkg"

rm -rf "$build_dir"
mkdir -p "$payload_dir" "$output_dir"
rsync -a --exclude '.qa-sync' --exclude '.env' --exclude 'dist' --exclude '.git' "$project_dir/" "$payload_dir/"
pkgbuild --root "$build_dir/payload" --identifier com.qasync.local --version "1.0.0" "$unsigned_pkg"

if [ -n "${DEVELOPER_ID_INSTALLER:-}" ]; then
  productsign --sign "$DEVELOPER_ID_INSTALLER" "$unsigned_pkg" "$final_pkg"
  pkgutil --check-signature "$final_pkg"
else
  cp "$unsigned_pkg" "$final_pkg"
  printf '%s\n' 'Paquete creado sin firma. Define DEVELOPER_ID_INSTALLER para firmarlo.'
fi
printf '%s\n' "$final_pkg"
