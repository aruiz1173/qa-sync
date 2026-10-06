#!/bin/sh
exec sh "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/start-background.sh"
