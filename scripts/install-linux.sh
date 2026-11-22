#!/usr/bin/env bash
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")/../installer/linux" && pwd)/install.sh" "$@"
