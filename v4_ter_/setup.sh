#!/bin/bash

set -e

if command -v uv >/dev/null 2>&1; then
    uv sync
fi
