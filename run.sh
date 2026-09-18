#!/bin/bash
# Loads .env and runs the app with the venv's Python.
cd "$(dirname "$0")"
set -a
[ -f .env ] && source .env
set +a
exec ./venv/bin/python app.py
