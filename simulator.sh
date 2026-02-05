#!/bin/bash
# Keystone Simulator - Build and Run
#
# Automatically opens in Terminal.app for QR screen scanning to work.

set -e

# Get the directory where this script lives
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Check if we're running in Terminal.app
if [ "$TERM_PROGRAM" != "Apple_Terminal" ]; then
    echo "Reopening in Terminal.app for QR scanning support..."
    osascript -e "tell application \"Terminal\" to do script \"cd '$SCRIPT_DIR' && ./simulator.sh $*\""
    exit 0
fi

cd "$SCRIPT_DIR"

# Activate venv if exists
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

# Check if rebuild needed (default: yes if --no-build not passed)
BUILD=true
if [ "$1" = "--no-build" ] || [ "$1" = "-n" ]; then
    BUILD=false
    shift
fi

if [ "$BUILD" = true ]; then
    echo "=== Building Cypherpunk Simulator ==="
    python3 build.py -t cypherpunk -o simulator
    echo ""
fi

echo "=== Starting Simulator ==="
exec ./build/simulator "$@"
