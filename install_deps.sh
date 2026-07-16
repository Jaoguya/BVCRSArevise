#!/bin/bash
set -e
echo "=== Installing pip ==="
python3 -m ensurepip --user 2>/dev/null || {
    echo "ensurepip failed, trying get-pip..."
    curl -sS https://bootstrap.pypa.io/get-pip.py | python3 - --user
}
echo "=== pip installed ==="
export PATH="$HOME/.local/bin:$PATH"
echo "=== Installing numpy pandas pymongo ==="
python3 -m pip install --user numpy pandas pymongo
echo "=== Verifying ==="
python3 -c "import numpy; import pandas; print('numpy:', numpy.__version__); print('pandas:', pandas.__version__)"
echo "=== DONE ==="
