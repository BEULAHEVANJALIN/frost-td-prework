# frost-td-prework

## Quick Start

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e vendor/frost

# verify imports resolve to the vendored package
python -c "import frost, sys; print('py:', sys.version); print('frost at:', frost.__file__)"

# run a smoke demo
python -m workshop.keygen_trusted_dealer
python -m workshop.signing
