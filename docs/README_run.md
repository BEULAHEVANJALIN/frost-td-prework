# Run guide (quick)

## Setup (Python 3.12+)
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e vendor/frost

## Demos
python -m workshop.keygen_trusted_dealer
python -m workshop.signing_demo
