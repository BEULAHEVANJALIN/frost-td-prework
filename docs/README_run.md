# Run guide

## Local Test / Sanity Check

1) Create and activate a venv (Python 3.12+), then install the vendored FROST:
```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e vendor/frost
````

2. Verify the import points at the vendored path:

```bash
python -c "import frost, sys; print('py:', sys.version); print('frost at:', frost.__file__)"
```

3. Run the workshop modules:

```bash
python -m workshop.keygen_trusted_dealer
python -m workshop.signing
# (DKG path)
python -m workshop.keygen_dkg
python -m workshop.signing
```