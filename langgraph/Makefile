.PHONY: venv install run-lite run-full resume portal clean

# -- Environment ----------------------------------------------------------
VENV    = .venv
PYTHON  = $(VENV)/bin/python
PIP     = $(VENV)/bin/pip

# Windows alternatives (run in PowerShell):
#   python -m venv .venv
#   .venv\Scripts\pip install -r requirements.txt
#   $env:NEXUS_MODEL="claude-opus-4-7"; python pipeline.py
#   $env:NEXUS_GATEWAY_URL="http://sift-vm:4508/mcp"; $env:NEXUS_BEARER_TOKEN="..."; python pipeline.py

# -- Targets --------------------------------------------------------------

venv:
	python3 -m venv $(VENV)

install: venv
	$(PIP) install -r requirements.txt

run-lite:
	NEXUS_MODEL=claude-opus-4-7 python pipeline.py

run-full:
	NEXUS_GATEWAY_URL=http://localhost:4508/mcp \
	NEXUS_BEARER_TOKEN=$(or $(NEXUS_BEARER_TOKEN),replace_with_real_token) \
	python pipeline.py

resume:
	python pipeline.py --resume

portal:
	@echo "Open http://localhost:4508/portal/ in your browser"
	@echo "Or run: nexus serve --http"

clean:
	rm -rf $(VENV) __pycache__ pipeline.sqlite
