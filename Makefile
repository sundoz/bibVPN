VENV ?= .venv
PY := $(VENV)/bin/python

.PHONY: dev xray test lint integration

dev: ## create venv with CLI, Ansible and test tools
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -q -e '.[deploy,qr,dev]' ansible-lint

xray: ## pinned Xray into ~/.local/bin (tests validate configs with it)
	scripts/install-xray.sh

test: ## unit tests (config is also checked by xray if it is on PATH)
	$(PY) -m pytest -q

lint:
	cd ansible && ../$(VENV)/bin/ansible-lint --offline site.yml

integration: ## full deploy into a throwaway systemd container (needs docker + xray)
	tests/integration/run.sh
