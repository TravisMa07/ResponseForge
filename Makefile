PYTHON ?= python3
UV ?= uv

.PHONY: check doctor sync test lint typecheck qualify schemas
check:
	$(PYTHON) scripts/check_foundation.py

doctor:
	$(PYTHON) scripts/doctor.py

sync:
	$(UV) sync --locked

test:
	$(UV) run --locked --offline pytest

lint:
	$(UV) run --locked --offline ruff check src tests scripts/export_contracts.py

typecheck:
	$(UV) run --locked --offline mypy

schemas:
	$(UV) run --locked --offline python scripts/export_contracts.py --check

qualify: test lint typecheck schemas
	$(UV) run --locked --offline python scripts/check_foundation.py
