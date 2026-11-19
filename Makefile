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
	$(UV) run --locked --offline ruff check src tests scripts/export_contracts.py scripts/export_api.py scripts/check_fixtures.py scripts/shuffle_plan.py scripts/check_shuffle_plan.py scripts/shuffle_runtime.py

typecheck:
	$(UV) run --locked --offline mypy

schemas:
	$(UV) run --locked --offline python scripts/export_contracts.py --check
	$(UV) run --locked --offline python scripts/export_api.py --check

qualify: test lint typecheck schemas
	$(UV) run --locked --offline python scripts/check_fixtures.py
	$(UV) run --locked --offline python scripts/check_shuffle_plan.py
	$(UV) run --locked --offline python scripts/check_foundation.py
