PYTHON ?= python3

.PHONY: check doctor
check:
	$(PYTHON) scripts/check_foundation.py

doctor:
	$(PYTHON) scripts/doctor.py
