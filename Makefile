PYTHON ?= python
PROJECT_ROOT := $(CURDIR)

check:
	$(PYTHON) scripts/bootstrap_check.py
	$(PYTHON) scripts/validate_samples.py
	$(PYTHON) scripts/validate_processed.py
	$(PYTHON) scripts/validate_botsv3_outputs.py
	PYTHONPATH=src $(PYTHON) -m pytest -q tests

prepare-sources:
	@test -n "$(ATTACK_ZIP)" || (echo "ATTACK_ZIP is required" && exit 1)
	@test -n "$(SIGMA_ZIP)" || (echo "SIGMA_ZIP is required" && exit 1)
	$(PYTHON) scripts/run_source_preparation.py --project-root $(PROJECT_ROOT) --attack-zip $(ATTACK_ZIP) --sigma-zip $(SIGMA_ZIP)

prepare-botsv3:
	@test -n "$(BOTSV3_ARCHIVE)" || (echo "BOTSV3_ARCHIVE is required" && exit 1)
	PYTHONPATH=src $(PYTHON) scripts/prepare_botsv3.py --source-archive $(BOTSV3_ARCHIVE) --project-root $(PROJECT_ROOT)
