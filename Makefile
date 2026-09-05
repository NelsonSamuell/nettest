PYTHON ?= python3
BUILD := build/zipapp

.PHONY: test dist clean

test:
	$(PYTHON) -m pytest -q

# A single netcheck.pyz that runs on any host with Python 3.11 and needs no
# install. Dependencies are vendored into the archive.
dist: clean
	mkdir -p $(BUILD)
	$(PYTHON) -m pip install --quiet --target $(BUILD) .
	$(PYTHON) -m zipapp $(BUILD) \
		--main netcheck.cli:main \
		--python "/usr/bin/env python3" \
		--output netcheck.pyz
	@echo "built netcheck.pyz"

clean:
	rm -rf build netcheck.pyz
