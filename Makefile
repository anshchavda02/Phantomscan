.PHONY: install build test check clean

install:
	pip install -r requirements.txt
	@if command -v npm >/dev/null 2>&1; then \
		cd engines/node && npm install && npx playwright install chromium; \
	fi

build:
	bash scripts/build.sh

check:
	bash scripts/check_deps.sh

test:
	python -m pytest
	@if command -v go >/dev/null 2>&1; then cd engines/go && go test ./...; fi
	@if command -v cargo >/dev/null 2>&1; then cd engines/rust && cargo test; fi
	@if command -v node >/dev/null 2>&1; then cd engines/node && node --test; fi

clean:
	rm -rf reports phantomscan.sqlite3 engines/go/bin engines/rust/target engines/node/node_modules .pytest_cache
