.PHONY: build test check clean

build:
	bash scripts/build.sh

check:
	bash scripts/check_deps.sh

test:
	python -m unittest discover tests/python
	cd engines/go && go test ./...
	cd engines/rust && cargo test
	cd engines/node && node --test

clean:
	rm -rf reports phantomscan.sqlite3 engines/go/bin engines/rust/target

