SHELL := /bin/sh

.PHONY: check go-check go-format-check go-vet go-build \
	web-install web-check web-format-check web-lint web-typecheck web-build \
	compose-check compose-up compose-down

check: go-check web-check

go-check: go-format-check go-vet go-build

go-format-check:
	@files="$$(find services -type f -name '*.go' -print)"; \
	unformatted="$$(gofmt -l $$files)"; \
	if [ -n "$$unformatted" ]; then echo "Go files require gofmt:"; echo "$$unformatted"; exit 1; fi

go-vet:
	cd services && go vet ./...

go-build:
	cd services && go build ./...

web-install:
	npm --prefix web ci

web-check: web-install web-format-check web-lint web-typecheck web-build

web-format-check:
	cd web && npx --no-install oxfmt --check app lib

web-lint:
	cd web && npx --no-install oxlint app lib

web-typecheck:
	cd web && npx --no-install tsc --noEmit --incremental false

web-build:
	npm --prefix web run build

compose-check:
	@test -n "$$VPSMGR_DEV_BOOTSTRAP_TOKEN" || \
		(echo "VPSMGR_DEV_BOOTSTRAP_TOKEN must be set"; exit 1)
	@test -n "$$VPSMGR_CONNECTOR_HMAC_KEY" || \
		(echo "VPSMGR_CONNECTOR_HMAC_KEY must be set"; exit 1)
	docker compose config --quiet

compose-up: compose-check
	docker compose up

compose-down:
	docker compose down
