.DEFAULT_GOAL := help
.ONESHELL:

MODULE_DIRS := . $(sort $(patsubst %/go.mod,%,$(shell git ls-files --cached --others --exclude-standard -- '*/go.mod')))
GOLANGCI_LINT ?= golangci-lint

.PHONY: tag
tag: ## Tags the repo with new version and tag all sub modules same time than push all
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "Refusing to tag a dirty worktree; commit all release files first"; \
		exit 1; \
	fi
	@latest=$$(git tag -l 'v[0-9]*' --sort=-v:refname | head -n1 || echo "none"); \
	printf "Enter the new version (latest: $$latest): "; read version; \
	if ! printf '%s\n' "$$version" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$$'; then \
		echo "Invalid version: $$version (expected vX.Y.Z or vX.Y.Z-prerelease)"; \
		exit 1; \
	fi; \
	echo "########################################################"; \
	echo "Checking require versions match $$version"; \
	version_re=$$(printf '%s\n' "$$version" | sed 's/\./\\./g'); \
	bad=$$(grep -rEn "^[[:space:]]*(require[[:space:]]+)?github.com/rakunlabs/ada[^[:space:]]*[[:space:]]+v[0-9]" \
		--include="go.mod" . \
		| grep -vE "[[:space:]]$${version_re}([[:space:]]|$$)" || true); \
	if [ -n "$$bad" ]; then \
		echo "Please fix these require versions before tagging $$version:"; \
		echo "$$bad"; \
		exit 1; \
	fi; \
	echo "All go.mod files are up to date"; \
	echo "########################################################"; \
	echo "Use git tag to add new version"; \
	tags=""; \
	for dir in $(filter-out _examples%,$(MODULE_DIRS)); do \
		if [ "$$dir" = "." ]; then tag="$$version"; else tag="$$dir/$$version"; fi; \
		if git rev-parse -q --verify "refs/tags/$$tag" >/dev/null; then \
			echo "Tag already exists: $$tag"; \
			exit 1; \
		fi; \
		echo "git tag $$tag"; \
		tags="$$tags $$tag"; \
	done; \
	echo "########################################################"; \
	echo "git push origin$$tags"

.PHONY: docs
docs: ## Serve documentation
	@cd _docs && pnpm run docs:dev

.PHONY: lint
lint: ## Lint Go files
	@$(GOLANGCI_LINT) run ./...

.PHONY: lint-all
lint-all: ## Lint every Go module
	@set -e; \
	for dir in $(MODULE_DIRS); do \
		printf '\n==> %s\n' "$$dir"; \
		(cd "$$dir" && $(GOLANGCI_LINT) run ./...); \
	done

.PHONY: test
test: ## Run unit tests
	@go test -v -race ./...

.PHONY: test-all
test-all: ## Run race tests in every Go module
	@set -e; \
	for dir in $(MODULE_DIRS); do \
		printf '\n==> %s\n' "$$dir"; \
		go -C "$$dir" test -race ./...; \
	done

.PHONY: vet-all
vet-all: ## Run go vet in every Go module
	@set -e; \
	for dir in $(MODULE_DIRS); do \
		printf '\n==> %s\n' "$$dir"; \
		go -C "$$dir" vet ./...; \
	done

.PHONY: examples-check
examples-check: ## Compile and test example modules
	@go -C _examples test ./...

.PHONY: benchmarks-check
benchmarks-check: ## Compile comparative benchmarks without running them
	@go -C _examples/benchmark test -run '^$$' ./...

.PHONY: coverage
coverage: ## Run unit tests with coverage
	@go test -v -race -cover -coverpkg=./... -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -func=coverage.out

.PHONY: example
example: ## Run example code
	cd _examples && go run main.go

.PHONY: help
help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
