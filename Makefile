.DEFAULT_GOAL := help
.ONESHELL:

.PHONY: tag
tag: ## Tags the repo with new version and tag all sub modules same time than push all
	@latest=$$(git tag -l 'v[0-9]*' --sort=-v:refname | head -n1 || echo "none"); \
	printf "Enter the new version (latest: $$latest): "; read version; \
	echo "########################################################"; \
	echo "Checking require versions match $$version"; \
	bad=$$(grep -rEn "^[[:space:]]*(require[[:space:]]+)?github.com/rakunlabs/ada[^[:space:]]*[[:space:]]+v[0-9]" \
		--include="go.mod" --exclude-dir="_examples" . \
		| grep -v "[[:space:]]$$version$$" || true); \
	if [ -n "$$bad" ]; then \
		echo "Please fix these require versions before tagging $$version:"; \
		echo "$$bad"; \
		exit 1; \
	fi; \
	echo "All go.mod files are up to date"; \
	echo "########################################################"; \
	echo "Use git tag to add new version"; \
	for dir in $$(find . -type f -name 'go.mod' -not -path "*/_examples/*" -exec dirname {} \; | sed 's|^\./||'); do \
		[ "$$dir" = "." ] && echo "git tag $$version" && continue; \
		echo "git tag $$dir/$$version"; \
	done

.PHONY: docs
docs: ## Serve documentation
	@cd _docs && pnpm run docs:dev

.PHONY: lint
lint: ## Lint Go files
	@GOPATH="$(shell dirname $(PWD))" golangci-lint run ./...

.PHONY: test
test: ## Run unit tests
	@go test -v -race ./...

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
