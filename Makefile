# Authn Platform — Enterprise Identity Engine
#
# Commands for working on the engine and the TypeScript SDKs. Everything here is
# a thin wrapper over a `go`, `pnpm` or `docker compose` invocation — nothing is
# hidden, so any target can be run by hand if you prefer.
#
# Configuration comes from .env, which is the single source of truth. Copy
# .env.example to get started; `make dev` does that for you if it is missing.

ENGINE_DIR := apps/auth-engine
GO         := go

# Both env files must be passed explicitly. Compose substitutes ${...} in the
# YAML only from files given with --env-file, so the values derived into
# .env.compose — including COMPOSE_PROFILES, which decides whether a database
# container starts — would otherwise be ignored.
COMPOSE := docker compose --env-file .env --env-file .env.compose

.DEFAULT_GOAL := help
.PHONY: help dev up down logs migrate bootstrap seed build test test-engine test-sdk vet fmt tidy clean compose-env

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.env:
	@cp .env.example .env
	@echo "Created .env from .env.example — review it before deploying."

compose-env: .env ## Derive container settings from DATABASE_URL into .env.compose
	@sh scripts/compose-env.sh

dev: compose-env ## Start the full stack (engine, database, redis) in the background
	$(COMPOSE) up -d --build
	@echo
	@echo "Engine starting. Follow it with:  make logs"
	@echo "Create your first tenant with:    make bootstrap NAME=\"Your Company\""

up: dev ## Alias for dev

down: compose-env ## Stop the stack, keeping database volumes
	$(COMPOSE) down

clean: compose-env ## Stop the stack and delete database volumes — destroys all local data
	$(COMPOSE) down -v

logs: ## Follow the engine's logs
	$(COMPOSE) logs -f auth-engine

migrate: ## Apply the schema to the configured database
	cd $(ENGINE_DIR) && $(GO) run ./cmd/migrate

# NAME is required; the recipe fails with a usable message rather than a Go
# flag error, because this is most operators' first command.
bootstrap: ## Create the first tenant and print its API keys. Usage: make bootstrap NAME="Acme"
	@test -n "$(NAME)" || { echo 'usage: make bootstrap NAME="Your Company" [SLUG=acme] [ENV=test]'; exit 2; }
	cd $(ENGINE_DIR) && $(GO) run ./cmd/bootstrap \
		-name "$(NAME)" \
		$(if $(SLUG),-slug "$(SLUG)") \
		$(if $(ENV),-env "$(ENV)")

seed: ## Install demo users and fixed development credentials — never in production
	cd $(ENGINE_DIR) && $(GO) run ./cmd/seed

build: ## Compile the engine binaries into apps/auth-engine/bin
	cd $(ENGINE_DIR) && $(GO) build -o bin/auth-engine ./cmd/server
	cd $(ENGINE_DIR) && $(GO) build -o bin/bootstrap ./cmd/bootstrap
	cd $(ENGINE_DIR) && $(GO) build -o bin/migrate ./cmd/migrate

test: test-engine test-sdk ## Run every suite CI gates on — engine, integration and SDKs

# Two invocations because everything under test/ is behind //go:build
# integration, so the first compiles none of it. -race on both to match CI,
# where it is what catches races in the first-admin claim and token rotation.
test-engine: ## Run the engine suite, unit and integration
	cd $(ENGINE_DIR) && $(GO) test -race ./...
	cd $(ENGINE_DIR) && $(GO) test -tags=integration -race ./test/...

test-sdk: ## Run the TypeScript SDK suites
	pnpm test

vet: ## Run go vet
	cd $(ENGINE_DIR) && $(GO) vet -tags=integration ./...

fmt: ## Format Go sources
	cd $(ENGINE_DIR) && gofmt -w .

tidy: ## Tidy module dependencies
	cd $(ENGINE_DIR) && $(GO) mod tidy
