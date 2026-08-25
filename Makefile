# Authn Platform — Enterprise Identity Engine
#
# There are two ways to run the engine, and they answer differently when a
# dependency is already up:
#
#   make dev    Everything in containers. Compose owns the database, Redis, the
#               mail catcher and the engine. Closest to production.
#   make run    Engine compiled and run as a host process, dependencies still in
#               containers. A code change costs a Go compile rather than an image
#               build, and a debugger can attach to it.
#
# In native mode a container already serving a port is reused — that is the
# normal state of a development machine. In Docker mode a container holding one
# of Compose's names but carrying no Compose labels is a genuine conflict, and
# `make adopt` resolves it without deleting anything.
#
# Every target is thin: it calls a script under scripts/ that does the work and
# explains its own failures. Start with `make doctor` when something is wrong,
# and `make help` for the full list.
#
# Configuration comes from .env, which is the single source of truth. `make env`
# creates it from .env.example, and any target that needs it does so for you.

SHELL := /bin/sh
# -e so a failing command in a recipe stops it rather than letting the next line
# run against a half-finished state; -u so a typo in a variable name is an error.
.SHELLFLAGS := -eu -c
MAKEFLAGS += --no-print-directory

ENGINE_DIR := apps/auth-engine

# Knobs the scripts read from the environment. Make does not export a variable
# to a recipe unless told to, so a value given on the command line — YES=1,
# APP=account — would otherwise be invisible to them.
export YES FORCE PRUNE NO_CACHE FROZEN SKIP_DEPS SKIP_MIGRATE RETRY_ATTEMPTS
export NAME SLUG ENV APP TARGET SERVICE TAIL

# PORT is exported only when it was actually set. The engine fills unset
# variables from .env but treats a set-but-empty one as authoritative, so
# exporting a blank PORT would override .env with nothing.
ifneq ($(strip $(PORT)),)
export PORT
endif

.DEFAULT_GOAL := help

.PHONY: help doctor env compose-env install setup list ports \
        dev up down restart rebuild clean logs ps adopt image \
        run serve stop deps deps-up deps-down deps-status deps-reset deps-logs \
        build build-engine build-js build-sdk build-react build-ui build-packages \
        build-web build-account dev-web dev-account start-web start-account \
        migrate bootstrap seed \
        test test-engine test-sdk lint lint-sh vet fmt tidy clean-build

##@ Getting started

help: ## Show this help
	@sh scripts/help.sh list

doctor: ## Check the toolchain, configuration, ports and containers, and report everything
	@sh scripts/doctor.sh

.env:
	@sh -c '. scripts/lib.sh && ensure_env'

env: .env ## Create .env from .env.example if it does not exist

compose-env: .env ## Derive container settings from .env into .env.compose
	@sh scripts/compose-env.sh

install: ## Install the JavaScript workspace dependencies
	@sh scripts/node.sh install

# setup is the one command for a fresh clone: configuration, dependencies,
# containers, schema, and the workspace builds the applications import.
setup: env install deps migrate build-packages ## Prepare a fresh clone end to end
	@printf '\nReady. Run the engine with "make run", or the whole stack with "make dev".\n'

list: ## List the JavaScript workspaces, their aliases, ports and scripts
	@sh scripts/node.sh list

ports: ## Show what is listening on every port this project uses
	@sh scripts/deps.sh status

##@ Docker stack — engine and dependencies in containers

dev: ## Build and start the full stack, then wait for the engine to report ready
	@sh scripts/stack.sh up

up: dev ## Alias for dev

down: ## Stop the stack, keeping data volumes
	@sh scripts/stack.sh down

restart: ## Restart the engine container and wait for it to report ready
	@sh scripts/stack.sh restart

rebuild: ## Rebuild the engine image without the layer cache
	@sh scripts/stack.sh rebuild

clean: ## Stop the stack and delete its volumes — destroys all local data
	@sh scripts/stack.sh clean

logs: ## Follow the engine's logs. Another service: make logs SERVICE=postgres
	@sh scripts/stack.sh logs

ps: ## Show this project's containers, and every other Authn container on the machine
	@sh scripts/stack.sh ps

# adopt is the answer to "the container name is already in use": containers
# Compose cannot manage are stopped and renamed, freeing the names without
# deleting a container or detaching a volume.
adopt: ## Free container names held outside Compose, without deleting anything
	@sh scripts/deps.sh adopt

image: ## Build the engine's Docker image without starting anything
	@sh scripts/stack.sh rebuild

##@ Native — run on the host, no image build

run: ## Start dependencies, apply the schema, compile the engine and run it
	@sh scripts/engine.sh run

serve: ## Run the already-compiled engine binary, skipping dependency and schema work
	@sh scripts/engine.sh start

stop: ## Stop the host engine by finding whatever holds its port
	@sh scripts/engine.sh stop

deps: deps-up ## Alias for deps-up

deps-up: ## Start the database, Redis and mail catcher, reusing whatever is already up
	@sh scripts/deps.sh up

deps-down: ## Stop the dependency containers this project manages
	@sh scripts/deps.sh down

deps-status: ## Report each dependency: its port, its container, and who manages it
	@sh scripts/deps.sh status

deps-reset: ## Delete the dependency volumes — destroys all local data
	@sh scripts/deps.sh reset

deps-logs: ## Follow the dependency containers' logs
	@sh scripts/deps.sh logs

##@ Build

build: build-engine build-js ## Build everything — engine binaries and all workspaces

build-engine: ## Compile the engine binaries into apps/auth-engine/bin
	@sh scripts/engine.sh build

build-js: ## Build every JavaScript workspace. One only: make build-js TARGET=sdk
	@sh scripts/node.sh build $(TARGET)

build-sdk: ## Build the JavaScript SDK — packages/sdk-js
	@sh scripts/node.sh build sdk

build-react: ## Build the React SDK — packages/sdk-react
	@sh scripts/node.sh build react

build-ui: ## Build the shared UI package — packages/ui
	@sh scripts/node.sh build ui

build-packages: ## Build the SDKs and the UI package, in dependency order
	@sh scripts/node.sh build packages

build-web: ## Build a web application for production: make build-web APP=account
	@sh scripts/node.sh build $(or $(APP),account)

build-account: ## Build the account application — apps/web-account
	@sh scripts/node.sh build account

clean-build: ## Delete every build artifact in the JavaScript workspaces
	@sh scripts/node.sh clean

##@ Run web applications

dev-web: ## Run a web application's dev server: make dev-web APP=account
	@sh scripts/node.sh dev $(or $(APP),account)

dev-account: ## Run the account application's dev server
	@sh scripts/node.sh dev account

start-web: ## Serve a web application's production build: make start-web APP=account
	@sh scripts/node.sh start $(or $(APP),account)

start-account: ## Serve the account application's production build
	@sh scripts/node.sh start account

##@ Data

migrate: ## Apply the schema to the configured database
	@sh scripts/engine.sh migrate

bootstrap: ## Create a tenant and print its API keys: make bootstrap NAME="Acme"
	@sh scripts/engine.sh bootstrap

seed: ## Install demo users and fixed development credentials — never in production
	@sh scripts/engine.sh seed

##@ Quality

test: test-engine test-sdk ## Run every suite CI gates on — engine, integration and SDKs

test-engine: ## Run the engine suites, unit and integration
	@sh scripts/engine.sh test

test-sdk: ## Run the TypeScript suites
	@sh scripts/node.sh test

lint: lint-sh ## Typecheck the JavaScript workspaces and check the build scripts
	@sh scripts/node.sh lint

# The build scripts are the thing every other target depends on, and the mistakes
# they are prone to are silent: syntax only some shells accept, and a function
# variable that a nested call overwrites.
lint-sh: ## Parse the build scripts and audit their variable scope
	@sh scripts/lint-sh.sh

vet: ## Run go vet over the engine, including the integration-tagged files
	@sh scripts/engine.sh vet

fmt: ## Format Go sources and list what changed
	@sh scripts/engine.sh fmt

tidy: ## Tidy the engine's module dependencies
	@sh scripts/engine.sh tidy

# .DEFAULT catches a target that does not exist, which make otherwise reports as
# "No rule to make target" — accurate but unhelpful when the cause is a typo.
.DEFAULT:
	@sh scripts/help.sh unknown "$@"
