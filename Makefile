SHELL := /bin/bash

SERVICE_NAME=virtual-lab-manager

define HELPTEXT
	Usage: make COMMAND
	commands for managing the project
	
	Commands:
		dev		Run development api server.
		init		Run project (keycloak and postgres) containers
		kill		Kill project (keycloak and postgres) containers
		build		Build docker image
		format          Check formatting of files and fixes any formatting issues
		format-check    Only check formatting of files but do not modify them to fix formatting issues 
		lint            Fix linting issues in files, if any
		lint-check      Check linting issues in files but do not modify them to fix linting issues
		style-check     Run formatting, and linting
		type-check      Run static type checks
		test            Run tests
		init-db         Create & seed db tables
		check-db-schema Checks if db schema change requires a migration. Note: Not all changes can be checked here.

endef
export HELPTEXT

help:
	@echo "$$HELPTEXT"

dev:
	poetry run uvicorn virtual_labs.api:app --reload

dev-p:
	@poetry run dotenv -f .env.local set STRIPE_WEBHOOK_SECRET $$(poetry run dotenv -f env-prep/stripe-data/.env.local get STRIPE_WEBHOOK_SECRET) > /dev/null
	poetry run uvicorn virtual_labs.api:app --reload

init:
	./dev-init.sh

kill: 
	cd env-prep && docker compose -f docker-compose-dev.yml -p vlm-project down --remove-orphans --volumes

build:
	docker build -t $(SERVICE_NAME) . --platform=linux/amd64

format:
	poetry run ruff format

format-check:
	poetry run ruff format --check

lint:
	poetry run ruff check --fix

lint-check:
	poetry run ruff check

style-check:
	poetry run pre-commit run --all-files --config ./.pre-commit-config-ci.yaml

type-check:
	poetry run mypy . --strict

test:
	poetry run pytest

init-db:
	poetry run alembic upgrade head

check-db-schema:
	poetry run alembic check
