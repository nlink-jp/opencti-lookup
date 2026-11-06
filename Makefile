# opencti-lookup
#
# Phase 0 holds only the development-stack targets. Build, test and release
# targets arrive with the Phase 1 scaffold.

COMPOSE := podman compose --env-file dev/.env -f dev/compose.yaml

.PHONY: dev-env dev-up dev-down dev-ps dev-logs dev-health dev-reset

dev-env: ## Generate dev/.env with random local secrets (once)
	@bash dev/gen-env.sh

dev-up: dev-env ## Start the OpenCTI 6.7.4 development stack
	$(COMPOSE) up -d

dev-down: ## Stop the stack, keeping its data
	$(COMPOSE) down

dev-ps: ## Show container state
	$(COMPOSE) ps

dev-logs: ## Follow the platform log
	$(COMPOSE) logs -f opencti

dev-health: ## One-shot health probe of the platform
	@. dev/.env && curl -sf "http://127.0.0.1:8080/health?health_access_key=$$OPENCTI_HEALTHCHECK_ACCESS_KEY" && echo || { echo "not healthy yet"; exit 1; }

dev-reset: ## Stop the stack AND delete its volumes (all ingested data)
	$(COMPOSE) down -v
