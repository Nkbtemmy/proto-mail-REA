REACTOR := reference-system/pom.xml
API     := reference-system/api/pom.xml
APP     := reference-system/app/pom.xml
CLI     := reference-system/cli/pom.xml
COMPOSE := reference-system/deployment/docker-compose.yml

.DEFAULT_GOAL := help
.PHONY: help test install jar demo cli api cluster docker-up docker-down clean

help: ## show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

test: ## build and run all tests (45 tests)
	mvn -f $(REACTOR) test

install: ## build and install all modules (skip tests)
	mvn -f $(REACTOR) -DskipTests install

jar: install ## build the runnable API jar (+ lib/) for Docker
	@echo "built: reference-system/api/target/reconmail-api.jar"

demo: ## run the end-to-end scenario
	mvn -f $(APP) -q -Dexec.mainClass=com.reconmail.app.EndToEndScenario exec:java

cli: ## run the interactive CLI
	mvn -f $(CLI) -q -Dexec.mainClass=com.reconmail.cli.Cli exec:java

api: ## run the single-process HTTP API on :8080
	mvn -f $(API) -q -Dexec.mainClass=com.reconmail.api.ApiMain exec:java

cluster: ## run the split stack (gateway + auth/keys/mail) in one JVM
	mvn -f $(API) -q -Dexec.mainClass=com.reconmail.api.ClusterMain exec:java

docker-up: jar ## build images and start the distributed stack (needs Docker)
	docker compose -f $(COMPOSE) up --build -d

docker-down: ## stop the stack and remove volumes
	docker compose -f $(COMPOSE) down -v

clean: ## remove build output
	mvn -f $(REACTOR) clean
