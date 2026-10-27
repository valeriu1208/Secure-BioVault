.PHONY: help db-up db-down db-reset db-clean db-connect db-logs 

DB_NAME = biovault_db
DB_USER = biovault_user
SQL_FILE = init.sql
COMPOSE_FILE = ../compose.yaml

## help: Display available commands
help:
	@echo "Available Docker commands:"
	@echo " make db-up 		- Start PostgreSQL container"
	@echo " make db-down	- Stop PostgreSQL container"
	@echo " make db-reset	- Re-execute init.sql inside the running container"
	@echo " make db-clean	- Stop container and wipe persistent data volumes"
	@echo " make db-connect	- Open psql shell inside the container"
	@echo " make db-logs 	- Tail PostgreSQL container logs"

## db-up: Start container in background
db-up:
	docker compose -f $(COMPOSE_FILE) up -d db

## db-down: Stop and remove only the database container
db-down:
	docker compose -f $(COMPOSE_FILE) stop db
	docker compose -f $(COMPOSE_FILE) rm -f db

## db-reset: Re-apply init.sql inside the container
db-reset:
	@echo "Re-applying database schema form $(SQL_FILE)..."
	@docker exec -i biovault_db psql -U $(DB_USER) -d $(DB_NAME) < $(SQL_FILE)
	@echo "Database successfully reset"

## db-clean: Stop container and delete volume data
db-clean:
	@echo "Stopping container and removing persistent volume..."
	docker compose -f $(COMPOSE_FILE) down -v
	@echo "Container and database volumes removed"

## db-connect: Open interactive psql console inside container
db-connect:
	docker exec -it biovault_db psql -U $(DB_USER) -d $(DB_NAME)

## db-logs: View live logs
db-logs:
	docker compose -f $(COMPOSE_FILE) logs -f db