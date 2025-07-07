# Makefile per la gestione del server di gioco Godot
.PHONY: build up down restart logs logs-db logs-server clean backup restore status

# Variabili
COMPOSE_FILE = docker-compose.yml
PROJECT_NAME = godot-game-server

# Build delle immagini
build:
	@echo "Building Docker images..."
	docker-compose -f $(COMPOSE_FILE) build --no-cache

# Avvia i servizi
up:
	@echo "Starting game server and database..."
	docker-compose -f $(COMPOSE_FILE) up -d
	@echo "Services started:"
	@echo "- Game server available on port 7000"
	@echo "- phpMyAdmin available on http://localhost:8080"
	@echo "- Database accessible via: make db-shell"

# Ferma i servizi
down:
	@echo "Stopping services..."
	docker-compose -f $(COMPOSE_FILE) down

# Riavvia i servizi
restart: down up

# Mostra i log di tutti i servizi
logs:
	docker-compose -f $(COMPOSE_FILE) logs -f

# Mostra i log del database
logs-db:
	docker-compose -f $(COMPOSE_FILE) logs -f mariadb

# Mostra i log del server di gioco
logs-server:
	docker-compose -f $(COMPOSE_FILE) logs -f game_server

# Stato dei servizi
status:
	docker-compose -f $(COMPOSE_FILE) ps

# Accesso alla shell del database
db-shell:
	docker-compose -f $(COMPOSE_FILE) exec mariadb mysql -u gameuser -p gamedb

# Accesso alla shell del server
server-shell:
	docker-compose -f $(COMPOSE_FILE) exec game_server /bin/bash

# Backup del database
backup:
	@echo "Creating database backup..."
	docker-compose -f $(COMPOSE_FILE) exec mariadb mysqldump -u root -p gamedb > backup_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "Backup completed"

# Ripristino del database (uso: make restore BACKUP_FILE=backup.sql)
restore:
	@if [ -z "$(BACKUP_FILE)" ]; then \
		echo "Errore: Specifica il file di backup con BACKUP_FILE=nome_file.sql"; \
		exit 1; \
	fi
	@echo "Restoring database from $(BACKUP_FILE)..."
	docker-compose -f $(COMPOSE_FILE) exec -T mariadb mysql -u root -p gamedb < $(BACKUP_FILE)
	@echo "Restore completed"

# Pulizia completa (ATTENZIONE: rimuove anche i volumi!)
clean:
	@echo "WARNING: This will remove all containers, images and volumes!"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ]
	docker-compose -f $(COMPOSE_FILE) down -v
	docker system prune -f
	docker volume prune -f

# Avvia solo database e phpMyAdmin (senza game server)
db-only:
	@echo "Starting database and phpMyAdmin..."
	docker-compose -f $(COMPOSE_FILE) up -d mariadb phpmyadmin
	@echo "Database services started:"
	@echo "- phpMyAdmin: http://localhost:8080"
	@echo "- Database shell: make db-shell"

# Setup iniziale completo
setup: build up

# Monitoraggio risorse
monitor:
	@echo "Monitoring resource usage..."
	docker stats $(PROJECT_NAME)_game_server_1 $(PROJECT_NAME)_mariadb_1

# Help
help:
	@echo "Available commands:"
	@echo "  build        - Build Docker images"
	@echo "  up           - Start services"
	@echo "  down         - Stop services" 
	@echo "  restart      - Restart services"
	@echo "  logs         - Show all logs"
	@echo "  logs-db      - Show database logs"
	@echo "  logs-server  - Show game server logs"
	@echo "  status       - Show services status"
	@echo "  db-shell     - Access database shell"
	@echo "  server-shell - Access server shell"
	@echo "  backup       - Backup database"
	@echo "  restore      - Restore database (specify BACKUP_FILE=file.sql)"
	@echo "  clean        - Remove all containers and volumes (DANGEROUS!)"
	@echo "  setup        - Build and start (first time setup)"
	@echo "  monitor      - Monitor resource usage"
	@echo "  help         - Show this help"