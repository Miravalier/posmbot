app:
	@if [ ! -f .env ]; then \
		echo "No .env found in $$PWD; copy example.env to .env and edit it"; \
		exit 1; \
	fi
	docker-compose down
	docker-compose build
	docker-compose up -d
