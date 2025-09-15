SHELL := /bin/bash

.PHONY: build run fmt vet lint e2e docker docker-up docker-down ci

build:
	go build ./...

run:
	go run ./cmd/server

fmt:
	gofmt -s -w .

vet:
	go vet ./...

lint: vet
	@echo "lint ok (vet only)"

e2e:
	go run ./cmd/e2e -base http://127.0.0.1:8080

docker:
	docker build -t ginkgoid:latest .

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down -v

ci: fmt vet build
	@echo "CI checks passed"

