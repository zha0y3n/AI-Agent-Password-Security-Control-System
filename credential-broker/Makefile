.PHONY: build test test-race vet fmt run run-mock docker clean

BIN := bin

build:
	go build -o $(BIN)/ ./cmd/...

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# 开发运行：先 `cp .env.example .env` 并填写，再 `set -a; . ./.env; set +a`
run:
	go run ./cmd/broker

run-mock:
	go run ./cmd/mock-upstream

docker:
	docker build -t credential-broker .

clean:
	rm -rf $(BIN) data
