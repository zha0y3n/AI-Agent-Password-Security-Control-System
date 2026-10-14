.PHONY: build test test-race vet fmt run run-mock docker clean interop

BIN := bin

build:
	go build -o $(BIN)/ ./cmd/...

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

# 跨语言联调：用 A 的 Python 代码签发 bundle，再由 Go Broker 完整执行并签发回执，
# 最后用 A 的 ReceiptVerifier 复核 Go 签发的回执。
# 需要先在仓库根目录安装 A（bash scripts/bootstrap.sh）。临时目录含测试私钥，结束后删除。
PYTHON ?= ../.venv/bin/python
interop:
	@dir=$$(mktemp -d) && trap 'rm -rf "$$dir"' EXIT && \
	$(PYTHON) scripts/gen-a-bundle.py "$$dir" && \
	BROKER_TEST_A_INTEROP_DIR="$$dir" BROKER_TEST_A_KEYS="$$dir/public-keys.json" \
	go test -count=1 -run 'Interop|ARuntime' -v ./internal/verifier/ ./internal/protocol/ && \
	$(PYTHON) scripts/verify-a-receipt.py "$$dir"

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
