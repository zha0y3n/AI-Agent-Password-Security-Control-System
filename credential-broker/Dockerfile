# 一个镜像包含 broker 与 mock-upstream 两个程序，通过 command 选择。
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/...

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/ /app/
ENV BROKER_DB_PATH=/app/data/broker.db \
    BROKER_SIGNING_KEY_FILE=/app/data/broker-sm2.key
USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/app/broker"]
