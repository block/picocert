build:
  go build -o build/ ./cmd/...

clean:
  go mod tidy || true
  rm -rf build
  go clean -cache

test:
  go test ./...
