BINARY_NAME=nas-manager
VERSION=$(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X github.com/SlashGordon/nas-manager/cmd.Version=${VERSION} -X github.com/SlashGordon/nas-manager/cmd.Commit=${COMMIT} -X github.com/SlashGordon/nas-manager/cmd.Date=${BUILD_TIME}"

.PHONY: build clean release lint test fmt vet

build:
	go build ${LDFLAGS} -o bin/${BINARY_NAME} .

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-linux-amd64 .

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-linux-arm64 .

build-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-darwin-amd64 .

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-darwin-arm64 .

build-all: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64

clean:
	rm -rf bin/

release: clean build-all
	@echo "Built binaries:"
	@ls -la bin/

# Development tools
fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test -v ./...

lint:
	@GOPATH=$$(go env GOPATH); \
	if ! [ -f "$$GOPATH/bin/golangci-lint" ]; then \
		echo "Installing golangci-lint..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b "$$GOPATH/bin" latest; \
	fi; \
	"$$GOPATH/bin/golangci-lint" run

test-coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

check: fmt vet test
	@echo "Core checks passed!"
	@echo "Run 'make lint' separately for linting (optional)"

check-all: fmt vet test lint
	@echo "All checks passed!"

# Git hooks (simple approach)
install-hooks:
	@echo "Setting up git hooks..."
	@mkdir -p .git/hooks
	@echo '#!/bin/sh\nmake check' > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Git pre-commit hook installed successfully!"