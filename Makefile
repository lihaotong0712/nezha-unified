.DEFAULT_GOAL := help

GO ?= go
PYTHON ?= python3
GOTOOLCHAIN ?= go$(shell awk '/^go / { print $$2 }' go.mod)
export GOTOOLCHAIN

TOOL_BIN := $(CURDIR)/.cache/bin
SWAG := $(TOOL_BIN)/swag
ACTIONLINT := $(TOOL_BIN)/actionlint
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo development)

.PHONY: help tools deps frontend prepare swagger build check check-go check-web check-tools ci run dev-admin

help:
	@echo 'make build      构建并内嵌管理前端和公开主题，输出 dist/dashboard'
	@echo 'make check / ci 执行与 GitHub Actions 相同的本地检查和构建'
	@echo 'make run        构建并在 127.0.0.1:8008 启动 Dashboard'
	@echo 'make dev-admin  启动管理前端开发服务器，后端需另行启动'

tools: $(SWAG) $(ACTIONLINT)

$(SWAG):
	GOBIN="$(TOOL_BIN)" $(GO) install github.com/swaggo/swag/cmd/swag@v1.16.6

$(ACTIONLINT):
	GOBIN="$(TOOL_BIN)" $(GO) install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12

deps:
	npm --prefix web/admin ci --no-audit --no-fund

frontend: deps
	npm --prefix web/admin run build

prepare: frontend
	$(PYTHON) script/prepare_frontends.py

swagger: $(SWAG)
	$(SWAG) init --pd -d cmd/dashboard -g main.go -o cmd/dashboard/docs

build: prepare swagger
	mkdir -p dist
	$(GO) build -mod=readonly -trimpath -ldflags '-X github.com/nezhahq/nezha/service/singleton.Version=$(VERSION)' -o dist/dashboard ./cmd/dashboard

check-web: deps
	npm --prefix web/admin run lint
	npm --prefix web/admin test

check-go: prepare swagger
	@files="$$(git ls-files -co --exclude-standard '*.go' -z | xargs -0 -r gofmt -l)"; \
	if [ -n "$$files" ]; then echo "以下 Go 文件需要格式化："; echo "$$files"; exit 1; fi
	$(GO) vet -mod=readonly ./...
	$(GO) test -mod=readonly -race -shuffle=on -count=1 ./...

check-tools: $(ACTIONLINT)
	uvx --from ruff==0.17.1 ruff check script/prepare_frontends.py
	uvx --from ruff==0.17.1 ruff format --check script/prepare_frontends.py
	uvx --from shellcheck-py==0.11.0.1 shellcheck script/bootstrap.sh
	$(ACTIONLINT) -shellcheck= .github/workflows/ci.yml
	git diff --check

check ci: check-tools check-web check-go build

run: build
	NZ_LISTENHOST=127.0.0.1 NZ_LISTENPORT=8008 ./dist/dashboard

dev-admin: deps
	npm --prefix web/admin run dev
