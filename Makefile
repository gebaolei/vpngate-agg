# vpngate-agg —— 单二进制，前端已经 embed 进去了，所以 build 出来的东西拷到机器上就能跑。
#
# 常用:
#   make            编译到 bin/vpngate-agg
#   make test       单元测试
#   make check      fmt + vet + test（提交前跑这个）
#   make release    交叉编译几套平台到 dist/
#   make package    交叉编译 + 打包成 dist/archives/*.tar.gz（发 Release 用）
#   make docker     构建镜像

GO       ?= go
BIN      := bin/vpngate-agg
PKG      := ./...
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)

# 目标平台，make release 会挨个编一遍。
PLATFORMS := linux/amd64 linux/arm64 linux/arm darwin/arm64 darwin/amd64 windows/amd64

.DEFAULT_GOAL := build

.PHONY: build build-linux test race cover vet fmt fmt-check tidy check run docker docker-run clean release package help

build: ## 编译当前平台
	@mkdir -p bin
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) .
	@echo "已生成 $(BIN)（版本 $(VERSION)）"

build-linux: ## 编译 linux/amd64（服务器上直接扔二进制时用这个）
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/vpngate-agg-linux-amd64 .

## 测试相关
test: ## 单元测试
	$(GO) test -count=1 $(PKG)

race: ## 带竞态检测（探测和 SSE 都是多线程，值得偶尔跑一次）
	$(GO) test -race -count=1 $(PKG)

cover: ## 覆盖率报告，输出 coverage.out 并可开 HTML
	$(GO) test -count=1 -coverprofile=coverage.out -covermode=atomic $(PKG)
	$(GO) tool cover -func=coverage.out | tail -1
	@echo "看 HTML: $(GO) tool cover -html=coverage.out"

vet:
	$(GO) vet $(PKG)

fmt:
	gofmt -s -w .

fmt-check: ## CI 用：有没格式化过的文件就失败
	@out=$$(gofmt -s -l . ); if [ -n "$$out" ]; then echo "这些文件没 gofmt:"; echo "$$out"; exit 1; fi

tidy:
	$(GO) mod tidy

check: fmt-check vet test ## 提交前的全套检查

run: build ## 直接跑起来（默认 :8080，数据在 ./data）
	./$(BIN) serve

## 部署
docker: ## 构建镜像
	docker build -t vpngate-agg:$(VERSION) -t vpngate-agg:latest --build-arg VERSION=$(VERSION) .

docker-run: docker ## 起一个试一下（数据用 named volume）
	docker rm -f vpngate-agg 2>/dev/null || true
	docker run -d --name vpngate-agg -p 8080:8080 -v vpngate-agg-data:/data vpngate-agg:$(VERSION)
	@echo "打开 http://127.0.0.1:8080/ ；随机口令看日志: docker logs vpngate-agg"

release: ## 交叉编译多平台到 dist/
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		name="dist/vpngate-agg-$$VERSION-$$os-$$arch$$ext"; \
		echo "→ $$name"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $$name . || exit 1; \
	done
	@cd dist && sha256sum vpngate-agg-* > SHA256SUMS 2>/dev/null || shasum -a 256 vpngate-agg-* > SHA256SUMS
	@cat dist/SHA256SUMS

## 发布产物
package: release ## 交叉编译 + 打包成 dist/archives/*.tar.gz（windows 优先 zip），发 Release 用的就是这一条
	@mkdir -p dist/archives
	@rm -f dist/archives/*
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=""; [ "$$os" = windows ] && ext=".exe"; \
		bin="dist/vpngate-agg-$(VERSION)-$$os-$$arch$$ext"; \
		[ -f "$$bin" ] || { echo "缺编译产物 $$bin"; exit 1; }; \
		stage="$$(mktemp -d)"; cp "$$bin" "$$stage/vpngate-agg$$ext"; cp README.md "$$stage/"; \
		name="dist/archives/vpngate-agg-$(VERSION)-$$os-$$arch"; \
		if [ "$$os" = windows ] && command -v zip >/dev/null 2>&1; then \
			(cd "$$stage" && zip -qr "$(OLDPWD)/$$name.zip" .); \
		else \
			tar -czf "$$name.tar.gz" -C "$$stage" .; \
		fi; \
		rm -rf "$$stage"; \
		echo "→ $$name"; \
	done
	@cd dist/archives && sha256sum vpngate-agg-* > SHA256SUMS 2>/dev/null || shasum -a 256 vpngate-agg-* > SHA256SUMS
	@echo "打包完成，校验值在 dist/archives/SHA256SUMS"

clean:
	rm -rf bin dist coverage.out

help: ## 列出目标
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'
