# curator-network-profiles: library + provider CLI `curator-network`.
# Every target is loopback-only; nothing here touches the real network
# beyond the Go module proxy (`go run …@version` for actionlint).

MODULE   := github.com/relux-works/curator-network-profiles
BIN      := bin/curator-network
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
REVISION ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
DIRTY    ?= $(shell if [ -n "$$(git status --porcelain 2>/dev/null)" ]; then echo true; else echo false; fi)
LDFLAGS  := -X $(MODULE)/internal/version.version=$(VERSION) \
            -X $(MODULE)/internal/version.revision=$(REVISION) \
            -X $(MODULE)/internal/version.dirty=$(DIRTY)
ACTIONLINT := github.com/rhysd/actionlint/cmd/actionlint@v1.7.12

.PHONY: build test race vet fmt-check lint-workflows vectors demo check clean

build:
	go build -p 1 -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/curator-network

# -count=1: the contract guards in internal/contract read
# spec/contract-appendix.md and testdata/contract/vectors.json, which live
# outside their package; a cached PASS would not re-read them.
test:
	go test -p 2 -count=1 -timeout 120s ./...

race:
	go test -p 2 -race -count=1 -timeout 120s ./...

vet:
	go vet ./...

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint-workflows:
	go run $(ACTIONLINT)

# Regenerate the contract vectors from the code; then paste the printed
# blocks into spec/contract-appendix.md (the guard test compares them).
vectors:
	go run -p 1 ./internal/contract/cmd/contract-vectors -write testdata/contract/vectors.json -markdown

demo:
	scripts/demo-two-egresses.sh

check: fmt-check vet test race

clean:
	rm -rf bin
