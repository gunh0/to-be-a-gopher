GO ?= go
PKGS := ./...

GOVULNCHECK ?= golang.org/x/vuln/cmd/govulncheck@v1.1.4

.PHONY: all fmt fmt-check vet test race cover vuln clean

all: fmt-check vet test

fmt:
	gofmt -w .

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet $(PKGS)

test:
	$(GO) test $(PKGS)

race:
	$(GO) test -race $(PKGS)

cover:
	$(GO) test -coverprofile=coverage.out $(PKGS)
	$(GO) tool cover -func=coverage.out | tail -1

vuln:
	$(GO) run $(GOVULNCHECK) ./...

clean:
	rm -f coverage.out
	rm -rf bin
