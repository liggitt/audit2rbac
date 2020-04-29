.PHONY: default install build build-cross clean test quicktest fmt vet lint install-deps update-deps clean-deps

default: fmt vet lint build quicktest

run:
	go run ./cmd/audit2rbac/audit2rbac.go

install-deps:
	go mod vendor
	build/update-vendor-notices.sh

update-deps:
	go mod vendor
	build/update-vendor-notices.sh

clean-deps:
	rm -fr vendor

build: check_go_version
	go build -o bin/audit2rbac $(shell ./build/print-ldflags.sh) ./cmd/audit2rbac

build-cross: check_go_version
	./build/build-cross.sh cmd/audit2rbac/audit2rbac.go

install:
	go install $(shell ./build/print-ldflags.sh) ./cmd/audit2rbac

clean:
	rm -fr bin

test:
	go test -v -race -cover ./pkg/...

quicktest:
	go test ./pkg/...

# Capture output and force failure when there is non-empty output
fmt:
	@echo gofmt -l ./pkg
	@OUTPUT=`gofmt -l ./pkg 2>&1`; \
	if [ "$$OUTPUT" ]; then \
		echo "gofmt must be run on the following files:"; \
		echo "$$OUTPUT"; \
		exit 1; \
	fi

vet:
	go vet -atomic -bool -copylocks -nilfunc -printf -rangeloops -unreachable -unsafeptr -unusedresult ./pkg

# https://github.com/golang/lint
# go get github.com/golang/lint/golint
# Capture output and force failure when there is non-empty output
lint:
	@echo golint ./pkg/...
	@OUTPUT=`golint ./pkg/... 2>&1`; \
	if [ "$$OUTPUT" ]; then \
		echo "golint errors:"; \
		echo "$$OUTPUT"; \
		exit 1; \
	fi

check_go_version:
	@OUTPUT=`go version`; \
	if [[ "$$OUTPUT" != *"go1.14."* ]]; then \
		echo "Expected: go version go1.14.*"; \
		echo "Found:    $$OUTPUT"; \
		exit 1; \
	fi
