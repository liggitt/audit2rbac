.PHONY: default install build test quicktest fmt vet lint install-deps update-deps clean

default: fmt vet lint build quicktest

run:
	go run ./cmd/audit2rbac/audit2rbac.go

install-deps: glide.yaml glide.lock
	glide install -v

update-deps: glide.yaml glide.lock
	glide update -v

install:
	go install ./cmd/audit2rbac

build:
	go build -o bin/audit2rbac ./cmd/audit2rbac

test:
	go test -v -race -cover ./pkg/...

quicktest:
	go test ./pkg/...

clean:
	rm -fr bin
	rm -fr vendor

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
	go tool vet -atomic -bool -copylocks -nilfunc -printf -shadow -rangeloops -unreachable -unsafeptr -unusedresult ./pkg

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
