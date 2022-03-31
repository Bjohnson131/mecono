# Configuration
MAIN_MODULE := ./cmd/main.go
BUILD_OS := linux
GOARCH := amd64

# Derived variables
GIT_COMMIT      = $(shell git rev-parse --short HEAD)
GO_BINARY_NAME := meconod-$(GIT_COMMIT)

# Go ld flags
LDFLAGS  = -extldflags \"-static\"
LDFLAGS += -X main.Version=0.0.1
LDFLAGS += -X main.BuildDate=$(shell date +'%Y-%m-%dT%H:%M:%SZ')
LDFLAGS += -X main.GitCommit=$(GIT_COMMIT)

# Debug vars
DEBUG_FLAGS ?=

ifeq (${DEBUG}, 1)
	DEBUG_FLAGS := -gcflags=all="-N -l"
endif

clean:
	rm -rf ./build/*

dep:
	go mod download -x

.PHONY: all clean build
build:
	export GO111MODULE=on
	go build $(DEBUG_FLAGS) -ldflags "$(LDFLAGS)" -o build/$(GO_BINARY_NAME) $(MAIN_MODULE)