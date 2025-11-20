# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2025 honeok <i@honeok.com>

# variables
DOCKER_USERNAME       := honeok
DOCKER_REPO           := openresty
DOCKER_BUILD_ARGS     := --no-cache --progress=plain
PLATFORMS             := linux/amd64,linux/arm64

RESTY_VERSION := $(shell wget -qO- https://api.github.com/repos/openresty/openresty/tags | grep '"name":' | sed -E 's/.*"name": *"([^"]+)".*/\1/' | sort -rV | head -n1 | sed 's/v//')
ZSTD_VERSION := $(shell wget -qO- https://api.github.com/repos/facebook/zstd/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/v//')

export DOCKER_BUILDKIT = 1

.PHONY: all release-deps release clean

# default
all: build

prepare:
	@find . -type f -name "*.sh" -print0 | xargs -0 dos2unix -q
	@find . -type f -name "*.sh" -exec chmod +x {} \;

build: prepare
	@docker build $(DOCKER_BUILD_ARGS) \
		--build-arg RESTY_VERSION="$(RESTY_VERSION)" \
		--build-arg ZSTD_VERSION="$(ZSTD_VERSION)" \
		--build-arg RESTY_STRIP_BINARIES=1 \
		--tag $(DOCKER_USERNAME)/$(DOCKER_REPO):dev .

release-deps:
	@docker buildx create --name builder --use || true
	@docker buildx inspect --bootstrap

release: prepare release-deps
	@echo "--> release $(DOCKER_REPO) version $(RESTY_VERSION) to the dockerhub $(DOCKER_USERNAME)/$(DOCKER_REPO)"
	@docker buildx build \
		$(DOCKER_BUILD_ARGS) \
		--platform $(PLATFORMS) \
		--build-arg RESTY_VERSION="$(RESTY_VERSION)" \
		--build-arg ZSTD_VERSION="$(ZSTD_VERSION)" \
		--build-arg RESTY_STRIP_BINARIES=1 \
		--tag $(DOCKER_USERNAME)/$(DOCKER_REPO):alpine \
		--tag $(DOCKER_USERNAME)/$(DOCKER_REPO):$(RESTY_VERSION)-alpine \
		--push \
		.
	@echo "--> version: $(RESTY_VERSION) build complete!"

clean:
	@docker buildx prune --all --force 2>/dev/null || true
	@docker system prune -af --volumes 2>/dev/null || true
	@docker buildx rm -f builder 2>/dev/null || true
