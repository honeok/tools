# Description: The automation entrypoint for managing the build, development, and release lifecycle of the earthquake dashboard service.
#
# Copyright (c) 2025 honeok <i@honeok.com>
# SPDX-License-Identifier: Apache-2.0

## variables
# general
DOCKER_USERNAME       := honeok
DOCKER_REPO           := earthquake
DOCKER_BUILD_ARGS     := --no-cache --progress=plain
PLATFORMS             := linux/amd64,linux/arm64
VERSION               := v$(shell date -u '+%Y.%m.%d' -d '+8 hours' | awk -F. '{printf("%d.%d.%d\n", substr($$1,3), $$2, $$3)}')

# dev
DEV_IMAGE             ?= $(DOCKER_USERNAME)/$(DOCKER_REPO):dev
CONTAINER_NAME        ?= earthquake
PORT                  ?= 8000

export DOCKER_BUILDKIT = 1

.PHONY: all build-dev run-dev clean-dev release-deps release clean help

all: help ## show this help information (default)

build-dev: ## build docker image for development
	@echo "--> build development image $(DEV_IMAGE)"
	@docker build $(DOCKER_BUILD_ARGS) --build-arg EARTHQUAKE_VERSION="$(VERSION)-dev" --tag $(DEV_IMAGE) .

run-dev: ## run development container
	@docker run -d -p $(PORT):8000 --name $(CONTAINER_NAME) $(DEV_IMAGE)
	@sleep 2
	@echo
	@docker ps | grep $(CONTAINER_NAME)

clean-dev: ## clean docker container for development
	@docker rm -f $(CONTAINER_NAME) || true

release-deps: ## setup the buildx builder environment
	@docker buildx create --name builder --use || true
	@docker buildx inspect --bootstrap

release: ## build multi platform images and push to dockerhub
	@echo "--> release version $(VERSION) to the dockerhub $(DOCKER_USERNAME)/$(DOCKER_REPO)"
	@docker buildx build \
		$(DOCKER_BUILD_ARGS) \
		--platform $(PLATFORMS) \
		--build-arg EARTHQUAKE_VERSION=$(VERSION) \
		--tag $(DOCKER_USERNAME)/$(DOCKER_REPO):$(VERSION) \
		--tag $(DOCKER_USERNAME)/$(DOCKER_REPO):latest \
		--push \
		.
	@echo "--> version: $(VERSION) build complete!"

clean: ## clean all build caches, containers and images
	@docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	@docker buildx prune --all --force 2>/dev/null || true
	@docker system prune -af --volumes 2>/dev/null || true
	@docker buildx rm -f builder 2>/dev/null || true

help: ## show this help information
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
