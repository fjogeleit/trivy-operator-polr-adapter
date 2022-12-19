GO ?= go
BUILD ?= build
REPO ?= ghcr.io/fjogeleit/trivy-operator-polr-adapter
IMAGE_TAG ?= 0.3.1
LD_FLAGS=-s -w
PLATFORMS ?= linux/arm64,linux/amd64

all: build

.PHONY: clean
clean:
	rm -rf $(BUILD)

.PHONY: prepare
prepare:
	mkdir -p $(BUILD)

.PHONY: build
build: prepare
	CGO_ENABLED=0 $(GO) build -v -ldflags='$(LD_FLAGS) -X main.Version=$(IMAGE_TAG)' -o $(BUILD)/trivy-operator-polr-adapter .

.PHONY: docker-build
docker-build:
	@docker buildx build --progress plane --platform $(PLATFORMS) --tag $(REPO):$(IMAGE_TAG) . --build-arg LD_FLAGS='$(LD_FLAGS) -X main.Version=$(IMAGE_TAG)'
	@docker buildx build --progress plane --platform $(PLATFORMS)x --tag $(REPO):latest . --build-arg LD_FLAGS='$(LD_FLAGS) -X main.Version=$(IMAGE_TAG)'

.PHONY: docker-push
docker-push:
	@docker buildx build --progress plane --platform $(PLATFORMS) --tag $(REPO):$(IMAGE_TAG) . --build-arg LD_FLAGS='$(LD_FLAGS) -X main.Version=$(IMAGE_TAG)' --push
	@docker buildx build --progress plane --platform $(PLATFORMS) --tag $(REPO):latest . --build-arg LD_FLAGS='$(LD_FLAGS) -X main.Version=$(IMAGE_TAG)' --push

.PHONY: docker-push-dev
docker-push-dev:
	@docker buildx build --progress plane --platform $(PLATFORMS) --tag $(REPO):dev . --build-arg LD_FLAGS='$(LD_FLAGS) -X main.Version=$(IMAGE_TAG)' --push
