############
# DEFAULTS #
############

KUBECONFIG           ?= ""
GO 					 ?= go
BUILD 				 ?= build
IMAGE_TAG 			 ?= 0.8.0
IMAGE_NAME   		 ?= "trivy-operator-polr-adapter"

#############
# VARIABLES #
#############

GIT_SHA             := $(shell git rev-parse HEAD)
KOCACHE             ?= /tmp/ko-cache
GOOS                ?= $(shell go env GOOS)
GOARCH              ?= $(shell go env GOARCH)
REGISTRY            ?= ghcr.io
OWNER               ?= fjogeleit
KO_REGISTRY         := ko.local
LD_FLAGS            := "-s -w"
LOCAL_PLATFORM      := linux/$(GOARCH)
PLATFORMS           := all
REPO                := $(REGISTRY)/$(OWNER)/$(IMAGE_NAME)
KO_TAGS             := $(shell git rev-parse --short HEAD)

ifndef VERSION
KO_TAGS         := $(shell git rev-parse --short HEAD)
else
KO_TAGS         := $(VERSION)
endif


#########
# TOOLS #
#########
TOOLS_DIR      					   := $(PWD)/.tools
KO             					   := $(TOOLS_DIR)/ko
KO_VERSION     					   := v0.15.1
GCI                                := $(TOOLS_DIR)/gci
GCI_VERSION                        := v0.9.1
GOFUMPT                            := $(TOOLS_DIR)/gofumpt
GOFUMPT_VERSION                    := v0.4.0
HELM                               := $(TOOLS_DIR)/helm
HELM_VERSION                       := v3.10.1
HELM_DOCS                          := $(TOOLS_DIR)/helm-docs
HELM_DOCS_VERSION                  := v1.11.0

$(HELM):
	@echo Install helm... >&2
	@GOBIN=$(TOOLS_DIR) go install helm.sh/helm/v3/cmd/helm@$(HELM_VERSION)

$(HELM_DOCS):
	@echo Install helm-docs... >&2
	@GOBIN=$(TOOLS_DIR) go install github.com/norwoodj/helm-docs/cmd/helm-docs@$(HELM_DOCS_VERSION)

$(KO):
	@echo Install ko... >&2
	@GOBIN=$(TOOLS_DIR) go install github.com/google/ko@$(KO_VERSION)

$(GCI):
	@echo Install gci... >&2
	@GOBIN=$(TOOLS_DIR) go install github.com/daixiang0/gci@$(GCI_VERSION)

$(GOFUMPT):
	@echo Install gofumpt... >&2
	@GOBIN=$(TOOLS_DIR) go install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)


.PHONY: gci
gci: $(GCI)
	@echo "Running gci"
	@$(GCI) write -s standard -s default -s "prefix(github.com/fjogeleit/trivy-operator-polr-adapter/)" .

.PHONY: gofumpt
gofumpt: $(GOFUMPT)
	@echo "Running gofumpt"
	@$(GOFUMPT) -w .

.PHONY: fmt
fmt: gci gofumpt

.PHONY: install-tools
install-tools: $(TOOLS) ## Install tools

.PHONY: clean-tools
clean-tools: ## Remove installed tools
	@echo Clean tools... >&2
	@rm -rf $(TOOLS_DIR)

###########
# CODEGEN #
###########

.PHONY: codegen-helm-docs
codegen-helm-docs: ## Generate helm docs
	@echo Generate helm docs... >&2
	@docker run -v ${PWD}/charts:/work -w /work jnorwood/helm-docs:v1.11.0 -s file

.PHONY: verify-helm-docs
verify-helm-docs: codegen-helm-docs ## Check Helm charts are up to date
	@echo Checking helm charts are up to date... >&2
	@git --no-pager diff -- charts
	@echo 'If this test fails, it is because the git diff is non-empty after running "make codegen-helm-docs".' >&2
	@echo 'To correct this, locally run "make codegen-helm-docs", commit the changes, and re-run tests.' >&2
	@git diff --quiet --exit-code -- charts

###################
# BUIDL / PUBLISH #
###################

.PHONY: ko-build
ko-build: $(KO)
	@echo Build image with ko... >&2
	@cd LDFLAGS='$(LD_FLAGS)' KOCACHE=$(KOCACHE) KO_DOCKER_REPO=$(KO_REGISTRY) \
		$(KO) build . --tags=$(KO_TAGS) --platform=$(LOCAL_PLATFORM)

.PHONY: ko-login
ko-login: $(KO)
	@$(KO) login $(REGISTRY) --username "$(REGISTRY_USERNAME)" --password "$(REGISTRY_PASSWORD)"

.PHONY: ko-publish
ko-publish: ko-login
	@echo Publishing image "$(KO_TAGS)" with ko... >&2
	@cd LDFLAGS='$(LD_FLAGS)' KOCACHE=$(KOCACHE) KO_DOCKER_REPO=$(REPO) \
		$(KO) build . --bare --tags=$(KO_TAGS) --push --platform=$(PLATFORMS)