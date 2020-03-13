PROJECT_NAME := "github.com/pip1998/secretly-lib"
PKG := "$(PROJECT_NAME)"
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)

.PHONY: all dep lint vet test clean

dep: ## Get the dependencies
		@go mod download

lint: ## Lint Golang files
		@golint -set_exit_status ${PKG_LIST}

vet: ## Run go vet
		@go vet ${PKG_LIST}

test: ## Run unittests
		@go test -short ${PKG_LIST}

build: ## Run build with gomobile
		@gomobile init
		@gomobile bind -v -target=android -javapkg com.zcytech.secretly.lib github.com/pip1998/secretly-lib/cmd/secretly/mobile

clean: ## Remove previous build
	@rm -f ./build

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'