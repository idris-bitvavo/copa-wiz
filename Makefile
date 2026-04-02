################################################################################
# Global: Variables                                                            #
################################################################################

# Formatted symbol markers (=>, [needs root]) for info output
INFOMARK = $(shell printf "\033[34;1m=>\033[0m")

# Go build metadata variables
GOARCH            := $(shell go env GOARCH)
GOOS              := $(shell go env GOOS)
BUILDTYPE_DIR     := release

# Build output variables
CLI_BINARY        := copa-wiz
OUT_DIR           := ./dist
BINS_OUT_DIR      := $(OUT_DIR)/$(GOOS)_$(GOARCH)/$(BUILDTYPE_DIR)

################################################################################
# Target: build (default action)                                               #
################################################################################
.PHONY: build
build:
	$(info $(INFOMARK) Building $(CLI_BINARY) ...)
	go build -o $(BINS_OUT_DIR)/$(CLI_BINARY) ./cmd/copa-wiz

################################################################################
# Target: install — puts copa-wiz on $GOBIN or $GOPATH/bin (must be on $PATH)  #
################################################################################
.PHONY: install
install:
	$(info $(INFOMARK) Installing $(CLI_BINARY) to $(shell go env GOPATH)/bin ...)
	go install ./cmd/copa-wiz

################################################################################
# Target: install-system — /usr/local/bin (survives minimal GUI / Docker PATH) #
################################################################################
.PHONY: install-system
install-system: build
	$(info $(INFOMARK) Installing $(CLI_BINARY) to /usr/local/bin (requires sudo) ...)
	sudo install -m 0755 $(BINS_OUT_DIR)/$(CLI_BINARY) /usr/local/bin/$(CLI_BINARY)

################################################################################
# Target: test - unit testing                                                  #
################################################################################
.PHONY: test
test:
	$(info $(INFOMARK) Running unit tests on pkg libraries ...)
	go test ./... $(CODECOV_OPTS)
