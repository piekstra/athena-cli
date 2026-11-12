BIN := athena
CARGO ?= cargo
# Tests, smoke and every command `make` runs use an empty keychain service,
# never the owner's real sign-ins.
export ATHENA_KEYCHAIN_SERVICE ?= piekstra.athena.hermetic-tests
# smoke's config and state, under target/ so `make clean` removes it. Each
# run starts from an empty index, so smoke never reads a keychain item.
SMOKE_HOME := target/smoke-home/$(shell date +%s)

.PHONY: build release test lint fmt fmt-check clean install deps smoke verify dev mock

# Every target that produces a binary signs it. `cargo build` and
# `cargo install` ad-hoc sign, minting a new code identity each time, and
# macOS scopes a keychain "Always Allow" to that identity, so an unsigned
# rebuild prompts again. ./target/release/athena is run most, so `release`
# signs too.
build: SIGN_TARGET = target/debug/$(BIN)
build:
	$(CARGO) build
	@$(SIGN)

release: SIGN_TARGET = target/release/$(BIN)
release:
	$(CARGO) build --release
	@$(SIGN)

test:
	$(CARGO) test

lint:
	$(CARGO) clippy --all-targets -- -D warnings

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check

clean:
	$(CARGO) clean

deps:
	$(CARGO) fetch

# `--locked` builds from Cargo.lock, the versions the tests and audit ran on.
install: SIGN_TARGET = $${CARGO_INSTALL_ROOT:-$$HOME/.cargo}/bin/$(BIN)
install:
	$(CARGO) install --path . --locked --force
	@$(SIGN)

dev: SIGN_TARGET = target/debug/$(BIN)
dev:
	$(CARGO) build
	@$(SIGN)

# The loopback mock of athenahealth, for dogfooding with synthetic patients.
mock:
	$(CARGO) run --example mock_server

# Offline smoke test: no keychain, no network, no athenahealth.
smoke: build
	@./target/debug/$(BIN) --version >/dev/null
	@./target/debug/$(BIN) info >/dev/null
	@./target/debug/$(BIN) completions bash >/dev/null
	@./target/debug/$(BIN) auth login --help >/dev/null
	@./target/debug/$(BIN) records export --help >/dev/null
	@./target/debug/$(BIN) documents download --help >/dev/null
	@mkdir -p $(SMOKE_HOME)
	@XDG_CONFIG_HOME=$(SMOKE_HOME) HOME=$(SMOKE_HOME) ./target/debug/$(BIN) --json auth status >/dev/null
	@XDG_CONFIG_HOME=$(SMOKE_HOME) HOME=$(SMOKE_HOME) ./target/debug/$(BIN) --json orgs list >/dev/null
	@XDG_CONFIG_HOME=$(SMOKE_HOME) HOME=$(SMOKE_HOME) ./target/debug/$(BIN) --json patients list >/dev/null
	@echo "smoke ok"

verify: fmt-check lint test smoke

define SIGN
if [ -x "$$HOME/Dev/cli-common/scripts/dev-sign.sh" ]; then \
	"$$HOME/Dev/cli-common/scripts/dev-sign.sh" "$(SIGN_TARGET)"; \
else echo "cli-common/scripts/dev-sign.sh not found: $(SIGN_TARGET) left ad-hoc signed"; fi
endef
