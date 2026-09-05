# SPDX-License-Identifier: Unlicense

# cargo installs under ~/.cargo/bin, which is not on the default PATH on the
# hosts this runs on, so put it there rather than making every caller remember.
export PATH := $(HOME)/.cargo/bin:$(PATH)

CARGO   ?= cargo
PREFIX  ?= /usr/local
DESTDIR ?=
BIN     := programmable-redfish-proxy
CONFIG  ?= /etc/$(BIN)/config.toml
# systemd reads units from under $(PREFIX) as well as /lib, so the default needs
# no special casing when PREFIX is /usr/local.
UNITDIR ?= $(PREFIX)/lib/systemd/system

.DEFAULT_GOAL := help
.PHONY: help all build debug test lint fmt fmt-check validate install restart clean

help:
	@echo 'Targets, and the three that CI runs are lint, test and build.'
	@echo ''
	@echo '  build      release binary, target/release/$(BIN)'
	@echo '  debug      unoptimised binary, for a backtrace worth reading'
	@echo '  test       the end-to-end suite, which is all the tests there are'
	@echo '  lint       clippy with pedantic gated, warnings are errors'
	@echo '  fmt        rewrite formatting in place'
	@echo '  fmt-check  fail instead of rewriting, which is what CI wants'
	@echo '  validate   check a real config and compile every script'
	@echo '  install    binary, config, scripts, facts and the unit; needs build'
	@echo '  restart    restart the installed service'
	@echo '  clean      remove target/'
	@echo ''
	@echo 'To deploy: make build && sudo make install'
	@echo ''
	@echo 'Variables: CONFIG=$(CONFIG) PREFIX=$(PREFIX) DESTDIR=$(DESTDIR)'
	@echo '           UNITDIR=$(UNITDIR)'

all: lint test build

build:
	$(CARGO) build --release --locked

debug:
	$(CARGO) build --locked

# The end-to-end suite is the whole suite. There is no library target, so
# `--lib` and `--doc` both fail rather than passing empty. Do not add them.
test:
	$(CARGO) test --locked --test e2e

lint:
	$(CARGO) clippy --all-targets --locked -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all --check

# Parses the config, loads the TLS material, compiles every route glob and
# every script, then exits. Needs a config whose paths actually exist.
validate: build
	./target/release/$(BIN) --config-path $(CONFIG) --check

# No `build` dependency, since cargo under sudo is a rustup shim with no root
# toolchain. The unit goes last, so it never points at a binary that is absent.
install:
	@test -x target/release/$(BIN) || { \
	  echo 'target/release/$(BIN) is not there; run `make build` first' >&2; exit 1; }
	install -Dm755 target/release/$(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)
	install -Dm644 config.toml $(DESTDIR)$(CONFIG)
	find scripts -name '*.rn' -exec install -Dm644 '{}' $(DESTDIR)/etc/$(BIN)/'{}' ';'
	install -Dm644 scripts/supermicro/facts.json \
	  $(DESTDIR)/etc/$(BIN)/scripts/supermicro/facts.json
	install -Dm644 $(BIN).service $(DESTDIR)$(UNITDIR)/$(BIN).service
# Placing the unit is packaging and enabling it is not. With DESTDIR set this is
# a staging directory rather than a system, so the enable is skipped there.
	@if [ -z "$(DESTDIR)" ]; then \
	  systemctl daemon-reload && systemctl enable $(BIN); \
	else \
	  echo 'DESTDIR set, so the unit is staged but not enabled'; \
	fi

# A restart rereads the config, where a reload only recompiles the scripts, which
# is what SIGHUP does and what an edit under script_dir usually wants.
restart:
	systemctl restart $(BIN)

clean:
	$(CARGO) clean
