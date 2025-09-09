# Copyright 2025 Dillution <hskimse1@gmail.com>.
#
# This file is part of DPIBreak.
#
# DPIBreak is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# DPIBreak is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License
# along with DPIBreak. If not, see <https://www.gnu.org/licenses/>.

PREFIX ?= /usr/local
MANPREFIX ?= $(PREFIX)/share/man

BUILD_TARGET ?= x86_64-unknown-linux-musl

PROJECT = DPIBreak
PROG = dpibreak
MAN = dpibreak.1
TARGET = target/$(BUILD_TARGET)/release/$(PROG)

.PHONY: install uninstall

$(PROG):
	cp "$(TARGET)" "$@"
	strip --strip-unneeded "$@"

install: $(PROG) $(MAN)
	@echo "Installing DPIBreak..."
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -d "$(DESTDIR)$(MANPREFIX)/man1"
	install -m 755 "$(PROG)" "$(DESTDIR)$(PREFIX)/bin/"
	install -m 644 "$(MAN)" "$(DESTDIR)$(MANPREFIX)/man1/"
	@echo "Installation complete."

uninstall:
	@echo "Uninstalling DPIBreak..."
	rm -f "$(DESTDIR)$(PREFIX)/bin/$(PROG)"
	rm -f "$(DESTDIR)$(MANPREFIX)/man1/$(MAN)"
	@echo "Uninstallation complete."

.PHONY: all build tarball clean

VERSION := $(shell cargo metadata --format-version=1 --no-deps \
	      | jq -r '.packages[0].version')
SOURCE_DATE_EPOCH := $(shell git log -1 --format=%ct)
export SOURCE_DATE_EPOCH

all: build

build:
	cargo build --release --locked --target "$(BUILD_TARGET)"

DIST_ELEMS = $(PROG) $(MAN) README.md CHANGELOG COPYING Makefile
DISTDIR	   = dist
DISTNAME   = $(PROJECT)-$(VERSION)-$(BUILD_TARGET)
TARBALL	   = $(DISTDIR)/$(DISTNAME).tar.gz
SHA256	   = $(TARBALL).sha256
BUILDINFO  = $(DISTDIR)/$(DISTNAME).buildinfo

tarball: $(SHA256) $(BUILDINFO)

$(DISTDIR):
	mkdir -p "$@"

$(DISTDIR)/$(DISTNAME): | $(DISTDIR)
	mkdir -p "$@"

$(TARBALL): build $(DIST_ELEMS) | $(DISTDIR)/$(DISTNAME)
	cp $(DIST_ELEMS) "$(DISTDIR)/$(DISTNAME)"
	tar -C "$(DISTDIR)" \
	    --sort=name \
	    --mtime="@$(SOURCE_DATE_EPOCH)" \
	    --owner=0 --group=0 --numeric-owner \
	    -czf "$@" "$(DISTNAME)"

$(SHA256): $(TARBALL)
	{ cd $(DISTDIR) && sha256sum "$(DISTNAME).tar.gz"; } > "$@"

$(BUILDINFO): | $(DISTDIR)
	{ \
	  echo "Name:	    $(PROJECT)"; \
	  echo "Version:    $(VERSION)"; \
	  echo "Commit:	    $$(git rev-parse HEAD)"; \
	  echo "Target:	    $(BUILD_TARGET)"; \
	  echo "Rustc:	    $$(rustc --version)"; \
	  echo "Cargo:	    $$(cargo --version)"; \
	  echo "Date:	    $$(date -u -d @$(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ)"; \
	  echo "Host:	    $$(uname -srvmo)"; \
	  if command -v getconf >/dev/null 2>&1 && getconf GNU_LIBC_VERSION >/dev/null 2>&1; then \
	    echo "libc:	      $$(getconf GNU_LIBC_VERSION)"; \
	  else \
	    echo "libc:	      $$(ldd --version 2>&1 | head -n1 || true)"; \
	  fi; \
	} > "$@"
clean:
	rm -rf "$(PROG)" \
	       "$(DISTDIR)/$(DISTNAME)" \
	       "$(TARBALL)" \
	       "$(SHA256)" \
	       "$(BUILDINFO)"
	cargo clean

.PHONY: help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "	 all	    Build the project (default)"
	@echo "	 build	    Build the release binary"
	@echo "	 install    Install the binary and man page"
	@echo "	 uninstall  Uninstall the binary and man page"
	@echo "	 tarball    Create a distributable tarball"
	@echo "	 clean	    Remove build artifacts"
	@echo "	 help	    Show this help message"
