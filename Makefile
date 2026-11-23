# Copyright 2025-2026 Dillution <hskimse1@gmail.com>.
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

.PHONY: install uninstall tarball

install:
	install -d "$(DESTDIR)$(PREFIX)/bin" "$(DESTDIR)$(MANPREFIX)/man1"
	install -m 755 $(PROG) "$(DESTDIR)$(PREFIX)/bin/"
	install -m 644 $(MAN) "$(DESTDIR)$(MANPREFIX)/man1/"

uninstall:
	rm -f "$(DESTDIR)$(PREFIX)/bin/$(PROG)" "$(DESTDIR)$(MANPREFIX)/man1/$(MAN)"

ifneq ($(wildcard Cargo.toml),)
VERSION := $(shell cargo metadata --format-version=1 --no-deps \
		| jq -r '.packages[] | select(.name == "dpibreak") | .version')
endif

ifneq ($(wildcard .git),)
SOURCE_DATE_EPOCH := $(shell git log -1 --format=%ct)
export SOURCE_DATE_EPOCH
endif

DISTDIR  = dist
DISTNAME = $(PROG)-$(VERSION)
ARCHIVE  = $(DISTNAME)-$(BUILD_TARGET)
STAGE    = $(DISTDIR)/$(DISTNAME)

tarball:
	cargo build --release --locked --target "$(BUILD_TARGET)"
	rm -rf "$(STAGE)"
	mkdir -p "$(STAGE)"
	cp "target/$(BUILD_TARGET)/release/$(PROG)" $(MAN) \
	   README.md CHANGELOG.md COPYING Makefile "$(STAGE)"
	strip --strip-unneeded "$(STAGE)/$(PROG)"
	tar -C "$(DISTDIR)" \
	    --sort=name \
	    --mtime="@$(SOURCE_DATE_EPOCH)" \
	    --owner=0 --group=0 --numeric-owner \
	    -czf "$(DISTDIR)/$(ARCHIVE).tar.gz" "$(DISTNAME)"
	cd "$(DISTDIR)" && sha256sum "$(ARCHIVE).tar.gz" > "$(ARCHIVE).tar.gz.sha256"
	{ \
	  echo "Name:         $(PROJECT)"; \
	  echo "Version:      $(VERSION)"; \
	  echo "Commit:       $$(git rev-parse HEAD)"; \
	  echo "Target:       $(BUILD_TARGET)"; \
	  echo "Rustc:        $$(rustc --version)"; \
	  echo "Cargo:        $$(cargo --version)"; \
	  echo "Date:         $$(date -u -d @$(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ)"; \
	  echo "Host:         $$(uname -srvmo)"; \
	  case "$(BUILD_TARGET)" in \
	    *gnu*) \
	      if getconf GNU_LIBC_VERSION >/dev/null 2>&1; then \
	        echo "libc:         $$(getconf GNU_LIBC_VERSION)"; \
	      else \
	        echo "libc:         $$(ldd --version 2>&1 | head -n1 || true)"; \
	      fi;; \
	    *musl*) echo "libc:         musl";; \
	    *)      echo "libc:         unknown";; \
	  esac; \
	} > "$(DISTDIR)/$(ARCHIVE).buildinfo"
