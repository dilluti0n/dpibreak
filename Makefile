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

PROG = dpibreak
TARGET = target/release/$(PROG)
MAN = dpibreak.1

.PHONY: build install uninstall

all: build

build:
	cargo build --release

$(PROG): build
	cp "$(TARGET)" .
	strip --strip-unneeded "$(PROG)"

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
