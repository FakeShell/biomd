CC = gcc
CFLAGS = `pkg-config --cflags gio-2.0 glib-2.0 libgbinder sqlite3` -Iinclude
LDFLAGS = `pkg-config --libs gio-2.0 glib-2.0 libgbinder sqlite3`
SOURCES = src/biomd.c \
          src/manager.c \
          src/fingerprint.c \
          src/fingerprint_backend.c \
          src/fingerprint_hidl_backend.c \
          src/fingerprint_binder_hidl.c \
          src/database.c \
          src/fpd_compat.c
TARGET = biomd
TARGET_CLIENT = client/biomdctl.py
HEADERS = include/biomd_enums.h
PREFIX ?= /usr

all: $(TARGET)

$(TARGET):
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install:
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/sbin/
	install -d $(DESTDIR)$(PREFIX)/share/dbus-1/system.d
	install -m 0644 data/io.FuriOS.Biomd.conf $(DESTDIR)$(PREFIX)/share/dbus-1/system.d/
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(TARGET_CLIENT) $(DESTDIR)$(PREFIX)/bin/biomdctl
	install -d $(DESTDIR)$(PREFIX)/include/biomd
	install -m 0644 $(HEADERS) $(DESTDIR)$(PREFIX)/include/biomd/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/$(TARGET)
	rm -f $(DESTDIR)$(PREFIX)/share/dbus-1/system.d/io.FuriOS.Biomd.conf

.PHONY: all clean install uninstall
