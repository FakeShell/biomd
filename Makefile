CC = gcc

CFLAGS = `pkg-config --cflags gio-2.0 glib-2.0 libgbinder sqlite3` -Iinclude
LDFLAGS = `pkg-config --libs gio-2.0 glib-2.0 libgbinder sqlite3` -lfart -lcrypto

CFLAGS_SESSION = `pkg-config --cflags gio-2.0 glib-2.0` -Iinclude
LDFLAGS_SESSION = `pkg-config --libs gio-2.0 glib-2.0`

CFLAGS_FPRINTD = `pkg-config --cflags gio-2.0 glib-2.0` -Iinclude
LDFLAGS_FPRINTD = `pkg-config --libs gio-2.0 glib-2.0`

CFLAGS_PAM = -fPIC -fno-stack-protector `pkg-config --cflags gio-2.0 glib-2.0` -Iinclude
LDFLAGS_PAM = -shared -lpam -lpthread `pkg-config --libs gio-2.0 glib-2.0`

SOURCES = src/biomd.c \
          src/manager.c \
          src/fingerprint.c \
          src/fingerprint_backend.c \
          src/fingerprint_hidl_backend.c \
          src/fingerprint_binder_hidl.c \
          src/database.c \
          src/fpd_compat.c \
          src/face.c \
          src/face_backend.c \
          src/face_fart_backend.c \
          src/face_tensorflow_fart.c

SOURCES_SESSION = src/session/biomd_session.c src/session/logind.c
SOURCES_FPRINTD = src/fprintd/fprintd.c
SOURCES_PAM = src/pam/pam_biomd.c

TARGET = biomd
TARGET_CLIENT = client/biomdctl.py
TARGET_SESSION = biomd-session
TARGET_FPRINTD = biomd-fprintd
TARGET_PAM = pam_biomd.so

HEADERS = include/biomd_enums.h

PREFIX ?= /usr
TRIPLET ?= $(shell $(CC) -dumpmachine)

all: $(TARGET) $(TARGET_SESSION) $(TARGET_FPRINTD) $(TARGET_PAM)

$(TARGET):
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

$(TARGET_SESSION):
	$(CC) $(CFLAGS_SESSION) $(SOURCES_SESSION) -o $(TARGET_SESSION) $(LDFLAGS_SESSION)

$(TARGET_FPRINTD):
	$(CC) $(CFLAGS_FPRINTD) $(SOURCES_FPRINTD) -o $(TARGET_FPRINTD) $(LDFLAGS_FPRINTD)

$(TARGET_PAM):
	$(CC) $(CFLAGS_PAM) $(SOURCES_PAM) -o $(TARGET_PAM) $(LDFLAGS_PAM)

clean:
	rm -f $(TARGET) $(TARGET_SESSION) $(TARGET_FPRINTD) $(TARGET_PAM)

install: all
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/sbin/

	install -d $(DESTDIR)$(PREFIX)/share/dbus-1/system.d
	install -m 0644 data/io.FuriOS.Biomd.conf $(DESTDIR)$(PREFIX)/share/dbus-1/system.d/

	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(TARGET_CLIENT) $(DESTDIR)$(PREFIX)/bin/biomdctl

	install -d $(DESTDIR)$(PREFIX)/include/biomd
	install -m 0644 $(HEADERS) $(DESTDIR)$(PREFIX)/include/biomd/

	install -d $(DESTDIR)$(PREFIX)/libexec
	install -m 0755 $(TARGET_SESSION) $(DESTDIR)$(PREFIX)/libexec/
	install -m 0755 $(TARGET_FPRINTD) $(DESTDIR)$(PREFIX)/libexec/

	install -d $(DESTDIR)$(PREFIX)/lib/systemd/system/fprintd.service.d
	install -d $(DESTDIR)$(PREFIX)/lib/systemd/user
	install -m 0644 data/10-biomd.conf $(DESTDIR)$(PREFIX)/lib/systemd/system/fprintd.service.d/
	install -m 0644 data/biomd-session.service $(DESTDIR)$(PREFIX)/lib/systemd/user/

	install -d $(DESTDIR)$(PREFIX)/lib/$(TRIPLET)/security
	install -m 0644 $(TARGET_PAM) $(DESTDIR)$(PREFIX)/lib/$(TRIPLET)/security/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/$(TARGET)
	rm -f $(DESTDIR)$(PREFIX)/bin/biomdctl
	rm -f $(DESTDIR)$(PREFIX)/share/dbus-1/system.d/io.FuriOS.Biomd.conf
	rm -f $(DESTDIR)$(PREFIX)/libexec/$(TARGET_SESSION)
	rm -f $(DESTDIR)$(PREFIX)/libexec/$(TARGET_FPRINTD)
	rm -f $(DESTDIR)$(PREFIX)/lib/$(TRIPLET)/security/$(TARGET_PAM)
	rm -f $(DESTDIR)$(PREFIX)/lib/systemd/user/biomd-session.service
	rm -f $(DESTDIR)$(PREFIX)/lib/systemd/system/fprintd.service.d/10-biomd.conf

.PHONY: all clean install uninstall
