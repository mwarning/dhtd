
CFLAGS ?= -Os -Wall -Wwrite-strings -pedantic
CFLAGS += -std=gnu99 -I/usr/local/include $(CPPFLAGS)
LDFLAGS += -L/usr/local/lib -lc
FEATURES ?= cmd lpd debug

OBJS = build/searches.o build/kad.o build/log.o \
	build/conf.o build/net.o build/utils.o \
	build/announces.o build/peerfile.o

ifeq ($(OS),Windows_NT)
  OBJS += build/unix.o build/windows.o
else
  OBJS += build/unix.o
endif

.PHONY: all clean strip install dhtd \
	arch-pkg deb-pkg osx-pkg manpage install uninstall

all: dhtd

ifeq ($(findstring cmd,$(FEATURES)),cmd)
  OBJS += build/ext-cmd.o
  CFLAGS += -DCMD
endif

ifeq ($(findstring lpd,$(FEATURES)),lpd)
  OBJS += build/ext-lpd.o
  CFLAGS += -DLPD
endif

ifeq ($(findstring debug,$(FEATURES)),debug)
  CFLAGS += -g -DDEBUG
endif

build/%.o : src/%.c src/%.h
	$(CC) $(CFLAGS) -c -o $@ $<

dhtd: build/main.o $(OBJS) $(EXTRA)
	$(CC) $(CFLAGS) build/main.o $(OBJS) $(LDFLAGS) -o build/dhtd
	ln -s dhtd build/dhtd-ctl 2> /dev/null || true

clean:
	rm -rf build/*

manpage:
	ronn --roff --manual=DHTd\ Manual --organization=mwarning --date=2023-01-01 misc/manpage.md
	mv misc/manpage.1 misc/manpage

install:
	cp build/dhtd $(DESTDIR)/usr/bin/ 2> /dev/null || true
	ln -s dhtd $(DESTDIR)/usr/bin/dhtd-ctl || true

uninstall:
	rm $(DESTDIR)/usr/bin/dhtd 2> /dev/null || true
	rm $(DESTDIR)/usr/bin/dhtd-ctl 2> /dev/null || true
