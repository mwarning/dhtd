CC ?= gcc 
ifneq (,$(findstring cosmocc,$(CC)))
    CFLAGS += -mclang -static -Wall -Wwrite-strings -pedantic -std=gnu99 -Wno-implicit-function-declaration
else
    CFLAGS += -Wall -Wwrite-strings -pedantic -std=gnu99
endif

LDFLAGS += -lc
# FEATURES ?= cli lpd debug
FEATURES ?= cli

OBJS = build/kad.o build/log.o build/results.o \
	build/conf.o build/net.o build/utils.o \
	build/announces.o build/peerfile.o

ifeq ($(OS),Windows_NT)
  OBJS += build/unix.o build/windows.o
else
  OBJS += build/unix.o
endif

.PHONY: all clean strip install \
		dhtd install uninstall

all: dhtd

ifeq ($(findstring cli,$(FEATURES)),cli)
  OBJS += build/ext-cli.o
  CFLAGS += -DCLI
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

install:
	cp build/dhtd $(DESTDIR)/usr/bin/ 2> /dev/null || true
	ln -s dhtd $(DESTDIR)/usr/bin/dhtd-ctl || true

uninstall:
	rm $(DESTDIR)/usr/bin/dhtd 2> /dev/null || true
	rm $(DESTDIR)/usr/bin/dhtd-ctl 2> /dev/null || true
