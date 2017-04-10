PREFIX=/usr/local

all:
	gcc -g -O2 -pthread -o mc-crusher mc-crusher.c $(LDFLAGS) -levent

static:
	gcc -g -O2 -pthread -o mc-crusher mc-crusher.c $(LDFLAGS) -Wl,-Bstatic -levent -Wl,-Bdynamic

.PHONY: install

install: mc-crusher
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp $< $(DESTDIR)$(PREFIX)/bin/mc-crusher
