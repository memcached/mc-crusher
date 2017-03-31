PREFIX=/usr/local

all:
	gcc -g -O2 -pthread -o mc-crusher mc-crusher.c -levent

.PHONY: install
install: mc-crusher
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp $< $(DESTDIR)$(PREFIX)/bin/mc-crusher
