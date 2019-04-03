PREFIX=/usr/local

all:
	gcc -g -O2 -pthread -o mc-crusher mc-crusher.c pcg-basic.c itoa_ljust.c $(LDFLAGS) -levent -lm
	gcc -g -O2 -o balloon balloon.c $(LDFLAGS)

static:
	gcc -g -O2 -pthread -o mc-crusher mc-crusher.c pcg-basic.c itoa_ljust.c $(LDFLAGS) -Wl,-Bstatic -levent -lm -Wl,-Bdynamic
	gcc -g -O2 -o balloon balloon.c $(LDFLAGS) -Wl,-Bstatic -Wl,-Bdynamic

tls:
	gcc -g -O2 -pthread -DUSE_TLS=1 -o mc-crusher-tls mc-crusher.c pcg-basic.c itoa_ljust.c $(LDFLAGS) -levent -lssl -lm
	gcc -g -O2 -o balloon balloon.c $(LDFLAGS)

.PHONY: install

install: mc-crusher
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp $< $(DESTDIR)$(PREFIX)/bin/mc-crusher
