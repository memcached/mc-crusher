all:
	gcc -g -O2 -pthread -o mc-crusher mc-crusher.c -levent
