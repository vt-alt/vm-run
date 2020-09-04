CFLAGS += -static
initrd-init: initrd-init.c
clean:
	-rm -f initrd-init *.o
.PHONY: clean
