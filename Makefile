CFLAGS += -static -Wl,-z,noexecstack
initrd-init: initrd-init.c
clean:
	-rm -f initrd-init *.o
.PHONY: clean
