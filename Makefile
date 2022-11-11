CC = gcc
CFLAGS += -Wall -Werror -fanalyzer
CFLAGS_STATIC += -static $(CFLAGS)
LDLIBS += $(shell pkg-config --libs --static blkid)

scripts = \
	vm-run \
	vm-run-stub \
	vm-init \
	vm-create-image \
	vm-resize \
	filetrigger \
	createimage \
	bash_completion

all: initrd-init fakesudo
initrd-init: initrd-init.c
	$(CC) $(CFLAGS_STATIC) $^ $(LDLIBS) -o $@
fakesudo: fakesudo.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	-rm -f initrd-init fakesudo *.o

check: $(scripts)
	$(foreach f,$^,bash -n $(f);)
	shellcheck --severity=error $^

.PHONY: clean check
