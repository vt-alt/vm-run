CFLAGS += -static -Wl,-z,noexecstack
scripts = \
	vm-run \
	vm-run-stub \
	vm-init \
	vm-create-image \
	vm-resize \
	filetrigger

initrd-init: initrd-init.c

clean:
	-rm -f initrd-init *.o

check: $(scripts)
	$(foreach f,$^,bash -n $(f);)
	shellcheck --severity=error $^

.PHONY: clean check
