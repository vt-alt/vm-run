#!/bin/bash -efu

qemu_help() {
	qemu-system-x86_64 -help
	qemu-system-i386 -help
	qemu-system-aarch64 -help
	qemu-system-ppc64 -help
}

echo "No arguments options:"
qemu_help \
	| grep -P '^-[\S]+  ' \
	| grep -v -e '-dtb' \
	| cut -d' ' -f 1 \
	| grep -v -x -e '-s' \
	| sort -u | fmt | tr ' ' '|' | sed 's/$/| \\/'

echo
echo "Options with argument:"
qemu_help \
	| sed -E '/-dtb[[:space:]]+file/s/[[:space:]]+/ /' \
	| grep -P '^-[\S]+ \S' \
	| cut -d' ' -f 1 \
	| tr '/' '\n' \
	| grep -v -x -e '-h' \
	| sort -u | fmt | tr ' ' '|' | sed 's/$/| \\/'
