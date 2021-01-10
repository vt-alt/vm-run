/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Simplistic initramfs init
 * Based on switch_root.c by Rob Landley.
 *
 * Copyright (c) 2020 Vitaly Chikunov <vt@altlinux.org>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>

#ifdef __KLIBC__
extern long init_module(void *, unsigned long, const char *);
# define reboot(flag) reboot(flag, NULL)
#else
# define init_module(image, len, param) syscall(__NR_init_module, image, len, param)
#endif

static char *newroot = "/newroot";
static char *modules = "modules.conf";
static char *init = "/usr/lib/vm-run/vm-init";

static void xerrno(int err, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	if (err)
		printf(": %s\n", strerror(err));
	else
		printf("\n");
	sleep(1);
	reboot(RB_POWER_OFF);
}

static void modprobe(void)
{
	FILE *fd = fopen(modules, "r");
	if (!fd) {
		printf("open '%s': %s", modules, strerror(errno));
		return;
	}
	char buf[256];
	while (fgets(buf, sizeof(buf), fd) && buf[0]) {
		buf[strlen(buf) - 1] = '\0';
		int f = open(buf, O_RDONLY | O_CLOEXEC);
		if (f < 0) {
			printf("open '%s' failed %s\n", buf, strerror(errno));
			continue;
		}
		struct stat st;
		if (fstat(f, &st))
			xerrno(errno, "fstat '%s'", buf);
		char *image = malloc(st.st_size);
		if (!image)
			xerrno(errno, "malloc %ld bytes", st.st_size);
		if (read(f, image, st.st_size) != st.st_size)
			xerrno(errno, "read %ld bytes from '%s'", st.st_size, buf);
		close(f);
		int r = init_module(image, st.st_size, "");
		if (r)
			printf("init_module '%s' error %d\n", buf, r);
		free(image);
	}
	fclose(fd);
}

int main(int argc, char **argv)
{
	/* poweroff is not always installed. */
	if (argc > 0 && !strcmp(argv[0], "poweroff"))
		reboot(RB_POWER_OFF);

	if (getpid() != 1)
		xerrno(0, "not pid 1");

	struct statfs stfs;
	if (statfs("/", &stfs) || stfs.f_type != 0x01021994)
		xerrno(0, "root is not tmpfs");

	modprobe();

	if (mkdir(newroot, 0755))
		xerrno(errno, "mkdir '%s'", newroot);

	if (mount("/dev/root", newroot, "9p", 0,
		    "version=9p2000.L,trans=virtio,access=any,loose,msize=262144"))
		xerrno(errno, "mount 9p");

	struct stat st1, st2;
	if (chdir(newroot) ||
	    stat(".", &st1) || stat("/", &st2) ||
	    st1.st_dev == st2.st_dev)
		xerrno(0, "bad newroot");

	if (mount(".", "/", NULL, MS_MOVE, NULL))
		xerrno(errno, "mount --move");

	if (chroot("."))
		xerrno(errno, "chroot");

	if (chdir("/"))
		xerrno(errno, "chdir");

	char * const args[] = { init, NULL };
	execv(init, args);
	xerrno(errno, "execv '%s'");
}
