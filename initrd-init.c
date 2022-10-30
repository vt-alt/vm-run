/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Simplistic initramfs init
 * Based on switch_root.c by Rob Landley.
 *
 * Copyright (c) 2020-2022 Vitaly Chikunov <vt@altlinux.org>
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
#include <ctype.h>

#ifdef __KLIBC__
extern long init_module(void *, unsigned long, const char *);
# define reboot(flag) reboot(flag, NULL)
#else
# define init_module(image, len, param) syscall(__NR_init_module, image, len, param)
#endif

static char *newroot = "/newroot";
static char *modules = "modules.conf";
static char *vm_init = "/usr/lib/vm-run/vm-init";

static void warn(int err, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	if (err)
		printf(": %s\n", strerror(err));
	else
		printf("\n");
}

static void xerrno(int err, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
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

#define COMMAND_LINE_SIZE 2048
static char cmdline[COMMAND_LINE_SIZE];
void get_cmdline(void)
{
	const char *proc = "/proc";
	if (mkdir(proc, 0755))
		xerrno(errno, "mkdir '%s'", proc);
	if (mount("proc", proc, "proc", 0, NULL))
		xerrno(errno, "mount '%s'", proc);
	const char *proc_cmdline = "/proc/cmdline";
	FILE *fd = fopen(proc_cmdline, "r");
	if (!fd)
		xerrno(errno, "open '%s'", proc_cmdline);
	if (!fgets(cmdline, sizeof(cmdline), fd))
		xerrno(errno, "read error '%s'", proc_cmdline);
	if (fclose(fd) == EOF)
		warn(errno, "fclose '%s'", proc_cmdline);
	if (umount(proc) == -1)
		warn(errno, "umount '%s'", proc);
}

/* Get value of cmdline option. Options w/o value are skipped. */
static char *get_option(const char *opt)
{
	char *p = cmdline;
	size_t optlen = strlen(opt);

	while (*p) {
		while (isspace(*p))
			p++;
		if (!*p)
			break;
		char *o = p; // start of option
		while (*p && !isspace(*p) && *p != '=')
			p++;
		int match = 0;
		if ((p - o) == optlen && !strncmp(opt, o, p - o))
			match++;
		if (!*p || isspace(*p))
			continue;
		o = ++p; // start of value
		if (*p == '"') {
			o = ++p; // skip opening quote
			while (*p && *p != '"')
				p++;
			if (match)
				return strndup(o, p - o);
			if (*p)
				p++; // skip closing quote
		} else {
			while (*p && !isspace(*p))
				p++;
			if (match)
				return strndup(o, p - o);
		}
	}
	return NULL;
}

// source name from qemu -device ..,mount_tag=
static char *find_mount_tag()
{
	const char *sys = "/sys";
	if (mkdir(sys, 0755))
		xerrno(errno, "mkdir '%s'", sys);
	if (mount("sysfs", sys, "sysfs", 0, NULL)) {
		warn(errno, "mount '%s'", sys);
		return NULL;
	}
	const char *mount_tag = "/sys/bus/virtio/drivers/9pnet_virtio/virtio0/mount_tag";
	FILE *fd = fopen(mount_tag, "r");
	if (!fd) {
		warn(errno, "open '%s'", mount_tag);
		goto out;
	}
	static char buf[128];
	if (!fread(buf, 1, sizeof(buf), fd))
		warn(errno, "read '%s'", mount_tag);
	if (fclose(fd) == EOF)
		warn(errno, "fclose '%s'", mount_tag);
out:
	if (umount(sys) == -1)
		warn(errno, "umount '%s'", sys);
	return buf[0] ? buf : NULL;
}

int main(int argc, char **argv)
{
	/* poweroff is not always installed. */
	if (argc > 0 && !strcmp(argv[0], "poweroff"))
		reboot(RB_POWER_OFF);

	if (getpid() != 1)
		xerrno(0, "not pid 1");

	struct statfs stfs;
	if (statfs("/", &stfs) ||
	    (stfs.f_type != 0x01021994 && stfs.f_type != 0x858458f6))
		xerrno(0, "root is not tmpfs or ramfs");

	modprobe();

	if (mkdir(newroot, 0755))
		xerrno(errno, "mkdir '%s'", newroot);

	get_cmdline();
	char *root = get_option("root");
	if (root) {
		char *rootfstype = get_option("rootfstype");
		char *rootflags = get_option("rootflags");
		/* Mount what user requested via root=. */
		if (mount(root, newroot, rootfstype, 0, rootflags))
			xerrno(errno, "mount root=%s", root);
	} else {
		char *mount_tag = find_mount_tag();
		if (mount_tag) {
			if (mount(mount_tag, newroot, "9p", 0,
				  "version=9p2000.L,trans=virtio,access=any,msize=262144")) {
				xerrno(errno, "mount root %s", mount_tag);
			}
		} else
			xerrno(0, "rootfs not found.");
	}

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

	/* Allow to run user specified init=, perhaps for experiments. */
	char *init = get_option("init");
	if (!init)
		init = vm_init;
	char * const args[] = { init, NULL };
	execv(init, args);
	xerrno(errno, "execv '%s'");
}
