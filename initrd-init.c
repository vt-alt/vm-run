/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Simplistic initramfs init
 * Based on switch_root.c by Rob Landley.
 *
 * Copyright (c) 2020-2022 Vitaly Chikunov <vt@altlinux.org>
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
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
#include <blkid/blkid.h>

# define init_module(image, len, param) syscall(__NR_init_module, image, len, param)

static int debug = 0;
static char *rdshell = NULL;

static char *newroot = "/newroot";
static char *modules = "modules.conf";
static char *vm_init = "/usr/lib/vm-run/vm-init";


__attribute__ ((format (printf, 2, 3)))
static void warn(int err, const char *fmt, ...)
{
	va_list args;

	printf("init: ");
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	if (err)
		printf(": %s\n", strerror(err));
	else
		printf("\n");
}

static void runner(char *pathname)
{
	char *argv0 = pathname;
	if (strstr(pathname, "box")) {
		/* Perhaps we don't want to run raw toybox but a shell from it. */
		argv0 = "sh";
	}
	char * const args[] = { argv0, NULL };
	if (debug)
		warn(0, "try %s [%s]", pathname, argv0);
	execv(pathname, args);
	if (debug)
		warn(errno, "execv '%s'", pathname);
}

#define SYS_PATH "/sbin:/usr/sbin:/bin:/usr/bin"
static void try_executable(char *binary)
{
	if (strstr(binary, "/")) {
		runner(binary);
		return;
	}
	/* Also try to run from '/'. */
	char *path = strdup(SYS_PATH ":/");
	if (!path) {
		warn(errno, "strdup");
		return;
	}
	for (char *tok = strtok(path, ":"); tok; tok = strtok(NULL, ":")) {
		char *where;
		if (tok[0] == '/' && tok[1] == '\0')
			*tok = '\0';
		if (asprintf(&where, "%s/%s", tok, binary) != -1) {
			if (access(where, X_OK) == 0)
				runner(where);
			free(where);
		} else
			warn(errno, "asprintf");
	}
	free(path);
	if (debug)
		warn(ENOENT, "exec '%s'", binary);
}

static int exec_rdshell(void)
{
	if (!rdshell)
		return 0;
	warn(0, "launching rdshell (%s)", rdshell);
	/* Make user slightly more happy by setting some env. */
	setenv("PS1", "rdshell# ", 0);
	setenv("PATH", SYS_PATH, 0);

	try_executable(rdshell);
	if (strcmp("sh", rdshell) == 0) {
		try_executable("toybox");
		try_executable("busybox");
	}
	warn(0, "rdshell failed");
	return -1;
}

static void terminate()
{
	sleep(1);
	if (reboot(RB_POWER_OFF) == -1)
		warn(errno, "reboot");
	exit(1);
}

__attribute__ ((format (printf, 2, 3)))
static void xerrno(int err, const char *fmt, ...)
{
	va_list args;

	printf("init: ");
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	if (err)
		printf(": %s\n", strerror(err));
	else
		printf("\n");

	exec_rdshell();
	terminate();
}

static int _modprobe(void)
{
	int loaded = 0, failed = 0;

	FILE *fd = fopen(modules, "r");
	if (!fd) {
		warn(errno, "open '%s'", modules);
		return 0;
	}
	char buf[256];
	while (fgets(buf, sizeof(buf), fd) && buf[0]) {
		buf[strlen(buf) - 1] = '\0';
		int f = open(buf, O_RDONLY | O_CLOEXEC);
		if (f < 0) {
			warn(errno, "open '%s'", buf);
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
		if (debug)
			warn(0, "insmod '%s'", buf);
		int r = init_module(image, st.st_size, "");
		if (!r) {
			loaded++;
		} else {
			int printerr = 0;
			if (errno != EEXIST && !(failed && errno == ENOENT)) {
				failed++;
				printerr++;
			}
			if (printerr || debug)
				warn(errno, "init_module '%s'", buf);
		}
		free(image);
	}
	fclose(fd);
	return failed ? loaded : 0;
}
static void modprobe(void)
{
	/* Load while it loads, to workaround intermittent load ordering failures. */
	while (_modprobe())
		warn(0, "Retry modules loading.");
}

#define COMMAND_LINE_SIZE 2048
static char cmdline[COMMAND_LINE_SIZE];
void get_cmdline(void)
{
	const char *proc = "/proc";
	if (mkdir(proc, 0755))
		xerrno(errno, "mkdir '%s'", proc);
	if (debug)
		warn(0, "mount proc to %s (for cmdline)", proc);
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
	/* Do not unmount in rdshell mode. */
	if (!rdshell && umount(proc) == -1)
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

static void mount_sys(void)
{
	const char *sys = "/sys";
	if (mkdir(sys, 0755))
		xerrno(errno, "mkdir '%s'", sys);
	if (debug)
		warn(0, "mount sysfs to %s", sys);
	if (mount("sysfs", sys, "sysfs", 0, NULL))
		warn(errno, "mount '%s'", sys);
}

// source name from qemu -device ..,mount_tag=
static char *find_mount_tag(void)
{
	mount_sys();

	glob_t globbuf;
	int n = glob("/sys/bus/virtio/drivers/9pnet_virtio/virtio*/mount_tag",
		     GLOB_NOSORT, NULL, &globbuf);
	if (n || globbuf.gl_pathc < 1) {
		warn(errno, "glob: 9p mount_tag not found (ret: %d)", n);
		return NULL;
	}
	const char *mount_tag = globbuf.gl_pathv[0];
	FILE *fd = fopen(mount_tag, "r");
	if (!fd) {
		warn(errno, "open '%s'", mount_tag);
		return NULL;
	}
	static char buf[128];
	if (!fread(buf, 1, sizeof(buf), fd))
		warn(errno, "read '%s'", mount_tag);
	if (fclose(fd) == EOF)
		warn(errno, "fclose '%s'", mount_tag);
	return buf[0] ? buf : NULL;
}

static void mount_devtmpfs()
{
	const char *dev = "dev";

	if (mkdir(dev, 0755) && errno != EEXIST)
		xerrno(errno, "mkdir '%s'", dev);
	if (debug)
		warn(0, "mount devtmpfs to %s", dev);
	if (mount("devtmpfs", dev, "devtmpfs", 0, NULL))
		xerrno(errno, "mount %s", dev);
	/* Will not be able to umount it, but it will disappear after
	 * `mount --move . /` on its own. */
}

int main(int argc, char **argv)
{
	/* We want to enable debug options as early as possible. */
	rdshell = getenv("rdshell");
	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "rddebug") == 0)
			debug++;
		else if (strcmp(argv[i], "rdshell") == 0)
			rdshell = "sh";
	}
	if (debug)
		warn(0, "vm-run initrd%s", rdshell ? " [rdshell]" : "");

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
	const char *root = get_option("root");
	const char *rootfstype = get_option("rootfstype");
	const char *rootflags  = get_option("rootflags");
	if (root) {
		mount_devtmpfs();
		if (strncmp(root, "/dev/", 5)) {
			mount_sys();
			/* Tag formats are in findfs(8). */
			char *dev = blkid_evaluate_tag(root, NULL, NULL);
			if (!dev) {
				/* There are some output from resolver, like
				 * 'Can't open blockdev', which interferes with
				 * this message on console. */
				warn(0, "unable to resolve '%s'", root);
			} else
				root = dev;
		}
		if (!rootfstype) {
			blkid_probe pr = blkid_new_probe_from_filename(root);
			if (pr && !blkid_do_fullprobe(pr)) {
				const char *type;
				if (!blkid_probe_lookup_value(pr, "TYPE", &type, NULL))
					rootfstype = type;
			}
		}
	} else {
		char *mount_tag = find_mount_tag();
		if (mount_tag) {
			rootflags = "version=9p2000.L,trans=virtio,access=any,msize=262144";
			rootfstype = "9p";
			root = mount_tag;
		} else
			xerrno(0, "rootfs not found.");
	}

	if (debug)
		warn(0, "mount %s from %s to %s flags '%s'", rootfstype, root, newroot,
		    rootflags ?: "");
	if (mount(root, newroot, rootfstype, 0, rootflags))
		xerrno(errno, "mount root=%s (type=%s flags=%s)", root, rootfstype, rootflags);

	if (exec_rdshell())
		terminate();
	/* If you really want rdshell after this point use `init=` instead. */

	if (debug)
		warn(0, "switch root");

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
	if (debug)
		warn(0, "exec '%s'", init);
	char * const args[] = { init, NULL };
	execv(init, args);
	xerrno(errno, "execv '%s'", init);
}
