/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Fake SUDO. Only permissions are set and some options are handled,
 * other options are ignored and env is not filtered.
 *
 * Copyright (c) 2022 Vitaly Chikunov <vt@altlinux.org>
 * (With some options parsing stuff from real sudo.)
 */

#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

static const char sudo_short_opts[] = "+Aa:BbC:c:D:Eeg:Hh::iKklnPp:R:r:SsT:t:U:u:Vv";
static struct option sudo_long_opts[] = {
	{  "askpass",           no_argument,        NULL,  'A'   },
	{  "auth-type",         required_argument,  NULL,  'a'   },
	{  "background",        no_argument,        NULL,  'b'   },
	{  "bell",              no_argument,        NULL,  'B'   },
	{  "chdir",             required_argument,  NULL,  'D'   },
	{  "chroot",            required_argument,  NULL,  'R'   },
	{  "close-from",        required_argument,  NULL,  'C'   },
	{  "command-timeout",   required_argument,  NULL,  'T'   },
	{  "edit",              no_argument,        NULL,  'e'   },
	{  "group",             required_argument,  NULL,  'g'   },
	{  "help",              no_argument,        NULL,  'h'   },
	{  "host",              required_argument,  NULL,  256   },
	{  "list",              no_argument,        NULL,  'l'   },
	{  "login-class",       required_argument,  NULL,  'c'   },
	{  "login",             no_argument,        NULL,  'i'   },
	{  "non-interactive",   no_argument,        NULL,  'n'   },
	{  "other-user",        required_argument,  NULL,  'U'   },
	{  "preserve-env",      optional_argument,  NULL,  'E'   },
	{  "preserve-groups",   no_argument,        NULL,  'P'   },
	{  "prompt",            required_argument,  NULL,  'p'   },
	{  "remove-timestamp",  no_argument,        NULL,  'K'   },
	{  "reset-timestamp",   no_argument,        NULL,  'k'   },
	{  "role",              required_argument,  NULL,  'r'   },
	{  "set-home",          no_argument,        NULL,  'H'   },
	{  "shell",             no_argument,        NULL,  's'   },
	{  "stdin",             no_argument,        NULL,  'S'   },
	{  "type",              required_argument,  NULL,  't'   },
	{  "user",              required_argument,  NULL,  'u'   },
	{  "validate",          no_argument,        NULL,  'v'   },
	{  "version",           no_argument,        NULL,  'V'   },
	{  NULL,                no_argument,        NULL,  '\0'  },
};

void usage(int err)
{
	printf("usage: fakesudo -h | -V\n");
	printf("usage: fakesudo [-P] [-g group] [-u user] [VAR=value] [-i|-s] [command]\n");
	exit(err);
}

int main(int argc, char **argv)
{
	const char *short_opts = sudo_short_opts;
	struct option *long_opts = sudo_long_opts;

	if (argc <= 0)
		usage(1);

	struct passwd *me = getpwuid(getuid());

	/* Returns true if the last option string was "--" */
#define got_end_of_args (optind > 1 && argv[optind - 1][0] == '-' && \
			 argv[optind - 1][1] == '-' && argv[optind - 1][2] == '\0')

	/* Returns true if next option is an environment variable */
#define is_envar (optind < argc && argv[optind][0] != '/' && \
		  strchr(argv[optind], '=') != NULL)

	int shell_mode = 0;
	int user_mode  = 0;
	int group_mode = 0;
	int preserve_groups = 0;
	char *shell_cmd   = NULL;
	const char *user  = "root";
	const char *group = "root";

	for (;;) {
		int ch;

		if ((ch = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
			char hn[HOST_NAME_MAX] = {};
			switch (ch) {
			case 'P':
				preserve_groups = 1;
				break;
			case 'g':
				group = optarg;
				group_mode = 1;
				break;
			case 'u':
				user = optarg;
				user_mode = 1;
				break;
			case 'i':
			case 's':
				shell_mode += ch;
				break;
			case 'D':
			case 'e':
			case 'T':
				printf("fakesudo: you are not permitted to use the -%c option\n", ch);
				exit(1);
			case 'l':
				gethostname(hn, sizeof hn);
				printf("User %s may run the following commands on %s:\n", me->pw_name, hn);
				printf("    (ALL) NOPASSWD: ALL\n");
				exit(0);
			case 'h':
			case 'V':
				usage(0);
			}
		} else if (!got_end_of_args && is_envar) {
			putenv(argv[optind]);
			optind++;
		} else {
			break;
		}
	}
	argc -= optind;
	argv += optind;

	struct passwd *pw;
	if (user[0] == '#')
		pw = getpwuid(atol(user + 1));
	else
		pw = getpwnam(user);
	if (!pw)
		errx(1, "fakesudo: unknown user %s", user);

	struct group *gr;
	if (group[0] == '#')
		gr = getgrgid(atol(group + 1));
	else
		gr = getgrnam(group);
	if (!gr)
		errx(1, "fakesudo: unknown group %s", group);

	if (shell_mode == 's') {
		shell_cmd = getenv("SHELL");
		if (!shell_cmd)
			shell_cmd = me->pw_shell;
	} else if (shell_mode == 'i') {
		shell_cmd = pw->pw_shell;
	} else if (shell_mode) {
		usage(1);
	}

	if (shell_cmd) {
		/* Create shell command using sudo algorithm. */
		char **av, *cmnd = NULL;
		int ac = 1;

		if (argc) {
			char *src, *dst;
			size_t size = 0;

			for (av = argv; *av != NULL; av++)
				size += strlen(*av) + 1;
			if (size == 0 ||
			    (cmnd = reallocarray(NULL, size, 2)) == NULL)
				err(1, "reallocarray");
			for (dst = cmnd, av = argv; *av != NULL; av++) {
				for (src = *av; *src != '\0'; src++) {
					if (!isalnum((unsigned char)*src) &&
					    *src != '_' &&
					    *src != '-' &&
					    *src != '$')
						*dst++ = '\\';
					*dst++ = *src;
				}
				*dst++ = ' ';
			}
			if (cmnd != dst)
				dst--;
			*dst = '\0';

			ac += 2;
		}

		if (!(av = reallocarray(NULL, ac + 1, sizeof(char *))))
			err(1, "reallocarray");
		av[0] = shell_cmd;
		if (cmnd != NULL) {
			av[1] = "-c";
			av[2] = cmnd;
		}
		av[ac] = NULL;

		argv = av;
		argc = ac;
	}

	if (!argc)
		usage(1);
	char *prog = argv[0];

	char *ptr;
	if (asprintf(&ptr, "%u", getgid()) != -1)
		setenv("SUDO_GID", ptr, 1);
	if (asprintf(&ptr, "%u", getuid()) != -1)
		setenv("SUDO_UID", ptr, 1);
	setenv("SUDO_USER", me->pw_name, 1);

	if (shell_mode == 'i') {
		/* login shell */
		if (chdir(pw->pw_dir))
			err(1, "chdir %s", pw->pw_dir);
		setenv("HOME",    pw->pw_dir, 1);
		setenv("SHELL",   pw->pw_shell, 1);
		setenv("LOGIN",   pw->pw_name, 1);
		setenv("LOGNAME", pw->pw_name, 1);
		setenv("USER",    pw->pw_name, 1);
		setenv("SHELL",   pw->pw_shell, 1);
		if (asprintf(argv, "-%s", prog) == -1)
			argv[0] = prog;
	}

	if (setgid(group_mode ? gr->gr_gid : pw->pw_gid))
		err(1, "setgid");
	if (group_mode && !user_mode) {
		/* -g is specified but no -u. */
		pw = me;
	}
	if (!preserve_groups) {
		if (initgroups(pw->pw_name, pw->pw_gid))
			err(1, "initgroups");
	}
	if (setuid(pw->pw_uid))
		err(1, "setuid");

	execvp(prog, &argv[0]);
	err(1, "execvp %s", argv[0]);
}
