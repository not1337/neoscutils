bin_PROGRAMS = neosc-appselect
sbin_PROGRAMS = neosc-shell
man_MANS = neosc-appselect.1 neosc-shell.1

neosc_appselect_SOURCES = neosc-appselect.c
neosc_appselect_CFLAGS = -Wall -O3
neosc_appselect_LDADD = -lneosc

neosc_shell_SOURCES = neosc-shell.c
neosc_shell_CFLAGS = -Wall -O3
neosc_shell_LDADD = -lreadline -lhistory -lneosc

install-exec-hook:
	strip $(bindir)/neosc-appselect
	strip $(sbindir)/neosc-shell
