AC_INIT([neoscutils], [1.0.0])
AC_CONFIG_SRCDIR([src/neosc-shell.c])
AM_INIT_AUTOMAKE
LT_INIT
AM_CONFIG_HEADER(config.h)
AC_PROG_CC
AC_PROG_INSTALL
AC_CHECK_LIB(neosc,neosc_pcsc_open,,AC_MSG_ERROR([Cannot find libneosc]))
AC_CHECK_LIB(readline,readline,,AC_MSG_ERROR([Cannot find libreadline]))
AC_CHECK_LIB(history,using_history,,AC_MSG_ERROR([Cannot find libhistory]))
AC_CHECK_HEADERS([libneosc.h],,AC_MSG_ERROR([Cannot find libneosc.h]))
AC_CHECK_HEADERS([readline/readline.h readline/history.h],,AC_MSG_ERROR([Cannot find readline headers]))
LIBS=
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
