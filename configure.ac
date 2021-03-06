AC_INIT([incc],[1.1],[luis.camp0.2009@gmail.com],[],[])
AM_INIT_AUTOMAKE(incc,1.1)
AM_PROG_LIBTOOL

AC_CONFIG_HEADER(config.h)

AC_CONFIG_MACRO_DIR([m4])
m4_include([m4/ax_python_module.m4])
m4_include([m4/debug.m4])

AC_PREREQ(2.59)

AC_PROG_INSTALL

AC_LANG([C])
AC_PROG_CC
AC_PROG_MAKE_SET
AC_SUBST([AM_CFLAGS], [-Wall -fPIC])

AM_PATH_PYTHON(2.6)

AC_PATH_PROGS([SWIG],[swig swig2.0])
if test -z "$SWIG" ; then
        enable_swig=no
else
        enable_swig=yes
        AX_PKG_SWIG(1.3.36, , AC_MSG_ERROR("Swig is required."))
        AX_SWIG_ENABLE_CXX
        AX_SWIG_MULTI_MODULE_SUPPORT
        AX_SWIG_PYTHON
fi

dnl Checks for libraries
AC_PYTHON_MODULE(unittest)

AX_PYTHON

dnl pcap 
AC_CHECK_LIB(pcap, main, ,AC_MSG_ERROR("Install pcap library"),)
AC_CHECK_HEADER(pcap.h, ,[AC_MSG_ERROR("pcap.h header not found.")],)

dnl pcap 
AC_CHECK_LIB(log4c, main, ,AC_MSG_ERROR("Install log4c library"),)
AC_CHECK_HEADER(log4c.h, ,[AC_MSG_ERROR("log4c.h header not found.")],)

AC_MSG_CHECKING(for perl regular expressions support)
AC_ARG_WITH(pcre, AC_HELP_STRING([--with-pcre],[Enable pcre support (default yes)]),
    [WITH_PCRE=$withval],[WITH_PCRE=yes])
AC_MSG_RESULT([$WITH_PCRE])

if test "$WITH_PCRE" != "no"; then
  AC_PATH_PROG(PCRECONFIG, pcre-config)

  if test x"$PCRECONFIG" != x; then
    PCRE_LIB=`$PCRECONFIG --libs`
    CPPFLAGS="$CPPFLAGS `$PCRECONFIG --cflags`"
    AC_DEFINE([HAVE_LIBPCRE], [1], [libpcre])
    AC_DEFINE([HAVE_PCRE_H], [1], [pcre.h])
  else
     AC_MSG_ERROR([pcre-config not found, install the pcre-devel package or build with --without-pcre])
  fi
fi

AC_SUBST(PCRE_LIB)
    AC_MSG_CHECKING(for PCRE JIT support)
    AC_TRY_COMPILE([ #include <pcre.h> ],
        [
        int jit = 0;
        pcre_config(PCRE_CONFIG_JIT, &jit);
        ],
        [ pcre_jit_available=yes ], [ pcre_jit_available=no ]
        )

    if test "x$pcre_jit_available" = "xyes"; then
       AC_MSG_RESULT(yes)
       AC_DEFINE([PCRE_HAVE_JIT], [1], [Pcre with JIT compiler support enabled])

       AC_MSG_CHECKING(for PCRE JIT support usability)
       AC_TRY_COMPILE([ #include <pcre.h> ],
           [
           const char* regexstr = "(a|b|c|d)";
           pcre *re;
           const char *error;
           pcre_extra *extra;
           int err_offset;
           re = pcre_compile(regexstr,0, &error, &err_offset,NULL);
           extra = pcre_study(re, PCRE_STUDY_JIT_COMPILE, &error);
           if (extra == NULL)
               exit(EXIT_FAILURE);
           int jit = 0;
           int ret = pcre_fullinfo(re, extra, PCRE_INFO_JIT, &jit);
           if (ret != 0 || jit != 1)
               exit(EXIT_FAILURE);
           exit(EXIT_SUCCESS);
           ],
           [ pcre_jit_works=yes ], [:]
       )
       if test "x$pcre_jit_works" != "xyes"; then
           AC_MSG_RESULT(no)
           echo
           echo "   PCRE JIT support detection worked but testing it failed"
           echo "   something odd is going on, please file a bug report."
           echo
           exit 1
       else
           AC_MSG_RESULT(yes)
       fi
    fi


PKG_CHECK_MODULES(
	[OPENSSL],
	[libcrypto >= 0.9.8],
	,
	[PKG_CHECK_MODULES(
		[OPENSSL],
		[openssl >= 0.9.8],
		,
		[AC_CHECK_LIB(
			[crypto],
			[RSA_verify],
			[OPENSSL_LIBS="-lcrypto ${SOCKETS_LIBS} ${DL_LIBS}"],
			[AC_MSG_ERROR([OpenSSL 0.9.8 or later is required. http://www.openssl.org/])],
			[${DL_LIBS}]
		)]
	)]
)

PKG_CHECK_MODULES(GLIB,[glib-2.0 >= 2.10.3],[],AC_MSG_ERROR($GLIB_PKG_ERRORS))

PKG_CHECK_MODULES(DBUS,dbus-1 )
# AC_CHECK_HEADER(dbus.h, ,[AC_MSG_ERROR("dbus.h header not found.")],)
# missing openssl for libssl for rc4

AC_CHECK_DEBUG

AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
	then AC_MSG_WARN([Doxygen not found - continuing without Doxygen support])
	enable_doxygen=no
else
	enable_doxygen=yes
fi


AC_OUTPUT([
Makefile
src/utils/Makefile
src/bus/Makefile
src/core/Makefile
extra/Makefile
test/Makefile
docs/Makefile
])

echo "
  InCC
  ($PACKAGE_NAME) version $PACKAGE_VERSION
  Platform................: $host
  Prefix..................: $prefix
  C preprocessor..........: $CPP
  C Compiler..............: $CC
  C preprocessor flags....: $CPPFLAGS
  C compiler flags........: $CFLAGS
  Linker flags............: $LDFLAGS 
  Extra libraries.........: $LIBS 
  Debug Build.............: $enable_debug
  Swig enable.............: $enable_swig
  Pcre JIT support........: $pcre_jit_available
"

