SOURCES = av.c byterun.c deb.c doio.c doop.c dump.c ebcdic.c \
          fake_dyna.c globals.c gv.c hv.c mg.c op.c perl.c perlio.c \
          perly.c pp.c pp_ctl.c pp_hot.c pp_sys.c regcomp.c regexec.c \
          run.c scope.c sv.c taint.c toke.c universal.c util.c MD5.c \
          md5c.c unix_perlmain.c

OUTPUT = perlbmk
#COMMAND = perlbmk -I./lib splitmail.pl 850 5 19 18 1500
COMMAND = perlbmk -I./lib splitmail.pl 1 5 19 18 1500
# 5 messages is good

-include ../Makefile.config

CFLAGS += -DSPEC_CPU2000_GLIBC22 -DSPEC_CPU2000_NEED_BOOL -DHAS_MEMCMP -DHAS_MEMCPY

ifdef __x86_64__
# SPEC 2000 is too old to know about x86-64:
CFLAGS += -DSPEC_CPU2000_LINUX_ALPHA
else
CFLAGS += -DSPEC_CPU2000_LINUX_I386
endif
