SOURCES = bitvec.c bmt.c bmt0.c bmt01.c bmt10.c bmtlib.c bmtobj.c        \
	        core01.c dba.c dbm0.c dbm1.c dbm2.c domain.c draw07.c draw7.c  \
	        drawlib.c drawobj.c emplib.c empobj.c env0.c env01.c env1.c    \
	        fm.c gdbm.c grp0.c grp1.c grp2.c hm.c iam.c ifm.c im.c km.c    \
	        list01.c mem00.c mem01.c mem10.c oa0.c oa1.c oadmp.c obj01.c   \
	        odbm.c ogrp.c om.c point.c primal.c pstub.c query.c rect.c     \
	        rects.c sa.c shell.c sm.c testobj.c tm.c trans00.c trans01.c   \
	        trans10.c trans20.c tree0.c tree00.c tree01.c ut.c vchunk.c    \
	        vdbm.c voa.c vom.c

OUTPUT = vortex
COMMAND = vortex lendian.raw > lendian.out
TEMPFILES = lendian.out

-include ../Makefile.config

ifdef __x86_64__
CFLAGS += -DSPEC_CPU2000_LP64
endif

