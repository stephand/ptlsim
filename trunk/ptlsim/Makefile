# -*- makefile -*-
#
# PTLsim: Cycle Accurate x86-64 Simulator
# Makefile
#
# Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
#

ifeq ($(findstring x86_64,$(MACHTYPE)),x86_64)
__x86_64__=1
endif

CC = g++
SVNREV=`svn info | grep "Last Changed Rev" | cut -d " " -f4`
SVNDATE=`svn info | grep "Last Changed Date" | cut -d " " -f4-`
INCFLAGS = -I. -DBUILDHOST="`hostname -f`" -DSVNREV="$(SVNREV)" -DSVNDATE="$(SVNDATE)"

ifdef __x86_64__
CFLAGS = -O99 -g -fomit-frame-pointer -march=k8 -falign-functions=16 -fno-trapping-math -fno-exceptions -fno-rtti -m64 -funroll-loops -mpreferred-stack-boundary=4 -fno-strict-aliasing -Wreturn-type -minline-all-stringops
#CFLAGS = -O0 -g3 -march=k8 -falign-functions=16 -fno-trapping-math -fno-strict-aliasing -fno-exceptions -fno-rtti -mpreferred-stack-boundary=4 -Wreturn-type
CFLAGS32BIT = -m32
else
# 32-bit PTLsim32 only, on a Pentium 4:
CFLAGS = -O99 -g -fomit-frame-pointer -march=pentium4 -falign-functions=16 -fno-trapping-math -fno-exceptions -fno-rtti -fomit-frame-pointer -funroll-loops -mpreferred-stack-boundary=4 -fno-strict-aliasing -Wreturn-type
# No optimizations:
#CFLAGS = -O0 -g3 -march=pentium4 -mtune=k8 -falign-functions=16 -fno-trapping-math -fno-exceptions -fno-rtti -funroll-loops -mpreferred-stack-boundary=4 -fno-strict-aliasing -Wreturn-type
CFLAGS32BIT = 
endif

BASEOBJS = superstl.o config.o mathlib.o syscalls.o
STDOBJS = glibc.o

ifdef __x86_64__
# IMPORTANT: linkstart.o and linkend.o must be at opposite ends of the list to set up constructor tables properly:
COMMONOBJS = linkstart.o lowlevel-64bit.o lowlevel-32bit.o ptlsim.o kernel.o ptlhwdef.o translate-x86.o uopimpl.o dcache.o datastore.o injectcode-32bit.o injectcode-64bit.o $(BASEOBJS) klibc.o linkend.o
else
# 32-bit PTLsim32 only:
COMMONOBJS = linkstart.o lowlevel-32bit.o ptlsim.o kernel.o ptlhwdef.o translate-x86.o uopimpl.o dcache.o datastore.o injectcode-32bit.o $(BASEOBJS) klibc.o linkend.o
endif

OOOOBJS = ooocore.o seqcore.o branchpred.o
OBJFILES = $(COMMONOBJS) $(OOOOBJS)

COMMONINCLUDES = logic.h dcacheint.h ptlhwdef.h dcache.h config.h ptlsim.h datastore.h superstl.h globals.h kernel.h ptlcalls.h loader.h mathlib.h klibc.h syscalls.h
OOOINCLUDES = branchpred.h ooohwdef.h
INCLUDEFILES = $(COMMONINCLUDES) $(OOOINCLUDES)

COMMONCPPFILES = ptlsim.cpp kernel.cpp superstl.cpp ptlhwdef.cpp translate-x86.cpp lowlevel-64bit.S lowlevel-32bit.S linkstart.S linkend.S uopimpl.cpp dcache.cpp config.cpp datastore.cpp injectcode.cpp ptlcalls.c cpuid.cpp ptlstats.cpp klibc.cpp glibc.cpp mathlib.cpp syscalls.cpp
OOOCPPFILES = ooocore.cpp seqcore.cpp branchpred.cpp
CPPFILES = $(COMMONCPPFILES) $(OOOCPPFILES)

#
# See the notes on "Performance Counter Support" in kernel.cpp
# for how to use this. Uncomment this only if you have perfctr
# kernel support and header files available.
#
# ENABLE_KERNEL_PERFCTRS = 1
#

ifdef ENABLE_KERNEL_PERFCTRS
	LIBPERFCTR = -lperfctr
else
	LIBPERFCTR = 
endif

CFLAGS += -D__PTLSIM_OOO_ONLY__

all: ptlsim ptlstats ptlcalls.o ptlcalls-32bit.o cpuid
	@echo "Compiled successfully..."

cpuid: cpuid.o $(BASEOBJS) $(STDOBJS)
	g++ -O2 cpuid.o $(BASEOBJS) $(STDOBJS) -o cpuid

ptlstats: ptlstats.o datastore.o ptlhwdef.o $(BASEOBJS) $(STDOBJS) Makefile
	g++ -g -O2 ptlstats.o datastore.o ptlhwdef.o $(BASEOBJS) $(STDOBJS) -o ptlstats

ifdef __x86_64__
injectcode-64bit.o: injectcode.cpp
	$(CC) $(CFLAGS) $(INCFLAGS) -m64 -O99 -fomit-frame-pointer -c injectcode.cpp -o injectcode-64bit.o

injectcode-32bit.o: injectcode.cpp
	$(CC) $(CFLAGS) $(INCFLAGS) -m32 -O99 -fomit-frame-pointer -c injectcode.cpp -o injectcode-32bit.o
else
injectcode-32bit.o: injectcode.cpp
	$(CC) $(CFLAGS) $(INCFLAGS) -DPTLSIM_FORCE_32BIT_ONLY -O99 -fomit-frame-pointer -c injectcode.cpp -o injectcode-32bit.o
endif

lowlevel-32bit.o: lowlevel-32bit.S
	$(CC) -c $(CFLAGS32BIT) $(INCFLAGS) -g -O3 lowlevel-32bit.S

ptlcalls-32bit.o: ptlcalls.c
	$(CC) -c $(CFLAGS) $(INCFLAGS) $(CFLAGS32BIT) -O99 -fomit-frame-pointer ptlcalls.c -o ptlcalls-32bit.o

ifdef __x86_64__
ptlsim: $(OBJFILES) Makefile ptlsim.lds
	ld -g -O2 $(OBJFILES) -o ptlsim $(LIBPERFCTR) -static --allow-multiple-definition -T ptlsim.lds -e ptlsim_preinit_entry `gcc -print-libgcc-file-name`
else
ptlsim: $(OBJFILES) Makefile ptlsim32.lds
	ld -g -O2 $(OBJFILES) -o ptlsim $(LIBPERFCTR) -static --allow-multiple-definition -T ptlsim32.lds -e ptlsim_preinit_entry `gcc -print-libgcc-file-name`
endif

BASEADDR = 0

test.dat-64bit.S: test.dat Makefile
	objdump --adjust-vma=$(BASEADDR) -rtd -b binary -m i386:x86-64:intel --disassemble-all test.dat > test.dat-64bit.S
	objdump --adjust-vma=$(BASEADDR) -rtd -b binary -m i386:x86-64 --disassemble-all test.dat > test.dat-64bit.alt.S

test.dat-32bit.S: test.dat Makefile
	objdump --adjust-vma=$(BASEADDR) -rtd -b binary -m i386:intel --disassemble-all test.dat > test.dat-32bit.S
	objdump --adjust-vma=$(BASEADDR) -rtd -b binary -m i386 --disassemble-all test.dat > test.dat-32bit.alt.S

%.o: %.cpp
	$(CC) $(CFLAGS) $(INCFLAGS) -c $<

%.o: %.S
	$(CC) $(CFLAGS) $(INCFLAGS) -c $<

%.o: %.c
	$(CC) $(CFLAGS) $(INCFLAGS) -c $<

clean:
	rm -fv ptlsim ptlstats cpuid *.o core core.[0-9]* .depend *.gch

OBJFILES = $(COMMONOBJS) $(PT2XOBJS) $(OOOOBJS)
INCLUDEFILES = $(COMMONINCLUDES) $(PT2XINCLUDES) $(OOOINCLUDES)
CPPFILES = $(COMMONCPPFILES) $(PT2XCPPFILES) $(OOOCPPFILES)

#
# Miscellaneous:
#

DISTFILES = $(CPPFILES) $(INCLUDEFILES) Makefile ptlsim.lds ptlsim32.lds COPYING README 

dist: $(DISTFILES)
	tar zcvf ptlsim-`date "+%Y%m%d%H%M%S"`.tar.gz $(DISTFILES)

backup: dist

distfiles: $(DISTFILES)
	@echo $(DISTFILES)

.depend:
	$(CC) $(CFLAGS) $(INCFLAGS) -MM $(CPPFILES) $(ASMFILES) > .depend

-include .depend

