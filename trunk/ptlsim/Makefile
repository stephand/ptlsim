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

#
# Build PTLsim/Xen full system simulator:
#
# Make sure you have Xen installed and have applied
# xen-3.0-ptlsim.diff before doing this!
#
# (Presently this is an experimental x86-64 only feature!)
#
PTLSIM_HYPERVISOR=1

CC = g++

# GCCVER_SPECIFIC = -fno-threadsafe-statics # eliminate __cxa_guard_acquire and __cxa_guard_release
GCCVER_SPECIFIC =

SVNREV=`svn info | grep "Last Changed Rev" | cut -d " " -f4`
SVNDATE=`svn info | grep "Last Changed Date" | cut -d " " -f4`
INCFLAGS = -I. -DBUILDHOST="`hostname -f`" -DSVNREV="$(SVNREV)" -DSVNDATE="$(SVNDATE)"

ifdef PTLSIM_HYPERVISOR
INCFLAGS += -DPTLSIM_HYPERVISOR -D__XEN__
endif

ifdef __x86_64__
CFLAGS = -O99 -g -fomit-frame-pointer -march=k8 -falign-functions=16 -minline-all-stringops
#CFLAGS = -O1 -g3 -march=k8 -falign-functions=16 $
CFLAGS32BIT = $(CFLAGS) -m32
else
# 32-bit PTLsim32 only, on a Pentium 4:
CFLAGS = -O99 -g -fomit-frame-pointer -march=pentium4 -falign-functions=16
# No optimizations:
#CFLAGS = -O1 -g3 -march=pentium4 -mtune=k8 -falign-functions=16
CFLAGS32BIT = $(CFLAGS) 
endif

ifdef PTLSIM_HYPERVISOR
CFLAGS += -fpic -mno-red-zone
endif

CFLAGS += -fno-trapping-math -fno-exceptions -fno-rtti -funroll-loops -mpreferred-stack-boundary=4 -fno-strict-aliasing -Wreturn-type $(GCCVER_SPECIFIC)

BASEOBJS = superstl.o config.o mathlib.o syscalls.o
STDOBJS = glibc.o

ifdef __x86_64__
# IMPORTANT: linkstart.o and linkend.o must be at opposite ends of the list to set up constructor tables properly:
ifdef PTLSIM_HYPERVISOR
COMMONOBJS = linkstart.o lowlevel-64bit-xen.o ptlxen.o ptlxen-common.o mm.o superstl.o config.o mathlib.o klibc.o ptlhwdef.o datastore.o decode-core.o decode-fast.o decode-complex.o decode-x87.o decode-sse.o uopimpl.o seqcore.o ptlsim.dst.o ooocore.o ooopipe.o oooexec.o branchpred.o dcache.o linkend.o
else
COMMONOBJS = linkstart.o lowlevel-64bit.o lowlevel-32bit.o ptlsim.o kernel.o mm.o ptlhwdef.o decode-core.o decode-fast.o decode-complex.o decode-x87.o decode-sse.o uopimpl.o dcache.o datastore.o injectcode-32bit.o injectcode-64bit.o $(BASEOBJS) klibc.o ptlsim.dst.o linkend.o
endif
else
# 32-bit PTLsim32 only:
COMMONOBJS = linkstart.o lowlevel-32bit.o ptlsim.o kernel.o mm.o ptlhwdef.o decode-core.o decode-fast.o decode-complex.o decode-x87.o decode-sse.o uopimpl.o dcache.o datastore.o injectcode-32bit.o $(BASEOBJS) klibc.o ptlsim.dst.o linkend.o
endif

OOOOBJS = ooocore.o seqcore.o branchpred.o
OBJFILES = $(COMMONOBJS) $(OOOOBJS)

COMMONINCLUDES = logic.h dcacheint.h ptlhwdef.h decode.h dcache.h config.h ptlsim.h datastore.h superstl.h globals.h kernel.h mm.h ptlcalls.h loader.h mathlib.h klibc.h syscalls.h ptlxen.h stats.h xen-types.h xc_ptlsim.h
OOOINCLUDES = branchpred.h ooocore.h cpthwdef.h
INCLUDEFILES = $(COMMONINCLUDES) $(OOOINCLUDES)

COMMONCPPFILES = ptlsim.cpp kernel.cpp mm.cpp superstl.cpp ptlhwdef.cpp decode-core.cpp decode-fast.cpp decode-complex.cpp decode-x87.cpp decode-sse.cpp lowlevel-64bit.S lowlevel-32bit.S linkstart.S linkend.S uopimpl.cpp dcache.cpp config.cpp datastore.cpp injectcode.cpp ptlcalls.c cpuid.cpp ptlstats.cpp klibc.cpp glibc.cpp mathlib.cpp syscalls.cpp

ifdef PTLSIM_HYPERVISOR
COMMONCPPFILES += lowlevel-64bit-xen.S ptlxen.cpp ptlxen-common.cpp ptlmon.cpp
endif
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
	$(CC) $(CFLAGS) $(INCFLAGS) -m32 -O99 -fomit-frame-pointer -Wa,--32  -c injectcode.cpp -o injectcode-32bit.o
else
injectcode-32bit.o: injectcode.cpp
	$(CC) $(CFLAGS) $(INCFLAGS) -DPTLSIM_FORCE_32BIT_ONLY -O99 -fomit-frame-pointer -c injectcode.cpp -o injectcode-32bit.o
endif

lowlevel-32bit.o: lowlevel-32bit.S
ifdef __x86_64__
	$(CC) -c $(CFLAGS32BIT) $(INCFLAGS) -g -O3 -Wa,--32 lowlevel-32bit.S
else
	$(CC) -c $(CFLAGS32BIT) $(INCFLAGS) -g -O3 lowlevel-32bit.S
endif

ptlcalls-32bit.o: ptlcalls.c
ifdef __x86_64__
	$(CC) -c $(CFLAGS) $(INCFLAGS) $(CFLAGS32BIT) -O99 -fomit-frame-pointer -Wa,--32 ptlcalls.c -o ptlcalls-32bit.o
else
	$(CC) -c $(CFLAGS) $(INCFLAGS) $(CFLAGS32BIT) -O99 -fomit-frame-pointer ptlcalls.c -o ptlcalls-32bit.o
endif

ptlsim.dst: dstbuild stats.h $(BASEOBJS) $(STDOBJS) datastore.o ptlhwdef.o
	cpp $(CFLAGS) $(INCFLAGS) -C stats.h > stats.i
	cat stats.i | dstbuild PTLsimStats > dstbuild.temp.cpp
	g++ $(CFLAGS) $(INCFLAGS) -DDSTBUILD -include stats.h dstbuild.temp.cpp $(BASEOBJS) $(STDOBJS) datastore.o ptlhwdef.o -o dstbuild.temp
	dstbuild.temp > ptlsim.dst
	rm -f dstbuild.temp destbuild.temp.cpp stats.i

ptlsim.dst.o: ptlsim.dst
	objcopy -I binary -O elf64-x86-64 -B i386 --rename-section .data=.dst,alloc,load,readonly,data,contents ptlsim.dst ptlsim.dst.o

ifdef PTLSIM_HYPERVISOR
ifdef __x86_64__
ptlxen.bin: $(COMMONOBJS) Makefile ptlxen.lds
	ld -v -g -O2 $(COMMONOBJS) -o ptlxen.bin -static --allow-multiple-definition -T ptlxen.lds `gcc -print-libgcc-file-name`

ptlxen.bin.o: ptlxen.bin Makefile
	objcopy -I binary -O elf64-x86-64 -B i386 --rename-section .data=.ptlxen,alloc,load,readonly,data,contents ptlxen.bin ptlxen.bin.o
endif
endif

ifdef __x86_64__
ifdef PTLSIM_HYPERVISOR
ptlsim: ptlmon.o ptlxen.bin.o $(BASEOBJS) $(STDOBJS) ptlxen-common.o ptlhwdef.o ptlmon.lds Makefile
	g++ $(CFLAGS) ptlmon.o ptlxen.bin.o $(BASEOBJS) $(STDOBJS) ptlxen-common.o ptlhwdef.o -lxenctrl -Wl,-T,ptlmon.lds -static -o ptlsim
else
ptlsim: $(OBJFILES) Makefile ptlsim.lds
	ld -g -O2 $(OBJFILES) -o ptlsim $(LIBPERFCTR) -static --allow-multiple-definition -T ptlsim.lds -e ptlsim_preinit_entry `gcc -print-libgcc-file-name`
endif # PTLSIM_HYPERVISOR
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
	rm -fv ptlsim ptlstats ptlxen.bin cpuid *.o core core.[0-9]* .depend *.gch

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

