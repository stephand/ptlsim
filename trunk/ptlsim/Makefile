#
# PTLsim: Cycle Accurate x86-64 Simulator
# Makefile
#
# Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
#


CC = g++

CFLAGS = -O99 -g -fomit-frame-pointer -pipe -march=k8 -falign-functions=16 -fno-trapping-math -fno-exceptions -fno-rtti -m64 -fomit-frame-pointer -funroll-loops -funit-at-a-time -mpreferred-stack-boundary=4 -fno-strict-aliasing -Wreturn-type
#CFLAGS = -O0 -g3 -pipe -march=k8 -falign-functions=16 -fno-trapping-math -fno-strict-aliasing -fno-exceptions -fno-rtti -mpreferred-stack-boundary=4 -Wreturn-type

INCFLAGS = -I. -DBUILDHOST="`hostname -f`"

COMMONOBJS = ptlsim.o kernel.o superstl.o ptlhwdef.o translate-x86.o uopimpl.o lowlevel-64bit.o lowlevel-32bit.o uopinterface.o dcache.o config.o datastore.o injectcode-32bit.o injectcode-64bit.o
OOOOBJS = ooocore.o branchpred.o
OBJFILES = $(COMMONOBJS) $(OOOOBJS)

COMMONINCLUDES = logic.h dcacheint.h ptlhwdef.h dcache.h config.h ptlsim.h datastore.h superstl.h globals.h kernel.h ptlcalls.h uopimpl.h loader.h
OOOINCLUDES = branchpred.h ooohwdef.h
INCLUDEFILES = $(COMMONINCLUDES) $(OOOINCLUDES)

COMMONCPPFILES = ptlsim.cpp kernel.cpp superstl.cpp ptlhwdef.cpp translate-x86.cpp uopimpl.S lowlevel-64bit.S lowlevel-32bit.S uopinterface.cpp dcache.cpp config.cpp datastore.cpp injectcode.cpp ptlcalls.c genoffsets.cpp cpuid.cpp ptlstats.cpp
OOOCPPFILES = ooocore.cpp branchpred.cpp
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

all: ptlsim ptlstats ptlcalls.o cpuid
	@echo "Compiled successfully..."

genoffsets: genoffsets.o superstl.o
	g++ -g -O2 genoffsets.o superstl.o -o genoffsets


cpuid: cpuid.o
	g++ -O2 cpuid.o superstl.o -o cpuid

simsynth-offsets.h: genoffsets
	./genoffsets > simsynth-offsets.h

# Compile this fast:
ptlstats.o: ptlstats.cpp globals.h superstl.h ptlhwdef.h ptlsim.h config.h
	gcc $(CFLAGS) -I. -O1 -g -fomit-frame-pointer -march=k8 -fno-exceptions -fno-rtti -m64 -c ptlstats.cpp

injectcode-64bit.o: injectcode.cpp
	g++ $(CFLAGS) $(INCFLAGS) -m64 -O99 -fomit-frame-pointer -c injectcode.cpp -o injectcode-64bit.o

injectcode-32bit.o: injectcode.cpp
	g++ $(CFLAGS) $(INCFLAGS) -m32 -O99 -fomit-frame-pointer -c injectcode.cpp -o injectcode-32bit.o

lowlevel-32bit.o: lowlevel-32bit.S
	gcc -c -m32 -O3 lowlevel-32bit.S

ptlcalls-32bit.o: ptlcalls.c
	gcc $(CFLAGS) $(INCFLAGS) -m32 -O99 -fomit-frame-pointer -c ptlcalls.c -o ptlcalls-32bit.o

ptlsim: $(OBJFILES) Makefile ptlsim.lds
	g++ -g -O2 $(OBJFILES) -o ptlsim $(LIBPERFCTR) -static -Wl,--allow-multiple-definition -Wl,-T,ptlsim.lds -Wl,-e,ptlsim_preinit_entry

ptlsim.objdump: ptlsim Makefile
	objdump -Crtd --no-show-raw-insn ptlsim | convert-disasm-x86 > ptlsim.objdump

ptlstats: ptlstats.o ptlhwdef.o superstl.o datastore.o config.o Makefile
	g++ -g -O2 ptlstats.o ptlhwdef.o superstl.o datastore.o config.o -o ptlstats

BASEADDR = 0

test.dat-64bit.S: test.dat Makefile
	objdump --adjust-vma=$(BASEADDR) -rtd -b binary -m i386:x86-64:intel --disassemble-all test.dat > test.dat-64bit.S
	objdump --adjust-vma=$(BASEADDR) -rtd -b binary -m i386:x86-64 --disassemble-all test.dat > test.dat-64bit.alt.S

test.dat-32bit.S: test.dat Makefile
	objdump --adjust-vma=$(BASEADDR) -rtd -b binary -m i386:intel --disassemble-all test.dat > test.dat-32bit.S
	objdump --adjust-vma=$(BASEADDR) -rtd -b binary -m i386 --disassemble-all test.dat > test.dat-32bit.alt.S

.cpp.o:
	$(CC) $(CFLAGS) $(INCFLAGS) -c $*.cpp

.S.o:
	$(CC) $(CFLAGS) $(INCFLAGS) -c $*.S

.c.o:
	gcc $(CFLAGS) $(INCFLAGS) -c $*.c

clean:
	rm -fv ptlsim ptlstats cpuid genoffsets *.o simsynth-offsets.h core core.[0-9]* .depend *.gch

OBJFILES = $(COMMONOBJS) $(PT2XOBJS) $(OOOOBJS)
INCLUDEFILES = $(COMMONINCLUDES) $(PT2XINCLUDES) $(OOOINCLUDES)
CPPFILES = $(COMMONCPPFILES) $(PT2XCPPFILES) $(OOOCPPFILES)

simsynth.out.S: simsynth.out
	objdump -rtd -b binary -m i386:x86-64:intel --disassemble-all simsynth.out > simsynth.out.S

#
# Miscellaneous:
#


dist: $(DISTFILES)
	tar zcvf ptlsim-`date "+%Y%m%d%H%M%S"`.tar.gz $(DISTFILES)

backup: dist

distfiles: $(DISTFILES)
	@echo $(DISTFILES)


.depend:
	touch simsynth-offsets.h
	$(CC) $(CFLAGS) $(INCFLAGS) -MM $(CPPFILES) $(ASMFILES) > .depend

-include .depend

