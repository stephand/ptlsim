SOURCES = c-parse.c c-lang.c c-lex.c c-pragma.c c-decl.c \
          c-typeck.c c-convert.c c-aux-info.c c-common.c \
          c-iterate.c toplev.c version.c tree.c print-tree.c \
          stor-layout.c fold-const.c function.c stmt.c expr.c \
          calls.c expmed.c explow.c optabs.c varasm.c rtl.c \
          print-rtl.c rtlanal.c emit-rtl.c real.c dbxout.c \
          sdbout.c dwarfout.c xcoffout.c integrate.c jump.c cse.c \
          loop.c unroll.c flow.c stupid.c combine.c regclass.c \
          local-alloc.c global.c reload.c reload1.c caller-save.c \
          insn-peep.c reorg.c sched.c final.c recog.c reg-stack.c \
          insn-opinit.c insn-recog.c insn-extract.c insn-output.c \
          insn-emit.c insn-attrtab.c m88k.c getpwd.c convert.c \
          bc-emit.c bc-optab.c obstack.c

CSOURCES = c-parse.c c-lang.c c-lex.c c-pragma.c c-decl.c \
          c-typeck.c c-convert.c c-aux-info.c c-common.c \
          c-iterate.c toplev.c version.c tree.c print-tree.c \
          stor-layout.c fold-const.c function.c stmt.c expr.c \
          calls.c expmed.c explow.c optabs.c varasm.c rtl.c \
          print-rtl.c rtlanal.c emit-rtl.c real.c dbxout.c \
          sdbout.c dwarfout.c xcoffout.c integrate.c jump.c cse.c \
          loop.c unroll.c flow.c stupid.c combine.c regclass.c \
          local-alloc.c global.c reload.c reload1.c caller-save.c \
          insn-peep.c reorg.c sched.c final.c recog.c reg-stack.c \
          insn-opinit.c insn-recog.c insn-extract.c insn-output.c \
          insn-emit.c insn-attrtab.c m88k.c getpwd.c convert.c \
          bc-emit.c bc-optab.c obstack.c

OUTPUT = gcc

COMMAND = ./gcc -quiet integrate.reduced.i -o integrate.S

-include ../Makefile.config

# NOTE: gcc-2.7.2 or whatever SPEC uses may be too old for modern optimization options...
#CFLAGS = -DBENCHMARK -DSPEC_CPU2000 -O2 -march=k8 -m64 -fno-trapping-math -mfpmath=sse -include ../../simtrigger.h
