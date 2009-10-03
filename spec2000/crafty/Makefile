SOURCES = searchr.c search.c repeat.c next.c nextr.c history.c \
          nexte.c quiesce.c evaluate.c movgen.c make.c unmake.c \
          lookup.c store.c attacks.c swap.c boolean.c draw.c \
          utility.c valid.c drawn.c edit.c enprise.c init.c \
          input.c interupt.c iterate.c main.c option.c output.c \
          phase.c ponder.c preeval.c root.c setboard.c time.c validate.c

OUTPUT = crafty
TEMPFILES = crafty.out
COMMAND = crafty < crafty.in > crafty.out

-include ../Makefile.config

ifdef __x86_64__
CFLAGS += -DLINUX_X86_64
else
CFLAGS += -DLINUX_i386
endif
