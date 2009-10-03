SOURCES = agcollec.c aggroup.c blister.c coding.c costab.c cyclotom.c    \
          eval.c finfield.c function.c gap.c gasman.c idents.c integer.c \
          list.c pcpresen.c permutat.c plist.c polynom.c range.c         \
          rational.c read.c record.c scanner.c set.c statemen.c string.c \
          system.c tietze.c unknown.c vecffe.c vector.c word.c

OUTPUT = gap
COMMAND = gap -q -m 192M -l data < data/test.in

-include ../Makefile.config

CFLAGS += -DSYS_IS_USG -DSYS_HAS_IOCTL_PROTO -DSYS_HAS_TIME_PROTO -DSYS_HAS_CALLOC_PROTO -DSYS_HAS_READ_PROTO -DSYS_HAS_WRITE_PROTO

ifdef __x86_64__
CFLAGS += -D__int64=long -DSPEC_CPU2000_LP64
endif

