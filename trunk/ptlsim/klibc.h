// -*- c++ -*-
//
// Standalone base libc functions suitable for in-kernel use
//
// Copyright 1997-2008 Matt T. Yourst <yourst@yourst.com>
//
// This program is free software; it is licensed under the
// GNU General Public License, Version 2.
//

#ifndef _BASELIBC_H
#define _BASELIBC_H

#include <syscalls.h>

//
// Division functions
//
#ifdef __x86_64__

#define do_div(n,base) ({					\
	W32 __base = (base);				\
	W32 __rem;						\
	__rem = ((W64)(n)) % __base;			\
	(n) = ((W64)(n)) / __base;				\
	__rem;							\
 })

#else

// 32-bit x86
#define do_div(n,base) ({ \
	W32 __upper, __low, __high, __mod, __base; \
	__base = (base); \
	asm("":"=a" (__low), "=d" (__high):"A" (n)); \
	__upper = __high; \
	if (__high) { \
		__upper = __high % (__base); \
		__high = __high / (__base); \
	} \
	asm("divl %2":"=a" (__low), "=d" (__mod):"rm" (__base), "0" (__low), "1" (__upper)); \
	asm("":"=A" (n):"a" (__low),"d" (__high)); \
	__mod; \
})

#endif

char* format_number(char* buf, char* end, W64 num, int base, int size, int precision, int type);
int format_integer(char* buf, int bufsize, W64s v, int size = 0, int flags = 0, int base = 10, int precision = 0);
int format_float(char* buf, int bufsize, double v, int precision = 6, int pad = 0);

//
// Fundamental system calls
//

void call_global_constuctors();

#endif // _BASELIBC_H
