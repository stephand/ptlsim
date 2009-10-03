#ifndef __TYPES_H__
#define __TYPES_H__

#ifndef __X86_TYPES_H__
#define __X86_TYPES_H__

#ifndef __ASSEMBLY__

//#include <xen/config.h>

typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;

#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
#if defined(__i386__)
typedef __signed__ long long __s64;
typedef unsigned long long __u64;
#elif defined(__x86_64__)
typedef __signed__ long __s64;
typedef unsigned long __u64;
#endif
#endif

typedef signed char s8;
typedef unsigned char u8;

typedef signed short s16;
typedef unsigned short u16;

typedef signed int s32;
typedef unsigned int u32;

#if defined(__i386__)
typedef signed long long s64;
typedef unsigned long long u64;
typedef unsigned long paddr_t;
#define PRIpaddr "08lx"
#elif defined(__x86_64__)
typedef signed long s64;
typedef unsigned long u64;
typedef unsigned long paddr_t;
#define PRIpaddr "016lx"
#endif

typedef unsigned long size_t;

typedef unsigned long xen_pfn_t;

#endif /* __ASSEMBLY__ */

#if defined(__i386__)
#define BITS_PER_LONG 32
#define BYTES_PER_LONG 4
#define LONG_BYTEORDER 2
#elif defined(__x86_64__)
#define BITS_PER_LONG 64
#define BYTES_PER_LONG 8
#define LONG_BYTEORDER 3
#endif

#endif /* __X86_TYPES_H__ */


//#include <xen/config.h>
//#include <asm/types.h>

#define BITS_TO_LONGS(bits) \
    (((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#define DECLARE_BITMAP(name,bits) \
    unsigned long name[BITS_TO_LONGS(bits)]

#ifndef NULL
#define NULL ((void*)0)
#endif

#ifndef INT_MAX
#define INT_MAX         ((int)(~0U>>1))
#endif

#ifndef INT_MIN
#define INT_MIN         (-INT_MAX - 1)
#endif

#ifndef UINT_MAX
#define UINT_MAX        (~0U)
#endif

#ifndef LONG_MAX
#define LONG_MAX        ((long)(~0UL>>1))
#endif

#ifndef LONG_MIN
#define LONG_MIN        (-LONG_MAX - 1)
#endif

#ifndef ULONG_MAX
#define ULONG_MAX       (~0UL)
#endif

/* bsd */
typedef unsigned char           u_char;
typedef unsigned short          u_short;
typedef unsigned int            u_int;
typedef unsigned long           u_long;

/* sysv */
typedef unsigned char           unchar;
typedef unsigned short          ushort;
typedef unsigned int            uint;
typedef unsigned long           ulong;

typedef         __u8            uint8_t;
typedef         __u8            u_int8_t;
typedef         __s8            int8_t;

typedef         __u16           uint16_t;
typedef         __u16           u_int16_t;
typedef         __s16           int16_t;

typedef         __u32           uint32_t;
typedef         __u32           u_int32_t;
typedef         __s32           int32_t;

typedef         __u64           uint64_t;
typedef         __u64           u_int64_t;
typedef         __s64           int64_t;

struct domain;
struct vcpu;

// Make sure we don't also include conflicting kernel type names
#define _LINUX_TYPES_H

#endif /* __TYPES_H__ */
