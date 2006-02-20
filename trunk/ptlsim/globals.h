// -*- c++ -*-
//
// Copyright 1997-2005 Matt T. Yourst <yourst@yourst.com>
//
// This program is free software; it is licensed under the
// GNU General Public License, Version 2.
//

#ifndef _GLOBALS_H
#define _GLOBALS_H

//
// We include these first just to make sure abs/fabs/min/max
// get defined before we try to redefine them to our own
// inline functions, which gcc can optimize much better:
//

typedef unsigned long long W64;
typedef signed long long W64s;
typedef unsigned int W32;
typedef signed int W32s;
typedef unsigned short W16;
typedef signed short W16s;
typedef unsigned char byte;
typedef unsigned char W8;
typedef signed char W8s;
#define null NULL

#ifdef __x86_64__
typedef W64 Waddr;
#else
typedef W32 Waddr;
#endif

#ifdef __cplusplus

namespace math {
#include <math.h>
#include <float.h>
};

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/user.h>

#define nan NAN
#define inf INFINITY

template <typename T> struct limits { static const T min = 0; static const T max = 0; };
#define MakeLimits(T, __min, __max) template <> struct limits<T> { static const T min = (__min); static const T max = (__max); };
MakeLimits(W8, 0, 0xff);
MakeLimits(W16, 0, 0xffff);
MakeLimits(W32, 0, 0xffffffff);
MakeLimits(W64, 0, 0xffffffffffffffffULL);
MakeLimits(W8s, 0x80, 0x7f);
MakeLimits(W16s, 0x8000, 0x7fff);
MakeLimits(W32s, 0x80000000, 0x7fffffff);
MakeLimits(W64s, 0x8000000000000000LL, 0x7fffffffffffffffLL);
#ifdef __x86_64__
MakeLimits(signed long, 0x8000000000000000LL, 0x7fffffffffffffffLL);
MakeLimits(unsigned long, 0x0000000000000000LL, 0xffffffffffffffffLL);
#else
MakeLimits(signed long, 0x80000000, 0x7fffffff);
MakeLimits(unsigned long, 0, 0xffffffff);
#endif
#undef MakeLimits

// Typecasts in bizarre ways required for binary form access
union W32orFloat { W32 w; float f; };
union W64orDouble { W64 w; double d; };
static inline const float W32toFloat(W32 x) { union W32orFloat c; c.w = x; return c.f; }
static inline const W32 FloatToW32(float x) { union W32orFloat c; c.f = x; return c.w; }
static inline const double W64toDouble(W64 x) { union W64orDouble c; c.w = x; return c.d; }
static inline const W64 DoubleToW64(double x) { union W64orDouble c; c.d = x; return c.w; }

//
// Functional constructor
//

template <typename T> static inline T min(const T& a, const T& b) { typeof (a) _a = a; typeof (b) _b = b; return _a > _b ? _b : _a; }
template <typename T> static inline T max(const T& a, const T& b) { typeof (a) _a = a; typeof (b) _b = b; return _a > _b ? _a : _b; }
template <typename T> static inline T clipto(const T& v, const T& minv, const T& maxv) { return min(max(v, minv), maxv); }
template <typename T> static inline bool inrange(const T& v, const T& minv, const T& maxv) { typeof (v) _v = v; return ((_v >= minv) & (_v <= maxv)); }
template <typename T> static inline T abs(T x) { typeof (x) _x = x; return (_x < 0) ? -_x : _x; }

#define sqr(x) ((x)*(x))
#define cube(x) ((x)*(x)*(x))
#define bit(x, n) (((x) >> (n)) & 1)

#define bitmask(l) (((l) == 64) ? (W64)(-1LL) : ((1LL << (l))-1LL))
#define bits(x, i, l) (((x) >> (i)) & bitmask(l))
#define lowbits(x, l) bits(x, 0, l)
#define setbit(x,i) ((x) |= (1LL << (i)))
#define clearbit(x, i) ((x) &= (W64)(~(1LL << (i))))
#define assignbit(x, i, v) ((x) = (((x) &= (W64)(~(1LL << (i)))) | (((W64)((bool)(v))) << i)));

#define foreach(i, n) for (size_t i = 0; i < (n); i++)

static inline W64s signext64(W64s x, const int i) { return (x << (64-i)) >> (64-i); }
static inline W32s signext32(W32s x, const int i) { return (x << (32-i)) >> (32-i); }
static inline W16s signext16(W16s x, const int i) { return (x << (16-i)) >> (16-i); }

static inline W64s bitsext64(W64s x, const int i, const int l) { return signext64(bits(x, i, l), l); }
static inline W32s bitsext32(W32s x, const int i, const int l) { return signext32(bits(x, i, l), l); }
static inline W16s bitsext16(W16s x, const int i, const int l) { return signext16(bits(x, i, l), l); }

// e.g., head (a, b, c) => a
// e.g., if list = (a, b, c), head list => a
//#define head(h, ...) (h)
//#define tail(h, ...) __VA_ARGS__

#define TOLERANCE 0.00001

/*
 * Sometimes floating point numbers do strange things. Like the fact
 * that -0 and +0 are in fact not bit-for-bit equal even though the
 * math says they are. Similar issues come up when dealing with numbers
 * computed from infinities, etc. This function is to make sure we
 * really follow the math, not the IEEE FP standard's idea of "equal".
 */
static inline bool fcmpeqtol(float a, float b) {
  return (a == b) || (math::fabs(a-b) <= TOLERANCE);
}

/*
 * Make these math functions available even inside of member functions with the same name:
 */
static inline float fsqrt(float v) { return (float)math::sqrt(v); }
static inline void freemem(void* p) { free(p); }

#define setzero(x) memset(x, 0, sizeof(x))
#define HI32(x) (W32)((x) >> 32LL)
#define LO32(x) (W32)((x) & 0xffffffffLL)
#define CONCAT64(hi, lo) ((((W64)(hi)) << 32) + (((W64)(lo)) & 0xffffffffLL))

template <typename T, typename A> static inline T floor(T x, A a) { return (T)(((T)x) & ~((T)(a-1))); }
template <typename T, typename A> static inline T trunc(T x, A a) { return (T)(((T)x) & ~((T)(a-1))); }
template <typename T, typename A> static inline T ceil(T x, A a) { return (T)((((T)x) + ((T)(a-1))) & ~((T)(a-1))); }
template <typename T, typename A> static inline T mask(T x, A a) { return (T)(((T)x) & ((T)(a-1))); }

template <typename T, typename A> static inline T* floorptr(T* x, A a) { return (T*)floor((Waddr)x, a); }
template <typename T, typename A> static inline T* ceilptr(T* x, A a) { return (T*)ceil((Waddr)x, a); }
template <typename T, typename A> static inline T* maskptr(T* x, A a) { return (T*)mask((Waddr)x, a); }
inline W64 mux64(W64 sel, W64 v0, W64 v1) { return (sel & v1) | ((~sel) & v0); }

#define typeof __typeof__
#define ptralign(ptr, bytes) ((typeof(ptr))((unsigned long)(ptr) & ~((bytes)-1)))
#define ptrmask(ptr, bytes) ((typeof(ptr))((unsigned long)(ptr) & ((bytes)-1)))

template <typename T>
inline void arraycopy(T* dest, const T* source, int count) { memcpy(dest, source, count * sizeof(T)); }

static inline float randfloat() { return ((float)rand() / RAND_MAX); }

static inline bool aligned(W64 address, int size) {
  return ((address & (W64)(size-1)) == 0);
}

inline bool strequal(const char* a, const char* b) {
  return (strcmp(a, b) == 0);
}

template <class T>
class range {
public:
  T lo, hi;
public:
  range() {} 
  range(T lo, T hi) { this->lo = lo; this->hi = hi; }
  inline bool contains(T p) { return ((p >= lo) && (p <= hi)); }
  inline T size() { return abs(hi - lo); }
  inline bool operator& (T p) { return contains(p); }
  inline bool operator~ () { return size(); }
};

template <typename T, int size> int lengthof(T (&)[size]) { return size; }

extern const byte popcountlut8bit[];
extern const byte lsbindexlut8bit[];

static inline int popcount8bit(byte x) {
  return popcountlut8bit[x];
}

static inline int lsbindex8bit(byte x) {
  return lsbindexlut8bit[x];
}

static inline int popcount(W32 x) {
  return (popcount8bit(x >> 0) + popcount8bit(x >> 8) + popcount8bit(x >> 16) + popcount8bit(x >> 24));
}

static inline int popcount64(W64 x) {
  return popcount(LO32(x)) + popcount(HI32(x));
}

typedef byte v16qi __attribute__ ((vector_size(16)));
typedef v16qi vec16b;
typedef W16 v8hi __attribute__ ((vector_size(16)));
typedef v8hi vec8w;
typedef float v4sf __attribute__ ((vector_size(16)));
typedef v4sf vec4f;
typedef float v2df __attribute__ ((vector_size(16)));
typedef v2df vec2d;

inline vec16b x86_sse_pcmpeqb(vec16b a, vec16b b) { asm("pcmpeqb %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec16b x86_sse_psubusb(vec16b a, vec16b b) { asm("psubusb %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec16b x86_sse_paddusb(vec16b a, vec16b b) { asm("paddusb %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec16b x86_sse_pandb(vec16b a, vec16b b) { asm("pand %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec8w x86_sse_pcmpeqw(vec8w a, vec8w b) { asm("pcmpeqw %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec8w x86_sse_psubusw(vec8w a, vec8w b) { asm("psubusb %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec8w x86_sse_paddusw(vec8w a, vec8w b) { asm("paddsub %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec8w x86_sse_pandw(vec8w a, vec8w b) { asm("pand %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec16b x86_sse_packsswb(vec8w a, vec8w b) { asm("packsswb %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return (vec16b)a; }
inline W32 x86_sse_pmovmskb(vec16b vec) { W32 mask; asm("pmovmskb %[vec],%[mask]" : [mask] "=r" (mask) : [vec] "x" (vec)); return mask; }
inline W32 x86_sse_pmovmskw(vec8w vec) { return x86_sse_pmovmskb(x86_sse_packsswb(vec, vec)) & 0xff; }

inline vec16b x86_sse_ldvbu(const vec16b* m) { vec16b rd; asm("movdqu %[m],%[rd]" : [rd] "=x" (rd) : [m] "xm" (*m)); return rd; }
inline void x86_sse_stvbu(vec16b* m, const vec16b ra) { asm("movdqu %[ra],%[m]" : [m] "=xm" (*m) : [ra] "x" (ra) : "memory"); }
inline vec8w x86_sse_ldvwu(const vec8w* m) { vec8w rd; asm("movdqu %[m],%[rd]" : [rd] "=x" (rd) : [m] "xm" (*m)); return rd; }
inline void x86_sse_stvwu(vec8w* m, const vec8w ra) { asm("movdqu %[ra],%[m]" : [m] "=xm" (*m) : [ra] "x" (ra) : "memory"); }

// If lddqu is available (SSE3: Athlon 64 (some cores, like X2), Pentium 4 Prescott), use that instead. It may be faster. 

extern const byte byte_to_vec16b[256][16];

inline vec16b x86_sse_dupb(const byte b) {
  return *((vec16b*)&byte_to_vec16b[b]);
}

inline vec8w x86_sse_dupw(const W16 b) {
  W32 w = (b << 16) | b;
  vec8w v;
  W32* wp = (W32*)&v;
  wp[0] = w; wp[1] = w; wp[2] = w; wp[3] = w;
  return v;
}

inline void x86_ldmxcsr(W32 value) { asm volatile("ldmxcsr %[value]" : : [value] "m" (value)); }
inline W32 x86_stmxcsr() { W32 value; asm volatile("stmxcsr %[value]" : [value] "=m" (value)); return value; }

inline W32 x86_bsf32(W32 b) { W64 r = 0; asm("bsf %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }
inline W64 x86_bsf64(W64 b) { W64 r = 0; asm("bsf %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }
inline W32 x86_bsr32(W32 b) { W64 r = 0; asm("bsr %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }
inline W64 x86_bsr64(W64 b) { W64 r = 0; asm("bsr %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }
inline W64 x86_bts64(W64 r, W64 b) { asm("bts %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }
inline W64 x86_btr64(W64 r, W64 b) { asm("btr %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }
inline W64 x86_btc64(W64 r, W64 b) { asm("btc %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }
inline void prefetch(const void* x) { asm volatile("prefetcht0 (%0)" : : "r" (x)); }

inline void cpuid(int op, W32& eax, W32& ebx, W32& ecx, W32& edx) {
	asm("cpuid" : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "0" (op));
}

extern const W64 expand_8bit_to_64bit_lut[256];

// Only call this for functions guaranteed to never return!
#ifdef __x86_64__
inline volatile void align_rsp() { asm volatile("and $-16,%rsp"); }
#else
inline volatile void align_rsp() { asm volatile("and $-16,%esp"); }
#endif

// LSB index:

// Operand must be non-zero or result is undefined:
inline unsigned int lsbindex32(W32 n) { return x86_bsf32(n); }

inline int lsbindexi32(W32 n) {
  int r = lsbindex32(n);
  return (n ? r : -1);
}

#ifdef __x86_64__
inline unsigned int lsbindex64(W64 n) { return x86_bsf64(n); }
#else
inline unsigned int lsbindex64(W64 n) {
  unsigned int z;
  W32 lo = LO32(n);
  W32 hi = HI32(n);

  int ilo = lsbindex32(lo);
  int ihi = lsbindex32(hi) + 32;

  return (lo) ? ilo : ihi;
}
#endif

inline unsigned int lsbindexi64(W64 n) {
  int r = lsbindex64(n);
  return (n ? r : -1);
}

// static inline unsigned int lsbindex(W32 n) { return lsbindex32(n); }
inline unsigned int lsbindex(W64 n) { return lsbindex64(n); }

// MSB index:

// Operand must be non-zero or result is undefined:
inline unsigned int msbindex32(W32 n) { return x86_bsr32(n); }

inline int msbindexi32(W32 n) {
  int r = msbindex32(n);
  return (n ? r : -1);
}

#ifdef __x86_64__
inline unsigned int msbindex64(W64 n) { return x86_bsr64(n); }
#else
inline unsigned int msbindex64(W64 n) {
  unsigned int z;
  W32 lo = LO32(n);
  W32 hi = HI32(n);

  int ilo = msbindex32(lo);
  int ihi = msbindex32(hi) + 32;

  return (hi) ? ihi : ilo;
}
#endif

inline unsigned int msbindexi64(W64 n) {
  int r = msbindex64(n);
  return (n ? r : -1);
}

// static inline unsigned int msbindex(W32 n) { return msbindex32(n); }
inline unsigned int msbindex(W64 n) { return msbindex64(n); }

#define percent(x, total) (100.0 * ((float)(x)) / ((float)(total)))

inline int modulo_span(int lower, int upper, int modulus) {
  int result = (upper - lower);
  if (upper < lower) result += modulus;
  return result;
}

inline int add_index_modulo(int index, int increment, int bufsize) {
  // Only if power of 2: return (index + increment) & (bufsize-1);
  index += increment;
  if (index < 0) index += bufsize;
  if (index >= bufsize) index -= bufsize;
  return index;
}

/*
//
// (for making the lookup table used in modulo_ranges_intersect():
//
static bool makelut(int x) {
  //
  // There are only four cases where the spans DO NOT intersect:
  //
  // [a0 a1 b0 b1] ...Aaaaa........ no
  //               .........Bbbb...
  //
  // [b0 b1 a0 a1] .........Aaaa... no
  //               ...Bbbbb........
  //
  // [b1 a0 a1 b0] ...Aaaaa........ no
  //               bb.......Bbbbbbb
  //
  // [a1 b0 b1 a0] aa.......Aaaaaaa no
  //               ...Bbbbb........
  //
  // AND (a0 != b0) & (a0 != b1) & (a1 != b0) & (a1 != b1);
  //
  // All other cases intersect.
  //

  bool le_a0a1 = bit(x, 0);
  bool le_a1b0 = bit(x, 1);
  bool le_b0b1 = bit(x, 2);
  bool le_b1a0 = bit(x, 3);
  bool ne_a0b0 = bit(x, 4);
  bool ne_a0b1 = bit(x, 5);
  bool ne_a1b0 = bit(x, 6);
  bool ne_a1b1 = bit(x, 7);

  bool separate1 =
    (le_a0a1 & le_a1b0 & le_b0b1) |
    (le_b0b1 & le_b1a0 & le_a0a1) |
    (le_b1a0 & le_a0a1 & le_a1b0) |
    (le_a1b0 & le_b0b1 & le_b1a0);

  bool separate2 = ne_a0b0 & ne_a0b1 & ne_a1b0 & ne_a1b1;

  return !(separate1 & separate2);
}
*/

inline bool modulo_ranges_intersect(int a0, int a1, int b0, int b1, int size) {

  int idx = 
    ((a0 <= a1) << 0) |
    ((a1 <= b0) << 1) |
    ((b0 <= b1) << 2) |
    ((b1 <= a0) << 3) |
    ((a0 != b0) << 4) |
    ((a0 != b1) << 5) |
    ((a1 != b0) << 6) | 
    ((a1 != b1) << 7);

  static const byte lut[256] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0
  };

  return lut[idx];
}

template <int n> struct lg { static const int value = 1 + lg<n/2>::value; };
template <> struct lg<1> { static const int value = 0; };
#define log2(v) (lg<(v)>::value)

template <int n> struct lg10 { static const int value = 1 + lg10<n/10>::value; };
template <> struct lg10<1> { static const int value = 0; };
template <> struct lg10<0> { static const int value = 0; };
#define log10(v) (lg10<(v)>::value)

#define __stringify_1(x) #x
#define stringify(x) __stringify_1(x)

#define alignto(x) __attribute__ ((aligned (x)))
#define insection(x) __attribute__ ((section (x)))

#include <superstl.h>

using namespace superstl;

template <class scalar>
inline ostream& operator <<(ostream& os, const range<scalar>& r) {
  os << '[' << r.lo << ' ' << r.hi << ']';
  return os;
}

ostream& operator <<(ostream& os, const vec16b& v);
ostream& operator ,(ostream& os, const vec16b& v);
ostream& operator <<(ostream& os, const vec8w& v);
ostream& operator ,(ostream& os, const vec8w& v);

#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x) (x) 

#endif // __cplusplus

#endif // _GLOBALS_H
