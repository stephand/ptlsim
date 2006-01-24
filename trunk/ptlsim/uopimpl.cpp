//
// PTLsim: Cycle Accurate x86-64 Simulator
// Interface to uop implementations
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <ptlsim.h>

#ifndef __x86_64__
#define EMULATE_64BIT
#endif

#ifdef __x86_64__
typedef W64 Wmax;
#else
typedef W32 Wmax;
#endif

void uop_impl_bogus(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) { asm("int3"); }

inline W64 x86_rotr64(W64 r, int n) { asm("ror %%cl,%[r]" : [r] "+r" (r) : [n] "c" (n)); return r; }
inline W64 x86_rotl64(W64 r, int n) { asm("rol %%cl,%[r]" : [r] "+r" (r) : [n] "c" (n)); return r; }

//
// Flags generation (all but CF and OF)
//
template <typename T>
inline byte x86_genflags(T r) {
  byte sf, zf, pf;
  asm("test %[r],%[r]\n"
      "sets %[sf]\n"
      "setz %[zf]\n"
      "setp %[pf]\n"
      : [sf] "=q" (sf), [zf] "=q" (zf), [pf] "=q" (pf)
      : [r] "q" (r));

  return (sf << 7) + (zf << 6) + (pf << 2);
}

template <typename T>
inline byte x86_genflags_separate(T sr, T zr, T pr) {
  byte sf, zf, pf;
  asm("test %[sr],%[sr]\n"
      "sets %[sf]\n"
      "test %[zr],%[zr]\n"
      "setz %[zf]\n"
      "test %[pr],%[pr]\n"
      "setp %[pf]\n"
      "shl  $7,%[sf]\n"
      "shl  $6,%[zf]\n"
      "shl  $2,%[pf]\n"
      : [sf] "=q" (sf), [zf] "=q" (zf), [pf] "=q" (pf)
      : [sr] "q" (sr), [zr] "q" (zr), [pr] "q" (pr));

  return (sf|zf|pf);
}

template byte x86_genflags<byte>(byte r);
template byte x86_genflags<W16>(W16 r);
template byte x86_genflags<W32>(W32 r);

#ifdef __x86_64__
template byte x86_genflags<W64>(W64 r);
#else
template <>
byte x86_genflags<W64>(W64 r) {

  W32 l = LO32(r);
  W32 h = HI32(r);
  return x86_genflags_separate(h, l|h, l^h);
}
#endif

//
// Flags format: OF - - - SF ZF - AF - PF - CF
//               11       7  6    4    2    0
//               rb       ra ra   ra   ra   rb
//

template <typename T>
inline W64 x86_merge(W64 rd, W64 ra) {
  union {
    W8 w8;
    W16 w16;
    W32 w32;
    W64 w64;
  } sizes;

  switch (sizeof(T)) {
  case 1: sizes.w64 = rd; sizes.w8 = ra; return sizes.w64;
  case 2: sizes.w64 = rd; sizes.w16 = ra; return sizes.w64;
  case 4: return LO32(ra);
  case 8: return ra;
  }

  return rd;
}

typedef void (*uopimpl_func_t)(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags);

#define ZAPS SETFLAG_ZF
#define CF SETFLAG_CF
#define OF SETFLAG_OF

#define make_exp_aluop(name, expr) \
template <typename T, int genflags> \
struct name { \
  T operator ()(T ra, T rb, T rc, W16 raflags, W16 rbflags, W16 rcflags, byte& cf, byte& of) { \
    cf = 0; of = 0; W64 rd; expr; return rd; \
  } \
}

#define make_x86_aluop2(name, opcode, pretext) \
template <typename T, int genflags> \
struct name { \
  T operator ()(T ra, T rb, T rc, W16 raflags, W16 rbflags, W16 rcflags, byte& cf, byte& of) { \
    if (genflags & (SETFLAG_CF|SETFLAG_OF)) \
      asm(pretext #opcode " %[rb],%[ra]; setc %[cf]; seto %[of]" : [ra] "+r" (ra), [cf] "=q" (cf), [of] "=q" (of) : [rb] "rm" (rb), [rcflags] "rm" (rcflags)); \
    else asm(#opcode " %[rb],%[ra]" : [ra] "+r" (ra) : [rb] "rm" (rb) : "flags"); \
    return ra; \
  } \
}

void uop_impl_nop(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  state.reg.rddata = 0;
  state.reg.rdflags = 0;
}

//
// 2-operand ALU operation
//
template <template<typename, int> class func, typename T, int genflags>
inline void aluop(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  byte cf = 0, of = 0;
  func<T, genflags> f;
  T rt = f(ra, rb, rc, raflags, rbflags, rcflags, cf, of);
  state.reg.rddata = x86_merge<T>(ra, rt);
  state.reg.rdflags = (of << 11) | cf | ((genflags & SETFLAG_ZF) ? x86_genflags<T>(rt) : 0);
}

#define make_anyop_all_sizes(mapname, opclass, nativeop, flagset) \
uopimpl_func_t mapname[4][2] = { \
  {&opclass<nativeop, W8,  0>, &opclass<nativeop, W8,  (flagset)>}, \
  {&opclass<nativeop, W16, 0>, &opclass<nativeop, W16, (flagset)>}, \
  {&opclass<nativeop, W32, 0>, &opclass<nativeop, W32, (flagset)>}, \
  {&opclass<nativeop, W64, 0>, &opclass<nativeop, W64, (flagset)>} \
}

#define make_aluop_all_sizes(mapname, nativeop, flagset) make_anyop_all_sizes(mapname, aluop, nativeop, flagset);

#define make_exp_aluop_all_sizes(name, exp, setflags) \
  make_exp_aluop(exp_op_ ## name, (exp)); \
  make_aluop_all_sizes(implmap_ ## name, exp_op_ ## name, (setflags));

#define make_x86_aluop_all_sizes(name, opcode, setflags, pretext) \
  make_x86_aluop2(x86_op_ ## name, opcode, pretext); \
  make_aluop_all_sizes(implmap_ ## name, x86_op_ ## name, (setflags));

#define PRETEXT_NO_FLAGS_IN ""
#define PRETEXT_ALL_FLAGS_IN "pushw %[rcflags]; popfw;"

make_x86_aluop_all_sizes(add, add, ZAPS|CF|OF, PRETEXT_NO_FLAGS_IN);
make_x86_aluop_all_sizes(sub, sub, ZAPS|CF|OF, PRETEXT_NO_FLAGS_IN);

make_exp_aluop_all_sizes(mov, (rd = (rb)), 0);
make_exp_aluop_all_sizes(and, (rd = (ra & rb)), ZAPS);
make_exp_aluop_all_sizes(or, (rd = (ra | rb)), ZAPS);
make_exp_aluop_all_sizes(xor, (rd = (ra ^ rb)), ZAPS);
make_exp_aluop_all_sizes(andnot, (rd = ((~ra) & rb)), ZAPS);
make_exp_aluop_all_sizes(ornot, (rd = ((~ra) | rb)), ZAPS);
make_exp_aluop_all_sizes(nand, (rd = (~(ra & rb))), ZAPS);
make_exp_aluop_all_sizes(nor, (rd = (~(ra | rb))), ZAPS);
make_exp_aluop_all_sizes(eqv, (rd = (~(ra ^ rb))), ZAPS);
make_exp_aluop_all_sizes(addm, (rd = ((ra + rb) & rc)), ZAPS);
make_exp_aluop_all_sizes(subm, (rd = ((ra - rb) & rc)), ZAPS);

make_exp_aluop_all_sizes(bt, (rb = lowbits(rb, log2(sizeof(T)*8)), cf = bit(ra, rb), rd = (cf) ? -1 : +1), CF);
make_exp_aluop_all_sizes(bts, (rb = lowbits(rb, log2(sizeof(T)*8)), cf = bit(ra, rb), rd = ra | (1LL << rb)), CF);
make_exp_aluop_all_sizes(btr, (rb = lowbits(rb, log2(sizeof(T)*8)), cf = bit(ra, rb), rd = ra & ~(1LL << rb)), CF);
make_exp_aluop_all_sizes(btc, (rb = lowbits(rb, log2(sizeof(T)*8)), cf = bit(ra, rb), rd = ra ^ (1LL << rb)), CF);

template <typename T> inline W64 x86_bswap(T v) { asm("bswap %[v]" : [v] "+r" (v)); return v; }

make_exp_aluop_all_sizes(bswap, (rd = ((sizeof(T) >= 4) ? x86_bswap(rb) : 0)), 0);

template <template<typename, int> class func, typename T, int genflags>
inline void ctzclzop(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  byte cf = 0, of = 0;
  func<T, genflags> f;
  T rt = f(ra, rb, rc, raflags, rbflags, rcflags, cf, of);
  state.reg.rddata = x86_merge<T>(ra, rt);
  state.reg.rdflags = (((T)rb) == 0) ? FLAG_ZF : 0;
}

make_exp_aluop(exp_op_ctz, (rd = (rb) ? lsbindex64(rb) : 0));
make_anyop_all_sizes(implmap_ctz, ctzclzop, exp_op_ctz, ZAPS);

make_exp_aluop(exp_op_clz, (rd = (rb) ? msbindex64(rb) : 0));
make_anyop_all_sizes(implmap_clz, ctzclzop, exp_op_clz, ZAPS);

void uop_impl_collcc(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  int flags = (raflags & FLAG_ZAPS) | (rbflags & FLAG_CF) | (rcflags & FLAG_OF);
  state.reg.rddata = flags;
  state.reg.rdflags = flags;
}

void uop_impl_movrcc(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  int flags = ra & FLAG_NOT_WAIT_INV;
  state.reg.rddata = flags;
  state.reg.rdflags = flags;
}

void uop_impl_movccr(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  int flags = raflags;
  state.reg.rddata = flags;
  state.reg.rdflags = flags;
}

void uop_impl_andcc(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  state.reg.rddata = 0;
  state.reg.rdflags = (raflags & rbflags) & FLAG_NOT_WAIT_INV;
}

void uop_impl_orcc(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  state.reg.rddata = 0;
  state.reg.rdflags = (raflags | rbflags) & FLAG_NOT_WAIT_INV;
}

void uop_impl_ornotcc(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  state.reg.rddata = 0;
  state.reg.rdflags = (raflags | (~rbflags)) & FLAG_NOT_WAIT_INV;
}

void uop_impl_xorcc(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  state.reg.rddata = 0;
  state.reg.rdflags = (raflags ^ rbflags) & FLAG_NOT_WAIT_INV;
}

#ifdef EMULATE_64BIT
#define make_x86_aluop2_chained_64bit(name, opcode1, opcode2, pretext) \
template <int genflags> \
struct x86_op_ ## name <W64, genflags> { \
  W64 operator ()(W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags, byte& cf, byte& of) { \
    W32 ralo = LO32(ra); W32 rahi = HI32(ra); W32 rblo = LO32(rb); W32 rbhi = HI32(rb); \
      asm(pretext \
          #opcode1 " %[rblo],%[ralo];" \
          #opcode2 " %[rbhi],%[rahi];" \
          "setc %[cf]; seto %[of]" : [ralo] "+r" (ralo), [rahi] "+r" (rahi), [cf] "=q" (cf), [of] "=q" (of) : [rblo] "rm" (rblo), [rbhi] "rm" (rbhi), [rcflags] "rm" (rcflags)); \
      return ((W64)rahi << 32) + ((W64)ralo); \
  } \
};
make_x86_aluop2_chained_64bit(add, add, adc, "");
make_x86_aluop2_chained_64bit(sub, sub, sbb, "");
#endif

make_x86_aluop_all_sizes(addc, adc, ZAPS|CF|OF, PRETEXT_ALL_FLAGS_IN);
make_x86_aluop_all_sizes(subc, sbb, ZAPS|CF|OF, PRETEXT_ALL_FLAGS_IN);

#ifdef EMULATE_64BIT
make_x86_aluop2_chained_64bit(addc, adc, adc, PRETEXT_ALL_FLAGS_IN);
make_x86_aluop2_chained_64bit(subc, sbb, sbb, PRETEXT_ALL_FLAGS_IN);
#endif

//
// 3-operand ALU operation with shift of rc by 0/1/2/3
//

#define make_x86_aluop3(name, opcode1, opcode2) \
template <typename T, int genflags> \
struct name { \
  T operator ()(T ra, T rb, T rc, W16 raflags, W16 rbflags, W16 rcflags, byte& cf, byte& of) { \
    if (genflags & (SETFLAG_CF|SETFLAG_OF)) \
      asm(#opcode1 " %[rb],%[ra];" #opcode2 " %[rc],%[ra]; setc %[cf]; seto %[of]" : [ra] "+r" (ra), [cf] "=q" (cf), [of] "=q" (of) : [rb] "rm" (rb), [rc] "rm" (rc)); \
    else asm(#opcode1 " %[rb],%[ra]; " #opcode2 " %[rc],%[ra]" : [ra] "+r" (ra) : [rb] "rm" (rb), [rc] "rm" (rc) : "flags"); \
    return ra; \
  } \
}

template <template<typename, int> class func, typename T, int genflags, int rcshift>
inline void aluop3s(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  byte cf = 0, of = 0;
  func<T, genflags> f;
  T rt = f(ra, rb, rc << rcshift, raflags, rbflags, rcflags, cf, of);
  state.reg.rddata = x86_merge<T>(ra, rt);
  state.reg.rdflags = (of << 11) | cf | ((genflags & SETFLAG_ZF) ? x86_genflags<T>(rt) : 0);
}

// [size][extshift][setflags]
#define make_aluop3s_all_sizes_all_shifts(mapname, nativeop, flagset) \
uopimpl_func_t mapname[4][4][2] = { \
  { \
    {&aluop3s<nativeop, W8,  0, 0>, &aluop3s<nativeop, W8,  (flagset), 0>}, \
    {&aluop3s<nativeop, W8,  0, 1>, &aluop3s<nativeop, W8,  (flagset), 1>}, \
    {&aluop3s<nativeop, W8,  0, 2>, &aluop3s<nativeop, W8,  (flagset), 2>}, \
    {&aluop3s<nativeop, W8,  0, 3>, &aluop3s<nativeop, W8,  (flagset), 3>}, \
  }, \
  { \
    {&aluop3s<nativeop, W16, 0, 0>, &aluop3s<nativeop, W16, (flagset), 0>}, \
    {&aluop3s<nativeop, W16, 0, 1>, &aluop3s<nativeop, W16, (flagset), 1>}, \
    {&aluop3s<nativeop, W16, 0, 2>, &aluop3s<nativeop, W16, (flagset), 2>}, \
    {&aluop3s<nativeop, W16, 0, 3>, &aluop3s<nativeop, W16, (flagset), 3>}, \
  }, \
  { \
    {&aluop3s<nativeop, W32, 0, 0>, &aluop3s<nativeop, W32, (flagset), 0>}, \
    {&aluop3s<nativeop, W32, 0, 1>, &aluop3s<nativeop, W32, (flagset), 1>}, \
    {&aluop3s<nativeop, W32, 0, 2>, &aluop3s<nativeop, W32, (flagset), 2>}, \
    {&aluop3s<nativeop, W32, 0, 3>, &aluop3s<nativeop, W32, (flagset), 3>}, \
  }, \
  { \
    {&aluop3s<nativeop, W64, 0, 0>, &aluop3s<nativeop, W64, (flagset), 0>}, \
    {&aluop3s<nativeop, W64, 0, 1>, &aluop3s<nativeop, W64, (flagset), 1>}, \
    {&aluop3s<nativeop, W64, 0, 2>, &aluop3s<nativeop, W64, (flagset), 2>}, \
    {&aluop3s<nativeop, W64, 0, 3>, &aluop3s<nativeop, W64, (flagset), 3>}, \
  }, \
}

#define make_x86_aluop3_all_sizes_all_shifts(name, opcode1, opcode2, setflags) \
  make_x86_aluop3(x86_op_ ## name, opcode1, opcode2); \
  make_aluop3s_all_sizes_all_shifts(implmap_ ## name, x86_op_ ## name, (setflags));

make_x86_aluop3_all_sizes_all_shifts(adda, add, add, ZAPS|CF|OF);
make_x86_aluop3_all_sizes_all_shifts(adds, add, sub, ZAPS|CF|OF);
make_x86_aluop3_all_sizes_all_shifts(suba, sub, add, ZAPS|CF|OF);
make_x86_aluop3_all_sizes_all_shifts(subs, sub, sub, ZAPS|CF|OF);

#ifdef EMULATE_64BIT

#define make_x86_aluop3_chained_64bit(name, opcode1, opcode2, opcode1c, opcode2c) \
template <int genflags> \
struct x86_op_ ## name <W64, genflags> { \
  W64 operator ()(W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags, byte& cf, byte& of) { \
    W32 ralo = LO32(ra); W32 rahi = HI32(ra); \
    W32 rblo = LO32(rb); W32 rbhi = HI32(rb); \
    W32 rclo = LO32(rc); W32 rchi = HI32(rc); \
    asm(#opcode1  " %[rblo],%[ralo];" \
        #opcode1c " %[rbhi],%[rahi];" \
        #opcode2  " %[rclo],%[ralo];" \
        #opcode2c " %[rchi],%[rahi];" \
        "setc %[cf]; seto %[of]" \
        : [ralo] "+r" (ralo), [rahi] "+r" (rahi), [cf] "=q" (cf), [of] "=q" (of) \
        : [rblo] "rm" (rblo), [rbhi] "rm" (rbhi), [rclo] "rm" (rclo), [rchi] "rm" (rchi), [rcflags] "rm" (rcflags)); \
    return ((W64)rahi << 32) + ((W64)ralo); \
  } \
}

make_x86_aluop3_chained_64bit(adda, add, add, adc, adc);
make_x86_aluop3_chained_64bit(adds, add, sub, adc, sbb);
make_x86_aluop3_chained_64bit(suba, sub, add, sbb, adc);
make_x86_aluop3_chained_64bit(subs, sub, sub, sbb, sbb);

#endif

//
// Shifts and rotates
//

#define make_x86_shiftop(name, opcode, pretext) \
template <typename T, int genflags> \
struct name { \
  T operator ()(T ra, T rb, T rc, W16 raflags, W16 rbflags, W16 rcflags, byte& cf, byte& of) { \
    if (genflags & (SETFLAG_CF|SETFLAG_OF)) \
      asm(pretext #opcode " %[rb],%[ra]; setc %[cf]; seto %[of]" : [ra] "+r" (ra), [cf] "=q" (cf), [of] "=q" (of) : [rb] "c" ((byte)rb), [rcflags] "rm" (rcflags)); \
    else asm(#opcode " %[rb],%[ra]" : [ra] "+r" (ra) : [rb] "c" ((byte)rb) : "flags"); \
    return ra; \
  } \
}

template <template<typename, int> class func, typename T, int genflags>
inline void shiftop(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  byte cf = 0, of = 0;
  func<T, genflags> f;
  T rt = f(ra, rb, rc, raflags, rbflags, rcflags, cf, of);
  state.reg.rddata = x86_merge<T>(ra, rt);
  int allflags = (of << 11) | cf | x86_genflags<T>(rt);
  state.reg.rdflags = (rb == 0) ? rcflags : allflags;
}

#define make_shiftop_all_sizes(mapname, nativeop, flagset) make_anyop_all_sizes(mapname, shiftop, nativeop, flagset)

#define make_x86_shiftop_all_sizes(name, opcode, setflags, pretext) \
  make_x86_shiftop(x86_op_ ## name, opcode, pretext); \
  make_shiftop_all_sizes(implmap_ ## name, x86_op_ ## name, (setflags));

#ifdef EMULATE_64BIT

#define make_exp_shiftop_64bit(name, expr) \
template <int genflags> \
struct x86_op_ ## name <W64, genflags> { \
  W64 operator ()(W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags, byte& cf, byte& of) { \
    cf = 0; of = 0; W64 rd; expr; return rd; \
  } \
}
#endif

make_x86_shiftop_all_sizes(shl, shl, ZAPS|CF|OF, PRETEXT_ALL_FLAGS_IN);
make_x86_shiftop_all_sizes(shr, shr, ZAPS|CF|OF, PRETEXT_ALL_FLAGS_IN);
make_x86_shiftop_all_sizes(sar, sar, ZAPS|CF|OF, PRETEXT_ALL_FLAGS_IN);

make_x86_shiftop_all_sizes(rotl, rol, ZAPS|CF|OF, PRETEXT_ALL_FLAGS_IN);
make_x86_shiftop_all_sizes(rotr, ror, ZAPS|CF|OF, PRETEXT_ALL_FLAGS_IN);
make_x86_shiftop_all_sizes(rotcl, rcl, ZAPS|CF|OF, PRETEXT_ALL_FLAGS_IN);
make_x86_shiftop_all_sizes(rotcr, rcr, ZAPS|CF|OF, PRETEXT_ALL_FLAGS_IN);

#ifdef EMULATE_64BIT
make_exp_shiftop_64bit(shl, (rb = lowbits(rb, log2(sizeof(W64)*8)), rd = (ra << rb), cf = bit(ra, (sizeof(W64)*8) - rb), of = cf ^ bit(rd, (sizeof(W64)*8)-1), rd));
make_exp_shiftop_64bit(shr, (rb = lowbits(rb, log2(sizeof(W64)*8)), rd = (ra >> rb), cf = bit(ra, (rb-1)), of = bit(rd, (sizeof(W64)*8)-1), ra));
make_exp_shiftop_64bit(sar, (rb = lowbits(rb, log2(sizeof(W64)*8)), rd = ((W64s)ra >> rb), cf = bit(ra, (rb-1)), of = bit(rd, (sizeof(W64)*8)-1), ra));

make_exp_shiftop_64bit(rotl, (rb = lowbits(rb, log2(sizeof(W64)*8)), rd = (ra << rb) | (ra >> (64 - rb)), cf = bit(ra, (sizeof(W64)*8) - rb), of = cf ^ bit(rd, (sizeof(W64)*8)-1), rd));
make_exp_shiftop_64bit(rotr, (rb = lowbits(rb, log2(sizeof(W64)*8)), rd = (ra >> rb) | (ra << (64 - rb)), cf = bit(ra, (rb-1)), of = bit(rd, (sizeof(W64)*8)-1), ra));
make_exp_shiftop_64bit(rotcl, (abort(), rd)); // not supported in 32-bit mode because it's too complex
make_exp_shiftop_64bit(rotcr, (abort(), rd)); // not supported in 32-bit mode because it's too complex
#endif

//
// Masks
//

#ifdef __x86_64__
W64 rotr64(W64 w, int c) { return x86_rotr64(w, c); }
#else
W64 rotr64(W64 w, int c) {
  return (w >> c) | (w << (64 - c));
}
#endif

W64 mask_gen_lut[64*64]; // (((1 << mc)-1) >>> ms)
W64 mask_bt_lut[64*64];  // mask[mc+ms] = 1
W64 mask_zxt_lut[64*64]; // 1'[(ms+mc-1):0]
W64 mask_sxt_lut[64*64]; // 1'[63:(ms+mc)]

void gen_mask_uop_masks() {
  foreach (mc, 64) {
    foreach (ms, 64) {
      W64 t = rotr64(bitmask(mc), ms);
      mask_gen_lut[(mc << 6) + ms] = t;
    }
  }

  foreach (mc, 64) {
    foreach (ms, 64) {
      W64 t = 0;
      setbit(t, (mc+ms-1));
      mask_bt_lut[(mc << 6) + ms] = t;
    }
  }

  foreach (mc, 64) {
    foreach (ms, 64) {
      W64 t = 0;
      for (int i = (ms+mc-1); i >= 0; i--) setbit(t, i);
      mask_zxt_lut[(mc << 6) + ms] = t;
    }
  }

  foreach (mc, 64) {
    foreach (ms, 64) {
      W64 t = 0;
      int limit = (ms+mc);
      for (int i = 63; i >= limit; i--) setbit(t, i);
      mask_sxt_lut[(mc << 6) + ms] = t;
    }
  }
}

// See testmasks.cpp for more information

template <typename T, int ZEROEXT, int SIGNEXT>
void exp_op_mask(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  int ms = bits(rc, 0, 6);
  int mc = bits(rc, 6, 6);
  int ds = bits(rc, 12, 6);
  
  int mcms = bits(rc, 0, 12);

  // mask_gen_lut[] = (((1 << mc)-1), ms);
  W64 M = mask_gen_lut[mcms];
  W64 rd = (ra & ~M) | (rotr64(rb, ds) & M);

#if 0
  // For debugging purposes:
  if (logable(99)) {
    logfile << "mask (ms=", ms, " mc=", mc, " ds=", ds, "):", endl;
    logfile << "  M      = ", bitstring(M, 64), endl;
    logfile << "  rot rb = ", bitstring(rotr64(rb, ds), 64), endl;
  }
#endif

  if (ZEROEXT) {
    // mask_zxt_lut[] = 1'[(ms+mc-1):0]
    rd = rd & mask_zxt_lut[mcms];
  } else if (SIGNEXT) {
    // mask_sxt_lut[] = 1'[63:(ms+mc)]
    W64 sxt = (rd | mask_sxt_lut[mcms]);
    W64 zxt = (rd & mask_zxt_lut[mcms]);
    // mask_zxt_lut[] = 1'[(ms+mc-1):0]
    // mask_bt_lut[] = 1'[mc+ms-1];
    rd = (rd & mask_bt_lut[mcms]) ? sxt : zxt;
  } else {
    rd = rd;
  }

  state.reg.rddata = x86_merge<T>(ra, rd);
  state.reg.rdflags = x86_genflags<T>(rd);
}

// [size][exttype]
uopimpl_func_t implmap_mask[4][3] = {
  {&exp_op_mask<W8,  0, 0>, &exp_op_mask<W8,  1, 0>, &exp_op_mask<W8,  0, 1>},
  {&exp_op_mask<W16, 0, 0>, &exp_op_mask<W16, 1, 0>, &exp_op_mask<W16, 0, 1>},
  {&exp_op_mask<W32, 0, 0>, &exp_op_mask<W32, 1, 0>, &exp_op_mask<W32, 0, 1>},
  {&exp_op_mask<W64, 0, 0>, &exp_op_mask<W64, 1, 0>, &exp_op_mask<W64, 0, 1>}
};

//
// Multiplies
//

#define make_x86_mulop(name, opcode, extrtext, extrtextsize1) \
template <typename T, int genflags> \
struct name { \
  T operator ()(T ra, T rb, T rc, W16 raflags, W16 rbflags, W16 rcflags, byte& cf, byte& of) { \
    Wmax rax = ra; \
    Wmax rdx; \
    asm(#opcode " %[rb]; setc %[cf]; seto %[of];" \
        : [rax] "+a" (rax), [rdx] "+d" (rdx), [cf] "=q" (cf), [of] "=q" (of) \
        : [rb] "q" (rb)); \
    Wmax rd; \
    if (sizeof(T) == 1) (extrtextsize1); else (extrtext); \
    return rd; \
  } \
}

#define make_mulop_all_sizes(mapname, nativeop, flagset) \
uopimpl_func_t mapname[4][2] = { \
  {&aluop<nativeop, W8,  0>, &aluop<nativeop, W8,  (flagset)>} \
  {&aluop<nativeop, W16, 0>, &aluop<nativeop, W16, (flagset)>} \
  {&aluop<nativeop, W32, 0>, &aluop<nativeop, W32, (flagset)>} \
  {&aluop<nativeop, W64, 0>, &aluop<nativeop, W64, (flagset)>} \
}

#define make_x86_mulop_all_sizes(name, opcode, setflags, extrtext, extrtextsize1) \
  make_x86_mulop(x86_op_ ## name, opcode, extrtext, extrtextsize1); \
  make_aluop_all_sizes(implmap_ ## name, x86_op_ ## name, (setflags));

make_x86_mulop_all_sizes(mull, imul, ZAPS|CF|OF, (rd = (T)rax), (rd = (T)rax));
make_x86_mulop_all_sizes(mulh, imul, ZAPS|CF|OF, (rd = (T)rdx), (rd = bits(rax, 8, 8)));
make_x86_mulop_all_sizes(mulhu, mul, ZAPS|CF|OF, (rd = (T)rdx), (rd = bits(rax, 8, 8)));

#ifndef __x86_64__
template <int genflags>
struct x86_op_mull<W64, genflags> { W64 operator ()(W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags, byte& cf, byte& of) { asm("int3"); return 0; } };

template <int genflags>
struct x86_op_mulh<W64, genflags> { W64 operator ()(W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags, byte& cf, byte& of) { asm("int3"); return 0; } };

template <int genflags>
struct x86_op_mulhu<W64, genflags> { W64 operator ()(W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags, byte& cf, byte& of) { asm("int3"); return 0; } };
#endif

//
// Condition code evaluation
//

template <int evaltype>
inline bool evaluate_cond(int ra, int rb) {
  switch (evaltype) {
  case 0:  // {0, REG_zero, REG_of},   // of:               jo
    return !!(rb & FLAG_CF);
  case 1:  // {0, REG_zero, REG_of},   // !of:              jno
    return !(rb & FLAG_CF);
  case 2:  // {0, REG_zero, REG_cf},   // cf:               jb jc jnae
    return !!(rb & FLAG_CF);
  case 3:  // {0, REG_zero, REG_cf},   // !cf:              jnb jnc jae
    return !(rb & FLAG_CF);
  case 4:  // {0, REG_zf,   REG_zero}, // zf:               jz je
    return !!(ra & FLAG_ZF);
  case 5:  // {0, REG_zf,   REG_zero}, // !zf:              jnz jne
    return !(ra & FLAG_ZF);
  case 6:  // {1, REG_zf,   REG_cf},   // cf|zf:            jbe jna
    return ((ra & FLAG_ZF) || (rb & FLAG_CF));
  case 7:  // {1, REG_zf,   REG_cf},   // !cf & !zf:        jnbe ja
    return !((ra & FLAG_ZF) || (rb & FLAG_CF));
  case 8:  // {0, REG_zf,   REG_zero}, // sf:               js 
    return !!(ra & FLAG_SF);
  case 9:  // {0, REG_zf,   REG_zero}, // !sf:              jns
    return !(ra & FLAG_SF);
  case 10: // {0, REG_zf,   REG_zero}, // pf:               jp jpe
    return !!(ra & FLAG_PF);
  case 11: // {0, REG_zf,   REG_zero}, // !pf:              jnp jpo
    return !(ra & FLAG_PF);
  case 12: // {1, REG_zf,   REG_of},   // sf != of:         jl jnge (*)
    return (!!(ra & FLAG_SF)) != (!!(rb & FLAG_OF));
  case 13: // {1, REG_zf,   REG_of},   // sf == of:         jnl jge (*)
    return !(!!(ra & FLAG_SF)) != (!!(rb & FLAG_OF));
  case 14: // {1, REG_zf,   REG_of},   // zf | (sf != of):  jle jng (*)
    return ((!!(ra & FLAG_ZF)) | ((!!(ra & FLAG_SF)) != (!!(rb & FLAG_OF))));
  case 15: // {1, REG_zf,   REG_of},   // !zf & (sf == of): jnle jg (*)
    return !((!!(ra & FLAG_ZF)) | ((!!(ra & FLAG_SF)) != (!!(rb & FLAG_OF))));
  }
}

#define make_condop_all_conds_any(subtype, subarrays, mapname, operation) \
uopimpl_func_t implmap_ ## mapname [16]subarrays = { \
  subtype(operation, 0), \
  subtype(operation, 1), \
  subtype(operation, 2), \
  subtype(operation, 3), \
  subtype(operation, 4), \
  subtype(operation, 5), \
  subtype(operation, 6), \
  subtype(operation, 7), \
  subtype(operation, 8), \
  subtype(operation, 9), \
  subtype(operation, 10), \
  subtype(operation, 11), \
  subtype(operation, 12), \
  subtype(operation, 13), \
  subtype(operation, 14), \
  subtype(operation, 15) \
}

#define make_condop(operation, cond) &operation<cond>
#define make_condop_all_sizes(operation, cond) {&operation<W8, cond>, &operation<W16, cond>, &operation<W32, cond>, &operation<W64, cond>}

#define make_condop_all_conds(mapname, operation) make_condop_all_conds_any(make_condop_one, [4], mapname, operation)
#define make_condop_all_conds_all_sizes(mapname, operation) make_condop_all_conds_any(make_condop_all_sizes, [4], mapname, operation)

template <typename T, int evaltype>
inline void selop(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  bool istrue = evaluate_cond<evaltype>(rcflags, rcflags);
  state.reg.rddata = x86_merge<T>(ra, (istrue) ? rb : ra);
  state.reg.rdflags = (istrue) ? rbflags : raflags;
}

make_condop_all_conds_all_sizes(sel, selop);

template <typename T, int evaltype>
inline void setop(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  bool istrue = evaluate_cond<evaltype>(rcflags, rcflags);
  state.reg.rddata = x86_merge<T>(ra, (istrue) ? rb : 0);
  state.reg.rdflags = (istrue) ? FLAG_CF : 0;
}

make_condop_all_conds_all_sizes(set, setop);

//
// Branches
//

template <typename T, int evaltype, bool excepting>
inline void uop_impl_condbranch(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  bool taken = evaluate_cond<evaltype>(raflags, rbflags);
  state.reg.rddata = (taken) ? state.brreg.riptaken : state.brreg.ripseq;
  state.reg.rdflags = 0;
  if (excepting & (!taken)) {
    state.reg.rddata = EXCEPTION_BranchMispredict;
    state.reg.rdflags = FLAG_INV;
  }
}

#define make_branchop_all_excepts(operation, cond) {&uop_impl_condbranch<W64, cond, false>, &uop_impl_condbranch<W64, cond, true>}

make_condop_all_conds_any(make_branchop_all_excepts, [2], br, anything);

#define function(expr, rettype, ...) class { public: rettype operator () (__VA_ARGS__) { return (expr); } }

template <typename T> struct sub_flag_gen_op { 
  W16 operator ()(T ra, T rb) { x86_op_sub<T, ZAPS|CF|OF> op; byte cf, of; T rd = op(ra, rb, 0, 0, 0, 0, cf, of); return (of << 11) | cf | x86_genflags<T>(rd); } 
};

template <typename T> struct and_flag_gen_op { 
  W16 operator ()(T ra, T rb) { return x86_genflags<T>(ra & rb); } 
};

template <typename T, int evaltype, bool excepting, template<typename> class func_t>
inline void uop_impl_alu_and_condbranch(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  func_t<T> func;
  int flags = func(ra, rb);
  bool taken = evaluate_cond<evaltype>(flags, flags);
  state.reg.rddata = (taken) ? state.brreg.riptaken : state.brreg.ripseq;
  state.reg.rdflags = flags;
  if (excepting & (!taken)) {
    state.reg.rddata = EXCEPTION_BranchMispredict;
    state.reg.rdflags = FLAG_INV;
  }
}

#define make_alu_and_branchop_all_sizes_all_excepts(operation, cond) \
  { \
    {&uop_impl_alu_and_condbranch<W8,  cond, false, operation>, &uop_impl_alu_and_condbranch<W8,  cond, true, operation>}, \
    {&uop_impl_alu_and_condbranch<W16, cond, false, operation>, &uop_impl_alu_and_condbranch<W16, cond, true, operation>}, \
    {&uop_impl_alu_and_condbranch<W32, cond, false, operation>, &uop_impl_alu_and_condbranch<W32, cond, true, operation>}, \
    {&uop_impl_alu_and_condbranch<W64, cond, false, operation>, &uop_impl_alu_and_condbranch<W64, cond, true, operation>}, \
  }

make_condop_all_conds_any(make_alu_and_branchop_all_sizes_all_excepts, [4][2], br_and, and_flag_gen_op);
make_condop_all_conds_any(make_alu_and_branchop_all_sizes_all_excepts, [4][2], br_sub, sub_flag_gen_op);

void uop_impl_jmp(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  bool taken = (state.brreg.riptaken == ra);
  state.reg.rddata = ra;
  state.reg.rdflags = 0;
}

void uop_impl_jmp_ex(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  bool taken = (state.brreg.riptaken == ra);
  state.reg.rddata = ra;
  state.reg.rdflags = 0;

  if (!taken) {
    state.reg.rddata = EXCEPTION_BranchMispredict;
    state.reg.rdflags = FLAG_INV;
  }
}

void uop_impl_bru(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  state.reg.rddata = state.brreg.riptaken;
  state.reg.rdflags = 0;
}

void uop_impl_brp(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  state.reg.rddata = state.brreg.riptaken;
  state.reg.rdflags = 0;
}

//
// Checks
//
template <int evaltype>
inline void uop_impl_chk(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  bool passed = evaluate_cond<evaltype>(raflags, rbflags);
  state.reg.rddata = (passed) ? 0 : EXCEPTION_SkipBlock;
  state.reg.addr = rc;
  state.reg.rdflags = (passed) ? 0 : FLAG_INV;
}

template <typename T, int evaltype>
inline void uop_impl_chk_sub(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  sub_flag_gen_op<T> func;
  int flags = func(ra, rb);
  bool passed = evaluate_cond<evaltype>(flags, flags);
  state.reg.rddata = (passed) ? 0 : EXCEPTION_SkipBlock;
  state.reg.addr = rc;
  state.reg.rdflags = (passed) ? 0 : FLAG_INV;
}

template <typename T, int evaltype>
inline void uop_impl_chk_and(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  and_flag_gen_op<T> func;
  int flags = func(ra, rb);
  bool passed = evaluate_cond<evaltype>(flags, flags);
  state.reg.rddata = (passed) ? 0 : EXCEPTION_SkipBlock;
  state.reg.addr = rc;
  state.reg.rdflags = (passed) ? 0 : FLAG_INV;
}

make_condop_all_conds_any(make_condop, [1], chk, uop_impl_chk);
make_condop_all_conds_all_sizes(chk_sub, uop_impl_chk_sub);
make_condop_all_conds_all_sizes(chk_and, uop_impl_chk_and);

extern W64 virt_addr_mask;

template <int level>
inline void uop_impl_prefetch(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  initiate_prefetch((ra + rb) & virt_addr_mask, level);
  state.reg.rddata = 0;
  state.reg.rdflags = 0;
}

//
// Prefetches
//
uopimpl_func_t implmap_ld_pre[4] = {&uop_impl_prefetch<0>, &uop_impl_prefetch<1>, &uop_impl_prefetch<2>, &uop_impl_prefetch<3>};

//
// Floating Point
//
#define make_exp_floatop(name, expr) template <typename T> struct name { T operator ()(T ra, T rb, T rc) { T rd; expr; return rd; } }

union SSEType {
  double d;
  struct { float lo, hi; } f;
  W64 w64;
  struct { W32 lo, hi; } w32;
};

template <template<typename> class F, int datatype>
inline void floatop(IssueState& state, W64 raraw, W64 rbraw, W64 rcraw, W16 raflags, W16 rbflags, W16 rcflags) {
  SSEType ra, rb, rc, rd;
  ra.w64 = raraw; rb.w64 = rbraw; rc.w64 = rcraw;

  switch (datatype) {
  case 0: { // scalar single
    F<float> func;
    rd.f.lo = func(ra.f.lo, rb.f.lo, rc.f.lo);
    rd.w32.hi = ra.w32.hi;
    break;
  }
  case 1: { // packed single
    F<float> func;
    rd.f.lo = func(ra.f.lo, rb.f.lo, rc.f.lo);
    rd.f.hi = func(ra.f.hi, rb.f.hi, rc.f.hi);
    break;
  }
  case 2: case 3: { // scalar double
    F<float> func;
    rd.d = func(ra.d, rb.d, rc.d);
    break;
  }
  }
  state.reg.rddata = rd.w64;
  state.reg.rdflags = 0;
}


#define make_exp_floatop_alltypes(name, expr) \
  make_exp_floatop(exp_op_##name, expr); \
  uopimpl_func_t implmap_##name[4] = {&floatop<exp_op_##name, 0>, &floatop<exp_op_##name, 1>,  &floatop<exp_op_##name, 2>,  &floatop<exp_op_##name, 3>}

//
// This looks strange since 32-bit x86 can only move from 64-bit memory to XMM.
// x86-64 can use movd to go straight from a GPR into the XMM register.
//
#ifdef __x86_64__
#define MOV_TO_XMM "movd"
#define W64_CONSTRAINT "rm"
#else
// 32-bit x86
#define MOV_TO_XMM "movq"
#define W64_CONSTRAINT "m"
#endif

#define make_x86_floatop2(name, opcode, typemask, extra) \
template <int datatype> \
void name(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) { \
  W64 rd; \
  vec16b fpa, fpb; \
  if ((datatype == 0) & bit(typemask, 0)) asm(MOV_TO_XMM " %[ra],%[fpa]; " MOV_TO_XMM " %[rb],%[fpb]; " #opcode "ss " extra "%[fpb],%[fpa]; movq %[fpa],%[rd];" \
     : [rd] "=" W64_CONSTRAINT (rd), [fpa] "=x" (fpa), [fpb] "=x" (fpb) : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); \
  if ((datatype == 1) & bit(typemask, 1)) asm(MOV_TO_XMM " %[ra],%[fpa]; " MOV_TO_XMM " %[rb],%[fpb]; " #opcode "ps " extra "%[fpb],%[fpa]; movq %[fpa],%[rd];" \
     : [rd] "=" W64_CONSTRAINT (rd), [fpa] "=x" (fpa), [fpb] "=x" (fpb) : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); \
  if ((datatype >= 2) & bit(typemask, 2)) asm(MOV_TO_XMM " %[ra],%[fpa]; " MOV_TO_XMM " %[rb],%[fpb]; " #opcode "sd " extra "%[fpb],%[fpa]; movq %[fpa],%[rd];" \
     : [rd] "=" W64_CONSTRAINT (rd), [fpa] "=x" (fpa), [fpb] "=x" (fpb) : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); \
  state.reg.rddata = rd; \
  state.reg.rdflags = 0; \
}

#define make_x86_floatop3(name, opcode1, opcode2, typemask) \
template <int datatype> \
void name(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) { \
  W64 rd; \
  vec16b fpa, fpb, fpc; \
  if ((datatype == 0) & bit(typemask, 0)) asm(MOV_TO_XMM " %[ra],%[fpa]; " MOV_TO_XMM " %[rb],%[fpb]; " MOV_TO_XMM " %[rc],%[fpc]; " #opcode1 "ss %[fpb],%[fpa]; " #opcode2 "ss %[fpc],%[fpa]; movq %[fpa],%[rd];" \
     : [rd] "=" W64_CONSTRAINT (rd), [fpa] "=x" (fpa), [fpb] "=x" (fpb), [fpc] "=x" (fpc) : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb), [rc] W64_CONSTRAINT (rc)); \
  if ((datatype == 1) & bit(typemask, 1)) asm(MOV_TO_XMM " %[ra],%[fpa]; " MOV_TO_XMM " %[rb],%[fpb]; " MOV_TO_XMM " %[rc],%[fpc]; " #opcode1 "ps %[fpb],%[fpa]; " #opcode2 "ps %[fpc],%[fpa]; movq %[fpa],%[rd];" \
     : [rd] "=" W64_CONSTRAINT (rd), [fpa] "=x" (fpa), [fpb] "=x" (fpb), [fpc] "=x" (fpc) : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb), [rc] W64_CONSTRAINT (rc)); \
  if ((datatype == 2) & bit(typemask, 2)) asm(MOV_TO_XMM " %[ra],%[fpa]; " MOV_TO_XMM " %[rb],%[fpb]; " MOV_TO_XMM " %[rc],%[fpc]; " #opcode1 "sd %[fpb],%[fpa]; " #opcode2 "sd %[fpc],%[fpa]; movq %[fpa],%[rd];" \
     : [rd] "=" W64_CONSTRAINT (rd), [fpa] "=x" (fpa), [fpb] "=x" (fpb), [fpc] "=x" (fpc) : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb), [rc] W64_CONSTRAINT (rc)); \
  state.reg.rddata = rd; \
  state.reg.rdflags = 0; \
}

#define SS (1<<0)
#define PS (1<<1)
#define DP (1<<2)

#define make_x86_floatop_alltypes(name, opcode, typemask) \
  make_x86_floatop2(x86_op_##name, opcode, typemask, ""); \
  uopimpl_func_t implmap_##name[4] = {&x86_op_##name<0>, &x86_op_##name<1>, &x86_op_##name<2>, &x86_op_##name<3>}

#define make_x86_floatop3_alltypes(name, opcode1, opcode2, typemask) \
  make_x86_floatop3(x86_op_##name, opcode1, opcode2, typemask); \
  uopimpl_func_t implmap_##name[4] = {&x86_op_##name<0>, &x86_op_##name<1>, &x86_op_##name<2>, &x86_op_##name<3>}

make_x86_floatop_alltypes(addf, add, SS|PS|DP);
make_x86_floatop_alltypes(subf, sub, SS|PS|DP);
make_x86_floatop_alltypes(mulf, mul, SS|PS|DP);
make_x86_floatop_alltypes(divf, div, SS|PS|DP);
make_x86_floatop_alltypes(sqrtf, sqrt, SS|PS|DP);
make_x86_floatop_alltypes(rcpf, rcp, SS|PS);
make_x86_floatop_alltypes(rsqrtf, rsqrt, SS|PS);
make_x86_floatop_alltypes(minf, min, SS|PS|DP);
make_x86_floatop_alltypes(maxf, max, SS|PS|DP);

make_x86_floatop3_alltypes(maddf, mul, add, SS|PS|DP);
make_x86_floatop3_alltypes(msubf, mul, sub, SS|PS|DP);

make_x86_floatop2(x86_op_cmpf0, cmp, SS|PS|DP, "$0,");
make_x86_floatop2(x86_op_cmpf1, cmp, SS|PS|DP, "$1,");
make_x86_floatop2(x86_op_cmpf2, cmp, SS|PS|DP, "$2,");
make_x86_floatop2(x86_op_cmpf3, cmp, SS|PS|DP, "$3,");
make_x86_floatop2(x86_op_cmpf4, cmp, SS|PS|DP, "$4,");
make_x86_floatop2(x86_op_cmpf5, cmp, SS|PS|DP, "$5,");
make_x86_floatop2(x86_op_cmpf6, cmp, SS|PS|DP, "$6,");
make_x86_floatop2(x86_op_cmpf7, cmp, SS|PS|DP, "$7,");

uopimpl_func_t implmap_cmpf[8][4] = {
  {&x86_op_cmpf0<0>, &x86_op_cmpf0<1>, &x86_op_cmpf0<2>, &x86_op_cmpf0<3>},
  {&x86_op_cmpf1<0>, &x86_op_cmpf1<1>, &x86_op_cmpf1<2>, &x86_op_cmpf1<3>},
  {&x86_op_cmpf2<0>, &x86_op_cmpf2<1>, &x86_op_cmpf2<2>, &x86_op_cmpf2<3>},
  {&x86_op_cmpf3<0>, &x86_op_cmpf3<1>, &x86_op_cmpf3<2>, &x86_op_cmpf3<3>},
  {&x86_op_cmpf4<0>, &x86_op_cmpf4<1>, &x86_op_cmpf4<2>, &x86_op_cmpf4<3>},
  {&x86_op_cmpf5<0>, &x86_op_cmpf5<1>, &x86_op_cmpf5<2>, &x86_op_cmpf5<3>},
  {&x86_op_cmpf6<0>, &x86_op_cmpf6<1>, &x86_op_cmpf6<2>, &x86_op_cmpf6<3>},
  {&x86_op_cmpf7<0>, &x86_op_cmpf7<1>, &x86_op_cmpf7<2>, &x86_op_cmpf7<3>}
};

template <int comptype>
void uop_impl_cmpccf(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  W64 rd;
  vec16b fpa, fpb;
  byte zf, pf, cf;
  switch (comptype) {
  case 0: // comiss
    asm(MOV_TO_XMM " %[ra],%[fpa]; " MOV_TO_XMM " %[rb],%[fpb]; comiss %[fpb],%[fpa]; setz %[zf]; setp %[pf]; setc %[cf];"
        : [rd] "=" W64_CONSTRAINT (rd), [fpa] "=x" (fpa), [fpb] "=x" (fpb), [zf] "=q" (zf), [pf] "=q" (pf), [cf] "=q" (cf)
        : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); break;
  case 1: // ucomiss
    asm(MOV_TO_XMM " %[ra],%[fpa]; " MOV_TO_XMM " %[rb],%[fpb]; ucomiss %[fpb],%[fpa]; setz %[zf]; setp %[pf]; setc %[cf];"
        : [rd] "=" W64_CONSTRAINT (rd), [fpa] "=x" (fpa), [fpb] "=x" (fpb), [zf] "=q" (zf), [pf] "=q" (pf), [cf] "=q" (cf)
        : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); break;
  case 2: // comisd
    asm(MOV_TO_XMM " %[ra],%[fpa]; " MOV_TO_XMM " %[rb],%[fpb]; comisd %[fpb],%[fpa]; setz %[zf]; setp %[pf]; setc %[cf];"
        : [rd] "=" W64_CONSTRAINT (rd), [fpa] "=x" (fpa), [fpb] "=x" (fpb), [zf] "=q" (zf), [pf] "=q" (pf), [cf] "=q" (cf)
        : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); break;
  case 3: // ucomisd
    asm(MOV_TO_XMM " %[ra],%[fpa]; " MOV_TO_XMM " %[rb],%[fpb]; ucomisd %[fpb],%[fpa]; setz %[zf]; setp %[pf]; setc %[cf];"
        : [rd] "=" W64_CONSTRAINT (rd), [fpa] "=x" (fpa), [fpb] "=x" (fpb), [zf] "=q" (zf), [pf] "=q" (pf), [cf] "=q" (cf)
        : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); break;
  }
  state.reg.rdflags = (zf << 6) + (pf << 2) + (cf << 0);
  state.reg.rddata = state.reg.rdflags;
}

uopimpl_func_t implmap_cmpccf[8][4] = {&uop_impl_cmpccf<0>, &uop_impl_cmpccf<1>, &uop_impl_cmpccf<2>, &uop_impl_cmpccf<3>};

#define make_simple_fp_convop(name, opcode, highpart) \
void uop_impl_##name(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) { \
  W64 rd; vec4f fpa, fpb; \
  if (highpart) { \
    asm(MOV_TO_XMM " %[ra],%[fpa]; " MOV_TO_XMM " %[rb],%[fpb]; " #opcode " %[fpb],%[fpa]; movhlps %[fpa],%[fpa]; movq %[fpa],%[rd];" \
        : [rd] "=" W64_CONSTRAINT (rd), [fpa] "=x" (fpa), [fpb] "=x" (fpb) \
        : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); \
  } else { \
    asm(MOV_TO_XMM " %[ra],%[fpa]; " MOV_TO_XMM " %[rb],%[fpb]; " #opcode " %[fpb],%[fpa]; movq %[fpa],%[rd];" \
        : [rd] "=" W64_CONSTRAINT (rd), [fpa] "=x" (fpa), [fpb] "=x" (fpb) \
        : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); \
  } \
  state.reg.rddata = rd; \
  state.reg.rdflags = 0; \
}

make_simple_fp_convop(cvtf_i2s_p,  cvtdq2ps, 0);
make_simple_fp_convop(cvtf_i2d_lo, cvtdq2pd, 0);
make_simple_fp_convop(cvtf_i2d_hi, cvtdq2pd, 1);
make_simple_fp_convop(cvtf_s2d_lo, cvtps2pd, 0);
make_simple_fp_convop(cvtf_s2d_hi, cvtps2pd, 1);
make_simple_fp_convop(cvtf_d2s_ins, cvtsd2ss, 0);

#define make_intsrc_fp_convop(name, op) \
void uop_impl_##name(IssueState& state, W64 raraw, W64 rbraw, W64 rcraw, W16 raflags, W16 rbflags, W16 rcflags) { \
  SSEType ra, rb, rc, rd; ra.w64 = raraw; rb.w64 = rbraw; rc.w64 = rcraw; op; state.reg.rddata = rd.w64; state.reg.rdflags = 0; \
}

make_intsrc_fp_convop(cvtf_i2s_ins, (rd.f.lo = (float)rb.w32.lo, rd.w32.hi = ra.w32.hi));
make_intsrc_fp_convop(cvtf_q2s_ins, (rd.f.lo = (float)rb.w64, rd.w32.hi = ra.w32.hi));
make_intsrc_fp_convop(cvtf_q2d, (rd.d = (double)rb.w64));

#define make_intdest_fp_convop(name, desttype, roundop, truncop) \
template <int trunc> \
void name(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) { \
  desttype rd; vec4f fpv; \
  if (trunc) { \
    asm(MOV_TO_XMM " %[ra],%[fpv]; " #truncop " %[fpv],%[rd];" \
        : [rd] "=" "r" (rd), [fpv] "=x" (fpv) : [ra] W64_CONSTRAINT (ra)); \
  } else { \
    asm(MOV_TO_XMM " %[ra],%[fpv]; " #roundop " %[fpv],%[rd];" \
        : [rd] "=" "r" (rd), [fpv] "=x" (fpv) : [ra] W64_CONSTRAINT (ra)); \
  } \
  state.reg.rddata = rd; \
  state.reg.rdflags = 0; \
}

#define make_intdest_fp_convop_allrounds(name, desttype, roundop, truncop) \
  make_intdest_fp_convop(uop_impl_##name, desttype, roundop, truncop); \
  uopimpl_func_t implmap_##name[2] = {&uop_impl_##name<0>, &uop_impl_##name<1>}

make_intdest_fp_convop_allrounds(cvtf_s2i, W32, cvtss2si, cvttss2si);
make_intdest_fp_convop_allrounds(cvtf_d2i, W32, cvtsd2si, cvttsd2si);

#ifdef __x86_64__
make_intdest_fp_convop_allrounds(cvtf_s2q, W64, cvtss2si, cvttss2si);
make_intdest_fp_convop_allrounds(cvtf_d2q, W64, cvtsd2si, cvttsd2si);
#else
//
// Regular 32-bit x86 does not have SSE instructions to handle 64-bit
// integer to/from float conversions. Therefore we have to use x87
//
#define make_intdest_fp_convop_x87_64bit(name, T) \
template <int trunc> \
void name(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) { \
  W64 rd = 0; \
  if (trunc) { \
    asm("fld %[ra]; fisttp %[rd];" : [rd] "=m" (rd) : [ra] "m" (*((T*)&ra))); \
  } else { \
    asm("fld %[ra]; fistp %[rd];" : [rd] "=m" (rd) : [ra] "m" (*((T*)&ra))); \
  } \
  state.reg.rddata = rd; \
  state.reg.rdflags = 0; \
}

make_intdest_fp_convop_x87_64bit(uop_impl_cvtf_s2q, float);
make_intdest_fp_convop_x87_64bit(uop_impl_cvtf_d2q, double);

uopimpl_func_t implmap_cvtf_s2q[2] = {&uop_impl_cvtf_s2q<0>, &uop_impl_cvtf_s2q<1>};
uopimpl_func_t implmap_cvtf_d2q[2] = {&uop_impl_cvtf_d2q<0>, &uop_impl_cvtf_d2q<1>};
#endif

#define make_trunctype_fp_convop(name, roundop, truncop) \
template <int trunc> \
void name(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) { \
  W64 rd; vec4f fpa, fpb; \
  if (trunc) { \
    asm(MOV_TO_XMM " %[ra],%[fpa]; " MOV_TO_XMM " %[rb],%[fpb]; movlhps %[fpa],%[fpb]; " #truncop " %[fpb],%[fpb]; " MOV_TO_XMM " %[fpb],%[rd];" \
        : [rd] "=" W64_CONSTRAINT (rd), [fpa] "=x" (fpa), [fpb] "=x" (fpb) \
        : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); \
  } else { \
    asm(MOV_TO_XMM " %[ra],%[fpa]; " MOV_TO_XMM " %[rb],%[fpb]; movlhps %[fpa],%[fpb]; " #roundop " %[fpb],%[fpb]; " MOV_TO_XMM " %[fpb],%[rd];" \
        : [rd] "=" W64_CONSTRAINT (rd), [fpa] "=x" (fpa), [fpb] "=x" (fpb) \
        : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); \
  } \
  state.reg.rddata = rd; \
  state.reg.rdflags = 0; \
}

#define make_fp_convop_allrounds(name, roundop, truncop) \
  make_trunctype_fp_convop(uop_impl_##name, roundop, truncop); \
  uopimpl_func_t implmap_##name[2] = {&uop_impl_##name<0>, &uop_impl_##name<1>}

make_fp_convop_allrounds(cvtf_s2i_p, cvtps2dq, cvttps2dq);
make_fp_convop_allrounds(cvtf_d2i_p, cvtpd2dq, cvttpd2dq);
make_fp_convop_allrounds(cvtf_d2s_p, cvtpd2ps, cvtpd2ps);

uopimpl_func_t get_synthcode_for_uop(int op, int size, bool setflags, int cond, int extshift, int sfra, int cachelevel, bool except, bool internal) {
  uopimpl_func_t func = null;
  switch (op) {
  case OP_nop:
    func = uop_impl_nop; break;
  case OP_mov: 
    func = implmap_mov[size][0]; break;
  case OP_and:
    func = implmap_and[size][setflags]; break;
  case OP_or: 
    func = implmap_or[size][setflags]; break;
  case OP_xor: 
    func = implmap_xor[size][setflags]; break;
  case OP_andnot: 
    func = implmap_andnot[size][setflags]; break;
  case OP_ornot: 
    func = implmap_ornot[size][setflags]; break;
  case OP_nand: 
    func = implmap_nand[size][setflags]; break;
  case OP_nor: 
    func = implmap_nor[size][setflags]; break;
  case OP_eqv: 
    func = implmap_eqv[size][setflags]; break;
  case OP_add: 
    func = implmap_add[size][setflags]; break;
  case OP_sub: 
    func = implmap_sub[size][setflags]; break;
  case OP_adda:
    func = implmap_adda[size][extshift][setflags]; break;
  case OP_adds:
    func = implmap_adds[size][extshift][setflags]; break;
  case OP_suba:
    func = implmap_suba[size][extshift][setflags]; break;
  case OP_subs:
    func = implmap_subs[size][extshift][setflags]; break;
  case OP_addm:
    func = implmap_addm[size][setflags]; break;
  case OP_subm: 
    func = implmap_subm[size][setflags]; break;
  case OP_addc: 
    func = implmap_addc[size][setflags]; break;
  case OP_subc: 
    func = implmap_subc[size][setflags]; break;

  case OP_sel:
    func = implmap_sel[cond][size]; break;
  case OP_set:
    func = implmap_set[cond][size]; break;
  case OP_br:
    func = implmap_br[cond][except]; break;
  case OP_br_sub:
    func = implmap_br_sub[cond][size][except]; break;
  case OP_br_and:
    func = implmap_br_and[cond][size][except]; break;
  case OP_jmp:
    func = (except ? uop_impl_jmp_ex: uop_impl_jmp); break;
  case OP_bru:
    func = uop_impl_bru; break;
  case OP_brp:
    func = uop_impl_brp; break;
  case OP_chk:
    func = implmap_chk[cond][0]; break;
  case OP_chk_sub:
    func = implmap_chk_sub[cond][size]; break;
  case OP_chk_and:
    func = implmap_chk_and[cond][size]; break;

  case OP_ld_pre:
    func = implmap_ld_pre[cachelevel]; break;

    //
    // Loads and stores are handled specially in the out-of-order core:
    //
  case OP_ld:
  case OP_ldx:
  case OP_st:
    func = uop_impl_nop; break;
  case OP_rotl: 
    func = implmap_rotl[size][setflags]; break;
  case OP_rotr: 
    func = implmap_rotr[size][setflags]; break;
  case OP_rotcl: 
    func = implmap_rotcl[size][setflags]; break;
  case OP_rotcr: 
    func = implmap_rotcr[size][setflags]; break;
  case OP_shl: 
    func = implmap_shl[size][setflags]; break;
  case OP_shr: 
    func = implmap_shr[size][setflags]; break;
  case OP_sar:
    func = implmap_sar[size][setflags]; break;
  case OP_mask:
    func = implmap_mask[size][cond]; break;

  case OP_shls: 
    func = implmap_shl[size][setflags]; break;
  case OP_shrs: 
    func = implmap_shr[size][setflags]; break;
  case OP_sars:
    func = implmap_sar[size][setflags]; break;
  case OP_maskb:
    func = implmap_mask[size][cond]; break;

  case OP_bswap:
    func = implmap_bswap[size][0]; break;
  case OP_collcc:
    func = uop_impl_collcc; break;
  case OP_movccr:
    func = uop_impl_movccr; break;
  case OP_movrcc:
    func = uop_impl_movrcc; break;
  case OP_andcc:
    func = uop_impl_andcc; break;
  case OP_orcc:
    func = uop_impl_orcc; break;
  case OP_ornotcc:
    func = uop_impl_ornotcc; break;
  case OP_xorcc:
    func = uop_impl_xorcc; break;

  case OP_mull:
    func = implmap_mull[size][setflags]; break;
  case OP_mulh:
    func = implmap_mulh[size][setflags]; break;
  case OP_mulhu:
    func = implmap_mulhu[size][setflags]; break;
  case OP_bt:
    func = implmap_bt[size][setflags]; break;
  case OP_bts:
    func = implmap_bts[size][setflags]; break;
  case OP_btr:
    func = implmap_btr[size][setflags]; break;
  case OP_btc:
    func = implmap_btc[size][setflags]; break;
  case OP_ctz: 
    func = implmap_ctz[size][setflags]; break;
  case OP_clz: 
    func = implmap_clz[size][setflags]; break;

  case OP_addf:
    func = implmap_addf[size]; break;
  case OP_subf:
    func = implmap_subf[size]; break;
  case OP_mulf:
    func = implmap_mulf[size]; break;
  case OP_maddf:
    func = implmap_maddf[size]; break;
  case OP_msubf:
    func = implmap_msubf[size]; break;
  case OP_divf:
    func = implmap_divf[size]; break;
  case OP_sqrtf:
    func = implmap_sqrtf[size]; break;
  case OP_rcpf:
    func = implmap_rcpf[size]; break;
  case OP_rsqrtf:
    func = implmap_rsqrtf[size]; break;
  case OP_minf:
    func = implmap_minf[size]; break;
  case OP_maxf:
    func = implmap_maxf[size]; break;
  case OP_cmpf:
    func = implmap_cmpf[cond][size]; break;
  case OP_cmpccf:
    func = implmap_cmpccf[cond][size]; break;

  case OP_cvtf_i2s_ins:
    func = uop_impl_cvtf_i2s_ins; break;

  case OP_cvtf_i2s_p:
    func = uop_impl_cvtf_i2s_p; break;
  case OP_cvtf_i2d_lo:
    func = uop_impl_cvtf_i2d_lo; break;
  case OP_cvtf_i2d_hi:
    func = uop_impl_cvtf_i2d_hi; break;

  case OP_cvtf_q2s_ins:
    func = uop_impl_cvtf_q2s_ins; break;
  case OP_cvtf_q2d:
    func = uop_impl_cvtf_q2d; break;

  case OP_cvtf_s2i:
    func = implmap_cvtf_s2i[size]; break;
  case OP_cvtf_s2q:
    func = implmap_cvtf_s2q[size]; break;
  case OP_cvtf_s2i_p:
    func = implmap_cvtf_s2i_p[size]; break;
  case OP_cvtf_d2i:
    func = implmap_cvtf_d2i[size]; break;
  case OP_cvtf_d2q:
    func = implmap_cvtf_d2q[size]; break;

  case OP_cvtf_d2i_p:
    func = implmap_cvtf_d2i_p[size]; break;
  case OP_cvtf_d2s_ins:
    func = uop_impl_cvtf_d2s_ins; break;
  case OP_cvtf_d2s_p:
    func = implmap_cvtf_d2s_p[0]; break;

  case OP_cvtf_s2d_lo:
    func = uop_impl_cvtf_s2d_lo; break;
  case OP_cvtf_s2d_hi:
    func = uop_impl_cvtf_s2d_hi; break;

  default:
    logfile << "Unknown uop opcode ", op, flush, " (", nameof(op), ")", endl, flush;
    assert(false);
  }
  return func;
}

void synth_uops_for_bb(BasicBlock& bb) {
  bb.synthops = new uopimpl_func_t[bb.count];
  foreach (i, bb.count) {
    const TransOp& transop = bb.transops[i];
    int sfra = 0;
    bool except = 0;

    uopimpl_func_t func = get_synthcode_for_uop(transop.opcode, transop.size, transop.setflags, transop.cond, transop.extshift, sfra, transop.cachelevel, except, transop.internal);
    bb.synthops[i] = func;
  }
}

uopimpl_func_t get_synthcode_for_cond_branch(int opcode, int cond, int size, bool except) {
  uopimpl_func_t func;

  switch (opcode) {
#ifdef __x86_64__
  case OP_br_sub:
    func = implmap_br_sub[cond][size][except]; break;
  case OP_br_and:
    func = implmap_br_and[cond][size][except]; break;
#endif
  case OP_br:
    func = implmap_br[cond][except]; break;
  default:
    assert(false);
  }

  return func;
}

void init_uops() {
  gen_mask_uop_masks();
}
