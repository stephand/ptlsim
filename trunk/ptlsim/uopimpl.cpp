//
// PTLsim: Cycle Accurate x86-64 Simulator
// Interface to uop implementations
//
// Copyright 2000-2007 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <ptlsim.h>


// No operation
inline void capture_uop_context(const IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags, int opcode, int size, int cond = 0, int extshift = 0, W64 riptaken = 0, W64 ripseq = 0) { }

#ifndef __x86_64__
#define EMULATE_64BIT
#endif

#ifdef __x86_64__
typedef W64 Wmax;
#else
typedef W32 Wmax;
#endif

// void uop_impl_bogus(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) { asm("int3"); }

template <typename T>
static inline T rotr(T r, int n) { asm("ror %%cl,%[r]" : [r] "+q" (r) : [n] "c" ((byte)n)); return r; }

template <typename T>
static inline T rotl(T r, int n) { asm("rol %%cl,%[r]" : [r] "+q" (r) : [n] "c" ((byte)n)); return r; }

#ifndef __x86_64__
// Need to emulate this on 32-bit x86
template <>
static inline W64 rotr(W64 r, int n) {
  return (r >> n) | (r << (64 - n));
}
#endif

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
      asm(pretext #opcode " %[rb],%[ra]; setc %[cf]; seto %[of]" : [ra] "+q" (ra), [cf] "=q" (cf), [of] "=q" (of) : [rb] "qm" (rb), [rcflags] "rm" (rcflags)); \
    else asm(#opcode " %[rb],%[ra]" : [ra] "+q" (ra) : [rb] "qm" (rb) : "flags"); \
    return ra; \
  } \
}

void uop_impl_nop(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  state.reg.rddata = 0;
  state.reg.rdflags = 0;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_nop, 0);
}

//
// 2-operand ALU operation
//
template <int ptlopcode, template<typename, int> class func, typename T, int genflags>
inline void aluop(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  byte cf = 0, of = 0;
  func<T, genflags> f;
  T rt = f(ra, rb, rc, raflags, rbflags, rcflags, cf, of);
  state.reg.rddata = x86_merge<T>(ra, rt);
  state.reg.rdflags = (of << 11) | cf | ((genflags & SETFLAG_ZF) ? x86_genflags<T>(rt) : 0);
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, log2(sizeof(T)));
}

#define make_anyop_all_sizes(ptlopcode, mapname, opclass, nativeop, flagset) \
uopimpl_func_t mapname[4][2] = { \
  {&opclass<ptlopcode, nativeop, W8,  0>, &opclass<ptlopcode, nativeop, W8,  (flagset)>}, \
  {&opclass<ptlopcode, nativeop, W16, 0>, &opclass<ptlopcode, nativeop, W16, (flagset)>}, \
  {&opclass<ptlopcode, nativeop, W32, 0>, &opclass<ptlopcode, nativeop, W32, (flagset)>}, \
  {&opclass<ptlopcode, nativeop, W64, 0>, &opclass<ptlopcode, nativeop, W64, (flagset)>} \
}

#define make_aluop_all_sizes(ptlopcode, mapname, nativeop, flagset) make_anyop_all_sizes(ptlopcode, mapname, aluop, nativeop, flagset);

#define make_exp_aluop_all_sizes(name, exp, setflags) \
  make_exp_aluop(exp_op_ ## name, (exp)); \
  make_aluop_all_sizes(OP_ ## name, implmap_ ## name, exp_op_ ## name, (setflags));

#define make_x86_aluop_all_sizes(name, opcode, setflags, pretext) \
  make_x86_aluop2(x86_op_ ## name, opcode, pretext); \
  make_aluop_all_sizes(OP_ ## name, implmap_ ## name, x86_op_ ## name, (setflags));

#define PRETEXT_NO_FLAGS_IN ""
#define PRETEXT_ALL_FLAGS_IN "pushw %[rcflags]; popfw; "

//make_x86_aluop_all_sizes(add, add, ZAPS|CF|OF, PRETEXT_NO_FLAGS_IN);
//make_x86_aluop_all_sizes(sub, sub, ZAPS|CF|OF, PRETEXT_NO_FLAGS_IN);

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

template <int ptlopcode, template<typename, int> class func, typename T, int genflags>
inline void ctzclzop(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  byte cf = 0, of = 0;
  func<T, genflags> f;
  T rt = f(ra, rb, rc, raflags, rbflags, rcflags, cf, of);
  state.reg.rddata = x86_merge<T>(ra, rt);
  state.reg.rdflags = (((T)rb) == 0) ? FLAG_ZF : 0;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, log2(sizeof(T)));
}

make_exp_aluop(exp_op_ctz, (rd = (rb) ? lsbindex64(rb) : 0));
make_anyop_all_sizes(OP_ctz, implmap_ctz, ctzclzop, exp_op_ctz, ZAPS);

make_exp_aluop(exp_op_clz, (rd = (rb) ? msbindex64(rb) : 0));
make_anyop_all_sizes(OP_clz, implmap_clz, ctzclzop, exp_op_clz, ZAPS);

void uop_impl_collcc(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  int flags = (raflags & FLAG_ZAPS) | (rbflags & FLAG_CF) | (rcflags & FLAG_OF);
  state.reg.rddata = flags;
  state.reg.rdflags = flags;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_collcc, 0);
}

void uop_impl_movrcc(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  int flags = rb & FLAG_NOT_WAIT_INV;
  state.reg.rddata = flags;
  state.reg.rdflags = flags;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_movrcc, 0);
}

void uop_impl_movccr(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  int flags = rbflags;
  state.reg.rddata = flags;
  state.reg.rdflags = flags;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_movccr, 0);
}

void uop_impl_andcc(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  state.reg.rddata = 0;
  state.reg.rdflags = (raflags & rbflags) & FLAG_NOT_WAIT_INV;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_andcc, 0);
}

void uop_impl_orcc(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  state.reg.rddata = 0;
  state.reg.rdflags = (raflags | rbflags) & FLAG_NOT_WAIT_INV;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_orcc, 0);
}

void uop_impl_ornotcc(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  state.reg.rddata = 0;
  state.reg.rdflags = (raflags | (~rbflags)) & FLAG_NOT_WAIT_INV;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_ornot, 0);
}

void uop_impl_xorcc(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  state.reg.rddata = 0;
  state.reg.rdflags = (raflags ^ rbflags) & FLAG_NOT_WAIT_INV;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_xorcc, 0);
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
#endif

make_x86_aluop_all_sizes(add, adc, ZAPS|CF|OF, PRETEXT_ALL_FLAGS_IN);
make_x86_aluop_all_sizes(sub, sbb, ZAPS|CF|OF, PRETEXT_ALL_FLAGS_IN);

#ifdef EMULATE_64BIT
make_x86_aluop2_chained_64bit(add, adc, adc, PRETEXT_ALL_FLAGS_IN);
make_x86_aluop2_chained_64bit(sub, sbb, sbb, PRETEXT_ALL_FLAGS_IN);
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

template <int ptlopcode, template<typename, int> class func, typename T, int genflags, int rcshift>
inline void aluop3s(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  byte cf = 0, of = 0;
  func<T, genflags> f;
  T rt = f(ra, rb, rc << rcshift, raflags, rbflags, rcflags, cf, of);
  state.reg.rddata = x86_merge<T>(ra, rt);
  // Do not generate of or cf for the 3-ops:
  state.reg.rdflags = x86_genflags<T>(rt);
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, log2(sizeof(T)), 0, rcshift);
}

// [size][extshift][setflags]
#define make_aluop3s_all_sizes_all_shifts(ptlopcode, mapname, nativeop, flagset) \
uopimpl_func_t mapname[4][4][2] = { \
  { \
    {&aluop3s<ptlopcode, nativeop, W8,  0, 0>, &aluop3s<ptlopcode, nativeop, W8,  (flagset), 0>}, \
    {&aluop3s<ptlopcode, nativeop, W8,  0, 1>, &aluop3s<ptlopcode, nativeop, W8,  (flagset), 1>}, \
    {&aluop3s<ptlopcode, nativeop, W8,  0, 2>, &aluop3s<ptlopcode, nativeop, W8,  (flagset), 2>}, \
    {&aluop3s<ptlopcode, nativeop, W8,  0, 3>, &aluop3s<ptlopcode, nativeop, W8,  (flagset), 3>}, \
  }, \
  { \
    {&aluop3s<ptlopcode, nativeop, W16, 0, 0>, &aluop3s<ptlopcode, nativeop, W16, (flagset), 0>}, \
    {&aluop3s<ptlopcode, nativeop, W16, 0, 1>, &aluop3s<ptlopcode, nativeop, W16, (flagset), 1>}, \
    {&aluop3s<ptlopcode, nativeop, W16, 0, 2>, &aluop3s<ptlopcode, nativeop, W16, (flagset), 2>}, \
    {&aluop3s<ptlopcode, nativeop, W16, 0, 3>, &aluop3s<ptlopcode, nativeop, W16, (flagset), 3>}, \
  }, \
  { \
    {&aluop3s<ptlopcode, nativeop, W32, 0, 0>, &aluop3s<ptlopcode, nativeop, W32, (flagset), 0>}, \
    {&aluop3s<ptlopcode, nativeop, W32, 0, 1>, &aluop3s<ptlopcode, nativeop, W32, (flagset), 1>}, \
    {&aluop3s<ptlopcode, nativeop, W32, 0, 2>, &aluop3s<ptlopcode, nativeop, W32, (flagset), 2>}, \
    {&aluop3s<ptlopcode, nativeop, W32, 0, 3>, &aluop3s<ptlopcode, nativeop, W32, (flagset), 3>}, \
  }, \
  { \
    {&aluop3s<ptlopcode, nativeop, W64, 0, 0>, &aluop3s<ptlopcode, nativeop, W64, (flagset), 0>}, \
    {&aluop3s<ptlopcode, nativeop, W64, 0, 1>, &aluop3s<ptlopcode, nativeop, W64, (flagset), 1>}, \
    {&aluop3s<ptlopcode, nativeop, W64, 0, 2>, &aluop3s<ptlopcode, nativeop, W64, (flagset), 2>}, \
    {&aluop3s<ptlopcode, nativeop, W64, 0, 3>, &aluop3s<ptlopcode, nativeop, W64, (flagset), 3>}, \
  }, \
}

  //make_x86_aluop3(x86_op_ ## name, opcode1, opcode2); \

#define make_exp_aluop3_all_sizes_all_shifts(ptlopcode, name, expr, setflags) \
  make_exp_aluop(exp_op_ ## name, (expr)); \
  make_aluop3s_all_sizes_all_shifts(ptlopcode, implmap_ ## name, exp_op_ ## name, (setflags));

make_exp_aluop3_all_sizes_all_shifts(OP_adda, adda, (rd = (ra + rb + rc)), 0);
make_exp_aluop3_all_sizes_all_shifts(OP_suba, suba, (rd = (ra - rb + rc)), 0);

/*
make_x86_aluop3_all_sizes_all_shifts(adda, add, add, ZAPS|CF|OF);
make_x86_aluop3_all_sizes_all_shifts(adds, add, sub, ZAPS|CF|OF);
make_x86_aluop3_all_sizes_all_shifts(suba, sub, add, ZAPS|CF|OF);
make_x86_aluop3_all_sizes_all_shifts(subs, sub, sub, ZAPS|CF|OF);
*/

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

/*
make_x86_aluop3_chained_64bit(adda, add, add, adc, adc);
make_x86_aluop3_chained_64bit(adds, add, sub, adc, sbb);
make_x86_aluop3_chained_64bit(suba, sub, add, sbb, adc);
make_x86_aluop3_chained_64bit(subs, sub, sub, sbb, sbb);
*/

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

template <int ptlopcode, template<typename, int> class func, typename T, int genflags>
inline void shiftop(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  byte cf = 0, of = 0;
  func<T, genflags> f;
  T rt = f(ra, rb, rc, raflags, rbflags, rcflags, cf, of);
  state.reg.rddata = x86_merge<T>(ra, rt);
  int allflags = (of << 11) | cf | x86_genflags<T>(rt);
  state.reg.rdflags = (rb == 0) ? rcflags : allflags;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, log2(sizeof(T)));
}

#define make_shiftop_all_sizes(ptlopcode, mapname, nativeop, flagset) make_anyop_all_sizes(ptlopcode, mapname, shiftop, nativeop, flagset)

#define make_x86_shiftop_all_sizes(name, opcode, setflags, pretext) \
  make_x86_shiftop(x86_op_ ## name, opcode, pretext); \
  make_shiftop_all_sizes(OP_ ## name, implmap_ ## name, x86_op_ ## name, (setflags));

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

make_x86_shiftop_all_sizes(shls, shl, ZAPS|CF|OF, PRETEXT_NO_FLAGS_IN);
make_x86_shiftop_all_sizes(shrs, shr, ZAPS|CF|OF, PRETEXT_NO_FLAGS_IN);
make_x86_shiftop_all_sizes(sars, sar, ZAPS|CF|OF, PRETEXT_NO_FLAGS_IN);

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
make_exp_shiftop_64bit(rotcl, (assert(false), rd)); // not supported in 32-bit mode because it's too complex
make_exp_shiftop_64bit(rotcr, (assert(false), rd)); // not supported in 32-bit mode because it's too complex
#endif

//
// Masks
//

template <int ptlopcode, typename T, int ZEROEXT, int SIGNEXT>
void exp_op_mask(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  static const int sizeshift = log2(sizeof(T));
  W64 shmask = bitmask(6); //bitmask(3 + sizeshift);
  shmask = shmask | (shmask << 6) | (shmask << 12);
  rc &= shmask;

  int ms = bits(rc, 0, 6);
  int mc = bits(rc, 6, 6);
  int ds = bits(rc, 12, 6);

  int mcms = bits(rc, 0, 12);

  // M = 1'[(ms+mc-1):ms]
  W64 M = rotr<T>(bitmask(mc), ms);
  W64 rd = (ra & ~M) | (rotr<T>(rb, ds) & M);

#if 0
  // For debugging purposes:
  if unlikely (logable(5)) {
    logfile << "mask [", sizeof(T), ", ", ZEROEXT, ", ", SIGNEXT, ", ss = ", sizeshift, ", mcms ", mcms, " [shmask ", bitstring(shmask, 18), " (ms=", ms, " mc=", mc, " ds=", ds, " (mcms ", mcms, "))]:", endl;
    logfile << "  M      = ", bitstring(M, 64), " 0x", hexstring(M, 64), endl;
    logfile << "  rot rb = ", bitstring(rotr<T>(rb, ds), 64), " 0x", hexstring(rotr<T>(rb, ds), 64), endl;
    logfile << "  ra     = ", hexstring(ra, 64), endl;
    logfile << "  rb     = ", hexstring(rb, 64), endl;
    logfile << "  rc     = ", hexstring(rc, 64), endl;
    logfile << "  initrd = ", hexstring(rd, 64), endl;
  }
#endif

  if (ZEROEXT) {
    // rd = rd & 1'[(ms+mc-1):0]
    rd = rd & bitmask(ms+mc);
  } else if (SIGNEXT) {
    // rd = (rd[mc+ms-1]) ? (rd | 1'[63:(ms+mc)]) : (rd & 1'[(ms+mc-1):0]);
    rd = signext64(rd, ms+mc);
  } else {
    rd = rd;
  }

  state.reg.rddata = x86_merge<T>(ra, rd);
  state.reg.rdflags = x86_genflags<T>(rd);
  bool sf = bit(state.reg.rdflags, log2(FLAG_SF));
  //
  // To simplify the microcode construction of the shrd instruction,
  // the following sequence may be used:
  //
  // shrd rd,rs:
  // shr  t = rd,c
  //      t.cf = rd[c-1] last bit shifted out
  //      t.of = rd[63]  or whatever rd's original sign bit position was
  // mask rd = t,rs,[ms=c, mc=c, ds=c]
  //      rd.cf = t.cf  inherited from t
  //      rd.of = (out.sf != t.of) i.e. did the sign bit change?
  //
  state.reg.rdflags |= bit(raflags, log2(FLAG_CF)) << (log2(FLAG_CF));
  state.reg.rdflags |= (sf != bit(raflags, log2(FLAG_OF))) << (log2(FLAG_OF));

  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, 0);
}

// [size][exttype]
uopimpl_func_t implmap_mask[4][3] = {
  {&exp_op_mask<OP_mask, W8,  0, 0>, &exp_op_mask<OP_mask, W8,  1, 0>, &exp_op_mask<OP_mask, W8,  0, 1>},
  {&exp_op_mask<OP_mask, W16, 0, 0>, &exp_op_mask<OP_mask, W16, 1, 0>, &exp_op_mask<OP_mask, W16, 0, 1>},
  {&exp_op_mask<OP_mask, W32, 0, 0>, &exp_op_mask<OP_mask, W32, 1, 0>, &exp_op_mask<OP_mask, W32, 0, 1>},
  {&exp_op_mask<OP_mask, W64, 0, 0>, &exp_op_mask<OP_mask, W64, 1, 0>, &exp_op_mask<OP_mask, W64, 0, 1>}
};

// [size][exttype]
uopimpl_func_t implmap_maskb[4][3] = {
  {&exp_op_mask<OP_maskb, W8,  0, 0>, &exp_op_mask<OP_maskb, W8,  1, 0>, &exp_op_mask<OP_maskb, W8,  0, 1>},
  {&exp_op_mask<OP_maskb, W16, 0, 0>, &exp_op_mask<OP_maskb, W16, 1, 0>, &exp_op_mask<OP_maskb, W16, 0, 1>},
  {&exp_op_mask<OP_maskb, W32, 0, 0>, &exp_op_mask<OP_maskb, W32, 1, 0>, &exp_op_mask<OP_maskb, W32, 0, 1>},
  {&exp_op_mask<OP_maskb, W64, 0, 0>, &exp_op_mask<OP_maskb, W64, 1, 0>, &exp_op_mask<OP_maskb, W64, 0, 1>}
};

//
// Permute bytes
//
// Technically this is a generalization of maskb, and maskb can be transformed
// into permb in the pipeline, at the cost of additional muxing logic.
//
void uop_impl_permb(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  union vec128 {
    struct { W64 lo, hi; } w64;
    struct { byte b[16]; } bytes;
  };

  union vec64 {
    struct { W64 data; } w64;
    struct { byte b[8]; } bytes;
  };
  
  vec128 ab;
  vec64 d;

  ab.w64.lo = ra;
  ab.w64.hi = rb;

  foreach (i, 8) {
    int which = bits(rc, i*4, 4);
    d.bytes.b[i] = ab.bytes.b[which];
  }

  state.reg.rddata = d.w64.data;
  state.reg.rdflags = x86_genflags<W64>(d.w64.data);

  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_permb, 0);
}

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
  make_aluop_all_sizes(OP_ ## name, implmap_ ## name, x86_op_ ## name, (setflags));

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
    return !!(rb & FLAG_OF);
  case 1:  // {0, REG_zero, REG_of},   // !of:              jno
    return !(rb & FLAG_OF);
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

#define make_condop_all_conds_any(ptlopcode, subtype, subarrays, mapname, operation) \
uopimpl_func_t implmap_ ## mapname [16]subarrays = { \
  subtype(ptlopcode, operation, 0), \
  subtype(ptlopcode, operation, 1), \
  subtype(ptlopcode, operation, 2), \
  subtype(ptlopcode, operation, 3), \
  subtype(ptlopcode, operation, 4), \
  subtype(ptlopcode, operation, 5), \
  subtype(ptlopcode, operation, 6), \
  subtype(ptlopcode, operation, 7), \
  subtype(ptlopcode, operation, 8), \
  subtype(ptlopcode, operation, 9), \
  subtype(ptlopcode, operation, 10), \
  subtype(ptlopcode, operation, 11), \
  subtype(ptlopcode, operation, 12), \
  subtype(ptlopcode, operation, 13), \
  subtype(ptlopcode, operation, 14), \
  subtype(ptlopcode, operation, 15) \
}

#define make_condop(ptlopcode, operation, cond) &operation<ptlopcode, cond>
#define make_condop_all_sizes(ptlopcode, operation, cond) {&operation<ptlopcode, W8, cond>, &operation<ptlopcode, W16, cond>, &operation<ptlopcode, W32, cond>, &operation<ptlopcode, W64, cond>}

#define make_condop_all_conds(mapname, operation) make_condop_all_conds_any(make_condop_one, [4], mapname, operation)
#define make_condop_all_conds_all_sizes(mapname, operation) make_condop_all_conds_any(OP_ ## mapname, make_condop_all_sizes, [4], mapname, operation)

template <int ptlopcode, typename T, int evaltype>
inline void selop(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  bool istrue = evaluate_cond<evaltype>(rcflags, rcflags);
  state.reg.rddata = x86_merge<T>(ra, (istrue) ? rb : ra);
  state.reg.rdflags = (istrue) ? rbflags : raflags;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, log2(sizeof(T)), evaltype);
}

make_condop_all_conds_all_sizes(sel, selop);

template <int ptlopcode, typename T, int evaltype>
inline void setop(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  bool istrue = evaluate_cond<evaltype>(rcflags, rcflags);
  state.reg.rddata = x86_merge<T>(ra, (istrue) ? rb : 0);
  state.reg.rdflags = (istrue) ? FLAG_CF : 0;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, log2(sizeof(T)));
}

make_condop_all_conds_all_sizes(set, setop);

//
// Branches
//

template <int ptlopcode, typename T, int evaltype, bool excepting>
inline void uop_impl_condbranch(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  W64 riptaken = state.brreg.riptaken;
  W64 ripseq = state.brreg.ripseq;
  bool taken = evaluate_cond<evaltype>(raflags, rbflags);
  state.reg.rddata = (taken) ? riptaken : ripseq;
  state.reg.rdflags = (taken) ? FLAG_BR_TK : 0;

  if (excepting & (!taken)) {
    state.reg.rddata = EXCEPTION_BranchMispredict;
    state.reg.rdflags |= FLAG_INV;
  }
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, log2(sizeof(T)), evaltype, excepting, riptaken, ripseq);
}

#define make_branchop_all_excepts(ptlopcode, operation, cond) {&uop_impl_condbranch<ptlopcode, W64, cond, false>, &uop_impl_condbranch<ptlopcode, W64, cond, true>}

make_condop_all_conds_any(OP_br, make_branchop_all_excepts, [2], br, anything);

#define function(expr, rettype, ...) class { public: rettype operator () (__VA_ARGS__) { return (expr); } }

template <typename T> struct sub_flag_gen_op { 
  W16 operator ()(T ra, T rb) { x86_op_sub<T, ZAPS|CF|OF> op; byte cf, of; T rd = op(ra, rb, 0, 0, 0, 0, cf, of); return (of << 11) | cf | x86_genflags<T>(rd); } 
};

template <typename T> struct and_flag_gen_op { 
  W16 operator ()(T ra, T rb) { return x86_genflags<T>(ra & rb); } 
};

template <int ptlopcode, typename T, int evaltype, bool excepting, template<typename> class func_t>
inline void uop_impl_alu_and_condbranch(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  W64 riptaken = state.brreg.riptaken;
  W64 ripseq = state.brreg.ripseq;
  func_t<T> func;
  int flags = func(ra, rb);
  bool taken = evaluate_cond<evaltype>(flags, flags);
  state.reg.rddata = (taken) ? riptaken : ripseq;
  state.reg.rdflags = flags | (taken ? FLAG_BR_TK : 0);

  if (excepting & (!taken)) {
    state.reg.rddata = EXCEPTION_BranchMispredict;
    state.reg.rdflags |= FLAG_INV;
  }
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, log2(sizeof(T)), evaltype, excepting, riptaken, ripseq);
}

#define make_alu_and_branchop_all_sizes_all_excepts(ptlopcode, operation, cond) \
  { \
    {&uop_impl_alu_and_condbranch<ptlopcode, W8,  cond, false, operation>, &uop_impl_alu_and_condbranch<ptlopcode, W8,  cond, true, operation>}, \
    {&uop_impl_alu_and_condbranch<ptlopcode, W16, cond, false, operation>, &uop_impl_alu_and_condbranch<ptlopcode, W16, cond, true, operation>}, \
    {&uop_impl_alu_and_condbranch<ptlopcode, W32, cond, false, operation>, &uop_impl_alu_and_condbranch<ptlopcode, W32, cond, true, operation>}, \
    {&uop_impl_alu_and_condbranch<ptlopcode, W64, cond, false, operation>, &uop_impl_alu_and_condbranch<ptlopcode, W64, cond, true, operation>}, \
  }

make_condop_all_conds_any(OP_br_and, make_alu_and_branchop_all_sizes_all_excepts, [4][2], br_and, and_flag_gen_op);
make_condop_all_conds_any(OP_br_sub, make_alu_and_branchop_all_sizes_all_excepts, [4][2], br_sub, sub_flag_gen_op);

void uop_impl_jmp(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  W64 riptaken = state.brreg.riptaken;
  bool taken = (riptaken == ra);
  state.reg.rddata = ra;
  state.reg.rdflags = (taken) ? FLAG_BR_TK : 0;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_jmp, 0, 0, 0, riptaken, riptaken);
}

void uop_impl_jmp_ex(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  W64 riptaken = state.brreg.riptaken;
  bool taken = (riptaken == ra);
  state.reg.rddata = ra;
  state.reg.rdflags = (taken) ? FLAG_BR_TK : 0;

  if (!taken) {
    state.reg.rddata = EXCEPTION_BranchMispredict;
    state.reg.rdflags |= FLAG_INV;
  }
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_jmp, 0, 0, 1, riptaken, riptaken);
}

void uop_impl_bru(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  W64 riptaken = state.brreg.riptaken;
  state.reg.rddata = riptaken;
  state.reg.rdflags = FLAG_BR_TK;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_bru, 0, 0, 0, riptaken, riptaken);
}

void uop_impl_brp(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  W64 riptaken = state.brreg.riptaken;
  state.reg.rddata = state.brreg.riptaken;
  state.reg.rdflags = FLAG_BR_TK;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_brp, 0, 0, 0, riptaken, riptaken);
}

//
// Checks
//
template <int ptlopcode, int evaltype>
inline void uop_impl_chk(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  bool passed = evaluate_cond<evaltype>(raflags, rbflags);
  state.reg.rddata = (passed) ? 0 : rc;
  state.reg.addr = 0;
  state.reg.rdflags = (passed) ? 0 : FLAG_INV;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_chk, 0);
}

template <int ptlopcode, typename T, int evaltype>
inline void uop_impl_chk_sub(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  sub_flag_gen_op<T> func;
  int flags = func(ra, rb);
  bool passed = evaluate_cond<evaltype>(flags, flags);
  state.reg.rddata = (passed) ? 0 : rc;
  state.reg.addr = 0;
  state.reg.rdflags = (passed) ? 0 : FLAG_INV;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, log2(sizeof(T)), evaltype);
}

template <int ptlopcode, typename T, int evaltype>
inline void uop_impl_chk_and(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  and_flag_gen_op<T> func;
  int flags = func(ra, rb);
  bool passed = evaluate_cond<evaltype>(flags, flags);
  state.reg.rddata = (passed) ? 0 : rc;
  state.reg.addr = 0;
  state.reg.rdflags = (passed) ? 0 : FLAG_INV;
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, log2(sizeof(T)), evaltype);
}

make_condop_all_conds_any(OP_chk, make_condop, [1], chk, uop_impl_chk);
make_condop_all_conds_all_sizes(chk_sub, uop_impl_chk_sub);
make_condop_all_conds_all_sizes(chk_and, uop_impl_chk_and);

//
// Floating Point
//
#define make_exp_floatop(name, expr) template <typename T> struct name { T operator ()(T ra, T rb, T rc) { T rd; expr; return rd; } }

template <int ptlopcode, template<typename> class F, int datatype>
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
  capture_uop_context(state, raraw, rbraw, rcraw, raflags, rbflags, rcflags, ptlopcode, datatype);
}

#define make_exp_floatop_alltypes(name, expr) \
  make_exp_floatop(exp_op_##name, expr); \
  uopimpl_func_t implmap_##name[4] = {&floatop<OP_ ##name, exp_op_##name, 0>, &floatop<OP_ ##name, exp_op_##name, 1>,  &floatop<OP_ ##name, exp_op_##name, 2>,  &floatop<OP_ ##name, exp_op_##name, 3>}

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
template <int ptlopcode, int datatype> \
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
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, datatype); \
}

#define make_x86_floatop3(name, opcode1, opcode2, typemask) \
template <int ptlopcode, int datatype> \
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
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, datatype); \
}

#define SS (1<<0)
#define PS (1<<1)
#define DP (1<<2)

#define make_x86_floatop_alltypes(name, opcode, typemask) \
  make_x86_floatop2(x86_op_##name, opcode, typemask, ""); \
  uopimpl_func_t implmap_##name[4] = {&x86_op_##name<OP_##name, 0>, &x86_op_##name<OP_##name, 1>, &x86_op_##name<OP_##name, 2>, &x86_op_##name<OP_##name, 3>}

#define make_x86_floatop3_alltypes(name, opcode1, opcode2, typemask) \
  make_x86_floatop3(x86_op_##name, opcode1, opcode2, typemask); \
  uopimpl_func_t implmap_##name[4] = {&x86_op_##name<OP_##name, 0>, &x86_op_##name<OP_##name, 1>, &x86_op_##name<OP_##name, 2>, &x86_op_##name<OP_##name, 3>}

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
  {&x86_op_cmpf0<OP_cmpf, 0>, &x86_op_cmpf0<OP_cmpf, 1>, &x86_op_cmpf0<OP_cmpf, 2>, &x86_op_cmpf0<OP_cmpf, 3>},
  {&x86_op_cmpf1<OP_cmpf, 0>, &x86_op_cmpf1<OP_cmpf, 1>, &x86_op_cmpf1<OP_cmpf, 2>, &x86_op_cmpf1<OP_cmpf, 3>},
  {&x86_op_cmpf2<OP_cmpf, 0>, &x86_op_cmpf2<OP_cmpf, 1>, &x86_op_cmpf2<OP_cmpf, 2>, &x86_op_cmpf2<OP_cmpf, 3>},
  {&x86_op_cmpf3<OP_cmpf, 0>, &x86_op_cmpf3<OP_cmpf, 1>, &x86_op_cmpf3<OP_cmpf, 2>, &x86_op_cmpf3<OP_cmpf, 3>},
  {&x86_op_cmpf4<OP_cmpf, 0>, &x86_op_cmpf4<OP_cmpf, 1>, &x86_op_cmpf4<OP_cmpf, 2>, &x86_op_cmpf4<OP_cmpf, 3>},
  {&x86_op_cmpf5<OP_cmpf, 0>, &x86_op_cmpf5<OP_cmpf, 1>, &x86_op_cmpf5<OP_cmpf, 2>, &x86_op_cmpf5<OP_cmpf, 3>},
  {&x86_op_cmpf6<OP_cmpf, 0>, &x86_op_cmpf6<OP_cmpf, 1>, &x86_op_cmpf6<OP_cmpf, 2>, &x86_op_cmpf6<OP_cmpf, 3>},
  {&x86_op_cmpf7<OP_cmpf, 0>, &x86_op_cmpf7<OP_cmpf, 1>, &x86_op_cmpf7<OP_cmpf, 2>, &x86_op_cmpf7<OP_cmpf, 3>}
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
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_cmpccf, comptype);
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
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_##name, 0); \
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
  capture_uop_context(state, raraw, rbraw, rcraw, raflags, rbflags, rcflags, OP_##name, 0); \
}

make_intsrc_fp_convop(cvtf_i2s_ins, (rd.f.lo = (float)(W32s)rb.w32.lo, rd.w32.hi = ra.w32.hi));
make_intsrc_fp_convop(cvtf_q2s_ins, (rd.f.lo = (float)(W64s)rb.w64, rd.w32.hi = ra.w32.hi));
make_intsrc_fp_convop(cvtf_q2d, (rd.d = (double)(W64s)rb.w64));

#define make_intdest_fp_convop(name, desttype, roundop, truncop) \
template <int ptlopcode, int trunc> \
void name(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) { \
  desttype rd; vec4f fpv; \
  if (trunc) { \
    asm(MOV_TO_XMM " %[rb],%[fpv]; " #truncop " %[fpv],%[rd];" \
        : [rd] "=r" (rd), [fpv] "=x" (fpv) : [rb] W64_CONSTRAINT (rb)); \
  } else { \
    asm(MOV_TO_XMM " %[rb],%[fpv]; " #roundop " %[fpv],%[rd];" \
        : [rd] "=r" (rd), [fpv] "=x" (fpv) : [rb] W64_CONSTRAINT (rb)); \
  } \
  state.reg.rddata = rd; \
  state.reg.rdflags = 0; \
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, trunc); \
}

#define make_intdest_fp_convop_allrounds(name, desttype, roundop, truncop) \
  make_intdest_fp_convop(uop_impl_##name, desttype, roundop, truncop); \
  uopimpl_func_t implmap_##name[2] = {&uop_impl_##name<OP_##name, 0>, &uop_impl_##name<OP_##name, 1>}

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
#define make_intdest_fp_convop_x87_64bit(name, T, x87op) \
template <int ptlopcode, int trunc> \
void name(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) { \
  W64 rd = 0; \
  if (trunc) { \
    /* Important! fisttpll (truncating version) is only available on SSE3 machines (P4 Prescott and later K8s) */ \
    /* Therefore, use the ordinary fistp with FPCW rounding tricks */ \
    W16 oldfpcw = cpu_get_fpcw(); \
    cpu_set_fpcw(oldfpcw | 0xc00); /* set truncate rounding mode */ \
    asm(x87op " %[rb]; fisttpll %[rd];" : [rd] "=m" (rd) : [rb] "m" (rb)); \
    cpu_set_fpcw(oldfpcw); \
  } else { \
    asm(x87op " %[rb]; fistpll %[rd];" : [rd] "=m" (rd) : [rb] "m" (rb)); \
  } \
  state.reg.rddata = rd; \
  state.reg.rdflags = 0; \
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, trunc); \
}

make_intdest_fp_convop_x87_64bit(uop_impl_cvtf_s2q, float, "fld");
make_intdest_fp_convop_x87_64bit(uop_impl_cvtf_d2q, double, "fldl");

uopimpl_func_t implmap_cvtf_s2q[2] = {&uop_impl_cvtf_s2q<OP_cvtf_s2q, 0>, &uop_impl_cvtf_s2q<OP_cvtf_s2q, 1>};
uopimpl_func_t implmap_cvtf_d2q[2] = {&uop_impl_cvtf_d2q<OP_cvtf_d2q, 0>, &uop_impl_cvtf_d2q<OP_cvtf_d2q, 1>};
#endif

#define make_trunctype_fp_convop(name, roundop, truncop) \
template <int trunc> \
void uop_impl_##name(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) { \
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
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, OP_##name, trunc); \
}

#define make_fp_convop_allrounds(name, roundop, truncop) \
  make_trunctype_fp_convop(name, roundop, truncop); \
  uopimpl_func_t implmap_##name[2] = {&uop_impl_##name<0>, &uop_impl_##name<1>}

make_fp_convop_allrounds(cvtf_s2i_p, cvtps2dq, cvttps2dq);
make_fp_convop_allrounds(cvtf_d2i_p, cvtpd2dq, cvttpd2dq);
make_fp_convop_allrounds(cvtf_d2s_p, cvtpd2ps, cvtpd2ps);

//
// Vector uops
//
#define make_x86_vecop2(name, opcode, sizemask, extra) \
template <int ptlopcode, int size> \
void name(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) { \
  W64 rd; \
  vec16b va, vb; \
  if ((size == 0) & bit(sizemask, 0)) asm(MOV_TO_XMM " %[ra],%[va]; " MOV_TO_XMM " %[rb],%[vb]; " #opcode "b " extra "%[vb],%[va]; movq %[va],%[rd];" \
     : [rd] "=" W64_CONSTRAINT (rd), [va] "=x" (va), [vb] "=x" (vb) : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); \
  if ((size == 1) & bit(sizemask, 1)) asm(MOV_TO_XMM " %[ra],%[va]; " MOV_TO_XMM " %[rb],%[vb]; " #opcode "w " extra "%[vb],%[va]; movq %[va],%[rd];" \
     : [rd] "=" W64_CONSTRAINT (rd), [va] "=x" (va), [vb] "=x" (vb) : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); \
  if ((size == 2) & bit(sizemask, 2)) asm(MOV_TO_XMM " %[ra],%[va]; " MOV_TO_XMM " %[rb],%[vb]; " #opcode "d " extra "%[vb],%[va]; movq %[va],%[rd];" \
     : [rd] "=" W64_CONSTRAINT (rd), [va] "=x" (va), [vb] "=x" (vb) : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); \
  if ((size == 3) & bit(sizemask, 3)) asm(MOV_TO_XMM " %[ra],%[va]; " MOV_TO_XMM " %[rb],%[vb]; " #opcode "q " extra "%[vb],%[va]; movq %[va],%[rd];" \
     : [rd] "=" W64_CONSTRAINT (rd), [va] "=x" (va), [vb] "=x" (vb) : [ra] W64_CONSTRAINT (ra), [rb] W64_CONSTRAINT (rb)); \
  state.reg.rddata = rd; \
  state.reg.rdflags = 0; \
  capture_uop_context(state, ra, rb, rc, raflags, rbflags, rcflags, ptlopcode, size); \
}

#define make_x86_vecop_allsizes(name, opcode, sizemask) \
  make_x86_vecop2(x86_op_##name, opcode, sizemask, ""); \
  uopimpl_func_t implmap_##name[4] = {&x86_op_##name<OP_##name, 0>, &x86_op_##name<OP_##name, 1>, &x86_op_##name<OP_##name, 2>, &x86_op_##name<OP_##name, 3>}

#define sizes(b,w,d,q) ((b << 0) | (w << 1) | (d << 2) | (q << 3))

make_x86_vecop_allsizes(addv,    padd,   sizes(1,1,1,1));
make_x86_vecop_allsizes(subv,    psub,   sizes(1,1,1,1));
make_x86_vecop_allsizes(addv_us, paddus, sizes(1,1,0,0));
make_x86_vecop_allsizes(subv_us, psubus, sizes(1,1,0,0));
make_x86_vecop_allsizes(addv_ss, padds,  sizes(1,1,0,0));
make_x86_vecop_allsizes(subv_ss, psubs,  sizes(1,1,0,0));

make_x86_vecop_allsizes(shlv,    psll,   sizes(0,1,1,1));
make_x86_vecop_allsizes(shrv,    psrl,   sizes(0,1,1,1));
// btv dealt with later
make_x86_vecop_allsizes(sarv,    psra,   sizes(0,1,1,0));

make_x86_vecop_allsizes(avgv,    pavg,   sizes(1,1,0,0));
// cmpv dealt with later
make_x86_vecop_allsizes(minv,    pminu,  sizes(1,0,0,0));
make_x86_vecop_allsizes(maxv,    pmaxu,  sizes(1,0,0,0));
make_x86_vecop_allsizes(minv_s,  pmins,  sizes(0,1,0,0));
make_x86_vecop_allsizes(maxv_s,  pmaxs,  sizes(0,1,0,0));

make_x86_vecop_allsizes(mullv,   pmull,  sizes(0,1,0,0));
make_x86_vecop_allsizes(mulhv,   pmulh,  sizes(0,1,0,0));
make_x86_vecop_allsizes(mulhuv,  pmulhu, sizes(0,1,0,0));

//
// btv (bit test vector):
//
// Hardware implementation:
//
// static const W64 masks[4] = {
//   0x0101010101010101ULL,
//   0x0001000100010001ULL,
//   0x0000000100000001ULL,
//   0x0000000000000001ULL
// };
//
// int sizebits = (1 << sizeshift) * 8;
// W64 mask = masks[sizeshift] << rb;
// ra &= mask;
//
template <int sizeshift>
void uop_impl_btv(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  int sizebits = (1 << sizeshift) * 8;

  rb = lowbits(rb, 3 + sizeshift);

  W64 rd = 0;

  for (int i = (1 << (3-sizeshift))-1; i >= 0; i--) {
    bool b = bit(ra, (i * sizebits) + rb);
    rd = (rd << 1) | b;
  }

  state.reg.rddata = rd;
  state.reg.rdflags = x86_genflags<W64>(rd);
}

uopimpl_func_t implmap_btv[4] = {&uop_impl_btv<0>, &uop_impl_btv<1>, &uop_impl_btv<2>, &uop_impl_btv<3>};

//
// cmpv (vector compare)
// uop.cond contains the condition test
//

template <typename T>
W16 compare_and_gen_flags(T ra, T rb) {
  byte cf = 0; byte of = 0;
  asm("sub %[rb],%[ra]; setc %[cf]; seto %[of]" : [ra] "+q" (ra), [cf] "=q" (cf), [of] "=q" (of) : [rb] "qm" (rb));
  
  return x86_genflags<T>(ra) | (W16(cf) << 0) | (W16(of) << 11);
}

#ifdef EMULATE_64BIT
template <>
W16 compare_and_gen_flags(W64 ra, W64 rb) {
  byte cf = 0; byte of = 0;
  W32 ralo = LO32(ra); W32 rahi = HI32(ra); W32 rblo = LO32(rb); W32 rbhi = HI32(rb);
  asm("sub %[rblo],%[ralo]\n"
      "sub %[rbhi],%[rahi]\n"
      "setc %[cf]; seto %[of]"
      : [ralo] "+r" (ralo), [rahi] "+r" (rahi), [cf] "=q" (cf), [of] "=q" (of)
      : [rblo] "rm" (rblo), [rbhi] "rm" (rbhi));

  return
    (x86_genflags<byte>(byte(ra)) & FLAG_PF) |
    ((ra) ? 0 : FLAG_ZF) |
    (bit(ra, 63) ? FLAG_SF : 0) |
    (W16(cf) << 0) |
    (W16(of) << 11);
}
#endif

template <int sizeshift, int cond>
void uop_impl_cmpv(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags) {
  int sizebits = (1 << sizeshift) * 8;

  W64 rd = 0;

  for (int i = (1 << (3-sizeshift))-1; i >= 0; i--) {
    W64 a = bits(ra, i*sizebits, sizebits);
    W64 b = bits(rb, i*sizebits, sizebits);
    W16 flags = 0;
    switch (sizeshift) {
    case 0: flags = compare_and_gen_flags<byte>(a, b); break;
    case 1: flags = compare_and_gen_flags<W16>(a, b); break;
    case 2: flags = compare_and_gen_flags<W32>(a, b); break;
    case 3: flags = compare_and_gen_flags<W64>(a, b); break;
    }

    bool z = evaluate_cond<cond>(flags, flags);

    rd <<= sizebits;
    rd |= (z) ? bitmask(sizebits) : 0;
  }

  state.reg.rddata = rd;
  state.reg.rdflags = x86_genflags<W64>(rd);
}

#define makecond(c) {&uop_impl_cmpv<0, c>, &uop_impl_cmpv<1, c>, &uop_impl_cmpv<2, c>, &uop_impl_cmpv<3, c>}

uopimpl_func_t implmap_cmpv[16][4] = {
  makecond(0),
  makecond(1),
  makecond(2),
  makecond(3),
  makecond(4),
  makecond(5),
  makecond(6),
  makecond(7),
  makecond(8),
  makecond(9),
  makecond(10),
  makecond(11),
  makecond(12),
  makecond(13),
  makecond(14),
  makecond(15)
};

#undef makecond
#undef sizes

    /*
    W64 a = lowbits(ra, sizebits);
    W64 b = lowbits(rb, sizebits);
    W64 as = signext64(a, sizebits);
    W64 bs = signext64(b, sizebits);

    bool z = 0;

    switch (cond) {
      // COND_o and COND_no not possible
    case COND_c: case COND_nc: {
      z = (a < b);
      break;
    }
    case COND_e: case COND_ne: {
      z = (a == b);
      break;
    }
    case COND_be: case COND_nbe: {
      // unsigned
      z = (a <= b);
      break;
    }
    // COND_s and COND_ns not possible
    case COND_l: case COND_nl: {
      // signed
      z = (as < bs);
      break;
    }
    case COND_le: case COND_nle: {
      // signed
      z = (as <= bs);
      break;
    }

    (i * (1 << (3+sizeshift)));

    bool b = bit(ra, (i * (1 << (3+sizeshift))) + rb);
    rd = (rd << 1) | b;
    */

uopimpl_func_t get_synthcode_for_uop(int op, int size, bool setflags, int cond, int extshift, bool except, bool internal) {
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
  case OP_suba:
    func = implmap_suba[size][extshift][setflags]; break;
  case OP_addm:
    func = implmap_addm[size][setflags]; break;
  case OP_subm: 
    func = implmap_subm[size][setflags]; break;
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

    //
    // Loads and stores are handled specially in the core model:
    //
  case OP_ld:
  case OP_ldx:
  case OP_ld_pre:
  case OP_st:
  case OP_mf:
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
    func = implmap_shls[size][setflags]; break;
  case OP_shrs: 
    func = implmap_shrs[size][setflags]; break;
  case OP_sars:
    func = implmap_sars[size][setflags]; break;
  case OP_maskb:
    func = implmap_maskb[size][cond]; break;

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
  case OP_permb:
    func = uop_impl_permb; break;

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
    func = implmap_cvtf_s2i[size & 1]; break;
  case OP_cvtf_s2q:
    func = implmap_cvtf_s2q[size & 1]; break;
  case OP_cvtf_s2i_p:
    func = implmap_cvtf_s2i_p[size & 1]; break;
  case OP_cvtf_d2i:
    func = implmap_cvtf_d2i[size & 1]; break;
  case OP_cvtf_d2q:
    func = implmap_cvtf_d2q[size & 1]; break;
  case OP_cvtf_d2i_p:
    func = implmap_cvtf_d2i_p[size & 1]; break;
  case OP_cvtf_d2s_ins:
    func = uop_impl_cvtf_d2s_ins; break;
  case OP_cvtf_d2s_p:
    func = implmap_cvtf_d2s_p[0]; break;

  case OP_cvtf_s2d_lo:
    func = uop_impl_cvtf_s2d_lo; break;
  case OP_cvtf_s2d_hi:
    func = uop_impl_cvtf_s2d_hi; break;

  case OP_addv:
    func = implmap_addv[size]; break;
  case OP_subv:
    func = implmap_subv[size]; break;
  case OP_addv_us:
    func = implmap_addv_us[size]; break;
  case OP_subv_us:
    func = implmap_subv_us[size]; break;
  case OP_addv_ss:
    func = implmap_addv_ss[size]; break;
  case OP_subv_ss:
    func = implmap_subv_ss[size]; break;
  case OP_shlv:
    func = implmap_shlv[size]; break;
  case OP_shrv:
    func = implmap_shrv[size]; break;
  case OP_btv:
    func = implmap_btv[size]; break;
  case OP_sarv:
    func = implmap_sarv[size]; break;
  case OP_avgv:
    func = implmap_avgv[size]; break;
  case OP_cmpv:
    func = implmap_cmpv[cond][size]; break;
  case OP_minv:
    func = implmap_minv[size]; break;
  case OP_maxv:
    func = implmap_maxv[size]; break;
  case OP_minv_s:
    func = implmap_minv_s[size]; break;
  case OP_maxv_s:
    func = implmap_maxv_s[size]; break;
  case OP_mullv:
    func = implmap_mullv[size]; break;
  case OP_mulhv:
    func = implmap_mulhv[size]; break;
  case OP_mulhuv:
    func = implmap_mulhuv[size]; break;
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
    uopimpl_func_t func = get_synthcode_for_uop(transop.opcode, transop.size, transop.setflags, transop.cond, transop.extshift, 0, transop.internal);
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
}

void shutdown_uops() {
}
