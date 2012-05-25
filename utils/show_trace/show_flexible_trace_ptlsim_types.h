/**
 * Manually collected copy of PTLsim's types to allow easy parsing of
 * flexible events.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * Copyright (c) 2010-2012 Advanced Micro Devices, Inc.
 * Contributed by Stephan Diestelhorst <stephan.diestelhorst@amd.com>
 */
#ifndef __SHOW_FLEXIBLE_TRACE_PTLSIM_TYPES_H__
#define __SHOW_FLEXIBLE_TRACE_PTLSIM_TYPES_H__

#include <stdint.h>

typedef uint64_t W64;
typedef uint32_t W32;
typedef uint16_t W16;
typedef uint8_t  W8;
typedef int64_t  W64s;
typedef int32_t  W32s;
typedef int16_t  W16s;
typedef int8_t   W8s;
typedef uint8_t  byte;
typedef W64      Waddr;


using std::ostream;

// TODO: These are a copies from the PTLsim include files. We should do better than that...
static const int MAX_OPERANDS = 4;
const int MAX_CLUSTERS = 4;

struct PTEUpdateBase {
  byte a:1, d:1, ptwrite:1, pad:5;
};

class selfqueuelink {
public:
  selfqueuelink* next;
  selfqueuelink* prev;
};

struct StateList: public selfqueuelink {
  char* name;
  int count;
  int listid;
  W64 dispatch_source_counter;
  W64 issue_source_counter;
  W32 flags;
  // Stripped member functions
};

struct SFR {
  W64 data;
  W64 addrvalid:1, invalid:1, datavalid:1, physaddr:45, bytemask:8, tag:8;
};

struct IssueState {
  union {
    struct {
      W64 rddata;
      W64 addr:48, rdflags:16;
    } reg;

    struct {
      W64 rddata;
      W64 physaddr:48, flags:8, lfrqslot:8;
    } ldreg;

    struct {
      W64 riptaken;
      W64 ripseq;
    } brreg;

    SFR st;
  };
};


inline W64 x86_bsf64(W64 b) { W64 r = 0; asm("bsf %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }
inline unsigned int lsbindex64(W64 n) { return x86_bsf64(n); }
inline unsigned int lsbindex(W64 n) { return lsbindex64(n); }
//
// Operation Classes
//

#define OPCLASS_LOGIC                   (1 << 0)

#define OPCLASS_ADDSUB                  (1 << 1)
#define OPCLASS_ADDSUBC                 (1 << 2)
#define OPCLASS_ADDSHIFT                (1 << 3)
#define OPCLASS_ADD                     (OPCLASS_ADDSUB|OPCLASS_ADDSUBC|OPCLASS_ADDSHIFT)

#define OPCLASS_SELECT                  (1 << 4)
#define OPCLASS_COMPARE                 (1 << 5)
#define OPCLASS_COND_BRANCH             (1 << 6)

#define OPCLASS_INDIR_BRANCH            (1 << 7)
#define OPCLASS_UNCOND_BRANCH           (1 << 8)
#define OPCLASS_ASSIST                  (1 << 9)
#define OPCLASS_BARRIER                 (OPCLASS_ASSIST)
#define OPCLASS_BRANCH                  (OPCLASS_COND_BRANCH|OPCLASS_INDIR_BRANCH|OPCLASS_UNCOND_BRANCH|OPCLASS_ASSIST)

#define OPCLASS_LOAD                    (1 << 11)
#define OPCLASS_STORE                   (1 << 12)
#define OPCLASS_PREFETCH                (1 << 13)
#define OPCLASS_FENCE                   ((1 << 10) | OPCLASS_STORE)
#define OPCLASS_MEM                     (OPCLASS_LOAD|OPCLASS_STORE|OPCLASS_PREFETCH|OPCLASS_FENCE)

#define OPCLASS_SIMPLE_SHIFT            (1 << 14)
#define OPCLASS_SHIFTROT                (1 << 15)
#define OPCLASS_MULTIPLY                (1 << 16)
#define OPCLASS_BITSCAN                 (1 << 17)
#define OPCLASS_FLAGS                   (1 << 18)
#define OPCLASS_CHECK                   (1 << 19)

#define OPCLASS_CONDITIONAL             (OPCLASS_SELECT|OPCLASS_COND_BRANCH|OPCLASS_CHECK)

#define OPCLASS_ALU_SIZE_MERGING        (OPCLASS_LOGIC|OPCLASS_ADD|OPCLASS_SELECT|OPCLASS_SIMPLE_SHIFT|OPCLASS_SHIFTROT|OPCLASS_MULTIPLY|OPCLASS_BITSCAN)

#define OPCLASS_FP_ALU                  (1 << 20)
#define OPCLASS_FP_DIVSQRT              (1 << 21)
#define OPCLASS_FP_COMPARE              (1 << 22)
#define OPCLASS_FP_PERMUTE              (1 << 23)
#define OPCLASS_FP_CONVERTI2F           (1 << 24)
#define OPCLASS_FP_CONVERTF2I           (1 << 25)
#define OPCLASS_FP_CONVERTFP            (1 << 26)

#define OPCLASS_FP                      (OPCLASS_FP_ALU | OPCLASS_FP_DIVSQRT | OPCLASS_FP_COMPARE | OPCLASS_FP_PERMUTE | OPCLASS_FP_CONVERTI2F | OPCLASS_FP_CONVERTF2I, OPCLASS_FP_CONVERTFP)

#define OPCLASS_VEC_ALU                 (1 << 27)

#define OPCLASS_ASF                     (1 << 28)

#define OPCLASS_COUNT                   29

#define OPCLASS_USECOND                 (OPCLASS_COND_BRANCH|OPCLASS_SELECT|OPCLASS_CHECK)

extern const char* opclass_names[OPCLASS_COUNT];

//
// Micro-operations (uops):
// See table in ptlhwdef.cpp for details.
//
enum {
  OP_nop,
  OP_mov,
  // Logical
  OP_and,
  OP_andnot,
  OP_xor,
  OP_or,
  OP_nand,
  OP_ornot,
  OP_eqv,
  OP_nor,
  // Mask, insert or extract bytes
  OP_maskb,
  // Add and subtract
  OP_add,
  OP_sub,
  OP_adda,
  OP_suba,
  OP_addm,
  OP_subm,
  // Condition code logical ops
  OP_andcc,
  OP_orcc,
  OP_xorcc,
  OP_ornotcc,
  // Condition code movement and merging
  OP_movccr,
  OP_movrcc,
  OP_collcc,
  // Simple shifting (restricted to small immediate 1..8)
  OP_shls,
  OP_shrs,
  OP_bswap,
  OP_sars,
  // Bit testing
  OP_bt,
  OP_bts,
  OP_btr,
  OP_btc,
  // Set and select
  OP_set,
  OP_set_sub,
  OP_set_and,
  OP_sel,
  OP_sel_cmp,
  // Branches
  OP_br,
  OP_br_sub,
  OP_br_and,
  OP_jmp,
  OP_bru,
  OP_jmpp,
  OP_brp,
  // Checks
  OP_chk,
  OP_chk_sub,
  OP_chk_and,
  // Loads and stores
  OP_ld,
  OP_ldx,
  OP_ld_pre,
  OP_st,
  OP_mf,
  // Shifts, rotates and complex masking
  OP_shl,
  OP_shr,
  OP_mask,
  OP_sar,
  OP_rotl,
  OP_rotr,
  OP_rotcl,
  OP_rotcr,
  // Multiplication
  OP_mull,
  OP_mulh,
  OP_mulhu,
  OP_mulhl,
  // Bit scans
  OP_ctz,
  OP_clz,
  OP_ctpop,
  OP_permb,
  // Integer divide and remainder step
  OP_div,
  OP_rem,
  OP_divs,
  OP_rems,
  // Minimum and maximum
  OP_min,
  OP_max,
  OP_min_s,
  OP_max_s,
  // Floating point
  OP_fadd,
  OP_fsub,
  OP_fmul,
  OP_fmadd,
  OP_fmsub,
  OP_fmsubr,
  OP_fdiv,
  OP_fsqrt,
  OP_frcp,
  OP_frsqrt,
  OP_fmin,
  OP_fmax,
  OP_fcmp,
  OP_fcmpcc,
  OP_fcvt_i2s_ins,
  OP_fcvt_i2s_p,
  OP_fcvt_i2d_lo,
  OP_fcvt_i2d_hi,
  OP_fcvt_q2s_ins,
  OP_fcvt_q2d,
  OP_fcvt_s2i,
  OP_fcvt_s2q,
  OP_fcvt_s2i_p,
  OP_fcvt_d2i,
  OP_fcvt_d2q,
  OP_fcvt_d2i_p,
  OP_fcvt_d2s_ins,
  OP_fcvt_d2s_p,
  OP_fcvt_s2d_lo,
  OP_fcvt_s2d_hi,
  // Vector integer uops
  // size defines element size: 00 = byte, 01 = W16, 10 = W32, 11 = W64 (same as normal ops)
  OP_vadd,
  OP_vsub,
  OP_vadd_us,
  OP_vsub_us,
  OP_vadd_ss,
  OP_vsub_ss,
  OP_vshl,
  OP_vshr,
  OP_vbt, // bit test vector (e.g. pack bit 7 of 8 bytes into 8-bit output, for pmovmskb)
  OP_vsar,
  OP_vavg,
  OP_vcmp,
  OP_vmin,
  OP_vmax,
  OP_vmin_s,
  OP_vmax_s,
  OP_vmull,
  OP_vmulh,
  OP_vmulhu,
  OP_vmaddp,
  OP_vsad,
  OP_vpack_us,
  OP_vpack_ss,
#ifdef ENABLE_ASF
  // ASF
  OP_spec,
  OP_spec_inv,
  OP_com,
  OP_val,
  OP_rel,
#endif
  OP_MAX_OPCODE,
};

// Limit for shls, shrs, sars rb immediate:
#define SIMPLE_SHIFT_LIMIT 8

struct OpcodeInfo {
  const char* name;
  W32 opclass;
  W16 flagops;
};

//
// flagops field encodings:
//
#define makeccbits(b0, b1, b2) ((b0 << 0) + (b1 << 1) + (b2 << 2))
#define ccA   makeccbits(1, 0, 0)
#define ccB   makeccbits(0, 1, 0)
#define ccAB  makeccbits(1, 1, 0)
#define ccABC makeccbits(1, 1, 1)
#define ccC   makeccbits(0, 0, 1)

#define makeopbits(b3, b4, b5) ((b3 << 3) + (b4 << 4) + (b5 << 5))

#define opA   makeopbits(1, 0, 0)
#define opAB  makeopbits(1, 1, 0)
#define opABC makeopbits(1, 1, 1)
#define opB   makeopbits(0, 1, 0)
#define opC   makeopbits(0, 0, 1)

// Size field is not used
#define opNOSIZE (1 << 6)

extern const OpcodeInfo opinfo[OP_MAX_OPCODE];

inline bool isclass(int opcode, W32 opclass) { return ((opinfo[opcode].opclass & opclass) != 0); }
inline int opclassof(int opcode) { return lsbindex(opinfo[opcode].opclass); }

inline bool isload(int opcode) { return isclass(opcode, OPCLASS_LOAD); }
inline bool isprefetch(int opcode) { return isclass(opcode, OPCLASS_PREFETCH); }
inline bool isstore(int opcode) { return isclass(opcode, OPCLASS_STORE); }
inline bool iscondbranch(int opcode) { return isclass(opcode, OPCLASS_COND_BRANCH|OPCLASS_INDIR_BRANCH); }
inline bool isbranch(int opcode) { return isclass(opcode, OPCLASS_BRANCH); }
inline bool isbarrier(int opcode) { return isclass(opcode, OPCLASS_BARRIER); }
inline bool isasf(int opcode) { return isclass(opcode, OPCLASS_ASF); }
inline const char* nameof(int opcode) { return (opcode < OP_MAX_OPCODE) ? opinfo[opcode].name : "INVALID"; }

const char* opclass_names[OPCLASS_COUNT] = {
  "logic", "addsub", "addsubc", "addshift", "sel", "cmp", "br.cc", "jmp", "bru",
  "assist", "mf", "ld", "st", "ld.pre", "shiftsimple", "shift", "mul", "bitscan", "flags",  "chk",
  "fpu", "fp-div-sqrt", "fp-cmp", "fp-perm", "fp-cvt-i2f", "fp-cvt-f2i", "fp-cvt-f2f", "vec", "asf",
};

//
// Micro-operation (uop) definitions
//
// SD: What is the third field good for? It is never used for anything?!
const OpcodeInfo opinfo[OP_MAX_OPCODE] = {
  // name, opclass, latency, fu
  {"nop",            OPCLASS_LOGIC,         opNOSIZE   },
  {"mov",            OPCLASS_LOGIC,         opAB|ccB   }, // move or merge
  // Logical
  {"and",            OPCLASS_LOGIC,         opAB       },
  {"andnot",         OPCLASS_LOGIC,         opAB       },
  {"xor",            OPCLASS_LOGIC,         opAB       },
  {"or",             OPCLASS_LOGIC,         opAB       },
  {"nand",           OPCLASS_LOGIC,         opAB       },
  {"ornot",          OPCLASS_LOGIC,         opAB       },
  {"eqv",            OPCLASS_LOGIC,         opAB       },
  {"nor",            OPCLASS_LOGIC,         opAB       },
  // Mask, insert or extract bytes
  {"maskb",          OPCLASS_SIMPLE_SHIFT,  opABC      }, // mask rd = ra,rb,[ds,ms,mc], bytes only; rcimm (8 bits, but really 18 bits)
  // Add and subtract
  {"add",            OPCLASS_ADDSUB,        opABC|ccC  }, // ra + rb
  {"sub",            OPCLASS_ADDSUB,        opABC|ccC  }, // ra - rb
  {"adda",           OPCLASS_ADDSHIFT,      opABC      }, // ra + rb + rc
  {"suba",           OPCLASS_ADDSHIFT,      opABC      }, // ra - rb + rc
  {"addm",           OPCLASS_ADDSUB,        opABC      }, // lowbits(ra + rb, m)
  {"subm",           OPCLASS_ADDSUB,        opABC      }, // lowbits(ra - rb, m)
  // Condition code logical ops
  {"andcc",          OPCLASS_FLAGS,         opAB|ccAB|opNOSIZE},
  {"orcc",           OPCLASS_FLAGS,         opAB|ccAB|opNOSIZE},
  {"xorcc",          OPCLASS_FLAGS,         opAB|ccAB|opNOSIZE},
  {"ornotcc",        OPCLASS_FLAGS,         opAB|ccAB|opNOSIZE},
  // Condition code movement and merging
  {"movccr",         OPCLASS_FLAGS,         opB|ccB|opNOSIZE},
  {"movrcc",         OPCLASS_FLAGS,         opB|opNOSIZE},
  {"collcc",         OPCLASS_FLAGS,         opABC|ccABC|opNOSIZE},
  // Simple shifting (restricted to small immediate 1..8)
  {"shls",           OPCLASS_SIMPLE_SHIFT,  opAB       }, // rb imm limited to 0-8
  {"shrs",           OPCLASS_SIMPLE_SHIFT,  opAB       }, // rb imm limited to 0-8
  {"bswap",          OPCLASS_LOGIC,         opAB       }, // byte swap rb
  {"sars",           OPCLASS_SIMPLE_SHIFT,  opAB       }, // rb imm limited to 0-8
  // Bit testing
  {"bt",             OPCLASS_LOGIC,         opAB       },
  {"bts",            OPCLASS_LOGIC,         opAB       },
  {"btr",            OPCLASS_LOGIC,         opAB       },
  {"btc",            OPCLASS_LOGIC,         opAB       },
  // Set and select
  {"set",            OPCLASS_SELECT,        opABC|ccAB }, // rd = rc <- (eval(ra,rb) ? 1 : 0)
  {"set.sub",        OPCLASS_SELECT,        opABC      }, // rd = rc <- (eval(ra-rb) ? 1 : 0)
  {"set.and",        OPCLASS_SELECT,        opABC      }, // rd = rc <- (eval(ra&rb) ? 1 : 0)
  {"sel",            OPCLASS_SELECT,        opABC|ccABC}, // rd = falsereg,truereg,condreg
  {"sel.cmp",        OPCLASS_SELECT,        opABC|ccAB }, // rd = falsereg,truereg,intreg
  // Branches
  {"br",             OPCLASS_COND_BRANCH,   opAB|ccAB|opNOSIZE}, // branch (rcimm: 32 to 53-bit target info)
  {"br.sub",         OPCLASS_COND_BRANCH,   opAB     }, // compare and branch ("cmp" form: subtract) (rcimm: 32 to 53-bit target info)
  {"br.and",         OPCLASS_COND_BRANCH,   opAB     }, // compare and branch ("test" form: and) (rcimm: 32 to 53-bit target info)
  {"jmp",            OPCLASS_INDIR_BRANCH,  opA      }, // indirect user branch (rcimm: 32 to 53-bit target info)
  {"bru",            OPCLASS_UNCOND_BRANCH, opNOSIZE }, // unconditional branch (rcimm: 32 to 53-bit target info)
  {"jmpp",           OPCLASS_INDIR_BRANCH|OPCLASS_BARRIER,  opA}, // indirect branch within PTL (rcimm: 32 to 53-bit target info)
  {"brp",            OPCLASS_UNCOND_BRANCH|OPCLASS_BARRIER, opNOSIZE}, // unconditional branch (PTL only) (rcimm: 32 to 53-bit target info)
  // Checks
  {"chk",            OPCLASS_CHECK,         opABC|ccAB|opNOSIZE}, // check condition and rollback if false (uses cond codes); (rcimm: 8-bit exception type)
  {"chk.sub",        OPCLASS_CHECK,         opABC     }, // check ("cmp" form: subtract)
  {"chk.and",        OPCLASS_CHECK,         opABC     }, // check ("test" form: and)
  // Loads and stores
  {"ld",             OPCLASS_LOAD,          opABC    }, // load zero extended
  {"ldx",            OPCLASS_LOAD,          opABC    }, // load sign extended
  {"ld.pre",         OPCLASS_PREFETCH,      opAB     }, // prefetch
  {"st",             OPCLASS_STORE,         opABC    }, // store
  {"mf",             OPCLASS_FENCE,         opNOSIZE }, // memory fence (extshift holds type: 01 = st, 10 = ld, 11 = ld.st)
  // Shifts, rotates and complex masking
  {"shl",            OPCLASS_SHIFTROT,      opABC|ccC},
  {"shr",            OPCLASS_SHIFTROT,      opABC|ccC},
  {"mask",           OPCLASS_SHIFTROT,      opAB     }, // mask rd = ra,rb,[ds,ms,mc]: (rcimm: 18 bits)
  {"sar",            OPCLASS_SHIFTROT,      opABC|ccC},
  {"rotl",           OPCLASS_SHIFTROT,      opABC|ccC},
  {"rotr",           OPCLASS_SHIFTROT,      opABC|ccC},
  {"rotcl",          OPCLASS_SHIFTROT,      opABC|ccC},
  {"rotcr",          OPCLASS_SHIFTROT,      opABC|ccC},
  // Multiplication
  {"mull",           OPCLASS_MULTIPLY,      opAB },
  {"mulh",           OPCLASS_MULTIPLY,      opAB },
  {"mulhu",          OPCLASS_MULTIPLY,      opAB },
  {"mulhl",          OPCLASS_MULTIPLY,      opAB },
  // Bit scans
  {"ctz",            OPCLASS_BITSCAN,       opB  },
  {"clz",            OPCLASS_BITSCAN,       opB  },
  {"ctpop",          OPCLASS_BITSCAN,       opB  },
  {"permb",          OPCLASS_SHIFTROT,      opABC},
  // Integer divide and remainder step
  {"div",            OPCLASS_MULTIPLY,      opABC}, // unsigned divide
  {"rem",            OPCLASS_MULTIPLY,      opABC}, // unsigned divide
  {"divs",           OPCLASS_MULTIPLY,      opABC}, // signed divide
  {"rems",           OPCLASS_MULTIPLY,      opABC}, // signed divide
  // Minimum and maximum
  {"min",            OPCLASS_ADDSUB,        opAB }, // min(ra, rb)
  {"max",            OPCLASS_ADDSUB,        opAB }, // max(ra, rb)
  {"min.s",          OPCLASS_ADDSUB,        opAB }, // min(ra, rb) (ra and rb are signed types)
  {"max.s",          OPCLASS_ADDSUB,        opAB }, // max(ra, rb) (ra and rb are signed types)
  // Floating point
  // uop.size bits have following meaning:
  // 00 = single precision, scalar (preserve high 32 bits of ra)
  // 01 = single precision, packed (two 32-bit floats)
  // 1x = double precision, scalar or packed (use two uops to process 128-bit xmm)
  {"fadd",           OPCLASS_FP_ALU,        opAB },
  {"fsub",           OPCLASS_FP_ALU,        opAB },
  {"fmul",           OPCLASS_FP_ALU,        opAB },
  {"fmadd",          OPCLASS_FP_ALU,        opABC},
  {"fmsub",          OPCLASS_FP_ALU,        opABC},
  {"fmsubr",         OPCLASS_FP_ALU,        opABC},
  {"fdiv",           OPCLASS_FP_DIVSQRT,    opAB },
  {"fsqrt",          OPCLASS_FP_DIVSQRT,    opAB },
  {"frcp",           OPCLASS_FP_DIVSQRT,    opAB },
  {"fsqrt",          OPCLASS_FP_DIVSQRT,    opAB },
  {"fmin",           OPCLASS_FP_COMPARE,    opAB },
  {"fmax",           OPCLASS_FP_COMPARE,    opAB },
  {"fcmp",           OPCLASS_FP_COMPARE,    opAB },
  // For fcmpcc, uop.size bits have following meaning:
  // 00 = single precision ordered compare
  // 01 = single precision unordered compare
  // 10 = double precision ordered compare
  // 11 = double precision unordered compare
  {"fcmpcc",         OPCLASS_FP_COMPARE,    opAB },
  // and/andn/or/xor are done using integer uops
  // For these conversions, uop.size bits select truncation mode:
  // x0 = normal IEEE-style rounding
  // x1 = truncate to zero
  {"fcvt.i2s.ins",   OPCLASS_FP_CONVERTI2F, opAB }, // one W32s <rb> to single, insert into low 32 bits of <ra> (for cvtsi2ss)
  {"fcvt.i2s.p",     OPCLASS_FP_CONVERTI2F, opB  }, // pair of W32s <rb> to pair of singles <rd> (for cvtdq2ps, cvtpi2ps)
  {"fcvt.i2d.lo",    OPCLASS_FP_CONVERTI2F, opB  }, // low W32s in <rb> to double in <rd> (for cvtdq2pd part 1, cvtpi2pd part 1, cvtsi2sd)
  {"fcvt.i2d.hi",    OPCLASS_FP_CONVERTI2F, opB  }, // high W32s in <rb> to double in <rd> (for cvtdq2pd part 2, cvtpi2pd part 2)
  {"fcvt.q2s.ins",   OPCLASS_FP_CONVERTI2F, opAB }, // one W64s <rb> to single, insert into low 32 bits of <ra> (for cvtsi2ss with REX.mode64 prefix)
  {"fcvt.q2d",       OPCLASS_FP_CONVERTI2F, opAB }, // one W64s <rb> to double in <rd>, ignore <ra> (for cvtsi2sd with REX.mode64 prefix)
  {"fcvt.s2i",       OPCLASS_FP_CONVERTF2I, opB  }, // one single <rb> to W32s in <rd> (for cvtss2si, cvttss2si)
  {"fcvt.s2q",       OPCLASS_FP_CONVERTF2I, opB  }, // one single <rb> to W64s in <rd> (for cvtss2si, cvttss2si with REX.mode64 prefix)
  {"fcvt.s2i.p",     OPCLASS_FP_CONVERTF2I, opB  }, // pair of singles in <rb> to pair of W32s in <rd> (for cvtps2pi, cvttps2pi, cvtps2dq, cvttps2dq)
  {"fcvt.d2i",       OPCLASS_FP_CONVERTF2I, opB  }, // one double <rb> to W32s in <rd> (for cvtsd2si, cvttsd2si)
  {"fcvt.d2q",       OPCLASS_FP_CONVERTF2I, opB  }, // one double <rb> to W64s in <rd> (for cvtsd2si with REX.mode64 prefix)
  {"fcvt.d2i.p",     OPCLASS_FP_CONVERTF2I, opAB }, // pair of doubles in <ra> (high), <rb> (low) to pair of W32s in <rd> (for cvtpd2pi, cvttpd2pi, cvtpd2dq, cvttpd2dq), clear high 64 bits of dest xmm
  {"fcvt.d2s.ins",   OPCLASS_FP_CONVERTFP,  opAB }, // double in <rb> to single, insert into low 32 bits of <ra> (for cvtsd2ss)
  {"fcvt.d2s.p",     OPCLASS_FP_CONVERTFP,  opAB }, // pair of doubles in <ra> (high), <rb> (low) to pair of singles in <rd> (for cvtpd2ps)
  {"fcvt.s2d.lo",    OPCLASS_FP_CONVERTFP,  opB  }, // low single in <rb> to double in <rd> (for cvtps2pd, part 1, cvtss2sd)
  {"fcvt.s2d.hi",    OPCLASS_FP_CONVERTFP,  opB  }, // high single in <rb> to double in <rd> (for cvtps2pd, part 2)
  // Vector integer uops
  // uop.size defines element size: 00 = byte, 01 = W16, 10 = W32, 11 = W64 (i.e. same as normal ALU uops)
  {"vadd",           OPCLASS_VEC_ALU,       opAB }, // vector add with wraparound
  {"vsub",           OPCLASS_VEC_ALU,       opAB }, // vector sub with wraparound
  {"vadd.us",        OPCLASS_VEC_ALU,       opAB }, // vector add with unsigned saturation
  {"vsub.us",        OPCLASS_VEC_ALU,       opAB }, // vector sub with unsigned saturation
  {"vadd.ss",        OPCLASS_VEC_ALU,       opAB }, // vector add with signed saturation
  {"vsub.ss",        OPCLASS_VEC_ALU,       opAB }, // vector sub with signed saturation
  {"vshl",           OPCLASS_VEC_ALU,       opAB }, // vector shift left
  {"vshr",           OPCLASS_VEC_ALU,       opAB }, // vector shift right
  {"vbt",            OPCLASS_VEC_ALU,       opAB }, // vector bit test (pack bit <rb> of each element in <ra> into low N bits of output)
  {"vsar",           OPCLASS_VEC_ALU,       opAB }, // vector shift right arithmetic (sign extend)
  {"vavg",           OPCLASS_VEC_ALU,       opAB }, // vector average ((<ra> + <rb> + 1) >> 1)
  {"vcmp",           OPCLASS_VEC_ALU,       opAB }, // vector compare (uop.cond specifies compare type; result is all 1's for true, or all 0's for false in each element)
  {"vmin",           OPCLASS_VEC_ALU,       opAB }, // vector minimum
  {"vmax",           OPCLASS_VEC_ALU,       opAB }, // vector maximum
  {"vmin.s",         OPCLASS_VEC_ALU,       opAB }, // vector signed minimum
  {"vmax.s",         OPCLASS_VEC_ALU,       opAB }, // vector signed maximum
  {"vmull",          OPCLASS_VEC_ALU,       opAB }, // multiply and keep low bits
  {"vmulh",          OPCLASS_VEC_ALU,       opAB }, // multiply and keep high bits
  {"vmulhu",         OPCLASS_VEC_ALU,       opAB }, // multiply and keep high bits (unsigned)
  {"vmaddp",         OPCLASS_VEC_ALU,       opAB }, // multiply and add adjacent pairs (signed)
  {"vsad",           OPCLASS_VEC_ALU,       opAB }, // sum of absolute differences
  {"vpack.us",       OPCLASS_VEC_ALU,       opAB }, // pack larger to smaller (unsigned saturation)
  {"vpack.ss",       OPCLASS_VEC_ALU,       opAB }, // pack larger to smaller (signed saturation)
#ifdef ENABLE_ASF
  {"asf.spec",       OPCLASS_ASF,           opB },
  {"asf.spec_inv",   OPCLASS_ASF,           opB },
  {"asf.com",        OPCLASS_ASF,           opB },
  {"asf.val",        OPCLASS_ASF,           opB },
  {"asf.rel",        OPCLASS_ASF,           opB },
#endif
};
struct PhysicalRegisterOperandInfo {
  W32 uuid;
  W16 physreg;
  W16 rob;
  byte state;
  byte rfid;
  byte archreg;
  byte pad1;
};

struct TransOpBase {
  // Opcode:
  byte opcode;
  // Size shift, extshift
  byte size:2, extshift:2, unaligned:1;
  // Condition codes (for loads/stores, cond = alignment)
  byte cond:4, setflags:3, nouserflags:1;
  // Loads and stores:
  byte internal:1, locked:1, cachelevel:2, datatype:4;
  // x86 semantics
  byte bytes:4, som:1, eom:1, is_sse:1, is_x87:1;
  // Operands
  byte rd, ra, rb, rc;
  // Index in basic block
  byte bbindex;
  // Misc info (terminal writer of targets in this insn, etc)
  // SD-TODO-MERGE: What is the marked flag used for?
  // Nothing! => Request on ML
  byte final_insn_in_bb:1, final_arch_in_insn:1, final_flags_in_insn:1, any_flags_in_insn:1, is_asf:1, invalidating: 1, pad:1, inverted:1;
  // Immediates
  W64s rbimm;
  W64s rcimm;
  W64 riptaken;
  W64 ripseq;
};

struct RIPVirtPhysBase {
  W64 rip;
  W64 mfnlo:28, use64:1, kernel:1, padlo:2, mfnhi:28, df:1, padhi:3;

  // 28 bits + 12 page offset bits = 40 bit physical addresses
  static const Waddr INVALID = 0xfffffff;

  ostream& print(ostream& os) const;
};

enum {
  EVENT_INVALID = 0,
  EVENT_FETCH_STALLED,
  EVENT_FETCH_ICACHE_WAIT,
  EVENT_FETCH_FETCHQ_FULL,
  EVENT_FETCH_IQ_QUOTA_FULL,
  EVENT_FETCH_BOGUS_RIP,
  EVENT_FETCH_ICACHE_MISS,
  EVENT_FETCH_SPLIT,
  EVENT_FETCH_ASSIST,
  EVENT_FETCH_TRANSLATE,
  EVENT_FETCH_OK,
  EVENT_RENAME_FETCHQ_EMPTY,
  EVENT_RENAME_ROB_FULL,
  EVENT_RENAME_PHYSREGS_FULL,
  EVENT_RENAME_LDQ_FULL,
  EVENT_RENAME_STQ_FULL,
  EVENT_RENAME_MEMQ_FULL,
  EVENT_RENAME_OK,
  EVENT_FRONTEND,
  EVENT_CLUSTER_NO_CLUSTER,
  EVENT_CLUSTER_OK,
  EVENT_DISPATCH_NO_CLUSTER,
  EVENT_DISPATCH_DEADLOCK,
  EVENT_DISPATCH_OK,
  EVENT_ISSUE_NO_FU,
  EVENT_ISSUE_OK,
  EVENT_REPLAY,
  EVENT_STORE_EXCEPTION,
  EVENT_STORE_WAIT,
  EVENT_STORE_PARALLEL_FORWARDING_MATCH,
  EVENT_STORE_ALIASED_LOAD,
  EVENT_STORE_ISSUED,
  EVENT_STORE_LOCK_RELEASED,
  EVENT_STORE_LOCK_ANNULLED,
  EVENT_STORE_LOCK_REPLAY,
  EVENT_LOAD_EXCEPTION,
  EVENT_LOAD_WAIT,
  EVENT_LOAD_HIGH_ANNULLED,
  EVENT_LOAD_HIT,
  EVENT_LOAD_MISS,
  EVENT_LOAD_BANK_CONFLICT,
  EVENT_LOAD_TLB_MISS,
  EVENT_LOAD_LOCK_REPLAY,
  EVENT_LOAD_LOCK_OVERFLOW,
  EVENT_LOAD_LOCK_ACQUIRED,
  EVENT_LOAD_LFRQ_FULL,
  EVENT_LOAD_WAKEUP,
  EVENT_TLBWALK_HIT,
  EVENT_TLBWALK_MISS,
  EVENT_TLBWALK_WAKEUP,
  EVENT_TLBWALK_NO_LFRQ_MB,
  EVENT_TLBWALK_COMPLETE,
  EVENT_FENCE_ISSUED,
  EVENT_ALIGNMENT_FIXUP,
  EVENT_ANNUL_NO_FUTURE_UOPS,
  EVENT_ANNUL_MISSPECULATION,
  EVENT_ANNUL_EACH_ROB,
  EVENT_ANNUL_PSEUDOCOMMIT,
  EVENT_ANNUL_FETCHQ_RAS,
  EVENT_ANNUL_FETCHQ,
  EVENT_ANNUL_FLUSH,
  EVENT_REDISPATCH_DEPENDENTS,
  EVENT_REDISPATCH_DEPENDENTS_DONE,
  EVENT_REDISPATCH_EACH_ROB,
  EVENT_COMPLETE,
  EVENT_BROADCAST,
  EVENT_FORWARD,
  EVENT_WRITEBACK,
  EVENT_COMMIT_FENCE_COMPLETED,
  EVENT_COMMIT_EXCEPTION_DETECTED,
  EVENT_COMMIT_EXCEPTION_ACKNOWLEDGED,
  EVENT_COMMIT_SKIPBLOCK,
  EVENT_COMMIT_SMC_DETECTED,
  EVENT_COMMIT_MEM_LOCKED,
  EVENT_COMMIT_ASSIST,
  EVENT_COMMIT_OK,
  EVENT_RECLAIM_PHYSREG,
  EVENT_RELEASE_MEM_LOCK,
  // ASF special events
  EVENT_ASF_ABORT,
  EVENT_ASF_CONFLICT,
  // Metadata events
  EVENT_META_COREID,
  EVENT_ASF_NESTLEVEL,
};

struct OutOfOrderCoreEvent {
  W16 type;
  W16 rob;
  W32 cycle;
  W32 uuid;
  RIPVirtPhysBase rip;
  TransOpBase uop;
  W16 physreg;
  W16 lsq;
  W16s lfrqslot;
  byte rfid;
  byte cluster;
  byte fu;
  W8 threadid;

  // Stripped out the methods

  union {
    byte start_flexible[0];
    struct  {
      W64 predrip;
      W16s missbuf;
      W16 bb_uop_count;
      W32 issueq_count;
    } fetch __attribute__ ((packed));
    struct {
      W16  oldphys;
      W16  oldzf;
      W16  oldcf;
      W16  oldof;
      PhysicalRegisterOperandInfo opinfo[MAX_OPERANDS];
    } rename __attribute__ ((packed));
    struct {
      W16 cycles_left;
    } frontend __attribute__ ((packed));
    struct {
      W16 allowed_clusters;
      W16 iq_avail[MAX_CLUSTERS];
    } select_cluster __attribute__ ((packed));
    struct  {
      PhysicalRegisterOperandInfo opinfo[MAX_OPERANDS];
    } dispatch __attribute__ ((packed));
    struct  {
      byte mispredicted:1;
      IssueState state;
      W16 cycles_left;
      W64 operand_data[MAX_OPERANDS];
      W16 operand_flags[MAX_OPERANDS];
      W64 predrip;
      W32 fu_avail;
    } issue __attribute__ ((packed));
    struct {
      PhysicalRegisterOperandInfo opinfo[MAX_OPERANDS];
      byte ready;
    } replay __attribute__ ((packed));
    struct {
      W64 virtaddr;
      W64 data_to_store;
      SFR sfr;
      SFR inherit_sfr;
      W64 inherit_sfr_uuid;
      W64 inherit_sfr_rip;
      W16 inherit_sfr_lsq;
      W16 inherit_sfr_rob;
      W16 inherit_sfr_physreg;
      W16 cycles_left;
      W64 locking_uuid;
      byte inherit_sfr_used:1, rcready:1, load_store_second_phase:1, predicted_alias:1;
      byte locking_vcpuid;
      W16 locking_rob;
      W8 threadid;
      W8 tlb_walk_level;
    } loadstore __attribute__ ((packed));
    struct {
      W16 somidx;
      W16 eomidx;
      W16 startidx;
      W16 endidx;
      byte annulras;
    } annul __attribute__ ((packed));
    struct {
      StateList* current_state_list;
      W16 iqslot;
      W16 count;
      byte dependent_operands;
      PhysicalRegisterOperandInfo opinfo[MAX_OPERANDS];
    } redispatch __attribute__ ((packed));
    struct {
      W8  forward_cycle;
      W8  operand;
      W8  target_operands_ready;
      W8  target_all_operands_ready;
      W16 target_rob;
      W16 target_physreg;
      W8  target_rfid;
      W8  target_cluster;
      W64 target_uuid;
      W16 target_lsq;
      W8  target_st;
    } forwarding __attribute__ ((packed));
    struct {
      W16 consumer_count;
      W16 flags;
      W64 data;
      byte transient:1, all_consumers_sourced_from_bypass:1, no_branches_between_renamings:1, dest_renamed_before_writeback:1;
    } writeback __attribute__ ((packed));
    struct {
      IssueState state;
      byte taken:1, predtaken:1, ld_st_truly_unaligned:1,krn:1;
      PTEUpdateBase pteupdate;
      W16s oldphysreg;
      W16 oldphysreg_refcount;
      W64 origvirt;
      W64 total_user_insns_committed;
      W64 total_insns_committed;
      W64 target_rip;
      W16 operand_physregs[MAX_OPERANDS];
    } commit __attribute__ ((packed));
    struct {
      W64 total_insns_committed;
      W32 abort_reason;
    } abort __attribute__ ((packed));
    struct {
      W64 phys_addr;
      W64 virt_addr;
      W8 src_id;
      W8 dst_id;
      W8 inv;
    } conflict __attribute__ ((packed));
    struct {
      int nest_level;
    } nestlevel __attribute__ ((packed));
  } __attribute__ ((packed));

  ostream& print(ostream& os) const;
}  __attribute__ ((packed));

struct MetadataCoreidEvent {
  W16 type;
  W16 coreid;
} __attribute__ ((packed));

#endif
