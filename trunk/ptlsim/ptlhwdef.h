// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Hardware Definitions
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#ifndef _PTLHWDEF_H
#define _PTLHWDEF_H

//
// NOTE: The first part of this file is included by assembly code,
// so do not put any C/C++-specific things here until the label
// __ASM_ONLY__ found below.
//

// Maximum number of SMT threads supported:
#define MAX_THREADS 2

// These are also used in simtemplates.S
#define FLAG_CF    0x001     // (1 << 0)
#define FLAG_INV   0x002     // (1 << 1)
#define FLAG_PF    0x004     // (1 << 2)
#define FLAG_WAIT  0x008     // (1 << 3)
#define FLAG_AF    0x010     // (1 << 4)
#define FLAG_ZF    0x040     // (1 << 6)
#define FLAG_SF    0x080     // (1 << 7)
#define FLAG_OF    0x800     // (1 << 11)
#define FLAG_SF_ZF 0x0c0     // (1 << 7) | (1 << 6)
#define FLAG_ZAPS  0x0d4     // 000011010100
#define FLAG_NOT_WAIT_INV 0x08f5 // 00000100011110101: exclude others not in ZAPS/CF/OF

#define COND_o   0
#define COND_no  1
#define COND_c   2
#define COND_nc  3
#define COND_e   4
#define COND_ne  5
#define COND_be  6
#define COND_nbe 7
#define COND_s   8
#define COND_ns  9
#define COND_p   10
#define COND_np  11
#define COND_l   12
#define COND_nl  13
#define COND_le  14
#define COND_nle 15

//
// Exceptions:
// These are PTL internal exceptions, NOT x86 exceptions:
//
#define EXCEPTION_NoException         0
// Exceptions causing rollbacks
#define EXCEPTION_Propagate           1
#define EXCEPTION_BranchMispredict    2
#define EXCEPTION_UnalignedAccess     3
#define EXCEPTION_PageFaultOnRead     4
#define EXCEPTION_PageFaultOnWrite    5
#define EXCEPTION_PageFaultOnExec     6
#define EXCEPTION_LoadStoreAliasing   11
#define EXCEPTION_CheckFailed         12
#define EXCEPTION_SkipBlock           13
#define EXCEPTION_CacheLocked         14
#define EXCEPTION_LFRQFull            15
#define EXCEPTION_FloatingPoint       16
// Asynchronous exceptions
#define EXCEPTION_Timer               17
#define EXCEPTION_External            18
#define EXCEPTION_COUNT               19

#define ARCHREG_INT_BASE 0
#define ARCHREG_SSE_BASE 16

//
// Registers
//
#define ARCHREG_COUNT 64

#define REG_rax     0
#define REG_rcx     1
#define REG_rdx     2
#define REG_rbx     3
#define REG_rsp     4
#define REG_rbp     5
#define REG_rsi     6
#define REG_rdi     7
#define REG_r8      8
#define REG_r9      9
#define REG_r10     10
#define REG_r11     11
#define REG_r12     12
#define REG_r13     13
#define REG_r14     14
#define REG_r15     15

#define REG_xmml0   16
#define REG_xmmh0   17
#define REG_xmml1   18
#define REG_xmmh1   19
#define REG_xmml2   20
#define REG_xmmh2   21
#define REG_xmml3   22
#define REG_xmmh3   23
#define REG_xmml4   24
#define REG_xmmh4   25
#define REG_xmml5   26
#define REG_xmmh5   27
#define REG_xmml6   28
#define REG_xmmh6   29
#define REG_xmml7   30
#define REG_xmmh7   31

#define REG_xmml8   32
#define REG_xmmh8   33
#define REG_xmml9   34
#define REG_xmmh9   35
#define REG_xmml10  36
#define REG_xmmh10  37
#define REG_xmml11  38
#define REG_xmmh11  39
#define REG_xmml12  40
#define REG_xmmh12  41
#define REG_xmml13  42
#define REG_xmmh13  43
#define REG_xmml14  44
#define REG_xmmh14  45
#define REG_xmml15  46
#define REG_xmmh15  47

#define REG_fptos   48
#define REG_fpsw    49
#define REG_fpcw    50
#define REG_fptags  51
#define REG_fp4     52
#define REG_fp5     53
#define REG_fp6     54
#define REG_fp7     55
#define REG_rip     56
#define REG_flags   57
#define REG_sr3     58
#define REG_mxcsr   59
#define REG_sr0     60
#define REG_sr1     61
#define REG_sr2     62
#define REG_zero    63

// For renaming only:

#define REG_temp0   64
#define REG_temp1   65
#define REG_temp2   66
#define REG_temp3   67
#define REG_temp4   68
#define REG_temp5   69
#define REG_temp6   70
#define REG_temp7   71

#define REG_zf      72
#define REG_cf      73
#define REG_of      74
#define REG_imm     75
#define REG_mem     76
#define REG_temp8   77
#define REG_temp9   78
#define REG_temp10  79

#define TRANSREG_COUNT (64+16)

#define ARCHREG_NULL REG_zero



#ifndef __ASM_ONLY__
//
// The following definitions are used by C++ code
//

#include <globals.h>
extern W64 sim_cycle;
#include <logic.h>
#include <config.h>

#define MAX_TRANSOPS_PER_USER_INSN 16
#define MAXBBLEN 64

#define LOADLAT 2 // Load unit latency, assuming fast bypass

extern const char* exception_names[EXCEPTION_COUNT];

static inline const char* exception_name(W64 exception) {
  return (exception < EXCEPTION_COUNT) ? exception_names[exception] : "Unknown";
}

//
// Store Forwarding Register definition
//
// Cleverness alert: FLAG_INV is bit 1 in both regular ALU flags
// AND bit 1 in the lowest byte of SFR.physaddr. This is critical
// to making the synthesized simulator code work efficiently.
//
// REMEMBER: sfr.physaddr is >> 3 so it fits in 45 bits (vs 48).
//
struct SFR {
  W64 data;
  W64 addrvalid:1, invalid:1, datavalid:1, physaddr:45, bytemask:8, tag:8;
};

stringbuf& operator <<(stringbuf& sb, const SFR& sfr);

inline ostream& operator <<(ostream& os, const SFR& sfr) {
  stringbuf sb;
  sb << sfr;
  return os << sb;
}

struct IssueState {
  union {
    struct {
      W64 rddata;
      W64 addr:48, rdflags:16;
    } reg;

    struct {
      W64 rddata;
      W64 physaddr:48, flags:16;
    } ldreg;

    struct { 
      W64 riptaken;
      W64 ripseq;
    } brreg;

    SFR st;
  };
};

ostream& operator <<(ostream& os, const IssueState& ctx);

struct IssueInput {
  W64 ra;
  W64 rb;
  W64 rc;
  W16 raflags;
  W16 rbflags;
  W16 rcflags;
};

typedef W64 UserContext[ARCHREG_COUNT];

ostream& operator <<(ostream& os, const UserContext& ctx);

//
// These are directly accessed by the PTL synthesized code:
//
extern W64 csbase;
extern W64 dsbase;
extern W64 esbase;
extern W64 ssbase;
extern W64 fsbase;
extern W64 gsbase;

extern W16 csreg;
extern W16 dsreg;
extern W16 esreg;
extern W16 ssreg;
extern W16 fsreg;
extern W16 gsreg;

extern W64 fpregs[8];


struct CoreState {
  UserContext commitarf;    
  UserContext specarf;
  W64 use64:1;
  W64 exception;

  CoreState() { }

  inline void reset() {
    memset(&commitarf, 0, sizeof(commitarf));
    memset(&specarf, 0, sizeof(specarf));
    exception = 0;
  }

  void complete();
  bool commit();
  void rollback();
  void restart();
};

ostream& operator <<(ostream& os, const CoreState& ctx);

extern CoreState ctx;

// Other flags not defined above
enum {
  FLAG_TF = (1 << 8),
  FLAG_IF = (1 << 9),
  FLAG_DF = (1 << 10),
  FLAG_IOPL = (1 << 12) | (1 << 13),
  FLAG_NT = (1 << 14),
  FLAG_RF = (1 << 16),
  FLAG_VM = (1 << 17),
  FLAG_AC = (1 << 18),
  FLAG_VIF = (1 << 19),
  FLAG_VIP = (1 << 20),
  FLAG_ID = (1 << 21),
  FLAG_COUNT = 22,
};

//
// Functional Units
//
#define FU_LDU0       (1 << 0)
#define FU_STU0       (1 << 1)
#define FU_LDU1       (1 << 2)
#define FU_STU1       (1 << 3)
#define FU_ALU0       (1 << 4)
#define FU_FPU0       (1 << 5)
#define FU_ALU1       (1 << 6)
#define FU_FPU1       (1 << 7)
#define FU_COUNT      8

#define LOAD_FU_COUNT 2

struct FunctionalUnit {
  const char* name;
};

extern struct FunctionalUnit FU[FU_COUNT];

//
// Operation Classes
// 
// NOTE: Even if a given opcode is not USESFLAGS, we still check all flags for FLAG_INV and FLAG_WAIT in the prescan:
// NOTE: If an opcode is USESFLAGS, generally it is also USESRC since often RC contains the carry flag but no value.

#define OPCLASS_USESFLAGS               0
#define OPCLASS_USESRC                  0

#define OPCLASS_LOGIC                   (1 << 0)

#define OPCLASS_ADDSUB                  (1 << 1)
#define OPCLASS_ADDSUBC                 ((1 << 2) | OPCLASS_USESFLAGS | OPCLASS_USESRC)
#define OPCLASS_ADDSHIFT                ((1 << 3) | OPCLASS_USESRC)
#define OPCLASS_ADD                     (OPCLASS_ADDSUB|OPCLASS_ADDSUBC|OPCLASS_ADDSHIFT)

#define OPCLASS_SELECT                  ((1 << 4) | OPCLASS_USESFLAGS | OPCLASS_USESRC)
#define OPCLASS_COMPARE                 (1 << 5)
#define OPCLASS_COND_BRANCH             ((1 << 6) | OPCLASS_USESFLAGS)
#define OPCLASS_CONDITIONAL             (OPCLASS_SELECT|OPCLASS_COMPARE|OPCLASS_COND_BRANCH)

#define OPCLASS_INDIR_BRANCH            (1 << 7)
#define OPCLASS_UNCOND_BRANCH           (1 << 8)
#define OPCLASS_ASSIST                  (1 << 9)
#define OPCLASS_BARRIER                 (OPCLASS_ASSIST)
#define OPCLASS_BRANCH                  (OPCLASS_COND_BRANCH|OPCLASS_INDIR_BRANCH|OPCLASS_UNCOND_BRANCH|OPCLASS_ASSIST)

#define OPCLASS_LOAD                    ((1 << 10) | OPCLASS_USESRC)
#define OPCLASS_STORE                   ((1 << 11) | OPCLASS_USESRC)
#define OPCLASS_PREFETCH                (1 << 12)
#define OPCLASS_MEM                     (OPCLASS_LOAD|OPCLASS_STORE|OPCLASS_PREFETCH)

#define OPCLASS_SIMPLE_SHIFT            (1 << 13)
#define OPCLASS_SHIFTROT                ((1 << 14) | OPCLASS_USESFLAGS | OPCLASS_USESRC)
#define OPCLASS_MULTIPLY                (1 << 15)
#define OPCLASS_BITSCAN                 (1 << 16)
#define OPCLASS_FLAGS                   (1 << 17)
#define OPCLASS_CHECK                   (1 << 18)

#define OPCLASS_FP_ALU                  (1 << 19)
#define OPCLASS_FP_DIVSQRT              (1 << 20)
#define OPCLASS_FP_COMPARE              (1 << 21)
#define OPCLASS_FP_PERMUTE              (1 << 22)
#define OPCLASS_FP_CONVERTI2F           (1 << 23)
#define OPCLASS_FP_CONVERTF2I           (1 << 24)
#define OPCLASS_FP_CONVERTFP            (1 << 25)

#define OPCLASS_FP                      (OPCLASS_FP_ALU | OPCLASS_FP_DIVSQRT | OPCLASS_FP_COMPARE | OPCLASS_FP_PERMUTE | OPCLASS_FP_CONVERTI2F | OPCLASS_FP_CONVERTF2I, OPCLASS_FP_CONVERTFP)

#define OPCLASS_COUNT                   26

#define OPCLASS_USECOND                 (OPCLASS_COND_BRANCH|OPCLASS_SELECT|OPCLASS_CHECK)

extern const char* opclass_names[OPCLASS_COUNT];

//
// Opcodes
//
enum {
  OP_nop,
  OP_mov,

  OP_and,
  OP_or,
  OP_xor,
  OP_andnot,
  OP_ornot,
  OP_nand,
  OP_nor,
  OP_eqv,
  OP_add,
  OP_sub,
  OP_adda,
  OP_suba,
  OP_addm,
  OP_subm,
  OP_addc,
  OP_subc,
  OP_sel,
  OP_set,
  OP_set_sub,
  OP_set_and,
  OP_br,
  OP_br_sub,
  OP_br_and,
  OP_jmp,
  OP_jmpp,
  OP_bru,
  OP_brp,
  OP_chk,
  OP_chk_sub,
  OP_chk_and,

  OP_ld,
  OP_ldx,
  OP_ld_jmp,
  OP_ld_and,
  OP_ld_lm,
  OP_ldx_lm,
  OP_ld_pre,
  OP_st,
  OP_st_lm,

  OP_rotl,
  OP_rotr,
  OP_rotcl,
  OP_rotcr,
  OP_shl,
  OP_shr,
  OP_sar,
  OP_mask,

  OP_shls,
  OP_shrs,
  OP_sars,
  OP_maskb,

  OP_bswap,

  OP_collcc,
  OP_movccr,
  OP_movrcc,
  OP_andcc,
  OP_orcc,
  OP_ornotcc,
  OP_xorcc,
  OP_mull,
  OP_mulh,
  OP_mulhu,
  OP_bt,
  OP_bts,
  OP_btr,
  OP_btc,
  OP_ctz,
  OP_clz,
  OP_ctpop,
  OP_addf,
  OP_subf,
  OP_mulf,
  OP_maddf,
  OP_msubf,
  OP_divf,
  OP_sqrtf,
  OP_rcpf,
  OP_rsqrtf,
  OP_minf,
  OP_maxf,
  OP_cmpf,
  OP_cmpccf,
  OP_permf,
  OP_cvtf_i2s_ins,
  OP_cvtf_i2s_p,
  OP_cvtf_i2d_lo,
  OP_cvtf_i2d_hi,
  OP_cvtf_q2s_ins,
  OP_cvtf_q2d,
  OP_cvtf_s2i,
  OP_cvtf_s2q,
  OP_cvtf_s2i_p,
  OP_cvtf_d2i,
  OP_cvtf_d2q,
  OP_cvtf_d2i_p,
  OP_cvtf_d2s_ins,
  OP_cvtf_d2s_p,
  OP_cvtf_s2d_lo,
  OP_cvtf_s2d_hi,
  OP_MAX_OPCODE,
};

// Limit for shls, shrs, sars rb immediate:
#define SIMPLE_SHIFT_LIMIT 8

struct OpcodeInfo {
  const char* name;
  W32 opclass;
  W16 latency;
  W16 flagops;
  W16 fu;
};

extern const OpcodeInfo opinfo[OP_MAX_OPCODE];

inline bool isclass(int opcode, W32 opclass) { return ((opinfo[opcode].opclass & opclass) != 0); }
inline int opclassof(int opcode) { return lsbindex(opinfo[opcode].opclass); }

inline bool isload(int opcode) { return isclass(opcode, OPCLASS_LOAD); }
inline bool isstore(int opcode) { return isclass(opcode, OPCLASS_STORE); }
inline bool iscondbranch(int opcode) { return isclass(opcode, OPCLASS_COND_BRANCH|OPCLASS_INDIR_BRANCH); }
inline bool isbranch(int opcode) { return isclass(opcode, OPCLASS_BRANCH); }
inline bool isbarrier(int opcode) { return isclass(opcode, OPCLASS_BARRIER); }
inline const char* nameof(int opcode) { return (opcode < OP_MAX_OPCODE) ? opinfo[opcode].name : "INVALID"; }

// Mask uop control
static inline W32 make_mask_control_info(int ms, int mc, int ds) {
  return (ms) | (mc << 6) | (ds << 12);
}

// These go in the extshift field of branch and/or jump operations; they are used as hints only: 
#define BRANCH_HINT_PUSH_RAS (1 << 0)
#define BRANCH_HINT_POP_RAS (1 << 1)

inline int invert_cond(int cond) {
  // Conveniently, x86 branch conds may be inverted by just flipping bit zero:
  return (cond ^ 1);
}

extern const char* arch_reg_names[TRANSREG_COUNT];

extern const char* cond_code_names[16];

/*
 * Convert a condition code (as in jump, setcc, cmovcc, etc) to
 * the one or two architectural registers last updated with the
 * flags that uop will test.
 */
struct CondCodeToFlagRegs {
  byte req2, ra, rb;
};

extern const CondCodeToFlagRegs cond_code_to_flag_regs[16];

enum {
  SETFLAG_ZF = (1 << 0),
  SETFLAG_CF = (1 << 1),
  SETFLAG_OF = (1 << 2),
  SETFLAG_COUNT = 3
};

extern const char* setflag_names[SETFLAG_COUNT];
extern const char* x86_flag_names[FLAG_COUNT];
extern const W16 setflags_to_x86_flags[1<<3];

//
// Structures
//

struct TransOpBase {
  W64 opcode:7, size:2, cond:4, som:1, eom:1, setflags:3, internal:1, memid:8, rd:7, ra:7, rb:7, rc:7, rbimmsz:3, rcimmsz:3, has_riptaken:1, has_ripseq:1;
  W64 bytes:4, tagcount:4, loadcount:3, storecount:3, branchcount:1, nouserflags:1, extshift:2, cachelevel:2, unaligned:1, index:8;
};

struct TransOp: public TransOpBase {
  W64s rbimm;
  W64s rcimm;
  W64 riptaken;
  W64 ripseq;

  TransOp() { }

  TransOp(int opcode, int rd, int ra, int rb, int rc, int size, W64s rbimm = 0, W64s rcimm = 0, W32 setflags = 0, int memid = 0) {
    this->opcode = opcode;
    this->rd = rd; 
    this->ra = ra;
    this->rb = rb;
    this->rc = rc;
    this->size = size;
    this->cond = 0;
    this->rbimm = rbimm;
    this->rcimm = rcimm;
    this->eom = 0;
    this->som = 0;
    this->setflags = setflags;
    this->memid = memid;
    this->riptaken = 0;
    this->ripseq = 0;
    this->bytes = 0;
    this->tagcount = 0;
    this->loadcount = 0;
    this->storecount = 0;
    this->branchcount = 0;
    this->internal = 0;
    this->nouserflags = 0;
    this->extshift = 0;
    this->cachelevel = 0;
    this->unaligned = 0;
    this->index = 0;
  }
};

ostream& operator <<(ostream& os, const TransOp& op);
stringbuf& operator <<(stringbuf& os, const TransOp& op);

struct BasicBlock;

typedef void (*uopimpl_func_t)(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags);


struct BasicBlockBase {
  W64 rip;
  W64 rip_taken;
  W64 rip_not_taken;
  W16 count;
  int refcount;
  W64 tagcount:10, memcount:8, storecount:8, repblock:1, user_insn_count:16;
  W64 usedregs;
  uopimpl_func_t* synthops;

  void acquire() {
    refcount++;
  }

  bool release() {
    refcount--;
    assert(refcount >= 0);
    return (!refcount);
  }
};

struct BasicBlock: public BasicBlockBase {
  TransOp transops[MAXBBLEN*2];

  void reset(W64 rip = 0);
  BasicBlock* clone();
  void free();
};

ostream& operator <<(ostream& os, const BasicBlock& bb);

stringbuf& nameof(stringbuf& sbname, const TransOp& uop);

char* regname(int r);

stringbuf& print_value_and_flags(stringbuf& sb, W64 value, W16 flags);

struct flagstring {
  W64 bits;
  int n;
  bool reverse;
  
  flagstring() { }
  
  flagstring(const W64 bits) {
    this->bits = bits;
  }
};

static inline ostream& operator <<(ostream& os, const flagstring& bs) {
  for (int i = 11; i >= 0; i--) {
    if (bit(bs.bits, i)) os << x86_flag_names[i];
  }

  return os;
}

static inline stringbuf& operator <<(stringbuf& sb, const flagstring& bs) {
  for (int i = 11; i >= 0; i--) {
    if (bit(bs.bits, i)) sb << x86_flag_names[i];
  }

  return sb;
}

typedef void (*assist_func_t)();

const char* assist_name(assist_func_t func);
int assist_index(assist_func_t func);


#endif // __ASM_ONLY__
#endif // _PTLHWDEF_H
