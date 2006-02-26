//
// PTLsim: Cycle Accurate x86-64 Simulator
// Hardware Definitions
//
// Copyright 2000-2004 Matt T. Yourst <yourst@yourst.com>
//

#include <ptlsim.h>
#include <dcache.h>

CoreState ctx alignto(4096) insection(".corectx");
CoreState dummyctx alignto(4096) insection(".corectx");
IssueState issuestate[8] alignto(64) insection(".corectx");
W64 fpregs[8] alignto(64) insection(".ldm");

extern void print_message(const char* text);

const char* opclass_names[OPCLASS_COUNT] = {
  "logic", "addsub", "addsubc", "addshift", "sel", "cmp", "br.cc", "jmp", "bru", 
  "assist", "ld", "st", "ld.pre", "shiftsimple", "shift", "mul", "bitscan", "flags",  "chk", 
  "fpu", "fp-div-sqrt", "fp-cmp", "fp-perm", "fp-cvt-i2f", "fp-cvt-f2i", "fp-cvt-f2f"
};

//
// Functional Units
//
struct FunctionalUnit FU[FU_COUNT] = {
  {"ldu0"},
  {"stu0"},
  {"ldu1"},
  {"stu1"},
  {"alu0"},
  {"fpu0"},
  {"alu1"},
  {"fpu1"},
};

//
// Opcodes and properties
//
#define ALU0 FU_ALU0
#define ALU1 FU_ALU1
#define STU0 FU_STU0
#define STU1 FU_STU1
#define LDU0 FU_LDU0
#define LDU1 FU_LDU1
#define FPU0 FU_FPU0
#define FPU1 FU_FPU1
#define A 1 // ALU latency, assuming fast bypass
#define L LOADLAT

#define ANYALU ALU0|ALU1
#define ANYLDU LDU0|LDU1
#define ANYSTU STU0|STU1
#define ANYFPU FPU0|FPU1
#define ANYINT ANYALU|ANYSTU|ANYLDU

//
// Which operands consume condition code flags?
//
// Full list, along with which operands are used to source condition code flags:
//
// addc           rc
// subc           rc
// sel      ra rb rc
// set            rc
// collcc   ra rb rc
// br       ra rb
// chk      ra rb
// rotl           rc
// rotr           rc
// rotcl          rc
// rotcr          rc
// shl            rc
// shr            rc
// sar            rc
// movccr   ra
// andcc    ra rb
// orcc     ra rb
// ornotcc  ra rb
// xorcc    ra rb
//
#define ccA   ((1 << 0) + (0 << 1) + (0 << 2))
#define ccAB  ((1 << 0) + (1 << 1) + (0 << 2))
#define ccABC ((1 << 0) + (1 << 1) + (1 << 2))
#define ccC   ((0 << 0) + (0 << 1) + (1 << 2))

const OpcodeInfo opinfo[OP_MAX_OPCODE] = {
  // name, opclass, latency, fu
  {"nop",            OPCLASS_LOGIC,         A, 0,     ANYINT|ANYFPU},
  {"mov",            OPCLASS_LOGIC,         A, 0,     ANYINT|ANYFPU}, // move or merge
  // Simple ALU operations
  {"and",            OPCLASS_LOGIC,         A, 0,     ANYINT|ANYFPU},
  {"or",             OPCLASS_LOGIC,         A, 0,     ANYINT|ANYFPU},
  {"xor",            OPCLASS_LOGIC,         A, 0,     ANYINT|ANYFPU},
  {"andnot",         OPCLASS_LOGIC,         A, 0,     ANYINT|ANYFPU},
  {"ornot",          OPCLASS_LOGIC,         A, 0,     ANYINT|ANYFPU},
  {"nand",           OPCLASS_LOGIC,         A, 0,     ANYINT|ANYFPU},
  {"nor",            OPCLASS_LOGIC,         A, 0,     ANYINT|ANYFPU},
  {"eqv",            OPCLASS_LOGIC,         A, 0,     ANYINT|ANYFPU},
  {"add",            OPCLASS_ADDSUB,        A, 0,     ANYINT}, // ra + rb
  {"sub",            OPCLASS_ADDSUB,        A, 0,     ANYINT}, // ra - rb
  {"adda",           OPCLASS_ADDSUB,        A, 0,     ANYINT}, // ra + rb + rc
  {"adds",           OPCLASS_ADDSUB,        A, 0,     ANYINT}, // ra + rb - rc
  {"suba",           OPCLASS_ADDSUB,        A, 0,     ANYINT}, // ra - rb + rc
  {"subs",           OPCLASS_ADDSUB,        A, 0,     ANYINT}, // ra - rb - rc
  {"addm",           OPCLASS_ADDSUB,        A, 0,     ANYINT}, // lowbits(ra + rb, m)
  {"subm",           OPCLASS_ADDSUB,        A, 0,     ANYINT}, // lowbits(ra - rb, m)
  {"addc",           OPCLASS_ADDSUBC,       A, ccC,   ANYINT},
  {"subc",           OPCLASS_ADDSUBC,       A, ccC,   ANYINT},
  {"sel",            OPCLASS_SELECT,        A, ccABC, ANYINT}, // rd = falsereg,truereg,condreg
  {"set",            OPCLASS_SELECT,        A, ccC,   ANYINT},
  {"set.sub",        OPCLASS_SELECT,        A, 0,     ANYINT},
  {"set.and",        OPCLASS_SELECT,        A, 0,     ANYINT},
  {"br",             OPCLASS_COND_BRANCH,   A, ccAB,  ANYINT}, // branch
  {"br.sub",         OPCLASS_COND_BRANCH,   A, 0,     ANYINT}, // compare and branch ("cmp" form: subtract)
  {"br.and",         OPCLASS_COND_BRANCH,   A, 0,     ANYINT}, // compare and branch ("test" form: and)
  {"jmp",            OPCLASS_INDIR_BRANCH,  A, 0,     ANYINT}, // indirect user branch
  {"jmpp",           OPCLASS_INDIR_BRANCH|OPCLASS_BARRIER,  A, 0,     ANYALU|ANYLDU}, // indirect branch within PTL
  {"bru",            OPCLASS_UNCOND_BRANCH, A, 0,     ANYINT}, // unconditional branch (branch cap)
  {"brp",            OPCLASS_UNCOND_BRANCH|OPCLASS_BARRIER, A, 0,     ANYALU|ANYLDU}, // unconditional branch (PTL only)
  {"chk",            OPCLASS_CHECK,         A, ccAB,  ANYINT}, // check condition and rollback if false (uses cond codes); rcimm is exception type
  {"chk.sub",        OPCLASS_CHECK,         A, 0,     ANYINT}, // check ("cmp" form: subtract)
  {"chk.and",        OPCLASS_CHECK,         A, 0,     ANYINT}, // check ("test" form: and)
  // User loads and stores
  {"ld",             OPCLASS_LOAD,          L, 0,     ANYLDU}, // load zero extended
  {"ldx",            OPCLASS_LOAD,          L, 0,     ANYLDU}, // load sign extended
  {"ld.jmp",         OPCLASS_LOAD|OPCLASS_INDIR_BRANCH, L, 0,     ANYLDU}, // load and indirect branch check
  {"ld.and",         OPCLASS_LOAD|OPCLASS_LOGIC, 2, 0,     ANYLDU}, // load and and (for test)
  {"ld.lm",          OPCLASS_LOAD,          1, 0,     ANYLDU}, // load from local memory 
  {"ldx.lm",         OPCLASS_LOAD,          1, 0,     ANYLDU}, // load from local memory, sign extended
  {"ld.pre",         OPCLASS_PREFETCH,      1, 0,     ANYLDU}, // prefetch
  {"st",             OPCLASS_STORE,         1, 0,     ANYSTU}, // store
  {"st.lm",          OPCLASS_STORE,         1, 0,     ANYSTU}, // store to local memory
  // Shifts and rotates
  {"rotl",           OPCLASS_SHIFTROT,      A, ccC,   ANYALU},  
  {"rotr",           OPCLASS_SHIFTROT,      A, ccC,   ANYALU},   
  {"rotcl",          OPCLASS_SHIFTROT,      A, ccC,   ANYALU},
  {"rotcr",          OPCLASS_SHIFTROT,      A, ccC,   ANYALU},  
  {"shl",            OPCLASS_SHIFTROT,      A, ccC,   ANYALU},
  {"shr",            OPCLASS_SHIFTROT,      A, ccC,   ANYALU},
  {"sar",            OPCLASS_SHIFTROT,      A, ccC,   ANYALU},   
  // Masking, insert and extract
  {"mask",           OPCLASS_SHIFTROT,      A, 0,     ANYALU}, // mask rd = ra,rb,[ds,ms,mc]
  // Simple shifting (restricted to small immediate)
  {"shls",           OPCLASS_SIMPLE_SHIFT,  A, 0,     ANYINT}, // rb imm limited to 0-8
  {"shrs",           OPCLASS_SIMPLE_SHIFT,  A, 0,     ANYINT}, // rb imm limited to 0-8
  {"sars",           OPCLASS_SIMPLE_SHIFT,  A, 0,     ANYINT}, // rb imm limited to 0-8
  {"maskb",          OPCLASS_SIMPLE_SHIFT,  A, 0,     ANYINT}, // mask rd = ra,rb,[ds,ms,mc], bytes only
  // Endian byte swap
  {"bswap",          OPCLASS_LOGIC,         A, 0,     ANYINT},
  // Flag operations
  {"collcc",         OPCLASS_FLAGS,         A, ccABC, ANYINT},
  {"movccr",         OPCLASS_FLAGS,         A, ccA,   ANYINT},
  {"movrcc",         OPCLASS_FLAGS,         A, 0,     ANYINT},
  {"andcc",          OPCLASS_FLAGS,         A, ccAB,  ANYINT},
  {"orcc",           OPCLASS_FLAGS,         A, ccAB,  ANYINT},
  {"ornotcc",        OPCLASS_FLAGS,         A, ccAB,  ANYINT},
  {"xorcc",          OPCLASS_FLAGS,         A, ccAB,  ANYINT},
  // Multiplication
  {"mull",           OPCLASS_MULTIPLY,      4, 0,     ANYFPU},
  {"mulh",           OPCLASS_MULTIPLY,      4, 0,     ANYFPU},
  {"mulhu",          OPCLASS_MULTIPLY,      4, 0,     ANYFPU},
  // Bit testing
  {"bt",             OPCLASS_LOGIC,         A, 0,     ANYALU},
  {"bts",            OPCLASS_LOGIC,         A, 0,     ANYALU},
  {"btr",            OPCLASS_LOGIC,         A, 0,     ANYALU},
  {"btc",            OPCLASS_LOGIC,         A, 0,     ANYALU},
  // Bit scans
  {"ctz",            OPCLASS_BITSCAN,       3, 0,     ANYFPU},
  {"clz",            OPCLASS_BITSCAN,       3, 0,     ANYFPU},
  {"ctpop",          OPCLASS_BITSCAN,       3, 0,     ANYFPU},  
  // Floating point
  // uop.size bits have following meaning:
  // 00 = single precision, scalar (preserve high 32 bits of ra)
  // 01 = single precision, packed (two 32-bit floats)
  // 1x = double precision, scalar or packed (use two uops to process 128-bit xmm)
  {"addf",           OPCLASS_FP_ALU,        6, 0,     ANYFPU},
  {"subf",           OPCLASS_FP_ALU,        6, 0,     ANYFPU},
  {"mulf",           OPCLASS_FP_ALU,        6, 0,     ANYFPU},
  {"maddf",          OPCLASS_FP_ALU,        6, 0,     ANYFPU},
  {"msubf",          OPCLASS_FP_ALU,        6, 0,     ANYFPU},
  {"divf",           OPCLASS_FP_DIVSQRT,    6, 0,     ANYFPU},
  {"sqrtf",          OPCLASS_FP_DIVSQRT,    6, 0,     ANYFPU},
  {"rcpf",           OPCLASS_FP_DIVSQRT,    6, 0,     ANYFPU},
  {"rsqrtf",         OPCLASS_FP_DIVSQRT,    6, 0,     ANYFPU},
  {"minf",           OPCLASS_FP_COMPARE,    4, 0,     ANYFPU},
  {"maxf",           OPCLASS_FP_COMPARE,    4, 0,     ANYFPU},
  {"cmpf",           OPCLASS_FP_COMPARE,    4, 0,     ANYFPU},
  // For fcmpcc, uop.size bits have following meaning:
  // 00 = single precision ordered compare
  // 01 = single precision unordered compare
  // 10 = double precision ordered compare
  // 11 = double precision unordered compare
  {"cmpccf",         OPCLASS_FP_COMPARE,    4, 0,     ANYFPU},
  // and/andn/or/xor are done using integer uops
  {"permf",          OPCLASS_FP_PERMUTE,    3, 0,     ANYFPU}, // shuffles
  // For these conversions, uop.size bits select truncation mode:
  // x0 = normal IEEE-style rounding
  // x1 = truncate to zero
  {"cvtf.i2s.ins",   OPCLASS_FP_CONVERTI2F, 6, 0,     ANYFPU}, // one W32s <rb> to single, insert into low 32 bits of <ra> (for cvtsi2ss)
  {"cvtf.i2s.p",     OPCLASS_FP_CONVERTI2F, 6, 0,     ANYFPU}, // pair of W32s <rb> to pair of singles <rd> (for cvtdq2ps, cvtpi2ps)
  {"cvtf.i2d.lo",    OPCLASS_FP_CONVERTI2F, 6, 0,     ANYFPU}, // low W32s in <rb> to double in <rd> (for cvtdq2pd part 1, cvtpi2pd part 1, cvtsi2sd)
  {"cvtf.i2d.hi",    OPCLASS_FP_CONVERTI2F, 6, 0,     ANYFPU}, // high W32s in <rb> to double in <rd> (for cvtdq2pd part 2, cvtpi2pd part 2)
  {"cvtf.q2s.ins",   OPCLASS_FP_CONVERTI2F, 6, 0,     ANYFPU}, // one W64s <rb> to single, insert into low 32 bits of <ra> (for cvtsi2ss with REX.mode64 prefix)
  {"cvtf.q2d",       OPCLASS_FP_CONVERTI2F, 6, 0,     ANYFPU}, // one W64s <rb> to double in <rd>, ignore <ra> (for cvtsi2sd with REX.mode64 prefix)
  {"cvtf.s2i",       OPCLASS_FP_CONVERTF2I, 6, 0,     ANYFPU}, // one single <rb> to W32s in <rd> (for cvtss2si, cvttss2si)
  {"cvtf.s2q",       OPCLASS_FP_CONVERTF2I, 6, 0,     ANYFPU}, // one single <rb> to W64s in <rd> (for cvtss2si, cvttss2si with REX.mode64 prefix)
  {"cvtf.s2i.p",     OPCLASS_FP_CONVERTF2I, 6, 0,     ANYFPU}, // pair of singles in <rb> to pair of W32s in <rd> (for cvtps2pi, cvttps2pi, cvtps2dq, cvttps2dq)
  {"cvtf.d2i",       OPCLASS_FP_CONVERTF2I, 6, 0,     ANYFPU}, // one double <rb> to W32s in <rd> (for cvtsd2si, cvttsd2si)
  {"cvtf.d2q",       OPCLASS_FP_CONVERTF2I, 6, 0,     ANYFPU}, // one double <rb> to W64s in <rd> (for cvtsd2si with REX.mode64 prefix)
  {"cvtf.d2i.p",     OPCLASS_FP_CONVERTF2I, 6, 0,     ANYFPU}, // pair of doubles in <ra> (high), <rb> (low) to pair of W32s in <rd> (for cvtpd2pi, cvttpd2pi, cvtpd2dq, cvttpd2dq), clear high 64 bits of dest xmm
  {"cvtf.d2s.ins",   OPCLASS_FP_CONVERTFP,  6, 0,     ANYFPU}, // double in <rb> to single, insert into low 32 bits of <ra> (for cvtsd2ss)
  {"cvtf.d2s.p",     OPCLASS_FP_CONVERTFP,  6, 0,     ANYFPU}, // pair of doubles in <ra> (high), <rb> (low) to pair of singles in <rd> (for cvtpd2ps)
  {"cvtf.s2d.lo",    OPCLASS_FP_CONVERTFP,  6, 0,     ANYFPU}, // low single in <rb> to double in <rd> (for cvtps2pd, part 1, cvtss2sd)
  {"cvtf.s2d.hi",    OPCLASS_FP_CONVERTFP,  6, 0,     ANYFPU}, // high single in <rb> to double in <rd> (for cvtps2pd, part 2)
};

#undef A
#undef L
#undef F

const char* exception_names[EXCEPTION_COUNT] = {
// 0123456789abcdef
  "NoException",
  "Propagate",
  "BranchMiss",
  "Unaligned",
  "PageRead",
  "PageWrite",
  "PageExec",
  "(reserved)",
  "(reserved)",
  "(reserved)",
  "(reserved)",
  "LdStAlias",
  "CheckFailed",
  "SkipBlock",
  "CacheLocked",
  "LFRQFull",
  "Float",
  "Timer",
  "External",
};

const char* arch_reg_names[TRANSREG_COUNT] = {
  // Integer registers
  "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
  // SSE registers
  "xmml0", "xmmh0", "xmml1", "xmmh1", "xmml2", "xmmh2", "xmml3", "xmmh3",
  "xmml4", "xmmh4", "xmml5", "xmmh5", "xmml6", "xmmh6", "xmml7", "xmmh7",
  "xmml8", "xmmh8", "xmml9", "xmmh9", "xmml10", "xmmh10", "xmml11", "xmmh11",
  "xmml12", "xmmh12", "xmml13", "xmmh13", "xmml14", "xmmh14", "xmml15", "xmmh15",
  // x87 FP/MMX
  "fptos", "fpsw", "fpcw", "fptags", "fp4", "fp5", "fp6", "fp7",
  // Special
  "rip", "flags", "sr3", "mxcsr", "sr0", "sr1", "sr2", "zero",
  // The following are ONLY used during the translation and renaming process:
  "tr0", "tr1", "tr2", "tr3", "tr4", "tr5", "tr6", "tr7",
  "zf", "cf", "of", "imm", "mem", "tr8", "tr9", "tr10",
};

/*
 * Convert a condition code (as in jump, setcc, cmovcc, etc) to
 * the one or two architectural registers last updated with the
 * flags that uop will test.
 */
const CondCodeToFlagRegs cond_code_to_flag_regs[16] = {
  {0, REG_zero, REG_of},   // of:               jo
  {0, REG_zero, REG_of},   // !of:              jno
  {0, REG_zero, REG_cf},   // cf:               jb jc jnae
  {0, REG_zero, REG_cf},   // !cf:              jnb jnc jae
  {0, REG_zf,   REG_zero}, // zf:               jz je
  {0, REG_zf,   REG_zero}, // !zf:              jnz jne
  {1, REG_zf,   REG_cf},   // cf|zf:            jbe jna
  {1, REG_zf,   REG_cf},   // !cf & !zf:        jnbe ja
  {0, REG_zf,   REG_zero}, // sf:               js 
  {0, REG_zf,   REG_zero}, // !sf:              jns
  {0, REG_zf,   REG_zero}, // pf:               jp jpe
  {0, REG_zf,   REG_zero}, // !pf:              jnp jpo
  {1, REG_zf,   REG_of},   // sf != of:         jl jnge (*)
  {1, REG_zf,   REG_of},   // sf == of:         jnl jge (*)
  {1, REG_zf,   REG_of},   // zf | (sf != of):  jle jng (*)
  {1, REG_zf,   REG_of},   // !zf & (sf == of): jnle jg (*)
  //
  // (*) Technically three flags are involved in the comparison here,
  // however as pursuant to the ZAPS trick, zf/af/pf/sf are always
  // either all written together or not written at all. Hence the
  // last writer of SF will also deliver ZF in the same result.
  //
};

const char* cond_code_names[16] = { "o", "no", "c", "nc", "e", "ne", "be", "nbe", "s", "ns", "p", "np", "l", "nl", "le", "nle" };
const char* x86_flag_names[FLAG_COUNT] = {"c", "X", "p", "W", "a", "?", "z", "s", "t", "i", "d", "o", "iopl0", "iopl1", "nt", "rf", "vm", "ac", "vif", "vip", "id"};

const char* setflag_names[SETFLAG_COUNT] = {"z", "c", "o"};
const W16 setflags_to_x86_flags[1<<3] = {
  0       | 0       | 0,         // 000 = n/a
  0       | 0       | FLAG_ZAPS, // 001 = Z
  0       | FLAG_CF | 0,         // 010 =  C
  0       | FLAG_CF | FLAG_ZAPS, // 011 = ZC
  FLAG_OF | 0       | 0,         // 100 =   O
  FLAG_OF | 0       | FLAG_ZAPS, // 101 = Z O
  FLAG_OF | FLAG_CF | 0,         // 110 =  CO
  FLAG_OF | FLAG_CF | FLAG_ZAPS, // 111 = ZCO
};

stringbuf& operator <<(stringbuf& sb, const TransOp& op) {
  static const char* size_names[4] = {"b", "w", "d", ""};
  // e.g. addfp, addfv, addfd, xxx
  static const char* fptype_names[4] = {"p", "v", "d", "d"};

  bool ld = isload(op.opcode);
  bool st = isstore(op.opcode);
  bool fp = (isclass(op.opcode, OPCLASS_FP_ALU));

  stringbuf sbname;

  sbname << nameof(op.opcode);
  sbname << (fp ? fptype_names[op.size] : size_names[op.size]);

  if (isclass(op.opcode, OPCLASS_USECOND)) sbname << ".", cond_code_names[op.cond];
  if (op.opcode == OP_ldx || op.opcode == OP_ldx_lm) sbname << (char)('0' + (1 << op.extshift));
  if (isload(op.opcode) || isstore(op.opcode)) {
    sbname << ((op.cond == LDST_ALIGN_LO) ? ".low" : (op.cond == LDST_ALIGN_HI) ? ".high" : "");
  } else if (op.opcode == OP_mask) {
    sbname << ((op.cond == 0) ? "" : (op.cond == 1) ? ".z" : (op.cond == 2) ? ".x" : ".???");
  }

  if ((ld|st) && (op.cachelevel > 0)) sbname << ".L", (char)('1' + op.cachelevel);
  if (op.internal) sbname << ".p";
  if (op.eom) sbname << ".";

  sb << padstring((char*)sbname, -12), " ", arch_reg_names[op.rd];
  sb << " = ";
  if (ld|st) sb << "[";
  sb << arch_reg_names[op.ra];
  if (op.rb == REG_imm) { sb << ",", op.rbimm; } else  { sb << ",", arch_reg_names[op.rb]; }
  if (ld|st) sb << "]";
  if (op.opcode == OP_mask) {
    sb << ",[ms=", bits(op.rcimm, 0, 6), " mc=", bits(op.rcimm, 6, 6), " ds=", bits(op.rcimm, 12, 6), "]";
  } else {
    if (op.rc != REG_zero) { if (op.rc == REG_imm) sb << ",", op.rcimm; else sb << ",", arch_reg_names[op.rc]; }
  }
  if ((op.opcode == OP_adda || op.opcode == OP_adds || op.opcode == OP_suba || op.opcode == OP_subs) && (op.extshift != 0)) sb << "*", (1 << op.extshift);

  if (op.setflags) {
    sb << " [";
    for (int i = 0; i < SETFLAG_COUNT; i++) {
      if (bit(op.setflags, i)) sb << setflag_names[i];
    }
    sb << "] ";
  }

  if (isbranch(op.opcode)) sb << " [taken ", (void*)(Waddr)op.riptaken, ", seq ", (void*)(Waddr)op.ripseq, "]";

  if (op.som) sb << " (", (int)op.bytes, "b ", (int)op.tagcount, "t ", (int)op.storecount, "s ", (int)op.loadcount, "l ", (int)op.branchcount, "br)";

  return sb;
}

ostream& operator <<(ostream& os, const TransOp& op) {
  stringbuf sb;
  sb << op;
  os << sb;
  return os;
}

void BasicBlock::reset(W64 rip) {
  this->rip = rip_taken = rip_not_taken = rip;
  count = 0;
  refcount = 0;
  repblock = 0;
  usedregs = 0;
  tagcount = 0;
  memcount = 0;
  storecount = 0;
  user_insn_count = 0;
  synthops = null;
}

//
// This is explicitly defined instead of just using a
// destructor since we do some fancy dynamic resizing
// in the clone() method that c++ will croak on.
//
// Once you call this, the basic block is *gone* and
// cannot be accessed ever again, even if it is still
// in scope. Don't call this with non-cloned() blocks.
//
void BasicBlock::free() {
  if (synthops) delete[] synthops;
  synthops = null;
  ::free(this);
}

BasicBlock* BasicBlock::clone() {
  BasicBlock* bb = (BasicBlock*)malloc(sizeof(BasicBlockBase) + (count * sizeof(TransOp)));

  bb->rip = rip;
  bb->rip_taken = rip_taken;
  bb->rip_not_taken = rip_not_taken;
  bb->count = count;
  bb->refcount = refcount;
  bb->repblock = repblock;
  bb->tagcount = tagcount;
  bb->memcount = memcount;
  bb->storecount = storecount;
  bb->user_insn_count = user_insn_count;
  bb->usedregs = usedregs;
  bb->synthops = null;
  foreach (i, count) bb->transops[i] = this->transops[i];
  return bb;
}

ostream& operator <<(ostream& os, const BasicBlock& bb) {
  os << "BasicBlock ", (void*)(Waddr)bb.rip, ": ", bb.count, " transops (", bb.tagcount, "t ", bb.memcount, "m ", bb.storecount, "s";
  if (bb.repblock) os << " rep";
  os << ", uses ", bitstring(bb.usedregs, 64, true), "), ";
  os << bb.refcount, " refs, ", (void*)(Waddr)bb.rip_taken, " taken, ", (void*)(Waddr)bb.rip_not_taken, " not taken:", endl;
  Waddr rip = bb.rip;
  int bytes_in_insn;

  foreach (i, bb.count) {
    const TransOp& transop = bb.transops[i];
    os << "  ", (void*)rip, ": ", transop;

    if (transop.som) os << " [som bytes ", transop.bytes, "]";
    if (transop.eom) os << " [eom]";
    os << endl;

    if (transop.som) bytes_in_insn = transop.bytes;
    if (transop.eom) rip += bytes_in_insn;

    //if (transop.eom) os << "  ;;", endl;
  }
  os << "Basic block terminates with taken rip ", (void*)(Waddr)bb.rip_taken, ", not taken rip ", (void*)(Waddr)bb.rip_not_taken, endl;
  return os;
}

char* regname(int r) {
  static stringbuf temp;
  assert(r >= 0);
  assert(r < 256);
  temp.reset();

  temp << 'r', r;
  return (char*)temp;
}

stringbuf& nameof(stringbuf& sbname, const TransOp& uop) {
  static const char* size_names[4] = {"b", "w", "d", ""};
  static const char* fptype_names[4] = {"ss", "ps", "sd", "pd"};
  int op = uop.opcode;

  bool ld = isload(op);
  bool st = isstore(op);
  bool fp = (isclass(op, OPCLASS_FP_ALU));

  sbname << nameof(op);

  sbname << (fp ? fptype_names[uop.size] : size_names[uop.size]);

  if (isclass(op, OPCLASS_USECOND))
    sbname << ".", cond_code_names[uop.cond];
  if (op == OP_ldx || op == OP_ldx_lm) sbname << (char)('0' + (1 << uop.cond));

  if (ld|st) {
    sbname << ((uop.cond == LDST_ALIGN_LO) ? ".low" : (uop.cond == LDST_ALIGN_HI) ? ".high" : "");
    if (uop.cachelevel > 0) sbname << ".L", (char)('1' + uop.cachelevel);
  }

  if (uop.internal) sbname << ".p";
  
  return sbname;
}

ostream& operator <<(ostream& os, const UserContext& arf) {
  static const int width = 4;
  foreach (i, ARCHREG_COUNT) {
    os << "  ", padstring(arch_reg_names[i], -6), " 0x", hexstring(arf[i], 64), "  ";
    if ((i % width) == (width-1)) os << endl;
  }
  for (int i = 7; i >= 0; i--) {
    int stackid = (i - (arf[REG_fptos] >> 3)) & 0x7;
    os << "  fp", i, "  st(", stackid, ")  ", /* (bit(arf[REG_fptags], i*8) ? "Valid" : "Empty"), */ "  0x", hexstring(fpregs[i], 64), " => ", *((double*)&fpregs[i]), endl;
  }
  return os;
}

ostream& operator <<(ostream& os, const IssueState& state) {
  os << "  rd 0x", hexstring(state.reg.rddata, 64), " (", flagstring(state.reg.rdflags), "), sfrd ", state.st, " (exception ", exception_name(state.reg.rddata), ")", endl;
  return os;
}

ostream& operator <<(ostream& os, const SFR& sfr) {
  if (sfr.invalid) {
    os << "< Invalid: fault 0x", hexstring(sfr.data, 8), " > ";
  } else {
    os << bytemaskstring((const byte*)&sfr.data, sfr.bytemask, 8), " ";
  }

  os << "@ 0x", hexstring(sfr.physaddr << 3, 64), " for memid tag ", sfr.tag;
  return os;
}

stringbuf& print_value_and_flags(stringbuf& sb, W64 value, W16 flags) {
  stringbuf flagsb;
  if (flags & FLAG_ZF) flagsb << 'z';
  if (flags & FLAG_PF) flagsb << 'p';
  if (flags & FLAG_SF) flagsb << 's';
  if (flags & FLAG_CF) flagsb << 'c';
  if (flags & FLAG_OF) flagsb << 'o';

  if (flags & FLAG_INV)
    sb << " < ", padstring(exception_name(value), -14), " >";
  else sb << " 0x", hexstring(value, 64);
  sb << "|", padstring(flagsb, -5);
  return sb;
}

ostream& operator <<(ostream& os, const CoreState& ctx) {
  os << "Architectural state:", endl;
  os << ctx.commitarf;

  os << "Speculative state:", endl;
  os << ctx.specarf;

  os << "Exception Flags", endl;
  os << "  Last exception:            ", "0x", hexstring(ctx.exception, 64), " (", exception_name(ctx.exception), ")", endl;

  return os;
}

