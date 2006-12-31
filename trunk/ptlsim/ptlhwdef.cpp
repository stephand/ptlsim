//
// PTLsim: Cycle Accurate x86-64 Simulator
// Hardware Definitions
//
// Copyright 1999-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <ptlsim.h>
#include <dcache.h>

#ifndef PTLSIM_HYPERVISOR
Context ctx alignto(4096) insection(".ctx");
#endif

extern void print_message(const char* text);

const char* opclass_names[OPCLASS_COUNT] = {
  "logic", "addsub", "addsubc", "addshift", "sel", "cmp", "br.cc", "jmp", "bru", 
  "assist", "mf", "ld", "st", "ld.pre", "shiftsimple", "shift", "mul", "bitscan", "flags",  "chk", 
  "fpu", "fp-div-sqrt", "fp-cmp", "fp-perm", "fp-cvt-i2f", "fp-cvt-f2i", "fp-cvt-f2f",
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

const OpcodeInfo opinfo[OP_MAX_OPCODE] = {
  // name, opclass, latency, fu
  {"nop",            OPCLASS_LOGIC,         A, 0,           ANYINT|ANYFPU},
  {"mov",            OPCLASS_LOGIC,         A, opAB,        ANYINT|ANYFPU}, // move or merge
  // Logical
  {"and",            OPCLASS_LOGIC,         A, opAB,        ANYINT|ANYFPU},
  {"andnot",         OPCLASS_LOGIC,         A, opAB,        ANYINT|ANYFPU},
  {"xor",            OPCLASS_LOGIC,         A, opAB,        ANYINT|ANYFPU},
  {"or",             OPCLASS_LOGIC,         A, opAB,        ANYINT|ANYFPU},
  {"nand",           OPCLASS_LOGIC,         A, opAB,        ANYINT|ANYFPU},
  {"ornot",          OPCLASS_LOGIC,         A, opAB,        ANYINT|ANYFPU},
  {"eqv",            OPCLASS_LOGIC,         A, opAB,        ANYINT|ANYFPU},
  {"nor",            OPCLASS_LOGIC,         A, opAB,        ANYINT|ANYFPU},
  // Mask, insert or extract bytes
  {"maskb",          OPCLASS_SIMPLE_SHIFT,  A, opAB,        ANYINT}, // mask rd = ra,rb,[ds,ms,mc], bytes only
  // Add and subtract
  {"add",            OPCLASS_ADDSUB,        A, opABC|ccC,   ANYINT}, // ra + rb
  {"sub",            OPCLASS_ADDSUB,        A, opABC|ccC,   ANYINT}, // ra - rb
  {"adda",           OPCLASS_ADDSHIFT,      A, opABC,       ANYINT}, // ra + rb + rc
  {"suba",           OPCLASS_ADDSHIFT,      A, opABC,       ANYINT}, // ra - rb + rc
  {"addm",           OPCLASS_ADDSUB,        A, opABC,       ANYINT}, // lowbits(ra + rb, m)
  {"subm",           OPCLASS_ADDSUB,        A, opABC,       ANYINT}, // lowbits(ra - rb, m)
  // Condition code logical ops
  {"andcc",          OPCLASS_FLAGS,         A, opAB|ccAB,   ANYINT},
  {"orcc",           OPCLASS_FLAGS,         A, opAB|ccAB,   ANYINT},
  {"xorcc",          OPCLASS_FLAGS,         A, opAB|ccAB,   ANYINT},
  {"ornotcc",        OPCLASS_FLAGS,         A, opAB|ccAB,   ANYINT},
  // Condition code movement and merging
  {"movccr",         OPCLASS_FLAGS,         A, opB|ccB,     ANYINT},
  {"movrcc",         OPCLASS_FLAGS,         A, opB,         ANYINT},
  {"collcc",         OPCLASS_FLAGS,         A, opABC|ccABC, ANYINT},
  // Simple shifting (restricted to small immediate 1..8)
  {"shls",           OPCLASS_SIMPLE_SHIFT,  A, opAB,        ANYINT}, // rb imm limited to 0-8
  {"shrs",           OPCLASS_SIMPLE_SHIFT,  A, opAB,        ANYINT}, // rb imm limited to 0-8
  {"bswap",          OPCLASS_LOGIC,         A, opAB,        ANYINT}, // byte swap rb
  {"sars",           OPCLASS_SIMPLE_SHIFT,  A, opAB,        ANYINT}, // rb imm limited to 0-8
  // Bit testing
  {"bt",             OPCLASS_LOGIC,         A, opAB,        ANYALU},
  {"bts",            OPCLASS_LOGIC,         A, opAB,        ANYALU},
  {"btr",            OPCLASS_LOGIC,         A, opAB,        ANYALU},
  {"btc",            OPCLASS_LOGIC,         A, opAB,        ANYALU},
  // Set and select
  {"set",            OPCLASS_SELECT,        A, opABC|ccC,   ANYINT},
  {"set.sub",        OPCLASS_SELECT,        A, opABC,       ANYINT},
  {"set.and",        OPCLASS_SELECT,        A, opABC,       ANYINT},
  {"sel",            OPCLASS_SELECT,        A, opABC|ccABC, ANYINT}, // rd = falsereg,truereg,condreg
  // Branches
  {"br",             OPCLASS_COND_BRANCH,   A, opAB|ccAB,   ANYINT}, // branch
  {"br.sub",         OPCLASS_COND_BRANCH,   A, opAB,        ANYINT}, // compare and branch ("cmp" form: subtract)
  {"br.and",         OPCLASS_COND_BRANCH,   A, opAB,        ANYINT}, // compare and branch ("test" form: and)
  {"jmp",            OPCLASS_INDIR_BRANCH,  A, opA,         ANYINT}, // indirect user branch
  {"bru",            OPCLASS_UNCOND_BRANCH, A, 0,     ANYINT}, // unconditional branch (branch cap)
  {"jmpp",           OPCLASS_INDIR_BRANCH|OPCLASS_BARRIER,  A, opA, ANYALU|ANYLDU}, // indirect branch within PTL
  {"brp",            OPCLASS_UNCOND_BRANCH|OPCLASS_BARRIER, A, 0, ANYALU|ANYLDU}, // unconditional branch (PTL only)
  // Checks
  {"chk",            OPCLASS_CHECK,         A, opAB|ccAB,   ANYINT}, // check condition and rollback if false (uses cond codes); rcimm is exception type
  {"chk.sub",        OPCLASS_CHECK,         A, opAB,        ANYINT}, // check ("cmp" form: subtract)
  {"chk.and",        OPCLASS_CHECK,         A, opAB,        ANYINT}, // check ("test" form: and)
  // Loads and stores
  {"ld",             OPCLASS_LOAD,          L, opABC,       ANYLDU}, // load zero extended
  {"ldx",            OPCLASS_LOAD,          L, opABC,       ANYLDU}, // load sign extended
  {"ld.pre",         OPCLASS_PREFETCH,      1, opAB,        ANYLDU}, // prefetch
  {"st",             OPCLASS_STORE,         1, opABC,       ANYSTU}, // store
  {"mf",             OPCLASS_FENCE,         1, 0,           STU0  }, // memory fence (extshift holds type: 01 = st, 10 = ld, 11 = ld.st)
  // Shifts, rotates and complex masking
  {"shl",            OPCLASS_SHIFTROT,      A, opABC|ccC,   ANYALU},
  {"shr",            OPCLASS_SHIFTROT,      A, opABC|ccC,   ANYALU},
  {"mask",           OPCLASS_SHIFTROT,      A, opAB,        ANYALU}, // mask rd = ra,rb,[ds,ms,mc]
  {"sar",            OPCLASS_SHIFTROT,      A, opABC|ccC,   ANYALU},
  {"rotl",           OPCLASS_SHIFTROT,      A, opABC|ccC,   ANYALU},  
  {"rotr",           OPCLASS_SHIFTROT,      A, opABC|ccC,   ANYALU},   
  {"rotcl",          OPCLASS_SHIFTROT,      A, opABC|ccC,   ANYALU},
  {"rotcr",          OPCLASS_SHIFTROT,      A, opABC|ccC,   ANYALU},  
  // Multiplication
  {"mull",           OPCLASS_MULTIPLY,      4, opAB,        ANYFPU},
  {"mulh",           OPCLASS_MULTIPLY,      4, opAB,        ANYFPU},
  {"mulhu",          OPCLASS_MULTIPLY,      4, opAB,        ANYFPU},
  // Bit scans
  {"ctz",            OPCLASS_BITSCAN,       3, opB,         ANYFPU},
  {"clz",            OPCLASS_BITSCAN,       3, opB,         ANYFPU},
  {"ctpop",          OPCLASS_BITSCAN,       3, opB,         ANYFPU},  
  {"permb",          OPCLASS_SHIFTROT,      4, opABC,       ANYFPU}, // from fpa port
  // Floating point
  // uop.size bits have following meaning:
  // 00 = single precision, scalar (preserve high 32 bits of ra)
  // 01 = single precision, packed (two 32-bit floats)
  // 1x = double precision, scalar or packed (use two uops to process 128-bit xmm)
  {"addf",           OPCLASS_FP_ALU,        6, opAB,        ANYFPU},
  {"subf",           OPCLASS_FP_ALU,        6, opAB,        ANYFPU},
  {"mulf",           OPCLASS_FP_ALU,        6, opAB,        ANYFPU},
  {"maddf",          OPCLASS_FP_ALU,        6, opABC,       ANYFPU},
  {"msubf",          OPCLASS_FP_ALU,        6, opABC,       ANYFPU},
  {"divf",           OPCLASS_FP_DIVSQRT,    6, opAB,        ANYFPU},
  {"sqrtf",          OPCLASS_FP_DIVSQRT,    6, opAB,        ANYFPU},
  {"rcpf",           OPCLASS_FP_DIVSQRT,    6, opAB,        ANYFPU},
  {"rsqrtf",         OPCLASS_FP_DIVSQRT,    6, opAB,        ANYFPU},
  {"minf",           OPCLASS_FP_COMPARE,    4, opAB,        ANYFPU},
  {"maxf",           OPCLASS_FP_COMPARE,    4, opAB,        ANYFPU},
  {"cmpf",           OPCLASS_FP_COMPARE,    4, opAB,        ANYFPU},
  // For fcmpcc, uop.size bits have following meaning:
  // 00 = single precision ordered compare
  // 01 = single precision unordered compare
  // 10 = double precision ordered compare
  // 11 = double precision unordered compare
  {"cmpccf",         OPCLASS_FP_COMPARE,    4, opAB,        ANYFPU},
  // and/andn/or/xor are done using integer uops
  {"permf",          OPCLASS_FP_PERMUTE,    3, opAB,        ANYFPU}, // shuffles
  // For these conversions, uop.size bits select truncation mode:
  // x0 = normal IEEE-style rounding
  // x1 = truncate to zero
  {"cvtf.i2s.ins",   OPCLASS_FP_CONVERTI2F, 6, opAB,        ANYFPU}, // one W32s <rb> to single, insert into low 32 bits of <ra> (for cvtsi2ss)
  {"cvtf.i2s.p",     OPCLASS_FP_CONVERTI2F, 6, opB,         ANYFPU}, // pair of W32s <rb> to pair of singles <rd> (for cvtdq2ps, cvtpi2ps)
  {"cvtf.i2d.lo",    OPCLASS_FP_CONVERTI2F, 6, opB,         ANYFPU}, // low W32s in <rb> to double in <rd> (for cvtdq2pd part 1, cvtpi2pd part 1, cvtsi2sd)
  {"cvtf.i2d.hi",    OPCLASS_FP_CONVERTI2F, 6, opB,         ANYFPU}, // high W32s in <rb> to double in <rd> (for cvtdq2pd part 2, cvtpi2pd part 2)
  {"cvtf.q2s.ins",   OPCLASS_FP_CONVERTI2F, 6, opAB,        ANYFPU}, // one W64s <rb> to single, insert into low 32 bits of <ra> (for cvtsi2ss with REX.mode64 prefix)
  {"cvtf.q2d",       OPCLASS_FP_CONVERTI2F, 6, opAB,        ANYFPU}, // one W64s <rb> to double in <rd>, ignore <ra> (for cvtsi2sd with REX.mode64 prefix)
  {"cvtf.s2i",       OPCLASS_FP_CONVERTF2I, 6, opB,         ANYFPU}, // one single <rb> to W32s in <rd> (for cvtss2si, cvttss2si)
  {"cvtf.s2q",       OPCLASS_FP_CONVERTF2I, 6, opB,         ANYFPU}, // one single <rb> to W64s in <rd> (for cvtss2si, cvttss2si with REX.mode64 prefix)
  {"cvtf.s2i.p",     OPCLASS_FP_CONVERTF2I, 6, opB,         ANYFPU}, // pair of singles in <rb> to pair of W32s in <rd> (for cvtps2pi, cvttps2pi, cvtps2dq, cvttps2dq)
  {"cvtf.d2i",       OPCLASS_FP_CONVERTF2I, 6, opB,         ANYFPU}, // one double <rb> to W32s in <rd> (for cvtsd2si, cvttsd2si)
  {"cvtf.d2q",       OPCLASS_FP_CONVERTF2I, 6, opB,         ANYFPU}, // one double <rb> to W64s in <rd> (for cvtsd2si with REX.mode64 prefix)
  {"cvtf.d2i.p",     OPCLASS_FP_CONVERTF2I, 6, opAB,        ANYFPU}, // pair of doubles in <ra> (high), <rb> (low) to pair of W32s in <rd> (for cvtpd2pi, cvttpd2pi, cvtpd2dq, cvttpd2dq), clear high 64 bits of dest xmm
  {"cvtf.d2s.ins",   OPCLASS_FP_CONVERTFP,  6, opAB,        ANYFPU}, // double in <rb> to single, insert into low 32 bits of <ra> (for cvtsd2ss)
  {"cvtf.d2s.p",     OPCLASS_FP_CONVERTFP,  6, opAB,        ANYFPU}, // pair of doubles in <ra> (high), <rb> (low) to pair of singles in <rd> (for cvtpd2ps)
  {"cvtf.s2d.lo",    OPCLASS_FP_CONVERTFP,  6, opB,         ANYFPU}, // low single in <rb> to double in <rd> (for cvtps2pd, part 1, cvtss2sd)
  {"cvtf.s2d.hi",    OPCLASS_FP_CONVERTFP,  6, opB,         ANYFPU}, // high single in <rb> to double in <rd> (for cvtps2pd, part 2)
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
  "StStAlias",
  "LdStAlias",
  "CheckFailed",
  "SkipBlock",
  "CacheLocked",
  "LFRQFull",
  "Float",
  "FloatNotAvail"
};

const char* x86_exception_names[256] = {
  "divide",
  "debug",
  "nmi",
  "breakpoint",
  "overflow",
  "bounds",
  "invalid opcode",
  "fpu not avail",
  "double fault",
  "coproc overrun",
  "invalid tss",
  "seg not present",
  "stack fault",
  "gp fault",
  "page fault",
  "spurious int",
  "fpu",
  "unaligned",
  "machine check",
  "sse",
  "int14h", "int15h", "int16h", "int17h",
  "int18h", "int19h", "int1Ah", "int1Bh", "int1Ch", "int1Dh", "int1Eh", "int1Fh",
  "int20h", "int21h", "int22h", "int23h", "int24h", "int25h", "int26h", "int27h",
  "int28h", "int29h", "int2Ah", "int2Bh", "int2Ch", "int2Dh", "int2Eh", "int2Fh",
  "int30h", "int31h", "int32h", "int33h", "int34h", "int35h", "int36h", "int37h",
  "int38h", "int39h", "int3Ah", "int3Bh", "int3Ch", "int3Dh", "int3Eh", "int3Fh",
  "int40h", "int41h", "int42h", "int43h", "int44h", "int45h", "int46h", "int47h",
  "int48h", "int49h", "int4Ah", "int4Bh", "int4Ch", "int4Dh", "int4Eh", "int4Fh",
  "int50h", "int51h", "int52h", "int53h", "int54h", "int55h", "int56h", "int57h",
  "int58h", "int59h", "int5Ah", "int5Bh", "int5Ch", "int5Dh", "int5Eh", "int5Fh",
  "int60h", "int61h", "int62h", "int63h", "int64h", "int65h", "int66h", "int67h",
  "int68h", "int69h", "int6Ah", "int6Bh", "int6Ch", "int6Dh", "int6Eh", "int6Fh",
  "int70h", "int71h", "int72h", "int73h", "int74h", "int75h", "int76h", "int77h",
  "int78h", "int79h", "int7Ah", "int7Bh", "int7Ch", "int7Dh", "int7Eh", "int7Fh",
  "int80h", "int81h", "int82h", "int83h", "int84h", "int85h", "int86h", "int87h",
  "int88h", "int89h", "int8Ah", "int8Bh", "int8Ch", "int8Dh", "int8Eh", "int8Fh",
  "int90h", "int91h", "int92h", "int93h", "int94h", "int95h", "int96h", "int97h",
  "int98h", "int99h", "int9Ah", "int9Bh", "int9Ch", "int9Dh", "int9Eh", "int9Fh",
  "intA0h", "intA1h", "intA2h", "intA3h", "intA4h", "intA5h", "intA6h", "intA7h",
  "intA8h", "intA9h", "intAAh", "intABh", "intACh", "intADh", "intAEh", "intAFh",
  "intB0h", "intB1h", "intB2h", "intB3h", "intB4h", "intB5h", "intB6h", "intB7h",
  "intB8h", "intB9h", "intBAh", "intBBh", "intBCh", "intBDh", "intBEh", "intBFh",
  "intC0h", "intC1h", "intC2h", "intC3h", "intC4h", "intC5h", "intC6h", "intC7h",
  "intC8h", "intC9h", "intCAh", "intCBh", "intCCh", "intCDh", "intCEh", "intCFh",
  "intD0h", "intD1h", "intD2h", "intD3h", "intD4h", "intD5h", "intD6h", "intD7h",
  "intD8h", "intD9h", "intDAh", "intDBh", "intDCh", "intDDh", "intDEh", "intDFh",
  "intE0h", "intE1h", "intE2h", "intE3h", "intE4h", "intE5h", "intE6h", "intE7h",
  "intE8h", "intE9h", "intEAh", "intEBh", "intECh", "intEDh", "intEEh", "intEFh",
  "intF0h", "intF1h", "intF2h", "intF3h", "intF4h", "intF5h", "intF6h", "intF7h",
  "intF8h", "intF9h", "intFAh", "intFBh", "intFCh", "intFDh", "intFEh", "intFFh"
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
  "fptos", "fpsw", "fptags", "fpstack", "tr4", "tr5", "tr6", "ctx",
  // Special
  "rip", "flags", "iflags", "selfrip","nextrip", "ar1", "ar2", "zero",
  // The following are ONLY used during the translation and renaming process:
  "tr0", "tr1", "tr2", "tr3", "tr4", "tr5", "tr6", "tr7",
  "zf", "cf", "of", "imm", "mem", "tr8", "tr9", "tr10",
};

void Context::fxsave(FXSAVEStruct& state) {
  state.cw = fpcw;
  // clear everything but 4 FP status flag bits (c3/c2/c1/c0):
  state.sw = commitarf[REG_fpsw] & ((0x7 << 8) | (1 << 14));
  int tos = commitarf[REG_fptos] >> 3;
  assert(inrange(tos, 0, 7));
  state.sw.tos = tos;
  state.tw = 0;

  // Prepare tag word (special format for FXSAVE)
  foreach (i, 8) state.tw |= (bit(commitarf[REG_fptags], i*8) << i);

  // Prepare actual registers
  foreach (i, 8) x87_fp_64bit_to_80bit(&state.fpregs[i].reg, fpstack[lowbits(tos + i, 3)]);

  state.fop = 0;

  if (use64) {
    state.use64.rip = 0;
    state.use64.rdp = 0;
  } else {
    state.use32.eip = 0;
    state.use32.cs = 0;
    state.use32.dp = 0;
    state.use32.ds = 0;
  }

  state.mxcsr = mxcsr;
  state.mxcsr_mask = 0x0000ffff; // all MXCSR features supported

  foreach (i, (use64) ? 16 : 8) {
    state.xmmregs[i].lo = commitarf[REG_xmml0 + i*2];
    state.xmmregs[i].hi = commitarf[REG_xmmh0 + i*2];
  }
}

void Context::fxrstor(const FXSAVEStruct& state) {
  commitarf[REG_fptos] = state.sw.tos * 8;
  commitarf[REG_fpsw] = state.sw;
  fpcw = state.cw;

  commitarf[REG_fptags] = 0;
  foreach (i, 8) {
    // FXSAVE struct uses an abbreviated tag word with 8 bits (0 = empty, 1 = used)
    int used = bit(state.tw, i);
    commitarf[REG_fptags] |= ((W64)used) << i*8;
  }

  // x86 FSAVE state is in order of stack rather than physical registers:
  foreach (i, 8) {
    fpstack[lowbits(state.sw.tos + i, 3)] = x87_fp_80bit_to_64bit(&state.fpregs[i].reg);
  }

  mxcsr = state.mxcsr & state.mxcsr_mask;

  foreach (i, (use64) ? 16 : 8) {
    commitarf[REG_xmml0 + i*2] = state.xmmregs[i].lo;
    commitarf[REG_xmmh0 + i*2] = state.xmmregs[i].hi;
  }
}

const char* datatype_names[DATATYPE_COUNT] = {
  "int", "float", "vec-float",
  "double", "vec-double", 
  "vec-8bit", "vec-16bit", 
  "vec-32bit", "vec-64bit", 
  "vec-128bit"
};

extern const char* datatype_names[DATATYPE_COUNT];
/*
 * Convert a condition code (as in jump, setcc, cmovcc, etc) to
 * the one or two architectural registers last updated with the
 * flags that uop will test.
 */
const CondCodeToFlagRegs cond_code_to_flag_regs[16] = {
  {0, REG_of,   REG_of},   // of:               jo          (rb only)
  {0, REG_of,   REG_of},   // !of:              jno         (rb only)
  {0, REG_cf,   REG_cf},   // cf:               jb jc jnae  (rb only)
  {0, REG_cf,   REG_cf},   // !cf:              jnb jnc jae (rb only)
  {0, REG_zf,   REG_zf},   // zf:               jz je       (ra only)
  {0, REG_zf,   REG_zf},   // !zf:              jnz jne     (ra only)
  {1, REG_zf,   REG_cf},   // cf|zf:            jbe jna
  {1, REG_zf,   REG_cf},   // !cf & !zf:        jnbe ja
  {0, REG_zf,   REG_zf},   // sf:               js          (ra only)
  {0, REG_zf,   REG_zf},   // !sf:              jns         (ra only)
  {0, REG_zf,   REG_zf},   // pf:               jp jpe      (ra only)
  {0, REG_zf,   REG_zf},   // !pf:              jnp jpo     (ra only)
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
const char* x86_flag_names[32] = {
  "c", "X", "p", "W", "a", "B", "z", "s", "t", "i", "d", "o", "iopl0", "iopl1", "nt", "0",
  "rf", "vm", "ac", "vif", "vip", "id", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31"
};

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

stringbuf& operator <<(stringbuf& sb, const TransOpBase& op) {
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

  if (ld|st) {
    if (op.opcode == OP_mf) {
      static const char* mf_names[4] = {"none", "st", "ld", "all"};
      sbname << '.', mf_names[op.extshift];
    }
    sbname << ((op.cond == LDST_ALIGN_LO) ? ".lo" : (op.cond == LDST_ALIGN_HI) ? ".hi" : "");
  } else if (op.opcode == OP_mask) {
    sbname << ((op.cond == 0) ? "" : (op.cond == 1) ? ".z" : (op.cond == 2) ? ".x" : ".???");
  }

  if ((ld|st) && (op.cachelevel > 0)) sbname << ".L", (char)('1' + op.cachelevel);
  if ((ld|st) && (op.locked)) sbname << ((ld) ? ".acq" : ".rel");
  if (op.internal) sbname << ".p";
  if (op.eom) sbname << ".";

  sb << padstring((char*)sbname, -12), " ", arch_reg_names[op.rd];
  sb << " = ";
  if (ld|st) sb << "[";
  sb << arch_reg_names[op.ra];
  if (op.rb == REG_imm) {
    if (abs(op.rbimm) <= 32768) sb << ",", op.rbimm; else sb << ",", (void*)op.rbimm;
  } else {
    sb << ",", arch_reg_names[op.rb];
  }
  if (ld|st) sb << "]";
  if ((op.opcode == OP_mask) | (op.opcode == OP_maskb)) {
    MaskControlInfo mci(op.rcimm);
    int sh = (op.opcode == OP_maskb) ? 3 : 0;
    sb << ",[ms=", (mci.info.ms >> sh), " mc=", (mci.info.mc >> sh), " ds=", (mci.info.ds >> sh), "]";
  } else {
    if (op.rc != REG_zero) { if (op.rc == REG_imm) sb << ",", op.rcimm; else sb << ",", arch_reg_names[op.rc]; }
  }
  if ((op.opcode == OP_adda || op.opcode == OP_suba) && (op.extshift != 0)) sb << "*", (1 << op.extshift);

  if (op.setflags) {
    sb << " ";
    if (op.nouserflags) sb << "int:";
    sb << "[";
    for (int i = 0; i < SETFLAG_COUNT; i++) {
      if (bit(op.setflags, i)) sb << setflag_names[i];
    }
    sb << "] ";
  }

  if (isbranch(op.opcode)) sb << " [taken ", (void*)(Waddr)op.riptaken, ", seq ", (void*)(Waddr)op.ripseq, "]";

  return sb;
}

ostream& operator <<(ostream& os, const TransOpBase& op) {
  stringbuf sb;
  sb << op;
  os << sb;
  return os;
}

ostream& RIPVirtPhysBase::print(ostream& os) const {
#ifdef PTLSIM_HYPERVISOR
  os << "[", (void*)(Waddr)rip;
  os << (use64 ? " 64b" : " 32b");
  os << (kernel ? " krn" : "");
  os << (df ? " df" : "");
  os << " mfn ", mfnlo;
  if (mfnlo != mfnhi) os << "|", mfnhi;
  os << "]";
#else
  os << (void*)(Waddr)rip;
#endif
  return os;
}

void BasicBlock::reset() {
  hashlink.reset();
  mfnlo_loc.reset();
  mfnhi_loc.reset();
  refcount = 0;
  repblock = 0;
  invalidblock = 0;
  call = 0;
  ret = 0;
  type = BB_TYPE_COND;
  usedregs = 0;
  count = 0;
  tagcount = 0;
  memcount = 0;
  storecount = 0;
  user_insn_count = 0;
  bytes = 0;
  synthops = null;
  hitcount = 0;
  predcount = 0;
  confidence = 0;
  lastused = 0;
  marked = 0;
  mfence = 0;
}

void BasicBlock::reset(const RIPVirtPhys& rip) {
  reset();
  this->rip = rip;
  rip_taken = rip;
  rip_not_taken = rip;
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

  memcpy(bb, this, sizeof(BasicBlockBase));

  bb->synthops = null;
  // hashlink, mfnlo_loc, mfnhi_loc are always updated after cloning
  bb->hashlink.reset();
  bb->use(0);

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

    // if (transop.som) os << " [som bytes ", transop.bytes, "]";
    // if (transop.eom) os << " [eom]";
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
  static const char* mask_exttype[4] = {"", "zxt", "sxt", "???"};

  int op = uop.opcode;

  bool ld = isload(op);
  bool st = isstore(op);
  bool fp = (isclass(op, OPCLASS_FP_ALU));

  sbname << nameof(op);

  if ((op != OP_maskb) & (op != OP_mask))
    sbname << (fp ? fptype_names[uop.size] : size_names[uop.size]);
  else sbname << ".", mask_exttype[uop.cond];

  if (isclass(op, OPCLASS_USECOND))
    sbname << ".", cond_code_names[uop.cond];

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
#ifndef PTLSIM_HYPERVISOR
  for (int i = 7; i >= 0; i--) {
    int stackid = (i - (arf[REG_fptos] >> 3)) & 0x7;
    os << "  fp", i, "  st(", stackid, ")  ", /* (bit(arf[REG_fptags], i*8) ? "Valid" : "Empty"), */ "  0x", hexstring(ctx.fpstack[i], 64), " => ", *((double*)&ctx.fpstack[i]), endl;
  }
#endif
  return os;
}

ostream& operator <<(ostream& os, const IssueState& state) {
  os << "  rd 0x", hexstring(state.reg.rddata, 64), " (", flagstring(state.reg.rdflags), "), sfrd ", state.st, " (exception ", exception_name(state.reg.rddata), ")", endl;
  return os;
}

stringbuf& operator <<(stringbuf& os, const SFR& sfr) {
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
    sb << " < ", padstring(exception_name(LO32(value)), -14), " >";
  else sb << " 0x", hexstring(value, 64);
  sb << "|", padstring(flagsb, -5);
  return sb;
}

ostream& operator <<(ostream& os, const PageFaultErrorCode& pfec) {
  os << "[";
  os << (pfec.p ? " present" : " not-present");
  os << (pfec.rw ? " write" : " read");
  os << (pfec.us ? " user" : " kernel");
  os << (pfec.rsv ? " reserved-bits-set" : "");
  os << (pfec.nx ? " execute" : "");
  os << " ]";

  return os;
}

ostream& operator <<(ostream& os, const SegmentDescriptor& seg) {
  os << "base ", hexstring(seg.getbase(), 32), ", limit ", hexstring(seg.getlimit(), 32),
    ", ring ", seg.dpl;
  os << ((seg.s) ? " sys" : " usr");
  os << ((seg.l) ? " 64bit" : "      ");
  os << ((seg.d) ? " 32bit" : " 16bit");
  os << ((seg.g) ? " g=4KB" : "      ");

  if (!seg.p) os << "not present";

  return os;
}

ostream& operator <<(ostream& os, const SegmentDescriptorCache& seg) {
  os << "0x", hexstring(seg.selector, 16), ": ";

  os << "base ", hexstring(seg.base, 64), ", limit ", hexstring(seg.limit, 64), ", ring ", seg.dpl, ":";
  os << ((seg.supervisor) ? " sys" : " usr");
  os << ((seg.use64) ? " 64bit" : "      ");
  os << ((seg.use32) ? " 32bit" : "      ");

  if (!seg.present) os << " (not present)";

  return os;
}

#ifdef PTLSIM_HYPERVISOR
ostream& operator <<(ostream& os, const CR0& cr0) {
  os << hexstring(cr0, 64);
  os << " ";
  os << (cr0.pe ? " PE" : " pe");
  os << (cr0.mp ? " MP" : " mp");
  os << (cr0.em ? " EM" : " em");
  os << (cr0.ts ? " TS" : " ts");
  os << (cr0.et ? " ET" : " et");
  os << (cr0.ne ? " NE" : " ne");
  os << (cr0.wp ? " WP" : " wp");
  os << (cr0.am ? " AM" : " am");
  os << (cr0.nw ? " NW" : " nw");
  os << (cr0.cd ? " CD" : " cd");
  os << (cr0.pg ? " PG" : " pg");
  return os;
}

ostream& operator <<(ostream& os, const CR4& cr4) {
  os << hexstring(cr4, 64);
  os << " ";
  os << (cr4.vme ? " VME" : " vme");
  os << (cr4.pvi ? " PVI" : " pvi");
  os << (cr4.tsd ? " TSD" : " tsd");
  os << (cr4.de  ? " DBE" : " dbe");
  os << (cr4.pse ? " PSE" : " pse");
  os << (cr4.pae ? " PAE" : " pae");
  os << (cr4.mce ? " MCE" : " mce");
  os << (cr4.pge ? " PGE" : " pge");
  os << (cr4.pce ? " PCE" : " pce");
  os << (cr4.osfxsr ? " FXS" : " fxs");
  os << (cr4.osxmmexcpt ? " MME" : " mme");
  return os;
}
#endif

ostream& operator <<(ostream& os, const Context& ctx) {
  static const int arfwidth = 4;

  os << "VCPU State:", endl;
  os << "  Architectural Registers:", endl;
  foreach (i, ARCHREG_COUNT) {
    os << "  ", padstring(arch_reg_names[i], -6), " 0x", hexstring(ctx.commitarf[i], 64);
    if ((i % arfwidth) == (arfwidth-1)) os << endl;
  }

#ifdef PTLSIM_HYPERVISOR
  os << "  Flags:", endl;
  os << "    Running?   ", ((ctx.running) ? "running" : "blocked"), endl;
  os << "    Mode:      ", ((ctx.kernel_mode) ? "kernel" : "user"), ((ctx.kernel_in_syscall) ? " (in syscall)" : ""), endl;
  os << "    32/64:     ", ((ctx.use64) ? "64-bit x86-64" : "32-bit x86"), endl;
  os << "    x87 state: ", ((ctx.i387_valid) ? "valid" : "invalid"), endl;
  os << "    Event dis: ", ((ctx.syscall_disables_events) ? " syscall" : ""), ((ctx.failsafe_disables_events) ? " failsafe" : ""), endl;
  os << "    IntEFLAGS: ", hexstring(ctx.internal_eflags, 32), " (df ", ((ctx.internal_eflags & FLAG_DF) != 0), ")", endl;
#endif
  os << "  Segment Registers:", endl;
  os << "    cs ", ctx.seg[SEGID_CS], endl;
  os << "    ss ", ctx.seg[SEGID_SS], endl;
  os << "    ds ", ctx.seg[SEGID_DS], endl;
  os << "    es ", ctx.seg[SEGID_ES], endl;
  os << "    fs ", ctx.seg[SEGID_FS], endl;
  os << "    gs ", ctx.seg[SEGID_GS], endl;
#ifdef PTLSIM_HYPERVISOR
  os << "  Segment Control Registers:", endl;
  os << "    ldt ", hexstring(ctx.ldtvirt, 64), "  ld# ", hexstring(ctx.ldtsize, 64), "  gd# ", hexstring(ctx.gdtsize, 64), endl;
  os << "    gdt mfns"; foreach (i, 16) { os << " ", ctx.gdtpages[i]; } os << endl;
  os << "    fsB ", hexstring(ctx.fs_base, 64), "  gsB ", hexstring(ctx.gs_base_user, 64), "  gkB ", hexstring(ctx.gs_base_kernel, 64), endl;
  os << "  Control Registers:", endl;
  os << "    cr0 ", ctx.cr0, endl;
  os << "    cr2 ", hexstring(ctx.cr2, 64), "  fault virtual address", endl;
  os << "    cr3 ", hexstring(ctx.cr3, 64), "  page table base (mfn ", (ctx.cr3 >> 12), ")", endl;
  os << "    cr4 ", ctx.cr4, endl;
  os << "    kss ", hexstring(ctx.kernel_ss, 64), "  ksp ", hexstring(ctx.kernel_sp, 64), "  vma ", hexstring(ctx.vm_assist, 64),endl;
  os << "    kPT ", intstring(ctx.kernel_ptbase_mfn, 16), endl;
  os << "    uPT ", intstring(ctx.user_ptbase_mfn, 16), endl;
  os << "  Debug Registers:", endl;
  os << "    dr0 ", hexstring(ctx.dr0, 64), "  dr1 ", hexstring(ctx.dr1, 64), "  dr2 ", hexstring(ctx.dr2, 64),  "  dr3 ", hexstring(ctx.dr3, 64), endl;
  os << "    dr4 ", hexstring(ctx.dr4, 64), "  dr5 ", hexstring(ctx.dr5, 64), "  dr6 ", hexstring(ctx.dr6, 64),  "  dr7 ", hexstring(ctx.dr7, 64), endl;
  os << "  Callbacks:", endl;
  os << "    event_callback_rip    ", hexstring(ctx.event_callback_rip, 64), endl;
  os << "    failsafe_callback_rip ", hexstring(ctx.failsafe_callback_rip, 64), endl;
  os << "    syscall_rip           ", hexstring(ctx.syscall_rip, 64), endl;
  os << "  Virtual IDT Trap Table:", endl;
  foreach (i, lengthof(ctx.idt)) {
    const TrapTarget& tt = ctx.idt[i];
    if (tt.rip) {
      os << "    ", intstring(i, 3), "  0x", hexstring(i, 8), ": ", hexstring((tt.cs << 3) | 3, 16), ":",
        hexstring(signext64(tt.rip, 48), 64), " cpl ", tt.cpl, (tt.maskevents ? " mask-events" : ""), endl;
    }
  }
  os << "  Exception and Event Control:", endl;
  os << "    exception ", intstring(ctx.x86_exception, 2), "  errorcode ", hexstring(ctx.error_code, 32),
    "  saved_upcall_mask ", hexstring(ctx.saved_upcall_mask, 8), endl;
#endif

  os << "  FPU:", endl;
  os << "    FP Control Word: 0x", hexstring(ctx.fpcw, 32), endl;
  os << "    MXCSR:           0x", hexstring(ctx.mxcsr, 32), endl;

  for (int i = 7; i >= 0; i--) {
    int stackid = (i - (ctx.commitarf[REG_fptos] >> 3)) & 0x7;
    os << "    fp", i, "  st(", stackid, ")  ", (bit(ctx.commitarf[REG_fptags], i*8) ? "Valid" : "Empty"),
      "  0x", hexstring(ctx.fpstack[i], 64), " => ", *((double*)&ctx.fpstack[i]), endl;
  }

  os << "  Internal State:", endl;
  os << "    Last internal exception: ", "0x", hexstring(ctx.exception, 64), " (", exception_name(ctx.exception), ")", endl;

  return os;
}

