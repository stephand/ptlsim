//
// PTLsim: Cycle Accurate x86-64 Simulator
// Decoder for x86 and x86-64 to PTL transops
//
// Copyright 1999-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <ptlsim.h>
#include <datastore.h>
#include <decode.h>
#include <stats.h>

BasicBlockCache bbcache;

struct BasicBlockChunkListHashtableLinkManager {
  static inline BasicBlockChunkList& objof(selflistlink* link) {
    return baseof(BasicBlockChunkList, hashlink, link);
  }

  static inline W64& keyof(BasicBlockChunkList& obj) {
    return obj.mfn;
  }

  static inline selflistlink& linkof(BasicBlockChunkList& obj) {
    return obj.hashlink;
  }
};

typedef SelfHashtable<W64, BasicBlockChunkList, BasicBlockChunkListHashtableLinkManager, 16384> BasicBlockPageCache;

BasicBlockPageCache bbpages;
CycleTimer translate_timer("translate");

//
// Calling convention:
// rip = return RIP after insn
// sr0 = RIP of insn
// sr1 = RIP after insn
// sr2 = argument
//

const assist_func_t assistid_to_func[ASSIST_COUNT] = {
  assist_div<byte>,
  assist_div<W16>,
  assist_div<W32>,
  assist_div<W64>,
  assist_idiv<byte>,
  assist_idiv<W16>,
  assist_idiv<W32>,
  assist_idiv<W64>,
  assist_x87_fprem,
  assist_x87_fyl2xp1,
  assist_x87_fsqrt,
  assist_x87_fsincos,
  assist_x87_frndint,
  assist_x87_fscale,
  assist_x87_fsin,
  assist_x87_fcos,
  assist_x87_fxam,
  assist_x87_f2xm1,
  assist_x87_fyl2x,
  assist_x87_fptan,
  assist_x87_fpatan,
  assist_x87_fxtract,
  assist_x87_fprem1,
  assist_x87_fld80,
  assist_x87_fstp80,
  assist_x87_fsave,
  assist_x87_frstor,
  assist_x87_finit,
  assist_x87_fclex,
  assist_ldmxcsr,
  assist_fxsave,
  assist_fxrstor,
  assist_int,
  assist_syscall,
  assist_sysenter,
  assist_cpuid,
  assist_invalid_opcode,
  assist_exec_page_fault,
  assist_gp_fault,
  assist_write_segreg,
  assist_popf,
  assist_cld,
  assist_std,
  assist_ptlcall,
  assist_wrmsr,
  assist_rdmsr,
  assist_write_cr0,
  assist_write_cr2,
  assist_write_cr3,
  assist_write_cr4,
  assist_write_debug_reg,
  assist_iret16,
  assist_iret32,
  assist_iret64,
  assist_ioport_in,
  assist_ioport_out,
};

const char* assist_names[ASSIST_COUNT] = {
  "div8",
  "div16",
  "div32",
  "div64",
  "idiv8",
  "idiv16",
  "idiv32",
  "idiv64",
  "x87_fprem",
  "x87_fyl2xp1",
  "x87_fsqrt",
  "x87_fsincos",
  "x87_frndint",
  "x87_fscale",
  "x87_fsin",
  "x87_fcos",
  "x87_fxam",
  "x87_f2xm1",
  "x87_fyl2x",
  "x87_fptan",
  "x87_fpatan",
  "x87_fxtract",
  "x87_fprem1",
  "x87_fld80",
  "x87_fstp80",
  "fsave",
  "frstor",
  "finit",
  "fclex",
  "ldmxcsr",
  "fxsave",
  "fxrstor",
  "int",
  "syscall",
  "sysenter",
  "cpuid",
  "invalid_opcode",
  "exec_page_fault",
  "gp_fault",
  "write_segreg",
  "popf",
  "cld",
  "std",
  "ptlcall",
  "wrmsr",
  "rdmsr",
  "write_cr0",
  "write_cr2",
  "write_cr3",
  "write_cr4",
  "write_debug_reg",
  "iret16",
  "iret32",
  "iret64",
  "in",
  "out"
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

int assist_index(assist_func_t assist) {
  foreach (i, ASSIST_COUNT) {
    if (assistid_to_func[i] == assist) { 
      return i;
    }
  }

  return -1;
}

const char* assist_name(assist_func_t assist) {
  foreach (i, ASSIST_COUNT) {
    if (assistid_to_func[i] == assist) { 
      return assist_names[i];
    }
  }

  return "unknown";
}

W64 assist_histogram[ASSIST_COUNT];
/*
W64 decoder_type_fast;
W64 decoder_type_complex;
W64 decoder_type_x87;
W64 decoder_type_sse;
*/

void update_assist_stats(assist_func_t assist) {
  int idx = assist_index(assist);
  assert(inrange(idx, 0, ASSIST_COUNT-1));
  assist_histogram[idx]++;
}

void reset_assist_stats() {
  setzero(assist_histogram);
}

/*
void save_assist_stats(DataStoreNode& root) {
  root.histogram("assists", assist_names, assist_histogram, ASSIST_COUNT);
  DataStoreNode& decoder = root("decoder"); {
    decoder.summable = 1;
    decoder.add("fast", decoder_type_fast);
    decoder.add("complex", decoder_type_complex);
    decoder.add("x87", decoder_type_x87);
    decoder.add("sse", decoder_type_sse);
  }

}
*/

void split_unaligned(const TransOp& transop, TransOpBuffer& buf) {
  assert(transop.unaligned);

  bool ld = isload(transop.opcode);
  bool st = isstore(transop.opcode);

  assert(ld|st);

  buf.reset();

  int idx;

  idx = buf.put();
  TransOp& ag = buf.uops[idx];
  ag = transop;
  ag.opcode = OP_add;
  ag.size = 3;
  ag.cond = 0;
  ag.eom = 0;
  ag.internal = 0;
  ag.unaligned = 0;
  ag.rd = REG_temp9;
  ag.rc = REG_zero;
  buf.synthops[idx] = get_synthcode_for_uop(OP_add, 3, 0, 0, 0, 0, 0, 0, 0);

  idx = buf.put();
  TransOp& lo = buf.uops[idx];
  lo = transop;
  lo.ra = REG_temp9;
  lo.rb = REG_zero;
  lo.cond = LDST_ALIGN_LO;
  lo.unaligned = 0;
  lo.eom = 0;
  buf.synthops[idx] = null; // loads and stores are not synthesized

  idx = buf.put();
  TransOp& hi = buf.uops[idx];
  hi = transop;
  hi.ra = REG_temp9;
  hi.rb = REG_zero;
  hi.cond = LDST_ALIGN_HI;
  hi.unaligned = 0;
  hi.som = 0;
  buf.synthops[idx] = null; // loads and stores are not synthesized

  if (ld) {
    // ld rd = [ra+rb]        =>   ld.lo rd = [ra+rb]           and    ld.hi rd = [ra+rb],rd
    lo.rd = REG_temp4;
    lo.size = 3; // always load 64-bit word
    hi.rb = REG_temp4;
  } else {
    //
    // For stores, expand     st sfrd = [ra+rb],rc    =>   st.lo sfrd1 = [ra+rb],rc    and    st.hi sfrd2 = [ra+rb],rc
    //
    // Make sure high part issues first in program order, so if there is
    // a page fault on the high page it overlaps, this will be triggered
    // before the low part overwrites memory.
    //
    lo.cond = LDST_ALIGN_HI;
    hi.cond = LDST_ALIGN_LO;
  }
}

static const W16 prefix_map_x86_64[256] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, PFX_ES, 0, 0, 0, 0, 0, 0, 0, PFX_CS, 0,
  0, 0, 0, 0, 0, 0, PFX_SS, 0, 0, 0, 0, 0, 0, 0, PFX_DS, 0,
  PFX_REX, PFX_REX, PFX_REX, PFX_REX, PFX_REX, PFX_REX, PFX_REX, PFX_REX, PFX_REX, PFX_REX, PFX_REX, PFX_REX, PFX_REX, PFX_REX, PFX_REX, PFX_REX,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, PFX_FS, PFX_GS, PFX_DATA, PFX_ADDR, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, PFX_FWAIT, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  PFX_LOCK, 0, PFX_REPNZ, PFX_REPZ, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static const W16 prefix_map_x86[256] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, PFX_ES, 0, 0, 0, 0, 0, 0, 0, PFX_CS, 0,
  0, 0, 0, 0, 0, 0, PFX_SS, 0, 0, 0, 0, 0, 0, 0, PFX_DS, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, PFX_FS, PFX_GS, PFX_DATA, PFX_ADDR, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, PFX_FWAIT, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  PFX_LOCK, 0, PFX_REPNZ, PFX_REPZ, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

const char* prefix_names[PFX_count] = {"repz", "repnz", "lock", "cs", "ss", "ds", "es", "fs", "gs", "datasz", "addrsz", "rex", "fwait"};

const char* uniform_arch_reg_names[APR_COUNT] = {
  // 64-bit
  "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
  // 32-bit
  "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
  // 16-bit
  "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
  // 8-bit
  "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
  // 8-bit with REX:
  "spl", "bpl", "sil", "dil",
  "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
  // SSE registers
  "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
  // segments
  "es", "cs", "ss", "ds", "fs", "gs",
  // special:
  "rip", "zero",
};

const ArchPseudoRegInfo reginfo[APR_COUNT] = {
  // 64-bit
  {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0},
  // 32-bit
  {2, 0}, {2, 0}, {2, 0}, {2, 0}, {2, 0}, {2, 0}, {2, 0}, {2, 0}, {2, 0}, {2, 0}, {2, 0}, {2, 0}, {2, 0}, {2, 0}, {2, 0}, {2, 0},
  // 16-bit
  {1, 0}, {1, 0}, {1, 0}, {1, 0}, {1, 0}, {1, 0}, {1, 0}, {1, 0}, {1, 0}, {1, 0}, {1, 0}, {1, 0}, {1, 0}, {1, 0}, {1, 0}, {1, 0},
  // 8-bit
  {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 1}, {0, 1}, {0, 1}, {0, 1},
  // 8-bit with REX, not double-counting the regular 8-bit regs:
  {0, 0}, {0, 0}, {0, 0}, {0, 0}, 
  {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0},
  // SSE registers
  {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 0},
  // segments:
  {1, 0}, {1, 0}, {1, 0}, {1, 0}, {1, 0}, {1, 0}, 
  // special:
  {3, 0}, {3, 0},
};

const byte reg64_to_uniform_reg[16] = { APR_rax, APR_rcx, APR_rdx, APR_rbx, APR_rsp, APR_rbp, APR_rsi, APR_rdi, APR_r8, APR_r9, APR_r10, APR_r11, APR_r12, APR_r13, APR_r14, APR_r15 };
const byte xmmreg_to_uniform_reg[16] = { APR_xmm0, APR_xmm1, APR_xmm2, APR_xmm3, APR_xmm4, APR_xmm5, APR_xmm6, APR_xmm7, APR_xmm8, APR_xmm9, APR_xmm10, APR_xmm11, APR_xmm12, APR_xmm13, APR_xmm14, APR_xmm15 };
const byte reg32_to_uniform_reg[16] = { APR_eax, APR_ecx, APR_edx, APR_ebx, APR_esp, APR_ebp, APR_esi, APR_edi, APR_r8d, APR_r9d, APR_r10d, APR_r11d, APR_r12d, APR_r13d, APR_r14d, APR_r15d };
const byte reg16_to_uniform_reg[16] = { APR_ax, APR_cx, APR_dx, APR_bx, APR_sp, APR_bp, APR_si, APR_di, APR_r8w, APR_r9w, APR_r10w, APR_r11w, APR_r12w, APR_r13w, APR_r14w, APR_r15w };
const byte reg8_to_uniform_reg[8] = { APR_al, APR_cl, APR_dl, APR_bl, APR_ah, APR_ch, APR_dh, APR_bh };
const byte reg8x_to_uniform_reg[16] = { APR_al, APR_cl, APR_dl, APR_bl, APR_spl, APR_bpl, APR_sil, APR_dil, APR_r8b, APR_r9b, APR_r10b, APR_r11b, APR_r12b, APR_r13b, APR_r14b, APR_r15b };
const byte segreg_to_uniform_reg[16] = { APR_es, APR_cs, APR_ss, APR_ds, APR_fs, APR_zero, APR_zero };

const byte arch_pseudo_reg_to_arch_reg[APR_COUNT] = {
  // 64-bit
  REG_rax, REG_rcx, REG_rdx, REG_rbx, REG_rsp, REG_rbp, REG_rsi, REG_rdi, REG_r8, REG_r9, REG_r10, REG_r11, REG_r12, REG_r13, REG_r14, REG_r15,
  // 32-bit
  REG_rax, REG_rcx, REG_rdx, REG_rbx, REG_rsp, REG_rbp, REG_rsi, REG_rdi, REG_r8, REG_r9, REG_r10, REG_r11, REG_r12, REG_r13, REG_r14, REG_r15,
  // 16-bit
  REG_rax, REG_rcx, REG_rdx, REG_rbx, REG_rsp, REG_rbp, REG_rsi, REG_rdi, REG_r8, REG_r9, REG_r10, REG_r11, REG_r12, REG_r13, REG_r14, REG_r15,
  // 8-bit
  REG_rax, REG_rcx, REG_rdx, REG_rbx, REG_rax, REG_rcx, REG_rdx, REG_rbx,
  // 8-bit with REX, not double-counting the regular 8-bit regs:
  REG_rsp, REG_rbp, REG_rsi, REG_rdi,
  REG_r8, REG_r9, REG_r10, REG_r11, REG_r12, REG_r13, REG_r14, REG_r15,
  // SSE registers
  REG_xmml0, REG_xmml1, REG_xmml2, REG_xmml3, REG_xmml4, REG_xmml5, REG_xmml6, REG_xmml7, REG_xmml8, REG_xmml9, REG_xmml10, REG_xmml11, REG_xmml12, REG_xmml13, REG_xmml14, REG_xmml15,
  // segments:
  REG_zero, REG_zero, REG_zero, REG_zero, REG_zero, REG_zero,
  // special:
  REG_rip, REG_zero
};

static const byte onebyte_has_modrm[256] = {
  /*       0 1 2 3 4 5 6 7 8 9 a b c d e f        */
  /*       -------------------------------        */
  /* 00 */ 1,1,1,1,_,_,_,_,1,1,1,1,_,_,_,_, /* 00 */
  /* 10 */ 1,1,1,1,_,_,_,_,1,1,1,1,_,_,_,_, /* 10 */
  /* 20 */ 1,1,1,1,_,_,_,_,1,1,1,1,_,_,_,_, /* 20 */
  /* 30 */ 1,1,1,1,_,_,_,_,1,1,1,1,_,_,_,_, /* 30 */
  /* 40 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* 40 */
  /* 50 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* 50 */
  /* 60 */ _,_,1,1,_,_,_,_,_,1,_,1,_,_,_,_, /* 60 */
  /* 70 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* 70 */
  /* 80 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 80 */
  /* 90 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* 90 */
  /* a0 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* a0 */
  /* b0 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* b0 */
  /* c0 */ 1,1,_,_,1,1,1,1,_,_,_,_,_,_,_,_, /* c0 */
  /* d0 */ 1,1,1,1,_,_,_,_,1,1,1,1,1,1,1,1, /* d0 */
  /* e0 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* e0 */
  /* f0 */ _,_,_,_,_,_,1,1,_,_,_,_,_,_,1,1  /* f0 */
  /*       -------------------------------        */
  /*       0 1 2 3 4 5 6 7 8 9 a b c d e f        */
};

static const byte twobyte_has_modrm[256] = {
  /*       0 1 2 3 4 5 6 7 8 9 a b c d e f        */
  /*       -------------------------------        */
  /* 00 */ 1,1,1,1,_,_,_,_,_,_,_,_,_,1,_,1, /* 0f */
  /* 10 */ 1,1,1,1,1,1,1,1,1,_,_,_,_,_,_,_, /* 1f */
  /* 20 */ 1,1,1,1,1,_,1,_,1,1,1,1,1,1,1,1, /* 2f */
  /* 30 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* 3f */
  /* 40 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 4f */
  /* 50 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 5f */
  /* 60 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 6f */
  /* 70 */ 1,1,1,1,1,1,1,_,_,_,_,_,1,1,1,1, /* 7f */
  /* 80 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* 8f */
  /* 90 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 9f */
  /* a0 */ _,_,_,1,1,1,1,1,_,_,_,1,1,1,1,1, /* af */
  /* b0 */ 1,1,1,1,1,1,1,1,_,_,1,1,1,1,1,1, /* bf */
  /* c0 */ 1,1,1,1,1,1,1,1,_,_,_,_,_,_,_,_, /* cf */
  /* d0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* df */
  /* e0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* ef */
  /* f0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,_  /* ff */
  /*       -------------------------------        */
  /*       0 1 2 3 4 5 6 7 8 9 a b c d e f        */
};

static const byte twobyte_uses_SSE_prefix[256] = {
  /*       0 1 2 3 4 5 6 7 8 9 a b c d e f        */
  /*       -------------------------------        */
  /* 00 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* 0f */
  /* 10 */ 1,1,1,1,1,1,1,1,_,_,_,_,_,_,_,_, /* 1f */
  /* 20 */ _,_,_,_,_,_,_,_,1,1,1,1,1,1,1,1, /* 2f */
  /* 30 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* 3f */
  /* 40 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* 4f */
  /* 50 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 5f */
  /* 60 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 6f */
  /* 70 */ 1,1,1,1,1,1,1,_,_,_,_,_,1,1,1,1, /* 7f */
  /* 80 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* 8f */
  /* 90 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* 9f */
  /* a0 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* af */
  /* b0 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /* bf */
  /* c0 */ _,_,1,_,1,1,1,_,_,_,_,_,_,_,_,_, /* cf */
  /* d0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* df */
  /* e0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* ef */
  /* f0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,_  /* ff */
  /*       -------------------------------        */
  /*       0 1 2 3 4 5 6 7 8 9 a b c d e f        */
};

//
// This determines if the insn is handled by the
// fast decoder or the complex microcode decoder.
// The expanded x86 opcodes are from 0x000 to 0x1ff,
// i.e. normal ones and those with the 0x0f prefix:
//
static const byte insn_is_simple[512] = {
  /*       0 1 2 3 4 5 6 7 8 9 a b c d e f        */
  /*       -------------------------------        */
  /* 00 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,_, /* 0f */
  /* 10 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 1f */
  /* 20 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 2f */
  /* 30 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 3f */
  /* 40 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 4f */
  /* 50 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 5f */
  /* 60 */ _,_,_,1,_,_,_,_,1,1,1,1,_,_,_,_, /* 6f */
  /* 70 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 7f */
  /* 80 */ 1,1,1,1,1,1,_,_,1,1,1,1,_,1,_,1, /* 8f */
  /* 90 */ 1,_,_,_,_,_,_,_,1,1,_,_,_,_,1,1, /* 9f */
  /* a0 */ 1,1,1,1,_,_,_,_,1,1,_,_,_,_,_,_, /* af */
  /* b0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* bf */
  /* c0 */ 1,1,1,1,_,_,1,1,1,1,_,_,_,_,_,_, /* cf */
  /* d0 */ 1,1,1,1,_,_,_,_,_,_,_,_,_,_,_,_, /* df */
  /* e0 */ _,_,_,_,_,_,_,_,1,1,_,1,_,_,_,_, /* ef */
  /* f0 */ _,_,_,_,_,1,1,1,1,1,_,_,0,0,1,1, /* ff */
  /*100 */ _,_,_,_,_,_,_,_,_,_,_,_,_,1,_,_, /*10f */
  /*110 */ _,_,_,_,_,_,_,_,1,_,_,_,_,_,_,_, /*11f */
  /*120 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /*12f */
  /*130 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /*13f */
  /*140 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /*14f */
  /*150 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /*15f */
  /*160 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /*16f */
  /*170 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /*17f */
  /*180 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /*18f */
  /*190 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /*19f */
  /*1a0 */ _,_,_,1,_,_,_,_,_,_,_,1,_,_,_,1, /*1af */
  /*1b0 */ _,_,_,1,_,_,1,1,_,_,1,1,1,1,1,1, /*1bf */
  /*1c0 */ _,_,_,_,_,_,_,_,1,1,1,1,1,1,1,1, /*1cf */
  /*1d0 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /*1df */
  /*1e0 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /*1ef */
  /*1f0 */ _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_, /*1ff */
  /*       -------------------------------        */
  /*       0 1 2 3 4 5 6 7 8 9 a b c d e f        */
};
#undef _

static int transop_histogram[MAX_TRANSOPS_PER_USER_INSN+1];

TraceDecoder::TraceDecoder(const RIPVirtPhys& rvp) {
  bb.reset(rvp);
  rip = rvp;
  ripstart = rvp;
  use64 = rvp.use64;
  kernel = rvp.kernel;
  dirflag = rvp.df;
  byteoffset = 0;

  transbufcount = 0;
  pfec = 0;
  faultaddr = 0;
  prefixes = 0;
  rex = 0;
  modrm = 0;
  user_insn_count = 0;
  last_flags_update_was_atomic = 1;
  invalid = 0;
  some_insns_complex = 0;
  used_microcode_assist = 0;
  end_of_block = false;
}

void TraceDecoder::put(const TransOp& transop) {
  assert(transbufcount < MAX_TRANSOPS_PER_USER_INSN);

  transbuf[transbufcount++] = transop;
  TransOp& firstop = transbuf[0];
  if ((transbufcount-1) == 0) firstop.som = 1;

  firstop.tagcount++;
  firstop.bytes = (rip - ripstart);
  if (isstore(transop.opcode)) firstop.storecount++;
  if (isload(transop.opcode)) firstop.loadcount++;
  if (isbranch(transop.opcode)) firstop.branchcount++;
  if (transop.setflags)
    last_flags_update_was_atomic = (transop.setflags == 0x7);
}

void TraceDecoder::lastop() {
  // Did we convert the last user insn into a nop and not output anything?
  if (!transbufcount)
    return;
    
  int bytes = (rip - ripstart);
  assert(bytes <= 15);

  TransOp& first = transbuf[0];
  TransOp& last = transbuf[transbufcount-1];
  last.eom = 1;

  foreach (i, transbufcount) {
    TransOp& transop = transbuf[i];
    if (bb.count >= MAX_BB_UOPS) {
      logfile << "ERROR: Too many transops (", bb.count, ") in basic block (max ", MAX_BB_UOPS, " allowed)", endl, flush;
      assert(bb.count < MAX_BB_UOPS);
    }

    bool ld = isload(transop.opcode);
    bool st = isstore(transop.opcode);

    transop.unaligned = 0;
    transop.bytes = bytes;
    transop.index = bb.count;
    transop.is_x87 = is_x87;
    transop.is_sse = is_sse;
    bb.transops[bb.count++] = transop;
    if (ld|st) bb.memcount++;
    if (st) bb.storecount++;
    bb.tagcount++;

    if (transop.rd < ARCHREG_COUNT) setbit(bb.usedregs, transop.rd);
    if (transop.ra < ARCHREG_COUNT) setbit(bb.usedregs, transop.ra);
    if (transop.rb < ARCHREG_COUNT) setbit(bb.usedregs, transop.rb);
    if (transop.rc < ARCHREG_COUNT) setbit(bb.usedregs, transop.rc);
  }

  stats.decoder.throughput.x86_insns++;
  stats.decoder.throughput.uops += transbufcount;
  stats.decoder.throughput.bytes += bytes;

  bb.user_insn_count++;
  bb.bytes += bytes;
  transbufcount = 0;
}

ostream& DecodedOperand::print(ostream& os) const {
  switch (type) {
  case OPTYPE_REG:
    os << uniform_arch_reg_names[reg.reg]; break;
  case OPTYPE_IMM:
    os << hexstring(imm.imm, 64); break;
  case OPTYPE_MEM:
    os << "mem", (1<<mem.size), " [", uniform_arch_reg_names[mem.basereg], " + ", uniform_arch_reg_names[mem.indexreg], "*", (1 << mem.scale), " + ", hexstring(mem.offset, 64),
      (mem.riprel) ? " riprel" : "", "]";
    break;
  default:
    break;
  }
  return os;
}

bool DecodedOperand::gform_ext(TraceDecoder& state, int bytemode, int regfield, bool def64, bool in_rex_base) {
  int add = ((in_rex_base) ? state.rex.extbase : state.rex.extreg) ? 8 : 0;

  this->type = OPTYPE_REG;
  switch (bytemode) {
  case b_mode: this->reg.reg = (state.rex) ? reg8x_to_uniform_reg[regfield + add] : reg8_to_uniform_reg[regfield]; break;
  case w_mode: this->reg.reg = reg16_to_uniform_reg[regfield + add]; break;
  case d_mode: this->reg.reg = reg32_to_uniform_reg[regfield + add]; break;
  case q_mode: this->reg.reg = reg64_to_uniform_reg[regfield + add]; break;
  case m_mode: this->reg.reg = (state.use64) ? reg64_to_uniform_reg[regfield + add] : reg32_to_uniform_reg[regfield + add]; break;
  case v_mode: case dq_mode: 
    this->reg.reg = (state.rex.mode64 | (def64 & (!state.opsize_prefix))) ? reg64_to_uniform_reg[regfield + add] : 
      ((!state.opsize_prefix) | (bytemode == dq_mode)) ? reg32_to_uniform_reg[regfield + add] :
      reg16_to_uniform_reg[regfield + add];
    break;
  case x_mode: this->reg.reg = xmmreg_to_uniform_reg[regfield + add]; break;
  default: return false;
  }

  return true;
}

bool DecodedOperand::gform(TraceDecoder& state, int bytemode) {
  return gform_ext(state, bytemode, state.modrm.reg);
}

bool DecodedOperand::iform(TraceDecoder& state, int bytemode) {
  this->type = OPTYPE_IMM;
  this->imm.imm = 0;

  switch (bytemode) {
  case b_mode:
    this->imm.imm = (W8s)state.fetch1(); break;
  case q_mode:
    this->imm.imm = (W64s)state.fetch8(); break;
  case v_mode:
    // NOTE: Even if rex.mode64 is specified, immediates are never longer than 32 bits (except for mov):
    if (state.rex.mode64 | (!state.opsize_prefix)) {
      this->imm.imm = (W32s)state.fetch4();
    } else {
      this->imm.imm = (W16s)state.fetch2();
    }
    break;
  case w_mode:
    this->imm.imm = (W16s)state.fetch2(); break;
  default:
    return false;
  }

  return true;
}

bool DecodedOperand::iform64(TraceDecoder& state, int bytemode) {
  this->type = OPTYPE_IMM;
  this->imm.imm = 0;

  switch (bytemode) {
  case b_mode:
    this->imm.imm = (W8s)state.fetch1(); break;
  case q_mode:
    this->imm.imm = (W64s)state.fetch8(); break;
  case v_mode:
    if (state.rex.mode64) {
      this->imm.imm = (W64s)state.fetch8();
    } else if (state.opsize_prefix) {
      this->imm.imm = (W16s)state.fetch2();
    } else {
      this->imm.imm = (W32s)state.fetch4();
    }
    break;
  case w_mode:
    this->imm.imm = (W16s)state.fetch2(); break;
  case d_mode:
    this->imm.imm = (W32s)state.fetch4(); break;
  default:
    return false;
  }
  return true;
}

bool DecodedOperand::eform(TraceDecoder& state, int bytemode) {
  if (state.modrm.mod == 3) {
    return gform_ext(state, bytemode, state.modrm.rm, false, true);
  }

  type = OPTYPE_MEM;
  mem.basereg = APR_zero;
  mem.indexreg = APR_zero;
  mem.offset = 0;
  mem.scale = 0;
  mem.riprel = 0;
  mem.size = 0;

  const int mod_and_rexextbase_and_rm_to_basereg_x86_64[4][2][8] = {
    {
      // mod = 00
      {APR_rax, APR_rcx, APR_rdx, APR_rbx, -1, APR_rip, APR_rsi, APR_rdi}, // rex.extbase = 0
      {APR_r8,  APR_r9,  APR_r10, APR_r11, -1, APR_rip, APR_r14, APR_r15}, // rex.extbase = 1
    }, {
      // mod = 01
      {APR_rax, APR_rcx, APR_rdx, APR_rbx, -1, APR_rbp, APR_rsi, APR_rdi}, // rex.extbase = 0
      {APR_r8,  APR_r9,  APR_r10, APR_r11, -1, APR_r13, APR_r14, APR_r15}, // rex.extbase = 1
    }, {
      // mod = 10
      {APR_rax, APR_rcx, APR_rdx, APR_rbx, -1, APR_rbp, APR_rsi, APR_rdi}, // rex.extbase = 0
      {APR_r8,  APR_r9,  APR_r10, APR_r11, -1, APR_r13, APR_r14, APR_r15}, // rex.extbase = 1
    }, {
      // mod = 11: not possible since this is g-form
      {-1, -1, -1, -1, -1, -1, -1, -1},
      {-1, -1, -1, -1, -1, -1, -1, -1},
    }
  };

  const int mod_and_rm_to_basereg_x86[4][8] = {
    {APR_eax, APR_ecx, APR_edx, APR_ebx, -1, APR_zero, APR_esi, APR_edi},
    {APR_eax, APR_ecx, APR_edx, APR_ebx, -1, APR_ebp,  APR_esi, APR_edi},
    {APR_eax, APR_ecx, APR_edx, APR_ebx, -1, APR_ebp, APR_esi, APR_edi},
    {-1, -1, -1, -1, -1, -1, -1, -1}, // mod = 11: not possible since this is g-form
  };

  mem.basereg = (state.use64)
    ? mod_and_rexextbase_and_rm_to_basereg_x86_64[state.modrm.mod][state.rex.extbase][state.modrm.rm]
    : mod_and_rm_to_basereg_x86[state.modrm.mod][state.modrm.rm];

  SIBByte sib;
  if (state.modrm.rm == 4) {
    sib = SIBByte(state.fetch1());
  }

  const byte mod_and_rm_to_immsize[4][8] = {
    {0, 0, 0, 0, 0, 4, 0, 0},
    {1, 1, 1, 1, 1, 1, 1, 1},
    {4, 4, 4, 4, 4, 4, 4, 4},
    {0, 0, 0, 0, 0, 0, 0, 0},
  };

  byte immsize = mod_and_rm_to_immsize[state.modrm.mod][state.modrm.rm];
  mem.offset = (immsize) ? signext32((W32s)state.fetch(immsize), immsize*8) : 0;
  mem.riprel = (mem.basereg == APR_rip);

  if (mem.basereg < 0) {
    // Have sib
    const int rexextbase_and_base_to_basereg[2][8] = {
      {APR_rax, APR_rcx, APR_rdx, APR_rbx, APR_rsp, -1, APR_rsi, APR_rdi}, // rex.extbase = 0
      {APR_r8,  APR_r9,  APR_r10, APR_r11, APR_r12, -1, APR_r14, APR_r15}, // rex.extbase = 1
    };

    mem.basereg = rexextbase_and_base_to_basereg[state.rex.extbase][sib.base];
    if (mem.basereg < 0) {
      const int rexextbase_and_mod_to_basereg[2][4] = {
        {APR_zero, APR_rbp, APR_rbp, -1}, // rex.extbase = 0
        {APR_zero, APR_r13, APR_r13, -1}, // rex.extbase = 1
      };

      mem.basereg = rexextbase_and_mod_to_basereg[state.rex.extbase][state.modrm.mod];

      if (!immsize) {
        switch (state.modrm.mod) {
        case 0:
        case 2:
          assert(!immsize);
          mem.offset = (W32s)state.fetch4();
          break;
        case 1:
          assert(!immsize);
          mem.offset = (W8s)state.fetch1();
          break;
        }
      }
    }

    const int rexextindex_and_index_to_indexreg[2][8] = {
      {APR_rax, APR_rcx, APR_rdx, APR_rbx, APR_zero, APR_rbp, APR_rsi, APR_rdi}, // rex.extindex = 0
      {APR_r8,  APR_r9,  APR_r10, APR_r11, APR_r12,  APR_r13, APR_r14, APR_r15}, // rex.extindex = 1
    };

    mem.indexreg = rexextindex_and_index_to_indexreg[state.rex.extindex][sib.index];
    mem.scale = sib.scale;
  }

  switch (bytemode) {
  case b_mode: mem.size = 0; break;
  case w_mode: mem.size = 1; break;
  case d_mode: mem.size = 2; break;
  case q_mode: mem.size = 3; break;
  case m_mode: mem.size = (state.use64) ? 3 : 2; break;
  case v_mode: case dq_mode: mem.size = (state.rex.mode64) ? 3 : ((!state.opsize_prefix) | (bytemode == dq_mode)) ? 2 : 1; break; // See table 1.2 (p35) of AMD64 ISA manual
  case x_mode: mem.size = 3; break;
  default: return false;
  }

  return true;
}

bool DecodedOperand::varreg(TraceDecoder& state, int regcode, bool def64) {
  this->type = OPTYPE_REG;

  // push and pop default to 64 bits in 64-bit mode, while all others default to 32 bit mode and need the REX prefix to make them 64-bit:
  // assert(mode_64bit);

  if (def64) {
    // Always a 64-bit operation
    this->reg.reg = reg64_to_uniform_reg[regcode + (state.rex.extbase * 8)];
  } else {
    this->reg.reg = (state.rex.mode64) ? reg64_to_uniform_reg[regcode + (state.rex.extbase * 8)] : 
      (state.opsize_prefix) ? reg16_to_uniform_reg[regcode + (state.rex.extbase * 8)]
      : reg32_to_uniform_reg[regcode + (state.rex.extbase * 8)];
  }

  return true;
}

bool DecodedOperand::varreg_def64(TraceDecoder& state, int regcode) {
  return DecodedOperand::varreg(state, regcode, true);
}

bool DecodedOperand::varreg_def32(TraceDecoder& state, int regcode) {
  return DecodedOperand::varreg(state, regcode, false);
}

void TraceDecoder::immediate(int rdreg, int sizeshift, W64s imm, bool issigned) {
  int totalbits = (sizeshift == 3) ? 64 : (8 * (1 << sizeshift));
  if (totalbits < 64) imm = (issigned) ? signext64(imm, totalbits) : bits(imm, 0, totalbits);
  // Only byte and word sized immediates need to be merged with the previous value:
  this << TransOp(OP_mov, rdreg, REG_zero, REG_imm, REG_zero, 3, imm);
}

int TraceDecoder::bias_by_segreg(int basereg) {
  if (prefixes & (PFX_CS|PFX_DS|PFX_ES|PFX_FS|PFX_GS|PFX_SS)) {
    int segid = 
      (prefixes & PFX_FS) ? SEGID_FS : 
      (prefixes & PFX_GS) ? SEGID_GS : 
      (prefixes & PFX_DS) ? SEGID_DS :
      (prefixes & PFX_SS) ? SEGID_SS :
      (prefixes & PFX_ES) ? SEGID_ES :
      (prefixes & PFX_CS) ? SEGID_CS : -1;

    assert(segid >= 0);

    int varoffs = offsetof(Context, seg[segid].base);

    TransOp ldp(OP_ld, REG_temp6, REG_ctx, REG_imm, REG_zero, 3, varoffs); ldp.internal = 1; this << ldp;
    this << TransOp(OP_add, REG_temp6, REG_temp6, basereg, REG_zero, 3);
    return REG_temp6;
  }

  return basereg;
}

void TraceDecoder::address_generate_and_load_or_store(int destreg, int srcreg, const DecodedOperand& memref, int opcode, int datatype, int cachelevel, bool force_seg_bias) {
  //
  // In the address generation form used by internally generated
  // uops, we need the full virtual address, including the segment base
  // bias. However, technically LEA is not supposed to add the segment
  // base, even if prefixes implying a base are applied.
  //
  // Therefore, any internal uses that need the full virtual address
  // can use the special hint force_seg_bias to generate it,
  // but not actually include any load or store uops.
  //
  bool memop = isload(opcode) | isstore(opcode) | (opcode == OP_ld_pre);
  force_seg_bias |= memop;

  int imm_bits = (memop) ? 32 : 64;

  int basereg = arch_pseudo_reg_to_arch_reg[memref.mem.basereg];
  int indexreg = arch_pseudo_reg_to_arch_reg[memref.mem.indexreg];
  // ld rd = ra,rb,rc
  // ra = base
  // rb = offset or imm8
  // rc = reg to merge low bytes with

  //
  // Encoding rules for loads:
  //
  // Loads have only one addressing mode: basereg + immN, where
  // N is a small number of bits. The immediate is shifted left
  // by ld.size to allow for a greater range, assuming the immN
  // is always a multiple of the load data size. If immN is not
  // properly aligned, or it exceeds the field width, it cannot
  // be represented in the load and must be encoded outside as
  // a separate move immediate uop.
  //
  // Note that the rbimm field in the load uop is not actually
  // modified; this is for simulation purposes only, since real
  // microprocessors do not have unlimited immediate lengths.
  //

  bool imm_is_not_encodable =
    (lowbits(memref.mem.offset, memref.mem.size) != 0) |
    (!inrange(memref.mem.offset >> memref.mem.size, (W64s)(-1LL << (imm_bits-1)), (W64s)(1LL << (imm_bits-1))-1));

  W64s offset = memref.mem.offset;

  if (basereg == REG_rip) {
    // [rip + imm32]: index always is zero and scale is 1
    // This mode is only possible in x86-64 code
    basereg = REG_zero;
    if (force_seg_bias) basereg = bias_by_segreg(basereg);

    int tempreg = (memop) ? REG_temp8 : destreg;

    this << TransOp(OP_add, tempreg, basereg, REG_imm, REG_zero, 3, (Waddr)rip + offset);

    if (memop) {
      TransOp ld(opcode, destreg, tempreg, REG_zero, srcreg, memref.mem.size);
      ld.datatype = datatype;
      ld.cachelevel = cachelevel;
      this << ld;
    }
  } else if (indexreg == REG_zero) {
    // [ra + imm32] or [ra]
    if (force_seg_bias) basereg = bias_by_segreg(basereg);
    if (imm_is_not_encodable) {
      this << TransOp(OP_add, REG_temp8, basereg, REG_imm, REG_zero, 3, offset);
      basereg = REG_temp8;
      offset = 0;
    }

    TransOp ldst(opcode, destreg, basereg, REG_imm, srcreg, memref.mem.size, offset);
    ldst.datatype = datatype;
    ldst.cachelevel = cachelevel;
    this << ldst;
  } else if (offset == 0) {
    // [ra + rb*scale] or [rb*scale]
    if (force_seg_bias) basereg = bias_by_segreg(basereg);

    int tempreg = (memop) ? REG_temp8 : destreg;

    if (memref.mem.scale) {
      TransOp addop(OP_adda, tempreg, basereg, REG_zero, indexreg, (memop) ? 3 : memref.mem.size);
      addop.extshift = memref.mem.scale;
      this << addop;
    } else {
      this << TransOp(OP_add, tempreg, basereg, indexreg, REG_zero, (memop) ? 3 : memref.mem.size);
    }

    if (memop) {
      // No need for this when we're only doing address generation:
      TransOp ldst(opcode, destreg, tempreg, REG_zero, srcreg, memref.mem.size);
      ldst.datatype = datatype;
      ldst.cachelevel = cachelevel;
      this << ldst;
    }
  } else {
    // [ra + imm32 + rb*scale]
    if (force_seg_bias) basereg = bias_by_segreg(basereg);

    if (imm_is_not_encodable) {
      this << TransOp(OP_add, REG_temp8, basereg, REG_imm, REG_zero, 3, offset);
      basereg = REG_temp8;
      offset = 0;
    }

    TransOp addop(OP_adda, REG_temp8, basereg, REG_zero, indexreg, 3);
    addop.extshift = memref.mem.scale;
    this << addop;
    TransOp ldst(opcode, destreg, REG_temp8, REG_imm, srcreg, memref.mem.size, offset);
    ldst.datatype = datatype;
    ldst.cachelevel = cachelevel;
    this << ldst;
  }
}

void TraceDecoder::operand_load(int destreg, const DecodedOperand& memref, int opcode, int datatype, int cachelevel) {
  address_generate_and_load_or_store(destreg, REG_zero, memref, opcode, datatype, cachelevel);
}

void TraceDecoder::result_store(int srcreg, int tempreg, const DecodedOperand& memref, int datatype) {
  address_generate_and_load_or_store(REG_mem, srcreg, memref, OP_st, datatype);
}

void TraceDecoder::alu_reg_or_mem(int opcode, const DecodedOperand& rd, const DecodedOperand& ra, W32 setflags, int rcreg, 
                                  bool flagsonly, bool isnegop, bool ra_rb_imm_form, W64s ra_rb_imm_form_rbimm) {
  if ((rd.type == OPTYPE_REG) && ((ra.type == OPTYPE_REG) || (ra.type == OPTYPE_IMM))) {
    //
    // reg,reg
    //
    assert(rd.reg.reg >= 0 && rd.reg.reg < APR_COUNT);
    if (ra.type == OPTYPE_REG) assert(ra.reg.reg >= 0 && ra.reg.reg < APR_COUNT);
    bool isimm = (ra.type == OPTYPE_IMM);
    int destreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int srcreg = (isimm) ? REG_imm : arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    int sizeshift = reginfo[rd.reg.reg].sizeshift;

    bool rdhigh = reginfo[rd.reg.reg].hibyte;
    bool rahigh = (isimm) ? 0 : reginfo[ra.reg.reg].hibyte;

    int rareg = destreg;
    if (rdhigh) { this << TransOp(OP_maskb, REG_temp2, REG_zero, rareg, REG_imm, 3, 0, MaskControlInfo(0, 8, 8)); rareg = REG_temp2; }

    int rbreg = srcreg;
    if (rahigh) { this << TransOp(OP_maskb, REG_temp3, REG_zero, srcreg, REG_imm, 3, 0, MaskControlInfo(0, 8, 8)); rbreg = REG_temp3; }

    if (flagsonly) {
      this << TransOp(opcode, REG_temp0, rareg, rbreg, rcreg, sizeshift, (isimm) ? ra.imm.imm : 0, 0, setflags);
    } else {
      if (isnegop) { rbreg = rareg; rareg = REG_zero; }
      if (ra_rb_imm_form) {
        this << TransOp(opcode, destreg, srcreg, REG_imm, (sizeshift >= 2) ? REG_zero : destreg, sizeshift, ra_rb_imm_form_rbimm, 0, setflags);
      } else {
        this << TransOp(opcode, (rdhigh) ? REG_temp2 : destreg, rareg, rbreg, rcreg, sizeshift,
                        (isimm) ? ra.imm.imm : 0, 0, setflags);
        if (rdhigh) { this << TransOp(OP_maskb, destreg, destreg, REG_temp2, REG_imm, 3, 0, MaskControlInfo(56, 8, 56)); }
      }
    }
  } else if ((rd.type == OPTYPE_REG) && (ra.type == OPTYPE_MEM)) {
    assert(rd.reg.reg >= 0 && rd.reg.reg < APR_COUNT);
    assert(ra.mem.basereg >= 0 && ra.mem.basereg < APR_COUNT);
    assert(ra.mem.indexreg >= 0 && ra.mem.indexreg < APR_COUNT);
    assert(ra.mem.scale >= 0 && ra.mem.scale <= 3);

    //
    // reg,[mem]
    //
    int destreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    operand_load(REG_temp0, ra);

    bool rdhigh = reginfo[rd.reg.reg].hibyte;

    int rareg = destreg;
    if (rdhigh) { this << TransOp(OP_maskb, REG_temp2, REG_zero, destreg, REG_imm, 3, 0, MaskControlInfo(0, 8, 8)); rareg = REG_temp2; }

    int sizeshift = reginfo[rd.reg.reg].sizeshift;
    if (flagsonly) {
      this << TransOp(opcode, REG_temp0, rareg, REG_temp0, rcreg, sizeshift, 0, 0, setflags);
    } else {
      if (ra_rb_imm_form) {
        this << TransOp(opcode, destreg, REG_temp0, REG_imm, (sizeshift >= 2) ? REG_zero : destreg, sizeshift, ra_rb_imm_form_rbimm, 0, setflags);
      } else {
        this << TransOp(opcode, (rdhigh) ? REG_temp2 : destreg, rareg, REG_temp0, rcreg, sizeshift, 0, 0, setflags);
        if (rdhigh) this << TransOp(OP_maskb, destreg, destreg, REG_temp2, REG_imm, 3, 0, MaskControlInfo(56, 8, 56));
      }
    }
  } else if ((rd.type == OPTYPE_MEM) && ((ra.type == OPTYPE_REG) || (ra.type == OPTYPE_IMM))) {
    //
    // [mem],reg
    //
    assert(rd.mem.basereg >= 0 && rd.mem.basereg < APR_COUNT);
    assert(rd.mem.indexreg >= 0 && rd.mem.indexreg < APR_COUNT);
    assert(rd.mem.scale >= 0 && rd.mem.scale <= 3);
    if (ra.type == OPTYPE_REG) assert(ra.reg.reg >= 0 && ra.reg.reg < APR_COUNT);

    bool isimm = (ra.type == OPTYPE_IMM);
    int srcreg = (isimm) ? REG_imm : arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    operand_load(REG_temp0, rd);

    int sizeshift = rd.mem.size;
    bool rahigh = (isimm) ? 0 : reginfo[ra.reg.reg].hibyte;

    if (rahigh) { this << TransOp(OP_maskb, REG_temp2, REG_zero, srcreg, REG_imm, 3, 0, MaskControlInfo(0, 8, 8)); srcreg = REG_temp2; }

    if (isimm) {
      this << TransOp(opcode, REG_temp0, REG_temp0, REG_imm, rcreg, sizeshift, ra.imm.imm, 0, setflags);
      if (!flagsonly) result_store(REG_temp0, REG_temp3, rd);
    } else {
      this << TransOp(opcode, REG_temp0, REG_temp0, srcreg, rcreg, sizeshift, 0, 0, setflags);
      if (!flagsonly) result_store(REG_temp0, REG_temp3, rd);
    }
  } else if ((rd.type == OPTYPE_MEM) && (ra.type == OPTYPE_MEM)) {
    //
    // unary operations only: [mem],[samemem]
    //
    assert(rd.mem.basereg >= 0 && ra.mem.basereg < APR_COUNT);
    assert(rd.mem.indexreg >= 0 && ra.mem.indexreg < APR_COUNT);
    assert(rd.mem.scale >= 0 && ra.mem.scale <= 3);

    operand_load(REG_temp0, rd);
    int sizeshift = rd.mem.size;
    this << TransOp(opcode, REG_temp0, (isnegop) ? REG_zero : REG_temp0, REG_temp0, rcreg, sizeshift, 0, 0, setflags);
    if (!flagsonly) result_store(REG_temp0, REG_temp3, rd);
  }
}

void TraceDecoder::move_reg_or_mem(const DecodedOperand& rd, const DecodedOperand& ra, int force_rd) {
  if ((rd.type == OPTYPE_REG) && ((ra.type == OPTYPE_REG) || (ra.type == OPTYPE_IMM))) {
    //
    // reg,reg
    //

    bool isimm = (ra.type == OPTYPE_IMM);
    int destreg = (force_rd != REG_zero) ? force_rd : arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int srcreg = (isimm) ? REG_imm : arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    int sizeshift = reginfo[rd.reg.reg].sizeshift;

    bool rdhigh = (force_rd != REG_zero) ? false : reginfo[rd.reg.reg].hibyte;
    bool rahigh = (isimm) ? 0 : reginfo[ra.reg.reg].hibyte;

    if (rdhigh || rahigh) {
      int maskctl = 
        (rdhigh && !rahigh) ? MaskControlInfo(56, 8, 56) : // insert high byte
        (!rdhigh && rahigh) ? MaskControlInfo(0, 8, 8) : // extract high byte
        (rdhigh && rahigh) ? MaskControlInfo(56, 8, 0) : // move between high bytes
        MaskControlInfo(0, 8, 0); // move between low bytes
      this << TransOp(OP_maskb, destreg, destreg, srcreg, REG_imm, 3, (isimm) ? ra.imm.imm : 0, maskctl);
    } else {
      // must be at least 16 bits
      // On x86-64, only 8-bit and 16-bit ops need to be merged; 32-bit is zero extended to full 64 bits:
      this << TransOp(OP_mov, destreg, (sizeshift < 2) ? destreg : REG_zero, srcreg, REG_zero, sizeshift, (isimm) ? ra.imm.imm : 0);
    }
  } else if ((rd.type == OPTYPE_REG) && (ra.type == OPTYPE_MEM)) {
    //
    // reg,[mem]
    //
    int destreg = (force_rd != REG_zero) ? force_rd : arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int sizeshift = reginfo[rd.reg.reg].sizeshift;

    if ((sizeshift >= 2) || (force_rd != REG_zero)) {
      // zero extend 32-bit to 64-bit or just load as 64-bit:
      operand_load(destreg, ra);
    } else {
      // need to merge 8-bit or 16-bit data:
      operand_load(REG_temp0, ra);
      if (reginfo[rd.reg.reg].hibyte) 
        this << TransOp(OP_maskb, destreg, destreg, REG_temp0, REG_imm, 3, 0, MaskControlInfo(56, 8, 56));
      else this << TransOp(OP_mov, destreg, destreg, REG_temp0, REG_zero, sizeshift);
    }
  } else if ((rd.type == OPTYPE_MEM) && ((ra.type == OPTYPE_REG) || (ra.type == OPTYPE_IMM))) {
    //
    // [mem],reg
    //
    bool isimm = (ra.type == OPTYPE_IMM);
    int srcreg = (isimm) ? REG_imm : arch_pseudo_reg_to_arch_reg[ra.reg.reg];

    bool rahigh = (isimm) ? 0 : reginfo[ra.reg.reg].hibyte;
    if (isimm) {
      // We need to load the immediate separately in any case since stores do not accept immediates:
      this << TransOp(OP_mov, REG_temp1, REG_zero, REG_imm, REG_zero, 3, ra.imm.imm);
      result_store(REG_temp1, REG_temp0, rd);
    } else if (rahigh) { 
      this << TransOp(OP_maskb, REG_temp1, REG_zero, srcreg, REG_imm, 3, 0, MaskControlInfo(0, 8, 8));
      result_store(REG_temp1, REG_temp0, rd);
    } else {
      result_store(srcreg, REG_temp0, rd);
    }
  }
}

void TraceDecoder::signext_reg_or_mem(const DecodedOperand& rd, DecodedOperand& ra, int rasize, bool zeroext) {
  int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
  int rdsize = reginfo[rd.reg.reg].sizeshift;

  if ((rd.type == OPTYPE_REG) && (ra.type == OPTYPE_REG)) {
    //
    // reg,reg
    //

    int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];

    assert(!reginfo[rd.reg.reg].hibyte);
    bool rahigh = reginfo[ra.reg.reg].hibyte;

    // For movsx, it is not possible to have rd be 8 bits: it's always 16/32/64 bits.
    if (rahigh) {
      this << TransOp(OP_maskb, REG_temp0, REG_zero, rareg, REG_imm, 3, 0, MaskControlInfo(0, 8, 8));
      rareg = REG_temp0;
    }

    assert(rasize < 3); // must be at most 32 bits
    // On x86-64, only 8-bit and 16-bit ops need to be merged; 32-bit is zero extended to full 64 bits:
    if (zeroext && rdsize >= 2) {
      // Just use regular move
      this << TransOp(OP_mov, rdreg, REG_zero, rareg, REG_zero, rasize);        
    } else {
      TransOp transop(OP_maskb, rdreg, (rdsize < 2) ? rdreg : REG_zero, rareg, REG_imm, rdsize, 0, MaskControlInfo(0, (1<<rasize)*8, 0));
      transop.cond = (zeroext) ? 1 : 2;
      this << transop;
    }
  } else if ((rd.type == OPTYPE_REG) && (ra.type == OPTYPE_MEM)) {
    //
    // reg,[mem]
    //
    ra.mem.size = rasize;

    if (rdsize >= 2) {
      // zero extend 32-bit to 64-bit or just load as 64-bit:
      operand_load(rdreg, ra, (zeroext) ? OP_ld : OP_ldx);
      // sign extend and then zero high 32 bits (old way was ldxz uop):
      if ((rdsize == 2) && (!zeroext)) this << TransOp(OP_mov, rdreg, REG_zero, rdreg, REG_zero, 2);
    } else {
      // need to merge 8-bit or 16-bit data:
      operand_load(REG_temp0, ra, (zeroext) ? OP_ld : OP_ldx);
      this << TransOp(OP_mov, rdreg, rdreg, REG_temp0, REG_zero, rdsize);
    }
  }
}

void TraceDecoder::microcode_assist(int assistid, Waddr selfrip, Waddr nextrip) {
  used_microcode_assist = 1;
  immediate(REG_selfrip, 3, (Waddr)selfrip);
  immediate(REG_nextrip, 3, (Waddr)nextrip);
  if (!last_flags_update_was_atomic) 
    this << TransOp(OP_collcc, REG_temp0, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
  TransOp transop(OP_brp, REG_rip, REG_zero, REG_zero, REG_zero, 3);
  transop.riptaken = transop.ripseq = (Waddr)assistid_to_func[assistid];
  this << transop;
}

//
// Core Decoder
//
void TraceDecoder::decode_prefixes() {
  prefixes = 0;
  rex = 0;

  for (;;) {
    byte b = insnbytes[byteoffset];
    W32 prefix = (use64) ? prefix_map_x86_64[b] : prefix_map_x86[b];
    if (!prefix) break;
    if (rex) {
      // REX is ignored when followed by another prefix:
      rex = 0;
      prefixes &= ~PFX_REX;
    }
    prefixes |= prefix;
    if (prefix == PFX_REX) { rex = b; }
    byteoffset++; rip++;
  }
}

void print_invalid_insns(int op, const byte* ripstart, const byte* rip, int valid_byte_count, const PageFaultErrorCode& pfec, Waddr faultaddr) {
  if (pfec) {
    if (logable(1)) logfile << "translate: page fault at iteration ", iterations, ", ", total_user_insns_committed, " commits: ",
      "ripstart ", ripstart, ", rip ", rip, ": required ", (rip - ripstart), " more bytes but only fetched ", valid_byte_count, " bytes; ",
      "page fault error code: ", pfec, endl, flush;
  } else {
    if (logable(1)) logfile << "translate: invalid opcode at iteration ", iterations, ": ", (void*)(Waddr)op, " commits ", total_user_insns_committed, " (at ripstart ", ripstart, ", rip ", rip, "); may be speculative", endl, flush;
    if (!config.dumpcode_filename.empty()) {
      byte insnbuf[256];
      PageFaultErrorCode copypfec;
      int valid_byte_count = contextof(0).copy_from_user(insnbuf, (Waddr)rip, sizeof(insnbuf), copypfec, faultaddr);
      odstream os(config.dumpcode_filename);
      os.write(insnbuf, sizeof(insnbuf));
      os.close();
    }
  }
}

void assist_invalid_opcode(Context& ctx) {
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_selfrip];
  ctx.propagate_x86_exception(EXCEPTION_x86_invalid_opcode);
}

static const bool log_code_page_ops = 0;

void BasicBlockCache::invalidate(BasicBlock* bb, int reason) {
  BasicBlockChunkList* pagelist;
  pagelist = bbpages.get(bb->rip.mfnlo);
  if (logable(3) | log_code_page_ops) logfile << "Remove bb ", bb, " (", bb->rip, ", ", bb->bytes, " bytes) from low page list ", pagelist, ": loc ", bb->mfnlo_loc.chunk, ":", bb->mfnlo_loc.index, endl;
  assert(pagelist);
  pagelist->remove(bb->mfnlo_loc);

  int page_crossing = ((lowbits(bb->rip, 12) + (bb->bytes-1)) >> 12);
  if (page_crossing) {
    pagelist = bbpages.get(bb->rip.mfnhi);
    if (logable(3) | log_code_page_ops) logfile << "Remove bb ", bb, " (", bb->rip, ", ", bb->bytes, " bytes) from high page list ", pagelist, ": loc ", bb->mfnhi_loc.chunk, ":", bb->mfnhi_loc.index, endl;
    assert(pagelist);
    pagelist->remove(bb->mfnhi_loc);
  }

  remove(bb);
  stats.decoder.bbcache.count = bbcache.count;
  stats.decoder.bbcache.invalidates[reason]++;

  bb->free();
}

void BasicBlockCache::invalidate(const RIPVirtPhys& rvp, int reason) {
  BasicBlock* bb = get(rvp);
  if (!bb) return;
  invalidate(bb, reason);
}

//
// Invalidate any basic blocks on the specified physical page.
// This function is suitable for calling from a reclaim handler
// when we run out of memory (it may not allocate any memory).
//

int BasicBlockCache::invalidate_page(Waddr mfn, int reason) {
  BasicBlockChunkList* pagelist = bbpages.get(mfn);

  //static const bool log_code_page_ops = 0;

  if (logable(3) | log_code_page_ops) logfile << "Invalidate page mfn ", mfn, ": pagelist ", pagelist, " has ", (pagelist ? pagelist->count() : 0), " entries", endl;

  if (!pagelist) return 0;

  int oldcount = pagelist->count();
  int n = 0;
  BasicBlockChunkList::Iterator iter(pagelist);
  BasicBlockPtr* entry;
  while (entry = iter.next()) {
    BasicBlock* bb = *entry;
    if (logable(3) | log_code_page_ops) logfile << "  Invalidate bb ", bb, " (", bb->rip, ", ", bb->bytes, " bytes)", endl;
    bbcache.invalidate(bb, reason);
    n++;
  }

  assert(n == oldcount);
  assert(pagelist->count() == 0);

  pagelist->clear();
  stats.decoder.pagecache.count = bbpages.count;
  stats.decoder.pagecache.invalidates[reason]++;

  smc_cleardirty(mfn);

  return n;
}

//
// Scan through the BB cache and try to free up
// <bytesreq> bytes, starting with the least
// recently used BBs.
//
int BasicBlockCache::reclaim(size_t bytesreq, int urgency) {
  bool DEBUG = 1; //logable(1);

  if (!count) return 0;

  if (DEBUG) logfile << "Reclaiming cached basic blocks at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits:", endl, flush;

  stats.decoder.reclaim_rounds++;

  W64 oldest = limits<W64>::max;
  W64 newest = 0;
  W64 average = 0;
  W64 total_bytes = 0;

  int n = 0;

  Iterator iter(this);
  BasicBlock* bb;

  while (bb = iter.next()) {
    oldest = min(oldest, bb->lastused);
    newest = max(newest, bb->lastused);
    average += bb->lastused;
    total_bytes += ptl_mm_getsize(bb);
    n++;
  }

  assert(count == n);
  assert(n > 0);
  average /= n;

  if unlikely (urgency < 0) {
    //
    // The allocator is so strapped for memory, we need to free
    // everything possible at all costs:
    //
    average = infinity;
  }

  if (DEBUG) {
    logfile << "Before:", endl;
    logfile << "  Basic blocks:   ", intstring(count, 12), endl;
    logfile << "  Bytes occupied: ", intstring(total_bytes, 12), endl;
    logfile << "  Oldest cycle:   ", intstring(oldest, 12), endl;
    logfile << "  Average cycle:  ", intstring(average, 12), endl;
    logfile << "  Newest cycle:   ", intstring(newest, 12), endl;
  }

  //
  // Reclaim all objects older than the average
  //
  n = 0;
  W64 reclaimed_bytes = 0;
  int reclaimed_objs = 0;

  iter.reset(this);
  while (bb = iter.next()) {
    // We use '<=' to guarantee even a uniform distribution will eventually be reclaimed:
    if likely (bb->lastused <= average) {
      reclaimed_bytes += ptl_mm_getsize(bb);
      reclaimed_objs++;
      invalidate(bb, INVALIDATE_REASON_RECLAIM);
    }
    n++;
  }

  if (DEBUG) {
    logfile << "After:", endl;
    logfile << "  Basic blocks:   ", intstring(reclaimed_objs, 12), " BBs reclaimed", endl;
    logfile << "  Bytes occupied: ", intstring(reclaimed_bytes, 12), " bytes reclaimed", endl;
    logfile << "  New pool size:  ", intstring(count, 12), " BBs", endl;
    logfile.flush();
  }

  //
  // Reclaim per-page chunklist heads
  //

  {
    BasicBlockPageCache::Iterator iter(&bbpages);
    BasicBlockChunkList* page;
    int pages_freed = 0;

    if (DEBUG) logfile << "Scanning ", bbpages.count, " code pages:", endl;
    while (page = iter.next()) {
      if (page->empty()) {
        if (DEBUG) logfile << "  mfn ", page->mfn, " has no entries; freeing", endl;
        bbpages.remove(page);
        delete page;
        pages_freed++;
      }
    }

    if (DEBUG) logfile << "Freed ", pages_freed, " empty pages", endl, flush;
  }

  return n;
}

void assist_exec_page_fault(Context& ctx) {
  //
  // We need to check if faultaddr is now a valid page, since the page tables
  // could have been updated since the cut-off basic block was speculatively
  // translated, such that the block is now valid. If the page at faultaddr
  // in REG_ar1 is now valid, we need to invalidate the currently executing
  // translation and tell the main loop to start translating again at the
  // cut-off instruction's starting byte.
  //
  Waddr faultaddr = ctx.commitarf[REG_ar1];
  PageFaultErrorCode pfec = ctx.commitarf[REG_ar2];

#ifdef PTLSIM_HYPERVISOR
  Level1PTE pte = ctx.virt_to_pte(faultaddr);
  bool page_now_valid = (pte.p & (!pte.nx) & ((!ctx.kernel_mode) ? pte.us : 1));
#else
  bool page_now_valid = asp.fastcheck((byte*)faultaddr, asp.execmap);
#endif
  if (page_now_valid) {
    if (logable(3)) {
      logfile << "Spurious PageFaultOnExec detected at fault rip ",
        (void*)(Waddr)ctx.commitarf[REG_selfrip], " with faultaddr ",
        (void*)faultaddr, " @ ", total_user_insns_committed, 
        " user commits (", sim_cycle, " cycles)";
    }
    bbcache.invalidate(RIPVirtPhys(ctx.commitarf[REG_selfrip]).update(ctx), INVALIDATE_REASON_SPURIOUS);
    ctx.commitarf[REG_rip] = ctx.commitarf[REG_selfrip];
    return;
  }

  ctx.commitarf[REG_rip] = ctx.commitarf[REG_selfrip];
  ctx.propagate_x86_exception(EXCEPTION_x86_page_fault, pfec, faultaddr);
}

void assist_gp_fault(Context& ctx) {
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_selfrip];
  ctx.propagate_x86_exception(EXCEPTION_x86_gp_fault, ctx.commitarf[REG_ar1]);
}

void TraceDecoder::invalidate() {
  if ((rip - bb.rip) > valid_byte_count) {
#ifdef PTLSIM_HYPERVISOR
    Level1PTE pte = contextof(0).virt_to_pte(ripstart);
    mfn_t mfn = (pte.p) ? pte.mfn : 0;
#else
    int mfn = 0;
#endif
    if (logable(3)) {
      logfile << "Translation crosses into invalid page (mfn ", mfn, "): ripstart ", (void*)ripstart, ", rip ", (void*)rip,
        ", faultaddr ", (void*)faultaddr, "; expected ", (rip - ripstart), " bytes but only got ", valid_byte_count, 
        " (next page ", (void*)(Waddr)ceil(ripstart, 4096), ")", endl;
    }

    print_invalid_insns(op, (const byte*)ripstart, (const byte*)rip, valid_byte_count, pfec, faultaddr);
    immediate(REG_ar1, 3, faultaddr);
    immediate(REG_ar2, 3, pfec);
    microcode_assist(ASSIST_EXEC_PAGE_FAULT, ripstart, faultaddr);
  } else {
    print_invalid_insns(op, (const byte*)ripstart, (const byte*)rip, valid_byte_count, 0, faultaddr);
    microcode_assist(ASSIST_INVALID_OPCODE, ripstart, rip);
  }
  end_of_block = 1;
  user_insn_count++;
  bb.invalidblock = 1;
  lastop();
}

//
// Fill the insnbytes buffer as much as possible,
// properly handling x86 semantics where the insn
// extends onto an invalid page. Return the number
// of valid bytes, if any.
//
// We limit BBs to at most MAX_BB_BYTES; this ensures
// we can do a bulk copy of the potentially unaligned
// instruction bytes into insnbytes once at the start,
// rather than having to constantly do checks.
//

int TraceDecoder::fillbuf(Context& ctx) {
  byteoffset = 0;
  faultaddr = 0;
  pfec = 0;
  invalid = 0;
  valid_byte_count = ctx.copy_from_user(insnbytes, bb.rip, MAX_BB_BYTES, pfec, faultaddr, true);
  return valid_byte_count;
}

//
// Decode and translate one x86 instruction
//
bool TraceDecoder::translate() {
  opsize_prefix = 0;
  addrsize_prefix = 0;
  bool uses_sse = 0;

  ripstart = rip;
  decode_prefixes();

#if 0
  logfile << "prefixes = ", prefixes, ":";
  foreach (i, PFX_count) {
    if (prefixes & (1 << i)) logfile << " ", prefix_names[i];
  }
  logfile << endl;
#endif

  if (prefixes & PFX_ADDR) addrsize_prefix = 1;

  op = fetch1();
  bool need_modrm = onebyte_has_modrm[op];
  if (op == 0x0f) {
    op = fetch1();
    need_modrm = twobyte_has_modrm[op];

    if (twobyte_uses_SSE_prefix[op]) {
      uses_sse = 1;
      if (prefixes & PFX_DATA) // prefix byte 0x66, typically OPpd
        op |= 0x500;
      else if (prefixes & PFX_REPNZ) // prefix byte 0xf2, typically OPsd
        op |= 0x400;
      else if (prefixes & PFX_REPZ) // prefix byte 0xf3, typically OPss
        op |= 0x200;
      else op |= 0x300; // no prefix byte, typically OPps
    } else {
      op |= 0x100;
    }
  }

  // SSE uses 0x66 prefix for an opcode extension:
  if (!uses_sse && (prefixes & PFX_DATA)) opsize_prefix = 1;

  modrm = ModRMByte((need_modrm) ? fetch1() : 0);

  if (inrange(op, 0xd8, 0xdf)) {
    op = 0x600 | (lowbits(op, 3) << 4) | modrm.reg;
  }

  bool rc;

  // logfile << "Decoding op 0x", hexstring(op, 12), " (class ", (op >> 8), ") @ ", (void*)ripstart, endl, flush;

  is_x87 = 0;
  is_sse = 0;

  invalid |= ((rip - (Waddr)bb.rip) > valid_byte_count);

  if (invalid) {
    invalidate();
    user_insn_count++;
    end_of_block = 1;
    lastop();
    return false;
  }

  switch (op >> 8) {
  case 0:
  case 1: {
    rc = decode_fast();

    // Try again with the complex decoder if needed
    bool iscomplex = ((rc == 0) & (!invalid));
    some_insns_complex |= iscomplex;
    if (iscomplex) rc = decode_complex();

    if unlikely (used_microcode_assist) {
      stats.decoder.x86_decode_type[DECODE_TYPE_ASSIST]++;
    } else {
      stats.decoder.x86_decode_type[DECODE_TYPE_FAST] += (!iscomplex);
      stats.decoder.x86_decode_type[DECODE_TYPE_COMPLEX] += iscomplex;
    }

    break;
  }
  case 2:
  case 3:
  case 4:
  case 5:
    stats.decoder.x86_decode_type[DECODE_TYPE_SSE]++;
    rc = decode_sse(); break;
  case 6:
    stats.decoder.x86_decode_type[DECODE_TYPE_X87]++;
    rc = decode_x87(); break;
  default: {
    MakeInvalid();
    break;
  }
  } // switch

  if (!rc) return rc;

  user_insn_count++;

  assert(!invalid);

  if (end_of_block) {
    // Block ended with a branch: close the uop and exit
    lastop();
    stats.decoder.bb_decode_type.all_insns_fast += (!some_insns_complex);
    stats.decoder.bb_decode_type.some_complex_insns += some_insns_complex;
    return false;
  } else {
    // Block did not end with a branch: do we have more room for another x86 insn?
    if (((MAX_BB_UOPS - bb.count) < (MAX_TRANSOPS_PER_USER_INSN))
        || ((rip - bb.rip) >= (MAX_BB_BYTES-15))
        || (user_insn_count >= MAX_BB_X86_INSNS)) {
      if (logable(5)) logfile << "Basic block ", (void*)(Waddr)bb.rip, " too long: cutting at ", bb.count, " transops (", transbufcount, " currently in buffer)", endl;
      // bb.rip_taken and bb.rip_not_taken were already filled out for the last instruction.
      if (!last_flags_update_was_atomic)
        this << TransOp(OP_collcc, REG_temp0, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
      TransOp transop(OP_bru, REG_rip, REG_zero, REG_zero, REG_zero, 3);
      transop.riptaken = (Waddr)rip;
      transop.ripseq = (Waddr)rip;
      bb.rip_taken = bb.rip_not_taken = (Waddr)rip;
      this << transop;
      lastop();
      stats.decoder.bb_decode_type.all_insns_fast += (!some_insns_complex);
      stats.decoder.bb_decode_type.some_complex_insns += some_insns_complex;
      return false;
    } else {
      lastop();
      return true;
    }
  }
#undef DECODE
}

ostream& printflags(ostream& os, W64 flags) {
  os << "0x", hexstring(flags, 32), " = [";

  for (int i = (FLAG_COUNT-1); i >= 0; i--) {
    if (bit(flags, i)) os << " ", x86_flag_names[i]; else os << " -";
  }
  os << " ] ";
  return os;
}

BasicBlock* BasicBlockCache::translate(Context& ctx, Waddr rip) {
  if unlikely (rip == config.start_log_at_rip) {
    config.start_log_at_iteration = 0;
    logenable = 1;
  }

  RIPVirtPhys rvp(rip);
  rvp.update(ctx);

  BasicBlock* bb = get(rvp);
  if (bb) return bb;

  if (smc_isdirty(rvp.mfnlo))
    invalidate_page(rvp.mfnlo, INVALIDATE_REASON_DIRTY);

  if (smc_isdirty(rvp.mfnhi))
    invalidate_page(rvp.mfnhi, INVALIDATE_REASON_DIRTY);

  translate_timer.start();

  TraceDecoder trans(rvp);
  trans.fillbuf(ctx);

  if (logable(5) | log_code_page_ops) logfile << "Translating ", rvp, " (", trans.valid_byte_count, " bytes valid) at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits", endl;

  if (rvp.mfnlo == RIPVirtPhys::INVALID) {
    assert(trans.valid_byte_count == 0);
  }

  for (;;) {
    //if (DEBUG) logfile << "rip ", (void*)trans.rip, ", relrip = ", (void*)(trans.rip - trans.bb.rip), endl, flush;
    if (!trans.translate()) break;
  }

  bb = trans.bb.clone();

  add(bb);
  stats.decoder.bbcache.count = this->count;
  stats.decoder.bbcache.inserts++;

  stats.decoder.throughput.basic_blocks++;

  BasicBlockChunkList* pagelist;

  smc_cleardirty(bb->rip.mfnlo);
  pagelist = bbpages.get(bb->rip.mfnlo);
  if (!pagelist) {
    //++MTY FIXME: This is allocated but never freed!
    pagelist = new BasicBlockChunkList(bb->rip.mfnlo);
    bbpages.add(pagelist);
    stats.decoder.pagecache.inserts++;
    stats.decoder.pagecache.count = bbpages.count;
  }

  pagelist->add(bb, bb->mfnlo_loc);
  if (logable(5) | log_code_page_ops) logfile << "Add bb ", bb, " (", bb->rip, ", ", bb->bytes, " bytes) to low page list ", pagelist, ": loc ", bb->mfnlo_loc.chunk, ":", bb->mfnlo_loc.index, endl;

  int page_crossing = ((lowbits(bb->rip, 12) + (bb->bytes-1)) >> 12);

  if (page_crossing) {
    smc_cleardirty(bb->rip.mfnhi);
    pagelist = bbpages.get(bb->rip.mfnhi);
    if (!pagelist) {
      //++MTY FIXME: This is allocated but never freed!
      pagelist = new BasicBlockChunkList(bb->rip.mfnhi);
      bbpages.add(pagelist);
      stats.decoder.pagecache.inserts++;
      stats.decoder.pagecache.count = bbpages.count;
    }
    pagelist->add(bb, bb->mfnhi_loc);
    if (logable(5) | log_code_page_ops) logfile << "Add bb ", bb, " (", bb->rip, ", ", bb->bytes, " bytes) to high page list ", pagelist, ": loc ", bb->mfnhi_loc.chunk, ":", bb->mfnhi_loc.index, endl;
  }

  if (logable(5)) {
    logfile << "=====================================================================", endl;
    logfile << *bb, endl;
    logfile << "End of basic block: rip ", trans.bb.rip, " -> taken rip 0x", (void*)(Waddr)trans.bb.rip_taken, ", not taken rip 0x", (void*)(Waddr)trans.bb.rip_not_taken, endl;
  }

  translate_timer.stop();
  return bb;
}

ostream& BasicBlockCache::print(ostream& os) {
  dynarray<BasicBlock*> bblist;
  getentries(bblist);

  foreach (i, bblist.length) {
    const BasicBlock& bb = *bblist[i];
    double percent_of_total_uops = ((double)(bb.hitcount * bb.tagcount) / (double)total_uops_committed);
    double percent_of_total_bbs = ((double)(bb.hitcount) / (double)total_basic_blocks_committed);

    os << "  ", bb.rip, ": ", 
      intstring(bb.tagcount, 4), "t ", intstring(bb.memcount - bb.storecount, 3), "ld ",
      intstring(bb.storecount, 3), "st ", intstring(bb.user_insn_count, 3), "u ",
      intstring(bb.hitcount, 10), "h ", intstring(bb.predcount, 10), "pr ",
      //floatstring(100.0 * (double)bb.predcount / (double)bb.hitcount, 10, 2), "%pr ",
      //floatstring(100.0 * percent_of_total_uops, 6, 2), "%uops",
      intstring(bb.hitcount * bb.tagcount, 10), "uu ",
      ": taken 0x", hexstring(bb.rip_taken, 48), ", seq ", hexstring(bb.rip_not_taken, 48);
    if (bb.rip_taken == bb.rip) os << " [loop]";
    if (bb.repblock) os << " [repblock]";
    os << endl;
  }

  delete& bblist;
  return os;
}

void bbcache_reclaim(size_t bytes, int urgency) {
  bbcache.reclaim(bytes, urgency);
}

void init_translate() {
  ptl_mm_register_reclaim_handler(bbcache_reclaim);
}
