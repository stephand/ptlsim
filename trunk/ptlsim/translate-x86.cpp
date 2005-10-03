//
// PTLsim: Cycle Accurate x86-64 Simulator
// Translation for x86 and x86-64 to PTL transops 
//
// Copyright 1999-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <ptlsim.h>

Hashtable<W64, BasicBlock*, 16384> bbcache;

int ChunkHashtable<W64, 1024, ChunkHashtableBlock_fit_in_bytes(W64, 64)>::setof(const W64& entry) {
  return bits(entry, 0, log2(1024));
}

typedef ChunkHashtable<W64, 1024, ChunkHashtableBlock_fit_in_bytes(W64, 64)> RIPHashtable;

RIPHashtable unaligned_ldst_rip_table;

void add_unaligned_ldst_rip(W64 rip) {
  unaligned_ldst_rip_table.add(rip);
}

void remove_unaligned_ldst_rip(W64 rip) {
  unaligned_ldst_rip_table.remove(rip);
}

bool check_unaligned_ldst_rip(W64 rip) {
  return (unaligned_ldst_rip_table(rip) != null);
}

static const bool ENABLE_LOAD_LATENCY_ADJUSTMENT = 0;

CycleTimer translate_timer("translate");

//
// Calling convention:
// rip = return RIP after insn
// sr0 = RIP of insn
// sr1 = RIP after insn
// sr2 = argument
//
void debug_assist_call(const char* name) {
  logfile << "assist: ", name, " called from ", (void*)ctx.commitarf[REG_sr0], ", return to ", (void*)ctx.commitarf[REG_sr1], ", argument ", (void*)ctx.commitarf[REG_sr2], endl; 
}

extern "C" {
  void assist_mul8();
  void assist_mul16();
  void assist_mul32();
  void assist_mul64();
  void assist_imul8();
  void assist_imul16();
  void assist_imul32();
  void assist_imul64();
  void assist_div8();
  void assist_div16();
  void assist_div32();
  void assist_div64();
  void assist_idiv8();
  void assist_idiv16();
  void assist_idiv32();
  void assist_idiv64();
  void assist_int();
  void assist_syscall();
  void assist_sysret();
  void assist_cpuid();
  void assist_invalid_opcode();
};

void assist_invalid_opcode() {
  // This is handled specially elsewhere
  assert(false);
}

//
// (mul, imul, div, idiv all defined in simtemplates.S) 
//

void assist_int() {
  handle_syscall_32bit();
}

void assist_syscall() {
  handle_syscall_64bit();
}

void assist_sysret() {
  // This should never be possible from user code
  debug_assist_call("sysret"); assert(false);
}

static const char cpuid_vendor[12+1] = "AuthenticPTL";
static const char cpuid_description[48+1] = "PTLsim 3.0 Cycle Accurate x86-64 Simulator Model";

void assist_cpuid() {
  debug_assist_call("cpuid");
  W64& rax = ctx.commitarf[REG_rax];
  W64& rbx = ctx.commitarf[REG_rbx];
  W64& rcx = ctx.commitarf[REG_rcx];
  W64& rdx = ctx.commitarf[REG_rdx];

  W32 func = rax;
  logfile << "assist_cpuid: func 0x", hexstring(func, 32), ":", endl;
  switch (func) {
  case 0: {
    // Max avail function spec and vendor ID:
    W32* vendor = (W32*)&cpuid_vendor;
    rax = 6;
    rbx = vendor[0];
    rdx = vendor[1];
    rcx = vendor[2];
    break;
  }

  case 0x80000000: {
    // Max avail extended function spec and vendor ID:
    W32 eax, ebx, ecx, edx;
    cpuid(func, eax, ebx, ecx, edx);
    W32* vendor = (W32*)&cpuid_vendor;
    rax = eax;
    rbx = vendor[0];
    rdx = vendor[1];
    rcx = vendor[2];
    break;
  }

  case 0x80000001: {
    // extended feature info
    W32 eax, ebx, ecx, edx;
    cpuid(func, eax, ebx, ecx, edx);
    rax = eax;
    rbx = ebx;
    rcx = ecx;
    rdx = edx;
    break;
  }

  case 0x80000002 ... 0x80000004: {
    // processor name string
    W32* cpudesc = (W32*)(&cpuid_description[(func - 0x80000002)*16]);
    rax = cpudesc[0];
    rbx = cpudesc[1];
    rcx = cpudesc[2];
    rdx = cpudesc[3];
    break;
  }

  default: {
    W32 eax, ebx, ecx, edx;
    cpuid(func, eax, ebx, ecx, edx);
    rax = eax;
    rbx = ebx;
    rcx = ecx;
    rdx = edx;
    break;
  }
  }
}

extern void assist_ptlcall();

assist_func_t assistid_to_func[ASSIST_COUNT] = {
  assist_mul8,  assist_mul16,  assist_mul32,  assist_mul64,
  assist_imul8, assist_imul16, assist_imul32, assist_imul64,
  assist_div8,  assist_div16,  assist_div32,  assist_div64,
  assist_idiv8, assist_idiv16, assist_idiv32, assist_idiv64,
  assist_int, assist_syscall, assist_sysret, assist_cpuid,
  assist_invalid_opcode, assist_ptlcall,
};

const char* assist_names[ASSIST_COUNT] = {
  "mul8",  "mul16",  "mul32",  "mul64",
  "imul8", "imul16", "imul32", "imul64",
  "div8",  "div16",  "div32",  "div64",
  "idiv8", "idiv16", "idiv32", "idiv64",
  "int", "syscall", "sysret", "cpuid",
  "invopcode", "ptlcall",
};

bool split_unaligned_memops_during_translate = false;

namespace TranslateX86 {

  //
  // x86-specific constructs
  //

  struct RexByte { 
    // a.k.a., b, x, r, w
    byte extbase:1, extindex:1, extreg:1, mode64:1, insnbits:4; 
    RexByte() { }
    RexByte(const byte& b) { *((byte*)this) = b; }
    operator byte() const { return (*((byte*)this)); }
  };

  struct ModRMByte { 
    byte rm:3, reg:3, mod:2; 
    ModRMByte() { }
    ModRMByte(const byte& b) { *((byte*)this) = b; }
    //operator bool() { return (*((byte*)this)) != 0; }
    operator byte() const { return (*((byte*)this)); }
  };

  struct SIBByte { byte base:3, index:3, scale:2; };

  static const int PFX_REPZ      = (1 << 0);
  static const int PFX_REPNZ     = (1 << 1);
  static const int PFX_LOCK      = (1 << 2);
  static const int PFX_CS        = (1 << 3);
  static const int PFX_SS        = (1 << 4);
  static const int PFX_DS        = (1 << 5);
  static const int PFX_ES        = (1 << 6);
  static const int PFX_FS        = (1 << 7);
  static const int PFX_GS        = (1 << 8);
  static const int PFX_DATA      = (1 << 9);
  static const int PFX_ADDR      = (1 << 10);
  static const int PFX_REX       = (1 << 11);
  static const int PFX_count     = 12;

  static const char* prefix_names[] = {"repz", "repnz", "lock", "cs", "ss", "ds", "es", "fs", "gs", "datasz", "addrsz", "rex"};

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
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    PFX_LOCK, 0, PFX_REPNZ, PFX_REPZ, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };

  //#define FLAGS_DEFAULT_ALU FLAG_OF|FLAG_SF|FLAG_ZF|FLAG_AF|FLAG_PF|FLAG_CF
#define FLAGS_DEFAULT_ALU SETFLAG_ZF|SETFLAG_CF|SETFLAG_OF

  enum {
    // 64-bit
    APR_rax, APR_rcx, APR_rdx, APR_rbx, APR_rsp, APR_rbp, APR_rsi, APR_rdi, APR_r8, APR_r9, APR_r10, APR_r11, APR_r12, APR_r13, APR_r14, APR_r15,
    // 32-bit
    APR_eax, APR_ecx, APR_edx, APR_ebx, APR_esp, APR_ebp, APR_esi, APR_edi, APR_r8d, APR_r9d, APR_r10d, APR_r11d, APR_r12d, APR_r13d, APR_r14d, APR_r15d,
    // 16-bit
    APR_ax, APR_cx, APR_dx, APR_bx, APR_sp, APR_bp, APR_si, APR_di, APR_r8w, APR_r9w, APR_r10w, APR_r11w, APR_r12w, APR_r13w, APR_r14w, APR_r15w,
    // 8-bit
    APR_al, APR_cl, APR_dl, APR_bl, APR_ah, APR_ch, APR_dh, APR_bh,
    // 8-bit with REX, not double-counting the regular 8-bit regs:
    APR_spl, APR_bpl, APR_sil, APR_dil,
    APR_r8b, APR_r9b, APR_r10b, APR_r11b, APR_r12b, APR_r13b, APR_r14b, APR_r15b,
    // SSE registers
    APR_xmm0, APR_xmm1, APR_xmm2, APR_xmm3, APR_xmm4, APR_xmm5, APR_xmm6, APR_xmm7, APR_xmm8, APR_xmm9, APR_xmm10, APR_xmm11, APR_xmm12, APR_xmm13, APR_xmm14, APR_xmm15, 
    // segments:
    APR_es, APR_cs, APR_ss, APR_ds, APR_fs, APR_gs,
    // special:
    APR_rip, APR_zero, APR_COUNT,
  };

  static const char* uniform_arch_reg_names[APR_COUNT] = {
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

  struct ArchPseudoRegInfo {
    W32 sizeshift:3, hibyte:1;
  };

  static const ArchPseudoRegInfo reginfo[APR_COUNT] = {
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

  byte reg64_to_uniform_reg[16] = { APR_rax, APR_rcx, APR_rdx, APR_rbx, APR_rsp, APR_rbp, APR_rsi, APR_rdi, APR_r8, APR_r9, APR_r10, APR_r11, APR_r12, APR_r13, APR_r14, APR_r15 };
  byte xmmreg_to_uniform_reg[16] = { APR_xmm0, APR_xmm1, APR_xmm2, APR_xmm3, APR_xmm4, APR_xmm5, APR_xmm6, APR_xmm7, APR_xmm8, APR_xmm9, APR_xmm10, APR_xmm11, APR_xmm12, APR_xmm13, APR_xmm14, APR_xmm15 };
  byte reg32_to_uniform_reg[16] = { APR_eax, APR_ecx, APR_edx, APR_ebx, APR_esp, APR_ebp, APR_esi, APR_edi, APR_r8d, APR_r9d, APR_r10d, APR_r11d, APR_r12d, APR_r13d, APR_r14d, APR_r15d };
  byte reg16_to_uniform_reg[16] = { APR_ax, APR_cx, APR_dx, APR_bx, APR_sp, APR_bp, APR_si, APR_di, APR_r8w, APR_r9w, APR_r10w, APR_r11w, APR_r12w, APR_r13w, APR_r14w, APR_r15w };
  byte reg8_to_uniform_reg[8] = { APR_al, APR_cl, APR_dl, APR_bl, APR_ah, APR_ch, APR_dh, APR_bh };
  byte reg8x_to_uniform_reg[16] = { APR_al, APR_cl, APR_dl, APR_bl, APR_spl, APR_bpl, APR_sil, APR_dil, APR_r8b, APR_r9b, APR_r10b, APR_r11b, APR_r12b, APR_r13b, APR_r14b, APR_r15b };
  byte segreg_to_uniform_reg[16] = { APR_es, APR_cs, APR_ss, APR_ds, APR_fs, APR_zero, APR_zero };

  static const byte arch_pseudo_reg_to_arch_reg[APR_COUNT] = {
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
    /* 00 */ 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0, /* 00 */
    /* 10 */ 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0, /* 10 */
    /* 20 */ 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0, /* 20 */
    /* 30 */ 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0, /* 30 */
    /* 40 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 40 */
    /* 50 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 50 */
    /* 60 */ 0,0,1,1,0,0,0,0,0,1,0,1,0,0,0,0, /* 60 */
    /* 70 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 70 */
    /* 80 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 80 */
    /* 90 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 90 */
    /* a0 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* a0 */
    /* b0 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* b0 */
    /* c0 */ 1,1,0,0,1,1,1,1,0,0,0,0,0,0,0,0, /* c0 */
    /* d0 */ 1,1,1,1,0,0,0,0,1,1,1,1,1,1,1,1, /* d0 */
    /* e0 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* e0 */
    /* f0 */ 0,0,0,0,0,0,1,1,0,0,0,0,0,0,1,1  /* f0 */
    /*       -------------------------------        */
    /*       0 1 2 3 4 5 6 7 8 9 a b c d e f        */
  };

  static const byte twobyte_has_modrm[256] = {
    /*       0 1 2 3 4 5 6 7 8 9 a b c d e f        */
    /*       -------------------------------        */
    /* 00 */ 1,1,1,1,0,0,0,0,0,0,0,0,0,1,0,1, /* 0f */
    /* 10 */ 1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0, /* 1f */
    /* 20 */ 1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1, /* 2f */
    /* 30 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 3f */
    /* 40 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 4f */
    /* 50 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 5f */
    /* 60 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 6f */
    /* 70 */ 1,1,1,1,1,1,1,0,0,0,0,0,1,1,1,1, /* 7f */
    /* 80 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 8f */
    /* 90 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 9f */
    /* a0 */ 0,0,0,1,1,1,1,1,0,0,0,1,1,1,1,1, /* af */
    /* b0 */ 1,1,1,1,1,1,1,1,0,0,1,1,1,1,1,1, /* bf */
    /* c0 */ 1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0, /* cf */
    /* d0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* df */
    /* e0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* ef */
    /* f0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0  /* ff */
    /*       -------------------------------        */
    /*       0 1 2 3 4 5 6 7 8 9 a b c d e f        */
  };

  static const byte twobyte_uses_SSE_prefix[256] = {
    /*       0 1 2 3 4 5 6 7 8 9 a b c d e f        */
    /*       -------------------------------        */
    /* 00 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0f */
    /* 10 */ 1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0, /* 1f */
    /* 20 */ 0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1, /* 2f */
    /* 30 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 3f */
    /* 40 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 4f */
    /* 50 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 5f */
    /* 60 */ 1,1,1,1,1,1,1,1,0,0,0,0,0,1,1,1, /* 6f */
    /* 70 */ 1,0,0,0,1,1,1,0,0,0,0,0,0,0,1,1, /* 7f */
    /* 80 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 8f */
    /* 90 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 9f */
    /* a0 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* af */
    /* b0 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* bf */
    /* c0 */ 0,0,1,0,1,1,1,0,0,0,0,0,0,0,0,0, /* cf */
    /* d0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* df */
    /* e0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* ef */
    /* f0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0  /* ff */
    /*       -------------------------------        */
    /*       0 1 2 3 4 5 6 7 8 9 a b c d e f        */
  };


  /* bits in sizeflag */
  //#define SUFFIX_ALWAYS 4
#define AFLAG 2
#define DFLAG 1

  enum { b_mode = 1, v_mode, w_mode, d_mode, q_mode, x_mode, m_mode, cond_jump_mode, loop_jcxz_mode, dq_mode };

  //
  // Decoded Operand
  //

  enum { OPTYPE_NONE, OPTYPE_REG, OPTYPE_MEM, OPTYPE_IMM };

  struct TraceDecoder;

  struct DecodedOperand {
    int type;
    bool indirect;
    union {
      struct {
        int reg;
      } reg;

      struct {
        W64s imm;
      } imm;

      struct {
        int size;
        int basereg;
        int indexreg;
        int scale;
        W64s offset;
        bool riprel;
      } mem;
    };

    bool gform_ext(TraceDecoder& state, int bytemode, int regfield, bool def64 = false, bool in_ext_z = false);
    bool gform(TraceDecoder& state, int bytemode);
    bool iform(TraceDecoder& state, int bytemode);
    bool iform64(TraceDecoder& state, int bytemode);
    bool eform(TraceDecoder& state, int bytemode);
    bool varreg(TraceDecoder& state, int bytemode, bool def64);
    bool varreg_def32(TraceDecoder& state, int bytemode);
    bool varreg_def64(TraceDecoder& state, int bytemode);

    ostream& print(ostream& os) const;
  };

  ostream& operator <<(ostream& os, const DecodedOperand& decop) {
    return decop.print(os);
  }

  static int transop_histogram[MAX_TRANSOPS_PER_USER_INSN+1];

  struct TraceDecoder {
    BasicBlock bb;
    byte* bbp;

    TransOp transbuf[MAX_TRANSOPS_PER_USER_INSN];
    int transbufcount;

    // Context:

    const byte* rip;
    const byte* ripstart;
    W32 prefixes;
    ModRMByte modrm;
    RexByte rex;
    int sizeflag;
    W64 user_insn_count;
    bool last_flags_update_was_atomic;
    bool invalid;

    TraceDecoder(W64 rip) {
      reset(rip);
    }

    TraceDecoder() { }

    void reset(W64 rip) {
      this->rip = (byte*)rip;
      bb.reset(rip);
      bbp = bb.data;
      transbufcount = 0;

      prefixes = 0;
      rex = 0;
      modrm = 0;
      sizeflag = 0;
      user_insn_count = 0;
      last_flags_update_was_atomic = 1;
      invalid = 0;
    }

    void decode_prefixes();
    void immediate(int rdreg, int sizeshift, W64s imm, bool issigned = true);
    int bias_by_segreg(int basereg);
    void operand_load(int destreg, const DecodedOperand& memref, int loadop = OP_ld, int cachelevel = 0);
    void operand_prefetch(const DecodedOperand& memref, int cachelevel);
    void result_store(int srcreg, int tempreg, const DecodedOperand& memref);
    void alu_reg_or_mem(int opcode, const DecodedOperand& rd, const DecodedOperand& ra, W32 setflags, int rcreg, 
                                        bool flagsonly = false, bool isnegop = false, bool ra_rb_imm_form = false, W64s ra_rb_imm_form_rbimm = 0);

    void move_reg_or_mem(const DecodedOperand& rd, const DecodedOperand& ra, int force_rd = REG_zero);
    void signext_reg_or_mem(const DecodedOperand& rd, DecodedOperand& ra, int rasize, bool zeroext = false);
    void microcode_assist(int assistid, const void* selfrip, const void* postrip);

    typedef int rep_and_size_to_assist_t[3][4];

    bool translate();
    void put(const TransOp& transop);
    void lastop();
    bool cap();
  };

  TraceDecoder* operator <<(TraceDecoder* dec, const TransOp& transop) {
    dec->put(transop);
    return dec;
  }

  TraceDecoder& operator <<(TraceDecoder& dec, const TransOp& transop) {
    dec.put(transop);
    return dec;
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

    assert((rip - ripstart) <= 15);

    TransOp& first = transbuf[0];
    TransOp& last = transbuf[transbufcount-1];
    last.eom = 1;

    bool unaligned = (split_unaligned_memops_during_translate && check_unaligned_ldst_rip((W64)ripstart));

    if (unaligned) {
      first.loadcount *= 2;
      first.storecount *= 2;
    }

    foreach (i, transbufcount) {
      TransOp& transop = transbuf[i];
      assert(bb.count < MAXBBLEN);
      byte* oldp = bbp;

      bool ld = isload(transop.opcode);
      bool st = isstore(transop.opcode);

      if ((ld|st) && unaligned) {
        if (ld) {
          // ld rd = [ra+rb]        =>   ld.low rd = [ra+rb]           and    ld.hi rd = [ra+rb],rd
          TransOp ldlo = transop;
          TransOp ldhi = transop;
          ldlo = transop;
          ldlo.rd = REG_temp4;
          ldlo.cond = LDST_ALIGN_LO;
          ldlo.size = 3; // always load 64-bit word
          ldlo.eom = 0;

          ldhi.rc = REG_temp4;
          ldhi.cond = LDST_ALIGN_HI;
          ldhi.som = 0;

          bbp = ldlo.compress(bbp);
          bbp = ldhi.compress(bbp);

          //logfile << "translate rip ", ripstart, ": split load ", transop, endl;
          bb.memcount += 2;
          bb.tagcount += 2;
          bb.count += 2;
        } else {
          assert(st);
          // For stores, expand     st sfrd = [ra+rb],rc    =>   st.low sfrd1 = [ra+rb],rc    and    st.hi sfrd2 = [ra+rb],rc
          TransOp stlo = transop;
          TransOp sthi = transop;

          stlo = transop;
          stlo.cond = LDST_ALIGN_LO;
          stlo.eom = 0;
          
          sthi = transop;
          sthi.cond = LDST_ALIGN_HI;
          sthi.som = 0;

          bbp = stlo.compress(bbp);
          bbp = sthi.compress(bbp);

          //logfile << "translate rip ", ripstart, ": split load ", transop, endl;
          bb.memcount += 2;
          bb.storecount += 2;
          bb.tagcount += 2;
          bb.count += 2;
        }
      } else {
        bbp = transop.compress(bbp);
        if (ld|st) bb.memcount++;
        if (st) bb.storecount++;
        bb.tagcount++;
        bb.count++;
      }

      if (transop.rd < ARCHREG_COUNT) setbit(bb.usedregs, transop.rd);
      if (transop.ra < ARCHREG_COUNT) setbit(bb.usedregs, transop.ra);
      if (transop.rb < ARCHREG_COUNT) setbit(bb.usedregs, transop.rb);
      if (transop.rc < ARCHREG_COUNT) setbit(bb.usedregs, transop.rc);

      bb.bytes += (bbp - oldp);
    }
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
    case m_mode: this->reg.reg = (ctx.use64) ? reg64_to_uniform_reg[regfield + add] : reg32_to_uniform_reg[regfield + add]; break;
    case v_mode: case dq_mode: 
      this->reg.reg = (state.rex.mode64 || (def64 && (state.sizeflag & DFLAG))) ? reg64_to_uniform_reg[regfield + add] : 
        ((state.sizeflag & DFLAG) || (bytemode == dq_mode)) ? reg32_to_uniform_reg[regfield + add] :
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
      this->imm.imm = *((W8s*)state.rip); state.rip += 1; break;
    case q_mode:
      this->imm.imm = *(W64s*)state.rip; state.rip += 8; break;
    case v_mode:
      // NOTE: Even if rex.mode64 is specified, immediates are never longer than 32 bits (except for mov):
      if (state.rex.mode64 || (state.sizeflag & DFLAG)) {
        this->imm.imm = *(W32s*)state.rip; state.rip += 4;
      } else {
        this->imm.imm = *(W16s*)state.rip; state.rip += 2;
      }
      break;
    case w_mode:
      this->imm.imm = *(W16s*)state.rip; state.rip += 2; break;
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
      this->imm.imm = *((W8s*)state.rip); state.rip += 1; break;
    case q_mode:
      this->imm.imm = *(W64s*)state.rip; state.rip += 8; break;
    case v_mode:
      if (state.rex.mode64) {
        this->imm.imm = *(W64s*)state.rip; state.rip += 8;
      } else if (state.sizeflag & DFLAG) {
        this->imm.imm = *(W32s*)state.rip; state.rip += 4;
      } else {
        this->imm.imm = *(W16s*)state.rip; state.rip += 2;
      }
      break;
    case w_mode:
      this->imm.imm = *(W16s*)state.rip; state.rip += 2; break;
    case d_mode:
      this->imm.imm = *(W32s*)state.rip; state.rip += 4; break;
    default:
      return false;
    }
    return true;
  }

  bool DecodedOperand::eform(TraceDecoder& state, int bytemode) {
    bool DEBUG = analyze_in_detail();

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

    //if (DEBUG) logfile << "--------------------", endl;
    //if (DEBUG) logfile << "mod=", state.modrm.mod, " reg=", state.modrm.reg, " rm=", state.modrm.rm, endl;

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

    mem.basereg = (ctx.use64)
      ? mod_and_rexextbase_and_rm_to_basereg_x86_64[state.modrm.mod][state.rex.extbase][state.modrm.rm]
      : mod_and_rm_to_basereg_x86[state.modrm.mod][state.modrm.rm];

    SIBByte sib;
    if (state.modrm.rm == 4) {
      sib = *((SIBByte*)state.rip++);
    }

    const byte mod_and_rm_to_immsize[4][8] = {
      {0, 0, 0, 0, 0, 4, 0, 0},
      {1, 1, 1, 1, 1, 1, 1, 1},
      {4, 4, 4, 4, 4, 4, 4, 4},
      {0, 0, 0, 0, 0, 0, 0, 0},
    };

    byte immsize = mod_and_rm_to_immsize[state.modrm.mod][state.modrm.rm];
    mem.offset = (immsize) ? signext32(*((W32s*)state.rip), immsize*8) : 0;
    state.rip += immsize;
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
            mem.offset = *((W32s*)state.rip);
            state.rip += 4;
            break;
          case 1:
            assert(!immsize);
            mem.offset = *((W8s*)state.rip);
            state.rip++;
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
    case m_mode: mem.size = (ctx.use64) ? 3 : 2; break;
    case v_mode: case dq_mode: mem.size = (state.rex.mode64) ? 3 : ((state.sizeflag & DFLAG) || (bytemode == dq_mode)) ? 2 : 1; break; // See table 1.2 (p35) of AMD64 ISA manual:
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
        (state.sizeflag & DFLAG) ? reg32_to_uniform_reg[regcode + (state.rex.extbase * 8)] : 
        reg16_to_uniform_reg[regcode + (state.rex.extbase * 8)];
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
      W64* varaddr = 
        (prefixes & PFX_FS) ? &fsbase : 
        (prefixes & PFX_GS) ? &gsbase : 
        (prefixes & PFX_DS) ? &dsbase :
        (prefixes & PFX_SS) ? &ssbase :
        (prefixes & PFX_ES) ? &esbase :
        (prefixes & PFX_CS) ? &csbase : 0;

      TransOp ldp(OP_ld, REG_temp6, REG_zero, REG_imm, REG_zero, 3, (W64)varaddr);
      ldp.internal = 1;
      this << ldp;
      this << TransOp(OP_add, REG_temp6, REG_temp6, basereg, REG_zero, 3);
      return REG_temp6;
    }

    return basereg;
  }

  void TraceDecoder::operand_load(int destreg, const DecodedOperand& memref, int opcode, int cachelevel) {
    int basereg = arch_pseudo_reg_to_arch_reg[memref.mem.basereg];
    int indexreg = arch_pseudo_reg_to_arch_reg[memref.mem.indexreg];
    // ld rd = ra,rb,rc
    // ra = base
    // rb = offset or imm8
    // rc = reg to merge low bytes with

    if (basereg == REG_rip) {
      // [rip + imm32]: index always is zero and scale is 1:
      // Assume we're addressing more than +/- 127 bytes from rip, since this is almost always the case
      basereg = bias_by_segreg(REG_zero);
      TransOp ld(opcode, destreg, basereg, REG_imm, REG_zero, memref.mem.size, (W64)rip + memref.mem.offset);
      if (ENABLE_LOAD_LATENCY_ADJUSTMENT) ld.cachelevel = cachelevel;
      this << ld;
    } else if ((memref.mem.offset == 0) && (memref.mem.scale == 0)) {
      // [ra + rb]
      basereg = bias_by_segreg(basereg);
      TransOp ld(opcode, destreg, basereg, indexreg, REG_zero, memref.mem.size);
      if (ENABLE_LOAD_LATENCY_ADJUSTMENT) ld.cachelevel = cachelevel;
      this << ld;
    } else if (indexreg == REG_zero) {
      // [ra + imm32]
      basereg = bias_by_segreg(basereg);
      TransOp ld(opcode, destreg, basereg, REG_imm, REG_zero, memref.mem.size, memref.mem.offset);
      if (ENABLE_LOAD_LATENCY_ADJUSTMENT) ld.cachelevel = cachelevel;
      this << ld;
    } else {
      // [ra + rb*scale + imm32]
      basereg = bias_by_segreg(basereg);
      TransOp addop(OP_adda, destreg, basereg, REG_imm, indexreg, 3, memref.mem.offset);
      addop.extshift = memref.mem.scale;
      this << addop;
      TransOp ld(opcode, destreg, destreg, REG_zero, REG_zero, memref.mem.size);
      if (ENABLE_LOAD_LATENCY_ADJUSTMENT) ld.cachelevel = cachelevel;
      this << ld;
    }
  }

  void TraceDecoder::operand_prefetch(const DecodedOperand& memref, int cachelevel) {
    int basereg = arch_pseudo_reg_to_arch_reg[memref.mem.basereg];
    int indexreg = arch_pseudo_reg_to_arch_reg[memref.mem.indexreg];
    // ld rd = ra,rb,rc
    // ra = base
    // rb = offset or imm8
    // rc = reg to merge low bytes with

    if (basereg == REG_rip) {
      // [rip + imm32]: index always is zero and scale is 1:
      // Assume we're addressing more than +/- 127 bytes from rip, since this is almost always the case
      basereg = bias_by_segreg(REG_zero);
      TransOp ld(OP_ld_pre, REG_temp0, basereg, REG_imm, REG_zero, 3, (W64)rip + memref.mem.offset);
      ld.cachelevel = cachelevel;
      this << ld;
    } else {
      // [ra + imm32 + rc*scale]
      basereg = bias_by_segreg(basereg);
      TransOp ld(OP_ld_pre, REG_temp0, basereg, REG_imm, indexreg, 3, memref.mem.offset);
      ld.extshift = memref.mem.scale;
      ld.cachelevel = cachelevel;
      this << ld;
    }
  }

  void TraceDecoder::result_store(int srcreg, int tempreg, const DecodedOperand& memref) {
    int basereg = arch_pseudo_reg_to_arch_reg[memref.mem.basereg];
    int indexreg = arch_pseudo_reg_to_arch_reg[memref.mem.indexreg];

    int addrsize = (ctx.use64) ? 3 : 2;

    if ((memref.mem.offset == 0) && (indexreg == REG_zero)) {
      // [ra]
      basereg = bias_by_segreg(basereg);
      this << TransOp(OP_st, REG_mem, basereg, REG_zero, srcreg, memref.mem.size);
    } else if (basereg == REG_rip) {
      // [rip + imm32]: index always is zero and scale is 1:
      // Assume we're addressing more than +/- 127 bytes from rip, since this is almost always the case
      assert(indexreg == REG_zero);
      // We need the long immediate form here anyway since stores don't accept an offset
      assert((prefixes & (PFX_FS|PFX_GS)) == 0);
      this << TransOp(OP_st, REG_mem, REG_zero, REG_imm, srcreg, memref.mem.size, (W64)rip + memref.mem.offset);
    } else if ((memref.mem.offset == 0) && (memref.mem.scale == 0)) {
      // [ra + rb]
      basereg = bias_by_segreg(basereg);
      this << TransOp(OP_st, REG_mem, basereg, indexreg, srcreg, memref.mem.size);
    } else if (indexreg == REG_zero) {
      // [ra + imm32]
      basereg = bias_by_segreg(basereg);
      this << TransOp(OP_st, REG_mem, basereg, REG_imm, srcreg, memref.mem.size, memref.mem.offset);
    } else {
      // [ra + rb*scale + imm32]
      basereg = bias_by_segreg(basereg);
      TransOp addop(OP_adda, tempreg, basereg, REG_imm, indexreg, 3, memref.mem.offset);
      addop.extshift = memref.mem.scale;
      this << addop;
      this << TransOp(OP_st, REG_mem, tempreg, REG_zero, srcreg, memref.mem.size);
    }
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
      if (rdhigh) { this << TransOp(OP_exthb, REG_temp2, rareg, REG_zero, REG_zero, 3); rareg = REG_temp2; }

      int rbreg = srcreg;
      if (rahigh) { this << TransOp(OP_exthb, REG_temp3, srcreg, REG_zero, REG_zero, 3); rbreg = REG_temp3; }
      if (flagsonly) {
        this << TransOp(opcode, REG_temp0, rareg, rbreg, rcreg, sizeshift, (isimm) ? ra.imm.imm : 0, 0, setflags);
      } else {
        if (isnegop) { rbreg = rareg; rareg = REG_zero; }
        if (ra_rb_imm_form) {
          this << TransOp(opcode, destreg, srcreg, REG_imm, (sizeshift >= 2) ? REG_zero : destreg, sizeshift, ra_rb_imm_form_rbimm, 0, setflags);
        } else {
          this << TransOp(opcode, (rdhigh) ? REG_temp2 : destreg, rareg, rbreg, rcreg, sizeshift,
                          (isimm) ? ra.imm.imm : 0, 0, setflags);
          if (rdhigh) { this << TransOp(OP_inshb, destreg, destreg, REG_temp2, REG_zero, 3); } 
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
      if (rdhigh) { this << TransOp(OP_exthb, REG_temp2, destreg, REG_zero, REG_zero, 3); rareg = REG_temp2; }

      int sizeshift = reginfo[rd.reg.reg].sizeshift;
      if (flagsonly) {
        this << TransOp(opcode, REG_temp0, rareg, REG_temp0, rcreg, sizeshift, 0, 0, setflags);
      } else {
        if (ra_rb_imm_form) {
          this << TransOp(opcode, destreg, REG_temp0, REG_imm, (sizeshift >= 2) ? REG_zero : destreg, sizeshift, ra_rb_imm_form_rbimm, 0, setflags);
        } else {
          this << TransOp(opcode, (rdhigh) ? REG_temp2 : destreg, rareg, REG_temp0, rcreg, sizeshift, 0, 0, setflags);
          if (rdhigh) { this << TransOp(OP_inshb, destreg, destreg, REG_temp2, REG_zero, 3); }
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

      int sizeshift = (isimm) ? rd.mem.size : reginfo[ra.reg.reg].sizeshift;
      bool rahigh = (isimm) ? 0 : reginfo[ra.reg.reg].hibyte;
      if (rahigh) { this << TransOp(OP_exthb, REG_temp2, srcreg, REG_zero, REG_zero, 3); srcreg = REG_temp2; }

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
        int opcode = (rdhigh) ? ((isimm || (!rahigh)) ? OP_inshb : OP_movhb) : (rahigh) ? OP_exthb : OP_nop;
        this << TransOp(opcode, destreg, destreg, srcreg, REG_zero, 3, (isimm) ? ra.imm.imm : 0);
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
        this << TransOp((reginfo[rd.reg.reg].hibyte) ? OP_inshb : OP_mov, destreg, destreg, REG_temp0, REG_zero, (reginfo[rd.reg.reg].hibyte) ? 3 : sizeshift);
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
        this << TransOp(OP_exthb, REG_temp1, srcreg, REG_zero, REG_zero, 3);
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
        this << TransOp(OP_exthb, REG_temp0, rareg, REG_zero, REG_zero, 3);
        rareg = REG_temp0;
      }

      // On x86-64, only 8-bit and 16-bit ops need to be merged; 32-bit is zero extended to full 64 bits:
      TransOp transop((zeroext) ? OP_zxt : OP_sxt, rdreg, (rdsize < 2) ? rdreg : REG_zero, rareg, REG_zero, rdsize);
      transop.cond = rasize;
      this << transop;
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

  void TraceDecoder::microcode_assist(int assistid, const void* selfrip, const void* postrip) {
    immediate(REG_sr0, 3, (W64)selfrip);
    immediate(REG_sr1, 3, (W64)postrip);
    if (!last_flags_update_was_atomic) 
      this << TransOp(OP_collcc, REG_temp0, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
    TransOp transop(OP_brp, REG_rip, REG_zero, REG_zero, REG_zero, 3);
    transop.riptaken = transop.ripseq = (W64)assistid_to_func[assistid];
    this << transop;
  }

  //
  // Core Translator
  //
  void TraceDecoder::decode_prefixes() {
    prefixes = 0;
    rex = 0;

    for (;;) {
      byte b = *rip;
      W32 prefix = (ctx.use64) ? prefix_map_x86_64[b] : prefix_map_x86[b];
      if (!prefix) break;
      if (rex) {
        // REX is ignored when followed by another prefix:
        rex = 0;
        prefixes &= ~PFX_REX;
      }
      prefixes |= prefix;
      if (prefix == PFX_REX) { rex = b; }
      rip++;
    }
  }

  void print_invalid_insns(int op, const byte* ripstart, const byte* rip) {
    logfile << "translate: invalid opcode or decode failure at iteration ", iterations, ": ", (void*)(W64)op, " commits ", total_user_insns_committed, " (at ripstart ", ripstart, ", rip ", rip, "); may be speculative", endl, flush;
    if (dumpcode_filename) {
      odstream os(dumpcode_filename);
      os.write(ripstart, 256);
      os.close();
    }
  }

  // Maximum number of bytes of x86 insns in any basic block (not counting 15 bytes for possible last max length insn)
#define MAX_USER_INSN_BB_BYTES (32760-15)    // (must fit in W16)

  bool TraceDecoder::translate() {
    bool DEBUG = analyze_in_detail();

    sizeflag = AFLAG | DFLAG;
    bool uses_sse = 0;

    bool end_of_block = false;

    invalid = 0;

    ripstart = rip;

    //logfile << "rip ", rip, ":", endl;
    decode_prefixes();

#if 0
    logfile << "prefixes = ", prefixes, ":";
    foreach (i, PFX_count) {
      if (prefixes & (1 << i)) logfile << " ", prefix_names[i];
    }
    logfile << endl;
#endif

    if (prefixes & PFX_ADDR) {
      sizeflag ^= AFLAG;
    }

    W32 op = *rip++;
    bool need_modrm = onebyte_has_modrm[op];
    if (op == 0x0f) {
      op = *rip++;
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
    if (!uses_sse && (prefixes & PFX_DATA)) {
      sizeflag ^= DFLAG;
    }

    modrm = (need_modrm) ? *((ModRMByte*)rip++) : ModRMByte(0);

    if (inrange(op, 0xd8, 0xdf)) {
      //logfile << "translate x87 FP ops at rip ", (void*)ripstart, " iter ", iterations, endl;
      op = 0x600 | (lowbits(op, 3) << 4) | modrm.reg;
    }

#define DECODE(form, decbuf, mode) invalid |= (!decbuf.form(*this, mode));
#define CheckInvalid() if (invalid) { print_invalid_insns(op, ripstart, rip); microcode_assist(ASSIST_INVALID_OPCODE, ripstart, ripstart); end_of_block = 1; user_insn_count++; lastop(); return false; }
#define MakeInvalid() { invalid |= true; CheckInvalid(); }

    DecodedOperand rd;
    DecodedOperand ra;

    switch (op) {

    case 0x00 ... 0x0e:
    case 0x10 ... 0x3f: {
      // Arithmetic: add, or, adc, sbb, and, sub, xor, cmp
      // Low 3 bits of opcode determine the format:
      switch (bits(op, 0, 3)) {
      case 0: DECODE(eform, rd, b_mode); DECODE(gform, ra, b_mode); break;
      case 1: DECODE(eform, rd, v_mode); DECODE(gform, ra, v_mode); break;
      case 2: DECODE(gform, rd, b_mode); DECODE(eform, ra, b_mode); break;
      case 3: DECODE(gform, rd, v_mode); DECODE(eform, ra, v_mode); break;
      case 4: rd.type = OPTYPE_REG; rd.reg.reg = APR_al; DECODE(iform, ra, b_mode); break;
      case 5: DECODE(varreg_def32, rd, 0); DECODE(iform, ra, v_mode); break;
      default: invalid |= true; break;
      }

      CheckInvalid();

      static const byte translate_opcode[8] = {OP_add, OP_or, OP_addc, OP_subc, OP_and, OP_sub, OP_xor, OP_sub};

      int translated_opcode = translate_opcode[bits(op, 3, 3)];
      int rcreg = isclass(translated_opcode, OPCLASS_ADDSUBC) ? REG_cf : REG_zero;
      alu_reg_or_mem(translated_opcode, rd, ra, FLAGS_DEFAULT_ALU, rcreg, (bits(op, 3, 3) == 7));

      break;
    }

    case 0x40 ... 0x4f: {
      // inc/dec in 32-bit mode only: for x86-64 this is not possible since it's the REX prefix
      ra.gform_ext(*this, v_mode, bits(op, 0, 3), false, true);
      int sizeshift = reginfo[ra.reg.reg].sizeshift;
      int r = arch_pseudo_reg_to_arch_reg[ra.reg.reg];

      this << TransOp(OP_add, r, r, REG_imm, REG_zero, sizeshift, bit(op, 3) ? -1 : +1, 0, SETFLAG_ZF|SETFLAG_OF); // save old rdreg
      break;
      break;
    }

    case 0x50 ... 0x5f: {
      // push (0x50..0x57) or pop (0x58..0x5f) reg (defaults to 64 bit; pushing bytes not possible)
      ra.gform_ext(*this, v_mode, bits(op, 0, 3), ctx.use64, true);
      int r = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      int sizeshift = reginfo[ra.reg.reg].sizeshift;
      if (ctx.use64 && (sizeshift == 2)) sizeshift = 3; // There is no way to encode 32-bit pushes and pops in 64-bit mode:
      int size = (1 << sizeshift);

      CheckInvalid();

      if (op < 0x58) {
        // push
        this << TransOp(OP_sub, REG_rsp, REG_rsp, REG_imm, REG_zero, (ctx.use64 ? 3 : 2), size);
        this << TransOp(OP_st, REG_mem, REG_rsp, REG_zero, r, sizeshift);
      } else {
        // pop
        this << TransOp(OP_ld, r, REG_rsp, REG_zero, REG_zero, sizeshift);
        this << TransOp(OP_add, REG_rsp, REG_rsp, REG_imm, REG_zero, (ctx.use64 ? 3 : 2), size);
      }
      break;
    }
 
    case 0x60: {
      // pusha [not used by gcc]
      MakeInvalid();
      break;
    }

    case 0x61: {
      // popa [not used by gcc]
      MakeInvalid();
      break;
    }

    case 0x62: {
      // bound [not used by gcc]
      MakeInvalid();
      break;
    }

    case 0x1b6 ... 0x1b7: {
      // zero extensions: movzx rd,byte / movzx rd,word
      int bytemode = (op == 0x1b6) ? b_mode : v_mode;
      DECODE(gform, rd, v_mode);
      DECODE(eform, ra, bytemode);
      int rasizeshift = bit(op, 0);
      CheckInvalid();
      signext_reg_or_mem(rd, ra, rasizeshift, true);
      break;
    }

    case 0x63: 
    case 0x1be ... 0x1bf: {
      // sign extensions: movsx movsxd
      int bytemode = (op == 0x1be) ? b_mode : v_mode;
      DECODE(gform, rd, v_mode);
      DECODE(eform, ra, bytemode);
      int rasizeshift = (op == 0x63) ? 2 : (op == 0x1be) ? 0 : (op == 0x1bf) ? 1 : 3;
      CheckInvalid();
      signext_reg_or_mem(rd, ra, rasizeshift);
      break;
    }

    case 0x64 ... 0x67: {
      // invalid (prefixes)
      MakeInvalid();
      break;
    }

    case 0x68:
    case 0x6a: {
      // push immediate
      DECODE(iform64, ra, (op == 0x68) ? v_mode : b_mode);

      int sizeshift = (sizeflag & DFLAG) ? ((ctx.use64) ? 3 : 2) : 1;
      int size = (1 << sizeshift);
      CheckInvalid();

      int r = REG_temp0;
      immediate(r, (op == 0x68) ? 2 : 0, ra.imm.imm);

      this << TransOp(OP_sub, REG_rsp, REG_rsp, REG_imm, REG_zero, 3, size);
      this << TransOp(OP_st, REG_mem, REG_rsp, REG_zero, r, sizeshift);
      break;
    }

    case 0x69:
    case 0x6b: {
      // multiplies with three operands including an immediate
      // 0x69: imul reg16/32/64, rm16/32/64, simm16/simm32
      // 0x6b: imul reg16/32/64, rm16/32/64, simm8
      int bytemode = (op == 0x6b) ? b_mode : v_mode;

      DECODE(gform, rd, v_mode);
      DECODE(eform, ra, v_mode);

      DecodedOperand rimm;
      DECODE(iform, rimm, bytemode);

      CheckInvalid();
      alu_reg_or_mem(OP_mull, rd, ra, FLAG_CF|FLAG_OF, REG_imm, false, false, true, rimm.imm.imm);
      break;
    }

    case 0x1af: {
      // multiplies with two operands
      // 0x69: imul reg16/32/64, rm16/32/64
      // 0x6b: imul reg16/32/64, rm16/32/64
      DECODE(gform, rd, v_mode);
      DECODE(eform, ra, v_mode);
      int rdreg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      int rdshift = reginfo[rd.reg.reg].sizeshift;

      CheckInvalid();
      alu_reg_or_mem(OP_mull, rd, ra, FLAG_CF|FLAG_OF, (rdshift < 2) ? rdreg : REG_zero);
      break;
    }

    case 0x6c ... 0x6f: {
      // insb/insw/outsb/outsw: not supported
      MakeInvalid();
      break;
    }

    case 0x70 ... 0x7f:
    case 0x180 ... 0x18f: {
      // near conditional branches with 8-bit displacement:
      DECODE(iform, ra, (inrange(op, 0x180, 0x18f) ? v_mode : b_mode));
      CheckInvalid();
      if (!last_flags_update_was_atomic) 
        this << TransOp(OP_collcc, REG_temp0, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
      int condcode = bits(op, 0, 4);
      TransOp transop(OP_br, REG_rip, cond_code_to_flag_regs[condcode].ra, cond_code_to_flag_regs[condcode].rb, REG_zero, 3, 0);
      transop.cond = condcode;
      transop.riptaken = (W64)rip + ra.imm.imm;
      transop.ripseq = (W64)rip;
      bb.rip_taken = (W64)rip + ra.imm.imm;
      bb.rip_not_taken = (W64)rip;
      // (branch id implied)

      this << transop;
      end_of_block = true;
      break;
    }

    case 0x80 ... 0x83: {
      // GRP1b, GRP1s, GRP1ss:
      switch (bits(op, 0, 2)) {
      case 0: DECODE(eform, rd, b_mode); DECODE(iform, ra, b_mode); break; // GRP1b
      case 1: DECODE(eform, rd, v_mode); DECODE(iform, ra, v_mode); break; // GRP1S
      case 2: invalid |= true; break;
      case 3: DECODE(eform, rd, v_mode); DECODE(iform, ra, b_mode); break; // GRP1Ss (sign ext byte)
      }
      // function in modrm.reg: add or adc sbb and sub xor cmp
      CheckInvalid();

      static const byte translate_opcode[8] = {OP_add, OP_or, OP_addc, OP_subc, OP_and, OP_sub, OP_xor, OP_sub};

      int translated_opcode = translate_opcode[modrm.reg];
      int rcreg = isclass(translated_opcode, OPCLASS_ADDSUBC) ? REG_cf : REG_zero;
      alu_reg_or_mem(translated_opcode, rd, ra, FLAGS_DEFAULT_ALU, rcreg, (modrm.reg == 7));

      break;
    }
    case 0x84 ... 0x85: {
      // test
      DECODE(eform, rd, (op & 1) ? v_mode : b_mode);
      DECODE(gform, ra, (op & 1) ? v_mode : b_mode);
      CheckInvalid();
      alu_reg_or_mem(OP_and, rd, ra, FLAGS_DEFAULT_ALU, REG_zero, true);
      break;
    }
    case 0x86 ... 0x87: {
      // xchg
      DECODE(eform, rd, bit(op, 0) ? v_mode : b_mode);
      DECODE(gform, ra, bit(op, 0) ? v_mode : b_mode);
      CheckInvalid();
      /*

      xchg [mem],ra

      becomes:

      move t0 = ra
      ld   ra,[mem],ra
      st   [mem],t0

      */
      int sizeshift = reginfo[ra.reg.reg].sizeshift;
      bool rahigh = reginfo[ra.reg.reg].hibyte;
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];

      if (rd.type == OPTYPE_REG) {
        int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
        bool rdhigh = reginfo[rd.reg.reg].hibyte;

        this << TransOp(OP_mov, REG_temp0, REG_zero, rdreg, REG_zero, 3); // save old rdreg

        int opcode1 = (rdhigh && !rahigh) ? OP_inshb : (!rdhigh && rahigh) ? OP_exthb : (rdhigh && rahigh) ? OP_movhb : OP_mov;
        int opcode2 = (rdhigh && !rahigh) ? OP_exthb : (!rdhigh && rahigh) ? OP_inshb : (rdhigh && rahigh) ? OP_movhb : OP_mov;
        this << TransOp(opcode1, rdreg, rdreg, rareg, REG_zero, (opcode1 == OP_mov) ? sizeshift : 3); // dl = al
        this << TransOp(opcode2, rareg, rareg, REG_temp0, REG_zero, (opcode2 == OP_mov) ? sizeshift : 3); // al = olddl
      } else {
        this << TransOp((rahigh) ? OP_exthb : OP_mov, REG_temp7, REG_zero, rareg, REG_zero, 3);
        
        //
        // ld ra = [mem],ra
        //
        int destreg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
        int mergewith = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
        if (sizeshift >= 2) {
          // zero extend 32-bit to 64-bit or just load as 64-bit:
          operand_load(destreg, rd);
        } else {
          // need to merge 8-bit or 16-bit data:
          operand_load(REG_temp0, rd);
          this << TransOp((reginfo[rd.reg.reg].hibyte) ? OP_inshb : OP_mov, destreg, destreg, REG_temp0, REG_zero, sizeshift);
        }

        //
        // st [mem] = t0
        //
        result_store(REG_temp7, REG_temp0, rd);
      }
      break;
    }

    case 0x88 ... 0x8b: {
      // moves
      int bytemode = bit(op, 0) ? v_mode : b_mode;
      switch (bit(op, 1)) {
      case 0: DECODE(eform, rd, bytemode); DECODE(gform, ra, bytemode); break;
      case 1: DECODE(gform, rd, bytemode); DECODE(eform, ra, bytemode); break;
      }
      CheckInvalid();
      move_reg_or_mem(rd, ra);
      break;
    }
    case 0x8c: {
      // Special form: always return 0x63 (gs seg) for segreg while in simulation mode (used for simcalls):
      DECODE(eform, rd, v_mode);
      DECODE(gform, ra, v_mode);
      CheckInvalid();
      ra.type = OPTYPE_IMM;
      ra.imm.imm = 0x63;
      move_reg_or_mem(rd, ra, REG_temp7);
      break;
    }
    case 0x8d: {
      // lea (zero extends result: no merging)
      DECODE(gform, rd, v_mode);
      DECODE(eform, ra, v_mode);
      CheckInvalid();
      int destreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int sizeshift = reginfo[rd.reg.reg].sizeshift;
      int basereg = arch_pseudo_reg_to_arch_reg[ra.mem.basereg];
      int indexreg = arch_pseudo_reg_to_arch_reg[ra.mem.indexreg];

      if (basereg == REG_rip) {
        // rip-relative addressing:
        this << TransOp(OP_mov, destreg, (sizeshift >= 2) ? REG_zero : destreg, REG_imm, REG_zero, sizeshift, (W64)rip + ra.mem.offset);
      } else {
        TransOp addop(OP_adda, (sizeshift >= 2) ? destreg : REG_temp0, basereg, REG_imm, indexreg, sizeshift, ra.mem.offset);
        addop.extshift = ra.mem.scale;
        this << addop;
        if (sizeshift < 2) this << TransOp(OP_mov, destreg, destreg, REG_temp0, REG_zero, sizeshift); break;
      }
      break;
    }
    case 0x8e: {
      // mov segreg,Ev
      DECODE(gform, rd, w_mode);
      DECODE(eform, ra, w_mode);
      CheckInvalid();

      static W64* base_cache_addrs[8] = {&esbase, &csbase, &ssbase, &dsbase, &fsbase, &gsbase, null, null};
      static W16* seg_reg_addrs[8] = {&esreg, &csreg, &ssreg, &dsreg, &fsreg, &gsreg, null, null};

      W64* basecache = base_cache_addrs[modrm.reg];
      W16* segregcache = seg_reg_addrs[modrm.reg];

      if (!basecache || !segregcache) MakeInvalid();

      int rareg = (ra.type == OPTYPE_MEM) ? REG_temp0 : arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      if (ra.type == OPTYPE_MEM) operand_load(REG_temp0, ra);

      TransOp stwp(OP_st, REG_mem, REG_zero, REG_imm, rareg, 1, (W64)segregcache); stwp.internal = 1; this << stwp;

      this << TransOp(OP_and, REG_temp0, rareg, REG_imm, REG_zero, 3, 0xfff8);

      TransOp ldp(OP_ld, REG_temp0, REG_temp0, REG_imm, REG_zero, 3, (W64)&ldt_seg_base_cache); ldp.internal = 1; this << ldp;
      TransOp stp(OP_st, REG_mem, REG_zero, REG_imm, REG_temp0, 3, (W64)basecache); stp.internal = 1; this << stp;
      break;
    }
    case 0x8f: {
      // pop Ev: pop to reg or memory
      DECODE(eform, rd, v_mode);
      CheckInvalid();

      int sizeshift = (rd.type == OPTYPE_REG) ? reginfo[rd.reg.reg].sizeshift : rd.mem.size;
      if (sizeshift == 2) sizeshift = 3; // There is no way to encode 32-bit pushes and pops in 64-bit mode:

      this << TransOp(OP_ld, REG_temp7, REG_rsp, REG_zero, REG_zero, sizeshift);

      ra.type = OPTYPE_REG;
      ra.reg.reg = 0; // not used
      // There is no way to encode 32-bit pushes and pops in 64-bit mode:
      if (rd.type == OPTYPE_MEM && rd.mem.size == 2) rd.mem.size = 3;
      move_reg_or_mem(rd, ra, REG_temp7);

      // Do this last since technically rsp update is not visible at address generation time:
      this << TransOp(OP_add, REG_rsp, REG_rsp, REG_imm, REG_zero, 3, (1 << sizeshift));

      break;
    }

    case 0x90: {
      // 0x90 (xchg eax,eax) is a NOP and in x86-64 is treated as such (i.e. does not zero upper 32 bits as usual)
      // NOTE! We still have to output something so %rip gets incremented correctly!
      this << TransOp(OP_nop, REG_temp0, REG_zero, REG_zero, REG_zero, 3);
      break;
    }
    case 0x91 ... 0x97: {
      // xchg A,reg (A = ax|eax|rax):
      ra.gform_ext(*this, v_mode, bits(op, 0, 3), false, true);
      CheckInvalid();

      int sizeshift = reginfo[ra.reg.reg].sizeshift;
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      int rdreg = REG_rax;

      this << TransOp(OP_mov, REG_temp0, REG_zero, rdreg, REG_zero, 3); // save old rdreg
      this << TransOp(OP_mov, rdreg, rdreg, rareg, REG_zero, sizeshift); // dl = al
      this << TransOp(OP_mov, rareg, rareg, REG_temp0, REG_zero, sizeshift); // al = olddl
      break;
    }
    case 0x98: {
      // cbw cwde cdqe
      int rashift = (sizeflag & DFLAG) ? ((rex.mode64) ? 2 : 1) : 0;
      int rdshift = rashift + 1;

      TransOp transop(OP_sxt, REG_rax, (rdshift < 3) ? REG_rax : REG_zero, REG_rax, REG_zero, rdshift);
      transop.cond = rashift;
      this << transop;
      break;
    }
    case 0x99: {
      // cwd cdq cqo
      int rashift = (sizeflag & DFLAG) ? ((rex.mode64) ? 3 : 2) : 1;
      this << TransOp(OP_dupbit, REG_rdx, (rashift < 2) ? REG_rdx : REG_zero, REG_rax, REG_imm, rashift, 0, ((1<<rashift)*8)-1);
      // zero out high bits of rax since technically both rdx and rax are modified:
      if (rashift == 2) this << TransOp(OP_mov, REG_rax, REG_zero, REG_rax, REG_zero, 2);
      break;
    }
    case 0x9a: {
      // call Ap (invalid in 64-bit mode)
      MakeInvalid();
      break;
    }
    case 0x9b: {
      // fwait (invalid; considered a prefix)
      MakeInvalid();
      break;
    }
    case 0x9c: {
      // pushfw/pushfq
      int sizeshift = (sizeflag & DFLAG) ? ((ctx.use64) ? 3 : 2) : 1;
      int size = (1 << sizeshift);

      if (!last_flags_update_was_atomic) 
        this << TransOp(OP_collcc, REG_temp0, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
      this << TransOp(OP_movccr, REG_temp0, REG_temp0, REG_zero, REG_zero, 3);
      //++MTY TODO This also needs to be merged with all the non-dynamic flags (IF,DF,etc.)
      this << TransOp(OP_sub, REG_rsp, REG_rsp, REG_imm, REG_zero, 3, size);
      this << TransOp(OP_st, REG_mem, REG_rsp, REG_zero, REG_temp0, sizeshift);

      break;
    }
    case 0x9d: {
      // popfw/popfq
      int sizeshift = (sizeflag & DFLAG) ? ((ctx.use64) ? 3 : 2) : 1;
      int size = (1 << sizeshift);

      this << TransOp(OP_ld, REG_temp0, REG_rsp, REG_zero, REG_zero, sizeshift);
      this << TransOp(OP_add, REG_rsp, REG_rsp, REG_imm, REG_zero, 3, size);
      //++MTY TODO This also needs to be merged with all the non-dynamic flags (IF,DF,etc.)
      this << TransOp(OP_movrcc, REG_temp0, REG_temp0, REG_zero, REG_zero, 3, 0, 0, FLAGS_DEFAULT_ALU);

      break;

    }
    case 0x9e ... 0x9f: {
      // lahf sahf (invalid in 64-bit mode)
      // This is the source of the infamous Intel x86-64 screwup: these insns are missing
      // on Prescott/Nocona, so AMD had to also invalidate them for compatibility reasons.
      MakeInvalid();
      break;
    }

    case 0xa0 ... 0xa3: {
      rd.gform_ext(*this, (op & 1) ? v_mode : b_mode, REG_rax);
      DECODE(iform64, ra, (ctx.use64 ? q_mode : (sizeflag & AFLAG) ? d_mode : w_mode));
      CheckInvalid();

      ra.mem.offset = ra.imm.imm;
      ra.mem.offset = (ctx.use64) ? ra.mem.offset : lowbits(ra.mem.offset, (sizeflag & AFLAG) ? 32 : 16);
      ra.mem.basereg = APR_zero;
      ra.mem.indexreg = APR_zero;
      ra.mem.scale = APR_zero;
      ra.mem.size = reginfo[rd.reg.reg].sizeshift;
      ra.type = OPTYPE_MEM;
      if (inrange(op, 0xa2, 0xa3)) {
        result_store(REG_rax, REG_temp0, ra);
      } else {
        operand_load(REG_rax, ra);
      }
      break;
    }

    case 0xa4 ... 0xa5:
    case 0xa6 ... 0xa7:
    case 0xaa ... 0xab:
    case 0xac ... 0xad:
    case 0xae ... 0xaf: {
      W64 rep = (prefixes & (PFX_REPNZ|PFX_REPZ));
      int sizeshift = (!bit(op, 0)) ? 0 : (rex.mode64) ? 3 : (sizeflag & DFLAG) ? 2 : 1;

      // only actually code if it is the very first insn in the block!
      // otherwise emit a branch:
      if (rep && ((W64)ripstart != (W64)bb.rip)) {
        if (!last_flags_update_was_atomic) 
          this << TransOp(OP_collcc, REG_temp0, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
        TransOp br(OP_bru, REG_rip, REG_zero, REG_zero, REG_zero, 3);
        br.riptaken = (W64)ripstart;
        br.ripseq = (W64)ripstart;
        this << br;
        end_of_block = 1;
      } else {
        // This is the very first x86 insn in the block, so translate it as a loop!
        if (rep) {
          TransOp chk(OP_chk,      REG_temp0, REG_rcx,    REG_imm,   REG_imm,   3, (W64)rip, EXCEPTION_SkipBlock);
          chk.cond = COND_e; // make sure rcx is not equal to zero
          this << chk;
          bb.repblock = 1;
        }
        this << TransOp(OP_bt,   REG_temp3, REG_mxcsr, REG_imm,   REG_zero, 3, 63);
        switch (op) {
        case 0xa4: case 0xa5: {
          // movs
          /*

          NOTE: x86 semantics are such that if rcx = 0, no repetition at all occurs. Normally this would
          require an additional basic block, which greatly complicates our scheme for translating rep xxx.

          It is assumed that rcx is almost never zero, so a check can be inserted at the top of the loop:

          # set checkcond MSR to CONST_LOOP_ITER_IS_ZERO and CHECK_RESULT to TARGET_AFTER_LOOP
          chk.nz  null = rcx,TARGET_AFTER_LOOP,CONST_LOOP_ITER_IS_ZERO
          chk.nz  rd = ra,imm8,imm8

          In response to a failed check of this type, an EXCEPTION_SkipBlock exception is raised and a rollback will
          occur to the start of the REP block. For loop-related checks, the PTL response is to advance the rip to the
          value stored by the chk uop in the checkcond MSR. This effectively skips the block.

          NOTE: For this hack to work, the scheduler must obey the following constraints:

          - The first rep basic block (repblock) at a given rip must start a new trace
          - Subsequent rep blocks AT THE SAME RIP ONLY may be merged
          - Any basic block entering another RIP must stop the trace as a barrier.

          When merging multiple iterations of reptraces, we must make sure that chk always uses the
          original value of %rsp at trace entry.

          */
          if (rep) assert(rep == PFX_REPZ); // only rep is allowed for movs and rep == repz here

          this << TransOp(OP_ld,     REG_temp0, REG_rsi,    REG_zero,  REG_zero,  sizeshift);          // ldSZ    t0 = [rsi]
          this << TransOp(OP_st,     REG_mem,   REG_rdi,    REG_zero,  REG_temp0, sizeshift);          // stSZ    [rdi] = t0
          TransOp    add1(OP_adda, REG_rsi,   REG_rsi,    REG_zero,  REG_temp3, 3);                  // adda  rsi = rsi,0,t1*SZ
          TransOp    add2(OP_adda, REG_rdi,   REG_rdi,    REG_zero,  REG_temp3, 3);                  // adda  rdi = rdi,0,t1*SZ
          add1.extshift = sizeshift;
          add2.extshift = sizeshift;
          this << add1;
          this << add2;
          if (rep) {
            TransOp sub(OP_sub,  REG_rcx,   REG_rcx,    REG_imm,   REG_zero, (ctx.use64 ? 3 : 2), 1, 0, SETFLAG_ZF);     // sub     rcx = rcx,1 [zf internal]
            sub.nouserflags = 1; // it still generates flags, but does not rename the user flags
            this << sub;
            TransOp br(OP_br, REG_rip, REG_rcx, REG_zero, REG_zero, 3);
            br.cond = COND_ne; // repeat while nonzero
            br.riptaken = (W64)ripstart;
            br.ripseq = (W64)rip;
            this << br;
          }
          break;
        }
        case 0xa6: case 0xa7: {
          // cmps
          this << TransOp(OP_ld,     REG_temp0, REG_rsi,    REG_zero,  REG_zero,  sizeshift);           // ldSZ    t0 = [rsi]
          this << TransOp(OP_ld,     REG_temp1, REG_rdi,    REG_zero,  REG_zero,  sizeshift);           // ldSZ    t1 = [rdi]
          TransOp    add1(OP_adda, REG_rsi,   REG_rsi,    REG_zero,  REG_temp3, 3);                   // adda  rsi = rsi,0,t1*SZ
          TransOp    add2(OP_adda, REG_rdi,   REG_rdi,    REG_zero,  REG_temp3, 3);                   // adda  rdi = rdi,0,t1*SZ
          add1.extshift = sizeshift;
          add2.extshift = sizeshift;
          this << add1;
          this << add2;
          this << TransOp(OP_sub,    REG_temp2, REG_temp0,  REG_temp1, REG_zero,  sizeshift, 0, 0, FLAGS_DEFAULT_ALU); // sub    t2 = t0,t1 (zco)

          if (rep) {
            /*
              ===> Equivalent sequence for repz cmps:

              If (rcx.z) ripseq;
              If (!t2.z) ripseq;
              else riploop;

              rip = (rcx.z | !t2.z) ? ripseq : riploop;

              ornotf   t3 = rcx,t2
              br.nz    rip = t3,zero [loop, seq]             # all branches are swapped so they are expected to be taken 

              ===> Equivalent sequence for repnz cmp:

              If (rcx.z) ripseq;
              If (t2.z) ripseq;
              else riploop;

              rip = (rcx.z | t2.z) ? ripseq : riploop;

              orf      t3 = rcx,t2
              br.nz    rip = t3,zero [loop, seq]
            */

            TransOp sub(OP_sub,  REG_rcx,   REG_rcx,    REG_imm,   REG_zero, (ctx.use64 ? 3 : 2), 1, 0, SETFLAG_ZF);     // sub     rcx = rcx,1 [zf internal]
            sub.nouserflags = 1; // it still generates flags, but does not rename the user flags
            this << sub;
            TransOp orxf((rep == PFX_REPZ) ? OP_ornotcc : OP_orcc, REG_temp0, REG_rcx, REG_temp2, REG_zero, (ctx.use64 ? 3 : 2), 0, 0, FLAGS_DEFAULT_ALU);
            orxf.nouserflags = 1;
            this << orxf;
            if (!last_flags_update_was_atomic) 
              this << TransOp(OP_collcc, REG_temp5, REG_temp2, REG_temp2, REG_temp2, 3);
            TransOp br(OP_br, REG_rip, REG_temp0, REG_zero, REG_zero, 3);
            br.cond = COND_ne; // repeat while nonzero
            br.riptaken = (W64)ripstart;
            br.ripseq = (W64)rip;
            this << br;
          }

          break;
        }
        case 0xaa: case 0xab: {
          // stos
          if (rep) assert(rep == PFX_REPZ); // only rep is allowed for movs and rep == repz here
          this << TransOp(OP_st,   REG_mem,   REG_rdi,    REG_zero,  REG_rax, sizeshift);            // stSZ    [rdi] = rax
          TransOp   addop(OP_adda, REG_rdi,   REG_rdi,    REG_zero,  REG_temp3, 3);                  // adda  rdi = rdi,0,t1*SZ
          addop.extshift = sizeshift;
          this << addop;
          if (rep) {
            TransOp sub(OP_sub,  REG_rcx,   REG_rcx,    REG_imm,   REG_zero, (ctx.use64 ? 3 : 2), 1, 0, SETFLAG_ZF);     // sub     rcx = rcx,1 [zf internal]
            sub.nouserflags = 1; // it still generates flags, but does not rename the user flags
            this << sub;
            TransOp br(OP_br, REG_rip, REG_rcx, REG_zero, REG_zero, 3);
            br.cond = COND_ne; // repeat while nonzero
            br.riptaken = (W64)ripstart;
            br.ripseq = (W64)rip;
            this << br;
          }
          break;
        }
        case 0xac ... 0xad: {
          // lods
          if (rep) assert(rep == PFX_REPZ); // only rep is allowed for movs and rep == repz here

          if (sizeshift >= 2) {
            this << TransOp(OP_ld,   REG_rax,   REG_rsi,    REG_zero,  REG_zero, sizeshift);           // ldSZ    rax = [rsi]
          } else {
            this << TransOp(OP_ld,   REG_temp0, REG_rsi,    REG_zero,  REG_zero, sizeshift);           // ldSZ    t0 = [rsi]
            this << TransOp(OP_mov,  REG_rax,   REG_rax,    REG_temp0, REG_zero, sizeshift);           // move    rax = rax,t0 (size adjustment)
          }

          TransOp     addop(OP_adda, REG_rsi,   REG_rsi,    REG_zero,  REG_temp3, 3);                  // adda  rsi = rsi,0,t1*SZ
          addop.extshift = sizeshift;
          this << addop;

          if (rep) {
            TransOp sub(OP_sub,  REG_rcx,   REG_rcx,    REG_imm,   REG_zero, (ctx.use64 ? 3 : 2), 1, 0, SETFLAG_ZF);     // sub     rcx = rcx,1 [zf internal]
            sub.nouserflags = 1; // it still generates flags, but does not rename the user flags
            this << sub;
            TransOp br(OP_br, REG_rip, REG_rcx, REG_zero, REG_zero, 3);
            br.cond = COND_ne; // repeat while nonzero
            br.riptaken = (W64)ripstart;
            br.ripseq = (W64)rip;
            this << br;
          }
          break;
        }
        case 0xae: case 0xaf: {
          // scas
          this << TransOp(OP_ld,   REG_temp1, REG_rdi,    REG_zero,  REG_zero, sizeshift);           // ldSZ    t1 = [rdi]
          TransOp   addop(OP_adda, REG_rdi,   REG_rdi,    REG_zero,  REG_temp3, 3);                  // adda    rdi = rdi,0,t1*SZ
          addop.extshift = sizeshift;
          this << addop;
          this << TransOp(OP_sub,  REG_temp2, REG_temp0,  REG_rax,   REG_zero, sizeshift, 0, 0, FLAGS_DEFAULT_ALU); // sub    t2 = t0,t1 (zco)

          if (rep) {
            TransOp sub(OP_sub,  REG_rcx,   REG_rcx,    REG_imm,   REG_zero, (ctx.use64 ? 3 : 2), 1, 0, SETFLAG_ZF);     // sub     rcx = rcx,1 [zf internal]
            sub.nouserflags = 1; // it still generates flags, but does not rename the user flags
            this << sub;
            TransOp orxf((rep == PFX_REPZ) ? OP_ornotcc : OP_orcc, REG_temp0, REG_rcx, REG_temp2, REG_zero, 3, 0, 0, FLAGS_DEFAULT_ALU);
            orxf.nouserflags = 1;
            this << orxf;
            if (!last_flags_update_was_atomic) 
              this << TransOp(OP_collcc, REG_temp5, REG_temp2, REG_temp2, REG_temp2, 3);
            TransOp br(OP_br, REG_rip, REG_temp0, REG_zero, REG_zero, 3);
            br.cond = COND_ne; // repeat while nonzero
            br.riptaken = (W64)ripstart;
            br.ripseq = (W64)rip;
            this << br;
          }

          break;
        }
        default:
          MakeInvalid();
          break;
        }
        if (rep) end_of_block = 1;
      }
      break;
    }

    case 0xa8 ... 0xa9: {
      // test al|ax,imm8|immV
      rd.gform_ext(*this, (op & 1) ? v_mode : b_mode, REG_rax);
      DECODE(iform, ra, (op & 1) ? v_mode : b_mode);
      CheckInvalid();
      alu_reg_or_mem(OP_and, rd, ra, FLAGS_DEFAULT_ALU, REG_zero, true);
      break;
    }

    case 0xb0 ... 0xb7: {
      // mov reg,imm8
      rd.gform_ext(*this, b_mode, bits(op, 0, 3), false, true);
      DECODE(iform, ra, b_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      this << TransOp(OP_mov, rdreg, rdreg, REG_imm, REG_zero, 0, ra.imm.imm);
      break;
    }
    case 0xb8 ... 0xbf: {
      // mov reg,imm16|imm32|imm64
      rd.gform_ext(*this, v_mode, bits(op, 0, 3), false, true);
      DECODE(iform64, ra, v_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int sizeshift = reginfo[rd.reg.reg].sizeshift;
      this << TransOp(OP_mov, rdreg, (sizeshift >= 2) ? REG_zero : rdreg, REG_imm, REG_zero, sizeshift, ra.imm.imm);
      break;
    }

    case 0xc0 ... 0xc1: 
    case 0xd0 ... 0xd1: 
    case 0xd2 ... 0xd3: {
      /*
        rol ror rcl rcr shl shr shl sar:
        Shifts and rotates, either by an imm8, implied 1, or %cl

        The shift and rotate instructions have some of the most bizarre semantics in the
        entire x86 instruction set: they may or may not modify flags depending on the
        rotation count operand, which we may not even know until the instruction
        issues. The specific rules are as follows:

        - If the count is zero, no flags are modified
        - If the count is one, both OF and CF are modified.
        - If the count is greater than one, only the CF is modified.
          (Technically the value in OF is undefined, but on K8 and P4,
          it retains the old value, so we try to be compatible).
        - Shifts also alter the ZAPS flags while rotates do not.

        For constant counts, this is easy to determine while translating:
        
        op   rd = ra,0       op rd = ra,1              op rd = ra,N
        Becomes:             Becomes:                  Becomes
        (nop)                op rd = ra,1 [set of cf]  op rd = ra,N [set cf]
        
        For variable counts, things are more complex. Since the shift needs
        to determine its output flags at runtime based on both the shift count
        and the input flags (CF, OF, ZAPS), we need to specify the latest versions
        in program order of all the existing flags. However, this would require
        three operands to the shift uop not even counting the value and count
        operands.
        
        Therefore, we use a collcc (collect flags) uop to get all
        the most up to date flags into one result, using three operands for
        ZAPS, CF, OF. This forms a zero word with all the correct flags
        attached, which is then forwarded as the rc operand to the shift.
        
        This may add additional scheduling constraints in the case that one
        of the operands to the shift itself sets the flags, but this is
        fairly rare (generally the shift amount is read from a table and
        loads don't generate flags.
        
        Conveniently, this also lets us directly implement the 65-bit
        rcl/rcr uops in hardware with little additional complexity.
        
        Example:
        
        shl         rd,rc
        
        Becomes:
        
        collcc       t0 = zf,cf,of
        sll<size>   rd = rd,rc,t0

      */

      DECODE(eform, rd, bit(op, 0) ? v_mode : b_mode);
      if (inrange(op, 0xc0, 0xc1)) {
        // byte immediate
        DECODE(iform, ra, b_mode);
      } else if (inrange(op, 0xd0, 0xd1)) {
        ra.type = OPTYPE_IMM;
        ra.imm.imm = 1;
      } else {
        ra.type = OPTYPE_REG;
        ra.reg.reg = APR_cl;
      }

      // Mask off the appropriate number of immediate bits:
      int size = (rd.type == OPTYPE_REG) ? reginfo[rd.reg.reg].sizeshift : rd.mem.size;
      ra.imm.imm = bits(ra.imm.imm, 0, (size == 3) ? 6 : 5);
      int count = ra.imm.imm;

      bool isrot = (bit(modrm.reg, 2) == 0);

      //
      // Variable rotations always set all the flags, possibly merging them with some
      // of the earlier flag values in program order depending on the count. Otherwise
      // the static count (0, 1, >1) determines which flags are set.
      //
      W32 setflags = (ra.type == OPTYPE_REG) ? FLAGS_DEFAULT_ALU : (!count) ? 0 : // count == 0
        (count == 1) ? (isrot ? (SETFLAG_OF|SETFLAG_CF) : (SETFLAG_ZF|SETFLAG_OF|SETFLAG_CF)) : // count == 1
        (isrot ? (SETFLAG_CF) : (SETFLAG_ZF|SETFLAG_CF)); // count > 1

      static const byte translate_opcode[8] = {OP_rotl, OP_rotr, OP_rotcl, OP_rotcr, OP_shl, OP_shr, OP_shl, OP_sar};
      int translated_opcode = translate_opcode[modrm.reg];

      CheckInvalid();

      // Generate the flag collect uop here:
      if (ra.type == OPTYPE_REG) {
        this << TransOp(OP_collcc, REG_temp5, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
      }
      int rcreg = (ra.type == OPTYPE_REG) ? REG_temp5 : (translated_opcode == OP_rotcl || translated_opcode == OP_rotcr) ? REG_cf : REG_zero;

      alu_reg_or_mem(translated_opcode, rd, ra, setflags, rcreg);

      break;
    }

    case 0xc2 ... 0xc3: {
      // ret near, with and without pop count
      int addend = 0;
      if (op == 0xc2) {
        DECODE(iform, ra, w_mode);
        addend = (W16)ra.imm.imm;
      }

      int sizeshift = (ctx.use64) ? ((sizeflag & DFLAG) ? 3 : 1) : ((sizeflag & DFLAG) ? 2 : 1);
      int size = (1 << sizeshift);
      addend = size + addend;

      CheckInvalid();

      this << TransOp(OP_ld, REG_temp7, REG_rsp, REG_zero, REG_zero, sizeshift);
      this << TransOp(OP_add, REG_rsp, REG_rsp, REG_imm, REG_zero, 3, addend);
      if (!last_flags_update_was_atomic)
        this << TransOp(OP_collcc, REG_temp5, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
      TransOp jmp(OP_jmp, REG_rip, REG_temp7, REG_zero, REG_zero, 3);
      jmp.extshift = BRANCH_HINT_POP_RAS;
      this << jmp;

      end_of_block = true;

      break;
    }

    case 0xc4 ... 0xc5: {
      // les lds (not supported)
      MakeInvalid();
      break;
    }

    case 0xc6 ... 0xc7: {
      // move reg_or_mem,imm8|imm16|imm32|imm64 (signed imm for 32-bit to 64-bit form)
      int bytemode = bit(op, 0) ? v_mode : b_mode;
      DECODE(eform, rd, bytemode); DECODE(iform, ra, bytemode);
      CheckInvalid();
      move_reg_or_mem(rd, ra);
      break;
    }

    case 0xc8: {
      // enter imm16,imm8
      // Format: 0xc8 imm16 imm8
      DECODE(iform, rd, w_mode);
      DECODE(iform, ra, b_mode);
      int bytes = (W16)rd.imm.imm;
      int level = (byte)ra.imm.imm;
      // we only support nesting level 0
      if (level != 0) invalid |= true;

      CheckInvalid();

      int sizeshift = (ctx.use64) ? ((sizeflag & DFLAG) ? 3 : 1) : ((sizeflag & DFLAG) ? 2 : 1);

      // Exactly equivalent to:
      // push %rbp
      // mov %rbp,%rsp
      // sub %rsp,imm8
      this << TransOp(OP_sub, REG_rsp, REG_rsp, REG_imm, REG_zero, 3, (1 << sizeshift));
      this << TransOp(OP_st, REG_mem, REG_rsp, REG_zero, REG_rbp, sizeshift);
      this << TransOp(OP_mov, REG_rbp, REG_zero, REG_rsp, REG_zero, sizeshift);
      this << TransOp(OP_sub, REG_rsp, REG_rsp, REG_imm, REG_zero, sizeshift, bytes);
      break;
    }

    case 0xc9: {
      // leave
      int sizeshift = (ctx.use64) ? ((sizeflag & DFLAG) ? 3 : 1) : ((sizeflag & DFLAG) ? 2 : 1);
      // Exactly equivalent to:
      // mov %rsp,%rbp
      // pop %rbp
      this << TransOp(OP_mov, REG_rsp, REG_zero, REG_rbp, REG_zero, sizeshift);
      this << TransOp(OP_ld, REG_rbp, REG_rsp, REG_zero, REG_zero, sizeshift);
      this << TransOp(OP_add, REG_rsp, REG_rsp, REG_imm, REG_zero, 3, (1 << sizeshift));
      break;
    }

    case 0xca ... 0xcb: {
      // ret far, with and without pop count (not supported)
      MakeInvalid();
      break;
    }

    case 0xcc: {
      // INT3 (breakpoint)
      immediate(REG_sr2, 3, 0);
      microcode_assist(ASSIST_INT, ripstart, rip);
      end_of_block = 1;
      break;
    }

    case 0xcd: {
      // int imm8
      DECODE(iform, ra, b_mode);
      CheckInvalid();
      immediate(REG_sr2, ra.imm.imm & 0xff, 0);
      microcode_assist(ASSIST_INT, ripstart, rip);
      end_of_block = 1;
      break;
    }

    case 0xce: {
      // INTO
      MakeInvalid();
      break;
    }

    case 0xcf: {
      // IRET
      MakeInvalid();
      break;
    }

    case 0xd4 ... 0xd6: {
      // aam/aad/salc (invalid in 64-bit mode anyway)
      MakeInvalid();
      break;
    }

    case 0xd7: {
      // xlat
      // (not used by gcc)
      MakeInvalid();
      break;
    }

      //
      // x87 floating point
      //
      // op = 0x600 | (lowbits(op, 3) << 4) | modrm.reg;
      //
      // 0x600 (0xd8): fadd fmul fcom fcomp fsub fsubr fdiv fdivr 
      // 0x610 (0xd9): fld32 inv fst fstp fldenv fldcw fnstenv fnstcw
      // | (if mod=11) fldreg fxch fnop (n/a) [fchs|fabs|ftst|fxam] fldCONST [f2xm1 fyl2x fptan tpatan fxtract fprem1 fdecstp fincstp] [fprem fyl2xp1 fsqrt fsincos frndint fscale fsin fcos]
      // 0x620 (0xda): fcmovb fcmove fcmovbe fcmovu (inv) (inv|fucompp) (inv) (inv)
      // 0x630 (0xdb): fcmovnb fcmovne fcmovnbe fcmovnu (inv|fnclex|fninit) fucomi fcomi (inv)
      // 0x640 (0xdc): fadd fmul fcom fcomp fsub fsubr fdiv fdivr
      // 0x650 (0xdd): fld64 fisttp fst fstp frstor inv fnsave fnstsw / (if mod=11) ffree (inv) fst fstp fucom fucomp (inv) (inv)
      // 0x660 (0xde): faddp fmulp (inv) (inv) fsubrp fsubp fdivrp fdivp [or fixxx for !11]
      // 0x670 (0xdf): fild fisttp fist fistp fbld fild fbstp fistp
      //

      /*
        ++MTY TODO: support full x87 FP
    case 0x600 .. 0x607: { // fOP mem32 or fOP reg
      if (modrm.mod == 3) {
        // replace st(0) with st(0) OP st(modrm.rm):
        TransOp ldp0(OP_ld, REG_temp1, REG_fptos, REG_imm, REG_zero, 3, (W64)&fpregs); ldp0.internal = 1; this << ldp0;
        this << TransOp(OP_addm, REG_temp0, REG_fptos, REG_imm, REG_imm, 3, 8*modrm.rm, 6);
        TransOp ldp1(OP_ld, REG_temp0, REG_temp0, REG_imm, REG_zero, 3, (W64)&fpregs); ldp1.internal = 1; this << ldp1;

        // fadd fmul fcom fcomp fsub fsubr fdiv fdivr
        static const int translate_opcode[8] = {OP_addf, OP_mulf, OP_cmpf, OP_fcmp, OP_sub, OP_sub, OP_xor, OP_sub};
        int translated_opcode = translate_opcode[modrm.reg];


        this << TransOp(OP_subm, REG_fptos, REG_fptos, REG_imm, REG_imm, 3, 8, 6); // push stack
        TransOp stp(OP_st, REG_mem, REG_fptos, REG_imm, REG_temp0, 3, (W64)&fpregs); stp.internal = 1; this << stp;
        this << TransOp(OP_bts, REG_fptags, REG_fptags, REG_fptos, REG_zero, 3);
      } else {
        // load from memory
        // ldd          t0 = [mem]
        // fcvt.s2d.lo  t0 = t0
        // st.lm.p      [FPREGS + fptos],t0
        // subm         fptos = fptos,8,6
        DECODE(eform, ra, d_mode);
        CheckInvalid();
        operand_load(REG_temp0, ra, OP_ld, 1);
        this << TransOp(OP_cvtf_s2d_lo, REG_temp0, REG_temp0, REG_zero, REG_zero, 3);
        this << TransOp(OP_subm, REG_fptos, REG_fptos, REG_imm, REG_imm, 3, 8, 6); // push stack
        TransOp stp(OP_st, REG_mem, REG_fptos, REG_imm, REG_temp0, 3, (W64)&fpregs); stp.internal = 1; this << stp;
        this << TransOp(OP_bts, REG_fptags, REG_fptags, REG_fptos, REG_zero, 3);
      }
      break;
    }
      */

    case 0x610: { // fld mem32 or fld reg
      if (modrm.mod == 3) {
        // load from FP stack register
        this << TransOp(OP_addm, REG_temp0, REG_fptos, REG_imm, REG_imm, 3, 8*modrm.rm, 6);
        TransOp ldp(OP_ld, REG_temp0, REG_temp0, REG_imm, REG_zero, 3, (W64)&fpregs); ldp.internal = 1; this << ldp;
        this << TransOp(OP_subm, REG_fptos, REG_fptos, REG_imm, REG_imm, 3, 8, 6); // push stack
        TransOp stp(OP_st, REG_mem, REG_fptos, REG_imm, REG_temp0, 3, (W64)&fpregs); stp.internal = 1; this << stp;
        this << TransOp(OP_bts, REG_fptags, REG_fptags, REG_fptos, REG_zero, 3);
      } else {
        // load from memory
        // ldd          t0 = [mem]
        // fcvt.s2d.lo  t0 = t0
        // st.lm.p      [FPREGS + fptos],t0
        // subm         fptos = fptos,8,6
        DECODE(eform, ra, d_mode);
        CheckInvalid();
        operand_load(REG_temp0, ra, OP_ld, 1);
        this << TransOp(OP_cvtf_s2d_lo, REG_temp0, REG_temp0, REG_zero, REG_zero, 3);
        this << TransOp(OP_subm, REG_fptos, REG_fptos, REG_imm, REG_imm, 3, 8, 6); // push stack
        TransOp stp(OP_st, REG_mem, REG_fptos, REG_imm, REG_temp0, 3, (W64)&fpregs); stp.internal = 1; this << stp;
        this << TransOp(OP_bts, REG_fptags, REG_fptags, REG_fptos, REG_zero, 3);
      }
      break;
    }

    case 0x650: { // fld mem64 or ffree
      if (modrm.mod == 3) {
        // ffree (just clear tag bit)
        this << TransOp(OP_btr, REG_fptags, REG_fptags, REG_fptos, REG_zero, 3);
      } else {
        // load from memory
        // ldq          t0 = [mem]
        // st.lm.p      [FPREGS + fptos],t0
        // subm         fptos = fptos,8,6
        DECODE(eform, ra, q_mode);
        CheckInvalid();
        operand_load(REG_temp0, ra, OP_ld, 1);
        this << TransOp(OP_subm, REG_fptos, REG_fptos, REG_imm, REG_imm, 3, 8, 6); // push stack
        TransOp stp(OP_st, REG_mem, REG_fptos, REG_imm, REG_temp0, 3, (W64)&fpregs); stp.internal = 1; this << stp;
        this << TransOp(OP_bts, REG_fptags, REG_fptags, REG_fptos, REG_zero, 3);
      }
      break;
    }

    case 0x612:
    case 0x613: { // fst/fstp mem32 or fnop
      if (modrm.mod == 0x3) {
        // fnop
        this << TransOp(OP_nop, REG_temp0, REG_zero, REG_zero, REG_zero, 3);
      } else {
        // store st0 to memory
        // ldd          t0 = [mem]
        // fcvt.s2d.lo  t0 = t0
        // st.lm.p      [FPREGS + fptos],t0
        // subm         fptos = fptos,8,6
        DECODE(eform, rd, d_mode);
        CheckInvalid();
        TransOp ldp(OP_ld, REG_temp0, REG_fptos, REG_imm, REG_zero, 3, (W64)&fpregs); ldp.internal = 1; this << ldp;
        this << TransOp(OP_cvtf_d2s_ins, REG_temp0, REG_zero, REG_temp0, REG_zero, 3);
        result_store(REG_temp0, REG_temp1, rd);

        if (bit(op, 0)) {
          this << TransOp(OP_btr, REG_fptags, REG_fptags, REG_fptos, REG_zero, 3); // pop: adjust tag word
          this << TransOp(OP_addm, REG_fptos, REG_fptos, REG_imm, REG_imm, 3, 8, 6); // pop: fstp
        }
      }
      break;
    }

    case 0x652:
    case 0x653: { // fst/fstp mem64 or fst st(0) to FP stack reg
      if (modrm.mod == 0x3) {
        // fst st(0) to FP stack reg
        this << TransOp(OP_addm, REG_temp1, REG_fptos, REG_imm, REG_imm, 3, 8*modrm.rm, 6);

        TransOp ldp(OP_ld, REG_temp0, REG_fptos, REG_imm, REG_zero, 3, (W64)&fpregs); ldp.internal = 1; this << ldp;
        TransOp stp(OP_st, REG_mem, REG_temp1, REG_imm, REG_temp0, 3, (W64)&fpregs); stp.internal = 1; this << stp;

        if (bit(op, 0)) this << TransOp(OP_addm, REG_fptos, REG_fptos, REG_imm, REG_imm, 3, 8, 6); // pop: fstp
      } else {
        // store st0 to memory
        // ldd          t0 = [mem]
        // fcvt.s2d.lo  t0 = t0
        // st.lm.p      [FPREGS + fptos],t0
        // subm         fptos = fptos,8,6
        DECODE(eform, rd, q_mode);
        CheckInvalid();

        TransOp ldp(OP_ld, REG_temp0, REG_fptos, REG_imm, REG_zero, 3, (W64)&fpregs);
        ldp.internal = 1;
        this << ldp;
        result_store(REG_temp0, REG_temp1, rd);

        if (bit(op, 0)) {
          this << TransOp(OP_btr, REG_fptags, REG_fptags, REG_fptos, REG_zero, 3); // pop: adjust tag word
          this << TransOp(OP_addm, REG_fptos, REG_fptos, REG_imm, REG_imm, 3, 8, 6); // pop: fstp
        }
      }
      break;
    }

    case 0x611: { // fxch
      if (modrm.mod == 0x3) {
        // load from FP stack register
        this << TransOp(OP_addm, REG_temp2, REG_fptos, REG_imm, REG_imm, 3, 8*modrm.rm, 6);
        TransOp ldptos(OP_ld, REG_temp0, REG_fptos, REG_imm, REG_zero, 3, (W64)&fpregs); ldptos.internal = 1; this << ldptos;
        TransOp ldpalt(OP_ld, REG_temp1, REG_temp2, REG_imm, REG_zero, 3, (W64)&fpregs); ldpalt.internal = 1; this << ldpalt;

        TransOp stptos(OP_st, REG_mem,   REG_fptos, REG_imm, REG_temp1, 3, (W64)&fpregs); stptos.internal = 1; this << stptos;
        TransOp stpalt(OP_st, REG_mem,   REG_temp2, REG_imm, REG_temp0, 3, (W64)&fpregs); stpalt.internal = 1; this << stpalt;
      } else {
        MakeInvalid();
      }
      break;
    }

    case 0x615: { // fldCONST
      if (modrm.mod == 0x3) {
        // fld1 fld2t fldl2e fldpi fldlg2 fldln2 fldz (inv):
        static const double constants[8] = {1.0, 3.3219280948873623479, 1.4426950408889634074, 3.1415926535897932385, .30102999566398119521, .69314718055994530942, 0, 0};
        // load from constant
        this << TransOp(OP_mov, REG_temp0, REG_zero, REG_imm, REG_zero, 3, ((W64*)&constants)[modrm.rm]);
        this << TransOp(OP_subm, REG_fptos, REG_fptos, REG_imm, REG_imm, 3, 8, 6); // push stack
        TransOp stp(OP_st, REG_mem, REG_fptos, REG_imm, REG_temp0, 3, (W64)&fpregs); stp.internal = 1; this << stp;
        this << TransOp(OP_bts, REG_fptags, REG_fptags, REG_fptos, REG_zero, 3); // push: set used bit in tag word
      } else {
        // fldcw
        MakeInvalid();
      }
      break;
    }

    case 0x670: { // ffreep (free and pop: not documented but widely used)
      if (modrm.mod == 0x3) {
        // ffreep
        this << TransOp(OP_btr, REG_fptags, REG_fptags, REG_fptos, REG_zero, 3); // pop: clear used bit in tag word
        this << TransOp(OP_addm, REG_fptos, REG_fptos, REG_imm, REG_imm, 3, 8, 6); // pop
      } else {
        // fild mem16
        // ldxw         t0 = [mem]
        // fcvt.q2d.lo  t0 = t0
        // st.lm.p      [FPREGS + fptos],t0
        // subm         fptos = fptos,8,6
        // bts          fptags = fptags,fptos
        DECODE(eform, ra, w_mode);
        CheckInvalid();
        operand_load(REG_temp0, ra, OP_ldx, 1);
        this << TransOp(OP_cvtf_q2d, REG_temp0, REG_temp0, REG_zero, REG_zero, 3);
        this << TransOp(OP_subm, REG_fptos, REG_fptos, REG_imm, REG_imm, 3, 8, 6); // push stack
        TransOp stp(OP_st, REG_mem, REG_fptos, REG_imm, REG_temp0, 3, (W64)&fpregs); stp.internal = 1; this << stp;
        this << TransOp(OP_bts, REG_fptags, REG_fptags, REG_fptos, REG_zero, 3);
      }
      break;
    }

    case 0x614: { // fchs fabs ? ? ftst fxam ? ?
      if (modrm.mod != 3) MakeInvalid();

      switch (modrm.rm) {
      case 0: { // fchs
        TransOp ldp(OP_ld, REG_temp0, REG_fptos, REG_imm, REG_zero, 3, (W64)&fpregs); ldp.internal = 1; this << ldp;
        this << TransOp(OP_xor, REG_temp0, REG_temp0, REG_imm, REG_zero, 3, (1LL << 63)); break;
      } 
      case 1: { // fabs
        TransOp ldp(OP_ld, REG_temp0, REG_fptos, REG_imm, REG_zero, 3, (W64)&fpregs); ldp.internal = 1; this << ldp;
        this << TransOp(OP_and, REG_temp0, REG_temp0, REG_imm, REG_zero, 3, ~(1LL << 63)); break;
      }
      default:
        MakeInvalid();
        break;
      }
      TransOp stp(OP_st, REG_mem, REG_fptos, REG_imm, REG_temp0, 3, (W64)&fpregs); stp.internal = 1; this << stp;
      break;
    }

    case 0x620 ... 0x623: // fcmovb fcmove fcmovbe fcmovu
    case 0x630 ... 0x633: { // fcmovnb fcmovne fcmovnbe fcmovnu
      if (modrm.mod != 3) {
        // fild mem32
        // ldxd         t0 = [mem]
        // fcvt.q2d.lo  t0 = t0
        // st.lm.p      [FPREGS + fptos],t0
        // subm         fptos = fptos,8,6
        // bts          fptags = fptags,fptos
        DECODE(eform, ra, d_mode);
        CheckInvalid();
        operand_load(REG_temp0, ra, OP_ldx, 1);

        this << TransOp(OP_cvtf_q2d, REG_temp0, REG_temp0, REG_zero, REG_zero, 3);
        this << TransOp(OP_subm, REG_fptos, REG_fptos, REG_imm, REG_imm, 3, 8, 6); // push stack
        TransOp stp(OP_st, REG_mem, REG_fptos, REG_imm, REG_temp0, 3, (W64)&fpregs); stp.internal = 1; this << stp;
        this << TransOp(OP_bts, REG_fptags, REG_fptags, REG_fptos, REG_zero, 3);
      } else {
        // fcmovCC
        this << TransOp(OP_addm, REG_temp1, REG_fptos, REG_imm, REG_imm, 3, 8*modrm.rm, 6);
        TransOp ldp0(OP_ld, REG_temp0, REG_fptos, REG_imm, REG_zero, 3, (W64)&fpregs); ldp0.internal = 1; this << ldp0;
        TransOp ldp1(OP_ld, REG_temp1, REG_temp1, REG_imm, REG_zero, 3, (W64)&fpregs); ldp1.internal = 1; this << ldp1;
        
        int cmptype = lowbits(op, 2);
        int rcond;
        int cond;
        bool invert = ((op & 0xff0) == 0x630);
        
        switch (lowbits(op, 2)) {
        case 0: // fcmovb (CF = 1)
          rcond = REG_cf;
          cond = (invert) ? COND_nc : COND_c;
          break;
        case 1: // fcmove (ZF = 1)
          rcond = REG_zf;
          cond = (invert) ? COND_ne : COND_e;
          break;
        case 2: // fcmovbe (ZF = 1 or CF = 1)
          this << TransOp(OP_collcc, REG_temp2, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
          cond = (invert) ? COND_nbe : COND_be;
          rcond = REG_temp2;
          break;
        case 3: // fcmovu (PF = 1)
          this << TransOp(OP_collcc, REG_temp2, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
          cond = (invert) ? COND_np : COND_p;
          rcond = REG_temp2;
          break;
        }
        
        TransOp sel(OP_sel, REG_temp0, rcond, REG_temp0, REG_temp1, 3);
        sel.cond = cond;
        this << sel;
        
        TransOp stp(OP_st, REG_mem, REG_fptos, REG_imm, REG_temp0, 3, (W64)&fpregs);
        stp.internal = 1;
        this << stp;
      }
      break;
    }

    case 0x635: // fucomi
    case 0x636: // fcomi
    case 0x675: // fucomip
    case 0x676: { // fcomip
      if ((op == 0x675) && (modrm.mod != 3)) {
        // fild mem64
        // ldq          t0 = [mem]
        // fcvt.q2d.lo  t0 = t0
        // st.lm.p      [FPREGS + fptos],t0
        // subm         fptos = fptos,8,6
        // bts          fptags = fptags,fptos
        DECODE(eform, ra, q_mode);
        CheckInvalid();
        operand_load(REG_temp0, ra, OP_ldx, 1);
        this << TransOp(OP_cvtf_q2d, REG_temp0, REG_temp0, REG_zero, REG_zero, 3);
        this << TransOp(OP_subm, REG_fptos, REG_fptos, REG_imm, REG_imm, 3, 8, 6); // push stack
        TransOp stp(OP_st, REG_mem, REG_fptos, REG_imm, REG_temp0, 3, (W64)&fpregs); stp.internal = 1; this << stp;
        this << TransOp(OP_bts, REG_fptags, REG_fptags, REG_fptos, REG_zero, 3);
      } else {
        //
        // For cmpccf, uop.size bits have following meaning:
        // 00 = single precision ordered compare
        // 01 = single precision unordered compare
        // 10 = double precision ordered compare
        // 11 = double precision unordered compare
        //
        this << TransOp(OP_addm, REG_temp1, REG_fptos, REG_imm, REG_imm, 3, 8*modrm.rm, 6);
        TransOp ldp0(OP_ld, REG_temp0, REG_fptos, REG_imm, REG_zero, 3, (W64)&fpregs); ldp0.internal = 1; this << ldp0;
        TransOp ldp1(OP_ld, REG_temp1, REG_temp1, REG_imm, REG_zero, 3, (W64)&fpregs); ldp1.internal = 1; this << ldp1;
        
        //
        // comisX and ucomisX set {zf pf cf} according to the comparison,
        // and always set {of sf af} to zero. The equivalent x87 version 
        // is fucomi/fcomi/fucomip/fcomip:
        //
        bool unordered = bit(op, 0);
        this << TransOp(OP_cmpccf, REG_temp0, REG_temp0, REG_temp1, REG_zero, (unordered ? 3 : 2), 0, 0, FLAGS_DEFAULT_ALU);
        
        if (bit(op, 0)) {
          this << TransOp(OP_btr, REG_fptags, REG_fptags, REG_fptos, REG_zero, 3); // pop: adjust tag word
          this << TransOp(OP_addm, REG_fptos, REG_fptos, REG_imm, REG_imm, 3, 8, 6); // pop: fstp
        }
      }
      break;
    }
    case 0xd8 ... 0xdf: {
      // x87 legacy FP
      // already handled as 0x6xx pseudo-opcodes

      MakeInvalid();
      break;
    }

    case 0xe0 ... 0xe3: {
      // loopne loope loop jcxz
      MakeInvalid();
      break;
    };

    case 0xe4 ... 0xe7: {
      // inb/inw/outb/outw imm8/imm16: NOT SUPPORTED
      MakeInvalid();
      assert(false);
    }

    case 0xe8:
    case 0xe9:
    case 0xeb: {
      bool iscall = (op == 0xe8);
      // CALL or JMP rel16/rel32/rel64
      // near conditional branches with 8-bit displacement:
      DECODE(iform, ra, (op == 0xeb) ? b_mode : v_mode);
      CheckInvalid();

      bb.rip_taken = (W64)rip + (W64s)ra.imm.imm;
      bb.rip_not_taken = bb.rip_taken;

      int sizeshift = (ctx.use64) ? 3 : 2;

      if (iscall) {
        immediate(REG_temp0, 3, (W64)rip);
        this << TransOp(OP_sub, REG_rsp, REG_rsp, REG_imm, REG_zero, sizeshift, (1 << sizeshift));
        this << TransOp(OP_st, REG_mem, REG_rsp, REG_zero, REG_temp0, sizeshift);
      }

      if (!last_flags_update_was_atomic)
        this << TransOp(OP_collcc, REG_temp0, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
      TransOp transop(OP_bru, REG_rip, REG_zero, REG_zero, REG_zero, 3);
      transop.extshift = (iscall) ? BRANCH_HINT_PUSH_RAS : 0;
      transop.riptaken = (W64)rip + (W64s)ra.imm.imm;
      transop.ripseq = (W64)rip + (W64s)ra.imm.imm;
      this << transop;

      end_of_block = true;
      break;
    }

    case 0xec ... 0xef: {
      // inb/inw/outb/outw ax,edx: NOT SUPPORTED
      MakeInvalid();
      break;
    }

    case 0xf0 ... 0xf3: {
      // (prefixes: lock icebrkpt repne repe)
      MakeInvalid();
      break;
    }

    case 0xf4: {
      // hlt (nop)
      this << TransOp(OP_nop, REG_temp0, REG_zero, REG_zero, REG_zero, 3);
      break;
    }
    case 0xf5: {
      // cmc
      // TransOp(int opcode, int rd, int ra, int rb, int rc, int size, W64s rbimm = 0, W64s rcimm = 0, W32 setflags = 0)
      this << TransOp(OP_xorcc, REG_temp0, REG_cf, REG_imm, REG_zero, 3, FLAG_CF, 0, SETFLAG_CF);
      break;
    }
    case 0xf6 ... 0xf7: {
      // GRP3b and GRP3S
      DECODE(eform, rd, (op & 1) ? v_mode : b_mode);
      CheckInvalid();

      switch (modrm.reg) {
      case 0: // test
        DECODE(iform, ra, (op & 1) ? v_mode : b_mode);
        alu_reg_or_mem(OP_and, rd, ra, FLAGS_DEFAULT_ALU, REG_zero, true);
        break;
      case 1: // (invalid)
        MakeInvalid();
        break;
      case 2: { // not
        // As an exception to the rule, NOT does not generate any flags. Go figure.
        alu_reg_or_mem(OP_nor, rd, rd, 0, REG_zero);
        break;
      }
      case 3: { // neg r1 => sub r1 = 0, r1
        alu_reg_or_mem(OP_sub, rd, rd, FLAGS_DEFAULT_ALU, REG_zero, false, true);
        break;
      }
        //
        // NOTE: gcc does not synthesize these forms of imul since they target both %rdx:%rax.
        // However, it DOES use idiv in this form, so we need to implement it. Probably a microcode
        // callout would be appropriate here: first get the operand into some known register,
        // then encode a microcode callout.
        //
      default:
        ra.type = OPTYPE_REG;
        ra.reg.reg = 0; // not used
        move_reg_or_mem(ra, rd, REG_sr2);

        int subop_and_size_to_assist_idx[4][4] = {
          {ASSIST_MUL8,  ASSIST_MUL16,  ASSIST_MUL32,  ASSIST_MUL64},
          {ASSIST_IMUL8, ASSIST_IMUL16, ASSIST_IMUL32, ASSIST_IMUL64},
          {ASSIST_DIV8,  ASSIST_DIV16,  ASSIST_DIV32,  ASSIST_DIV64},
          {ASSIST_IDIV8, ASSIST_IDIV16, ASSIST_IDIV32, ASSIST_IDIV64}
        };

        int size = (rd.type == OPTYPE_REG) ? reginfo[rd.reg.reg].sizeshift : rd.mem.size;

        microcode_assist(subop_and_size_to_assist_idx[modrm.reg - 4][size], ripstart, rip);
        end_of_block = 1;
        //++MTY FIXME We need to handle getting the result back into the correct output
        // register when it's ah/bh/ch/dh.
      }
      break;
    }

    case 0xf8: { // clc
      this << TransOp(OP_andcc, REG_temp0, REG_zero, REG_zero, REG_zero, 3, 0, 0, SETFLAG_CF);
      break;
    }
    case 0xf9: { // stc
      this << TransOp(OP_orcc, REG_temp0, REG_zero, REG_imm, REG_zero, 3, FLAG_CF, 0, SETFLAG_CF);
      break;
    }
    case 0xfa: { // cli
      // (nop)
      // NOTE! We still have to output something so %rip gets incremented correctly!
      this << TransOp(OP_nop, REG_temp0, REG_zero, REG_zero, REG_zero, 3);
      break;
    }
    case 0xfb: { // sti
      // (nop)
      // NOTE! We still have to output something so %rip gets incremented correctly!
      this << TransOp(OP_nop, REG_temp0, REG_zero, REG_zero, REG_zero, 3);
      break;
    }
    case 0xfc: { // cld
      // bit 63 of mxcsr is the direction flag:
      this << TransOp(OP_and, REG_mxcsr, REG_mxcsr, REG_imm, REG_zero, 3, (W64)~(1LL<<63));
      break;
    }
    case 0xfd: { // std
      // bit 63 of mxcsr is the direction flag:
      this << TransOp(OP_or, REG_mxcsr, REG_mxcsr, REG_imm, REG_zero, 3, (W64)(1LL<<63));
      //assert(false);
      break;
    }

    case 0xfe: {
      // Group 4: inc/dec Eb in register or memory
      // Increments are unusual in that they do NOT update CF.
      DECODE(eform, rd, b_mode);
      CheckInvalid();
      ra.type = OPTYPE_IMM;
      ra.imm.imm = (bit(modrm.reg, 0)) ? -1 : +1;
      alu_reg_or_mem(OP_add, rd, ra, SETFLAG_ZF|SETFLAG_OF, REG_zero);
      break;
    }

    case 0xff: {
      switch (modrm.reg) {
      case 0:
      case 1: {
        // inc/dec Ev in register or memory
        // Increments are unusual in that they do NOT update CF.
        DECODE(eform, rd, v_mode);
        CheckInvalid();
        ra.type = OPTYPE_IMM;
        ra.imm.imm = (bit(modrm.reg, 0)) ? -1 : +1;
        alu_reg_or_mem(OP_add, rd, ra, SETFLAG_ZF|SETFLAG_OF, REG_zero);
        break;
      }
      case 2:
      case 4: {
        bool iscall = (modrm.reg == 2);
        // call near Ev
        DECODE(eform, ra, v_mode);
        if (DEBUG) logfile << ra, endl;
        CheckInvalid();
        // destination unknown:
        bb.rip_taken = 0;
        bb.rip_not_taken = 0;

        if (!last_flags_update_was_atomic)
          this << TransOp(OP_collcc, REG_temp0, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);

        int sizeshift = (ctx.use64) ? 3 : 2;
        if (ra.type == OPTYPE_REG) {
          int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
          int rashift = reginfo[ra.reg.reg].sizeshift;
          // there is no way to encode a 32-bit jump address in x86-64 mode:
          if (ctx.use64 && (rashift == 2)) rashift = 3;
          if (iscall) {
            immediate(REG_temp6, 3, (W64)rip);
            this << TransOp(OP_sub, REG_rsp, REG_rsp, REG_imm, REG_zero, sizeshift, 1 << sizeshift);
            this << TransOp(OP_st, REG_mem, REG_rsp, REG_zero, REG_temp6, sizeshift);
          }
          // We do not know the taken or not-taken directions yet so just leave them as zero:
          TransOp transop(OP_jmp, REG_rip, rareg, REG_zero, REG_zero, rashift);
          transop.extshift = (iscall) ? BRANCH_HINT_PUSH_RAS : 0;
          this << transop;
        } else if (ra.type == OPTYPE_MEM) {
          // there is no way to encode a 32-bit jump address in x86-64 mode:
          if (ctx.use64 && (ra.mem.size == 2)) ra.mem.size = 3;
          operand_load(REG_temp0, ra);
          if (iscall) {
            immediate(REG_temp6, 3, (W64)rip);
            this << TransOp(OP_sub, REG_rsp, REG_rsp, REG_imm, REG_zero, sizeshift, 1 << sizeshift);
            this << TransOp(OP_st, REG_mem, REG_rsp, REG_zero, REG_temp6, sizeshift);
          }
          // We do not know the taken or not-taken directions yet so just leave them as zero:
          TransOp transop(OP_jmp, REG_rip, REG_temp0, REG_zero, REG_zero, ra.mem.size);
          transop.extshift = (iscall) ? BRANCH_HINT_PUSH_RAS : 0;
          this << transop;
        }

        end_of_block = true;
        break;
      }
      case 6: {
        // push Ev: push reg or memory
        DECODE(eform, ra, v_mode);
        CheckInvalid();
        rd.type = OPTYPE_REG;
        rd.reg.reg = 0; // not used
        // There is no way to encode 32-bit pushes and pops in 64-bit mode:
        if (ctx.use64 && ra.type == OPTYPE_MEM && ra.mem.size == 2) ra.mem.size = 3;
        move_reg_or_mem(rd, ra, REG_temp7);

        int sizeshift = (ra.type == OPTYPE_REG) ? reginfo[ra.reg.reg].sizeshift : ra.mem.size;
        if (ctx.use64 && sizeshift == 2) sizeshift = 3; // There is no way to encode 32-bit pushes and pops in 64-bit mode:
        this << TransOp(OP_sub, REG_rsp, REG_rsp, REG_imm, REG_zero, (ctx.use64 ? 3 : 2), (1 << sizeshift));
        this << TransOp(OP_st, REG_mem, REG_rsp, REG_zero, REG_temp7, sizeshift);

        break;
      }
      default:
        MakeInvalid();
        break;
      }
      break;
    }
      /*
    case 0x120 ... 0x123:
      // moves to/from CRx or DRx (not supported)
      break;
    }
      */

    case 0x140 ... 0x14f: {
      // cmov: conditional moves
      DECODE(gform, rd, v_mode);
      DECODE(eform, ra, v_mode);
      CheckInvalid();

      int srcreg;
      int destreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int sizeshift = reginfo[rd.reg.reg].sizeshift;

      if (ra.type == OPTYPE_REG) {
        srcreg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      } else {
        assert(ra.type == OPTYPE_MEM);
        operand_load(REG_temp7, ra);
        srcreg = REG_temp7;
      }

      int condcode = bits(op, 0, 4);
      const CondCodeToFlagRegs& cctfr = cond_code_to_flag_regs[condcode];

      int condreg;
      if (cctfr.req2) {
        this << TransOp(OP_collcc, REG_temp0, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
        condreg = REG_temp0;
      } else {
        condreg = (cctfr.ra != REG_zero) ? cctfr.ra : cctfr.rb;
      }
      assert(condreg != REG_zero);

      TransOp transop(OP_sel, destreg, condreg, destreg, srcreg, sizeshift);
      transop.cond = condcode;
      this << transop, endl;
      break;
    }

    case 0x190 ... 0x19f: {
      // conditional sets
      DECODE(eform, rd, v_mode);
      CheckInvalid();

      int r;

      if (rd.type == OPTYPE_REG) {
        r = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      } else {
        assert(rd.type == OPTYPE_MEM);
        r = REG_temp7;
      }

      int condcode = bits(op, 0, 4);
      const CondCodeToFlagRegs& cctfr = cond_code_to_flag_regs[condcode];

      int condreg;
      if (cctfr.req2) {
        this << TransOp(OP_collcc, REG_temp0, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
        condreg = REG_temp0;
      } else {
        condreg = (cctfr.ra != REG_zero) ? cctfr.ra : cctfr.rb;
      }
      assert(condreg != REG_zero);

      TransOp transop(OP_set, r, condreg, (rd.type == OPTYPE_MEM) ? REG_zero : r, REG_zero, 0);
      transop.cond = condcode;
      this << transop, endl;

      if (rd.type == OPTYPE_MEM) {
        rd.mem.size = 0;
        result_store(r, REG_temp0, rd);
      }
      break;
    }

    case 0x1ac ... 0x1ad: // shrd
    case 0x1a4 ... 0x1a5: { // shld
      // shrd imm-or-reg
      DECODE(eform, rd, v_mode);
      DECODE(gform, ra, v_mode);

      bool right = (op == 0x1ac || op == 0x1ad);

      bool immform = (bit(op, 0) == 0);
      DecodedOperand rimm;
      if (immform) DECODE(iform, rimm, b_mode);

      CheckInvalid();
      // technically it's allowed in 64-bit mode, but no compiler uses it
      if (ctx.use64) MakeInvalid();

      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];

      // low 32 bits and result in rd, high 32 bits in ra
      if (rd.type == OPTYPE_MEM) operand_load(REG_temp1, rd);
      int rdreg = (rd.type == OPTYPE_MEM) ? REG_temp1 : arch_pseudo_reg_to_arch_reg[rd.reg.reg];

      // Form a 64-bit register to shift
      if (right)
        this << TransOp(OP_movhl, REG_temp0, rareg, rdreg, REG_zero, 3);
      else this << TransOp(OP_movhl, REG_temp0, rdreg, rareg, REG_zero, 3);

      // Collect the old flags here in case the shift count was zero:
      this << TransOp(OP_collcc, REG_temp5, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);

      // Perform the double width 64-bit shift, but only set the CF flag (see below)
      this << TransOp(right ? OP_shr : OP_shl, REG_temp0, REG_temp0, (immform) ? REG_imm : REG_rcx, REG_temp5, 3, (immform ? rimm.imm.imm : 0), 0, SETFLAG_CF);

      // Put high back in low
      if (!right) this << TransOp(OP_shr, REG_temp0, REG_temp0, REG_imm, REG_zero, 3, 32);

      //
      // This dummy add is used solely to generate the ZAPS flags only for 32-bit output
      // since we can't do it correctly in the shift itself (which must have a 64-bit result).
      // OF is special: it is only set if a sign change occurred AND the shift count was 1.
      // The meaning of this is ambiguous so we will hope it is never used (CHECKME) and won't
      // create problems. Apparently other chips don't implement it consistently either.
      //
      this << TransOp(OP_add, rdreg, REG_temp0, REG_zero, REG_zero, 2, 0, 0, SETFLAG_ZF|SETFLAG_OF);

      if (rd.type == OPTYPE_MEM) result_store(rdreg, REG_temp4, rd);

      // (32-bit result is complete at this point, but we still need to compute the flags)

      // Collect all flags once more:
      this << TransOp(OP_collcc, REG_temp2, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);

      // If the shift count was zero, never set any flags at all.
      this << TransOp(OP_xor, REG_temp3, REG_rcx, REG_rcx, REG_zero, 0, 0, 0, FLAGS_DEFAULT_ALU);
      TransOp selop(OP_sel, REG_temp5, REG_temp3, REG_temp5, REG_temp2, 3, 0, 0, FLAGS_DEFAULT_ALU);
      selop.cond = COND_e;
      this << selop;
      break;
    };

      // 0x1af (imul Gv,Ev) covered above
      // 0x1b6 ... 0x1b7 (movzx Gv,Eb | Gv,Ew) covered above
      // 0x1be ... 0x1bf (movsx Gv,Eb | Gv,Ew) covered above

    case 0x1b0 ... 0x1b1: {
      // cmpxchg
      DECODE(eform, rd, bit(op, 0) ? v_mode : b_mode);
      DECODE(gform, ra, bit(op, 0) ? v_mode : b_mode);
      CheckInvalid();

      int sizeshift = reginfo[ra.reg.reg].sizeshift;
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];

      /*
      
      Action:
      - Compare rax with [mem]. 
      - If (rax == [mem]), [mem] := ra. 
      - Else rax := [mem]

      cmpxchg8b [mem],ra

      becomes:

      ld     t0 = [mem]               # Load [mem]
      cmp    t1 = rax,t0              # Compare (rax == [mem]) and set flags
      sel.eq t2 = t1,t0,RAREG         # Compute value to store back (only store ra iff (rax == [mem]))
      sel.ne rax = t1,rax,t0          # If (rax != [mem]), rax = [mem]
      st     [mem] = t2               # Store back selected value

      */

      operand_load(REG_temp0, rd, OP_ld, 1);

      this << TransOp(OP_sub, REG_temp1, REG_rax, REG_temp0, REG_zero, sizeshift, 0, 0, FLAGS_DEFAULT_ALU);

      TransOp selmem(OP_sel, REG_temp2, REG_temp1, REG_temp0, rareg, sizeshift);
      selmem.cond = COND_e;
      this << selmem;

      TransOp selreg(OP_sel, REG_rax, REG_temp1, REG_rax, REG_temp0, sizeshift);
      selreg.cond = COND_ne;
      this << selreg;

      result_store(REG_temp2, REG_temp0, rd);

      break;
    }

    case 0x1c0 ... 0x1c1: {
      // xadd
      DECODE(eform, rd, bit(op, 0) ? v_mode : b_mode);
      DECODE(gform, ra, bit(op, 0) ? v_mode : b_mode);
      CheckInvalid();

      int sizeshift = reginfo[ra.reg.reg].sizeshift;
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];

      /*
      
      Action:
      - Exchange [rd],ra
      - Add [rd]+ra and set flags
      - Store result to [rd]

      xadd [mem],ra

      becomes:

      ld     t0 = [mem]               # Load [mem]
      add    t1 = t0,ra               # Add temporary
      st     [mem] = t1               # Store back added value
      mov    ra = t0                  # Swap back old value

      */

      operand_load(REG_temp0, rd, OP_ld, 1);
      this << TransOp(OP_add, REG_temp1, REG_temp0, rareg, REG_zero, sizeshift, 0, 0, FLAGS_DEFAULT_ALU);
      result_store(REG_temp1, REG_temp2, rd);
      this << TransOp(OP_mov, rareg, rareg, REG_temp0, REG_zero, sizeshift);

      break;
    }

    case 0x105: {
      // syscall
      // Saves return address into %rcx and jumps to MSR_LSTAR
      immediate(REG_rcx, 3, (W64)rip);
      microcode_assist(ASSIST_SYSCALL, ripstart, rip);
      end_of_block = 1;
      break;
    }

    case 0x131: {
      // rdtsc: put result into %edx:%eax
      TransOp ldp(OP_ld, REG_rdx, REG_zero, REG_imm, REG_zero, 3, (W64)&sim_cycle);
      ldp.internal = 1;
      this << ldp;
      this << TransOp(OP_mov, REG_rax, REG_zero, REG_rdx, REG_zero, 2);
      this << TransOp(OP_shr, REG_rdx, REG_rdx, REG_imm, REG_zero, 3, 32);
      break;
    }

    case 0x1a2: {
      // cpuid: update %rax,%rbx,%rcx,%rdx
      microcode_assist(ASSIST_CPUID, ripstart, rip);
      end_of_block = 1;
      break;
    }

    case 0x118: {
      // prefetchN [eform]
      DECODE(eform, ra, b_mode);
      CheckInvalid();

      static const byte x86_prefetch_to_pt2x_cachelevel[8] = {2, 1, 2, 3};
      int level = x86_prefetch_to_pt2x_cachelevel[modrm.reg];
      operand_prefetch(ra, level);
      break;
    }

    case 0x10d: {
      // prefetchw [eform] (NOTE: this is an AMD-only insn from K6 onwards)
      DECODE(eform, ra, b_mode);
      CheckInvalid();

      int level = 2;
      operand_prefetch(ra, level);
      break;
    }

    case 0x1bc: 
    case 0x1bd: {
      // bsf/bsr:
      DECODE(gform, rd, v_mode); DECODE(eform, ra, v_mode);
      CheckInvalid();
      alu_reg_or_mem((op == 0x1bc) ? OP_ctz: OP_clz, rd, ra, FLAGS_DEFAULT_ALU, REG_zero);
      break;
    }

    case 0x1c8 ... 0x1cf: {
      // bswap
      rd.gform_ext(*this, v_mode, bits(op, 0, 3), false, true);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int sizeshift = reginfo[rd.reg.reg].sizeshift;
      this << TransOp(OP_bswap, rdreg, (sizeshift >= 2) ? REG_zero : rdreg, rdreg, REG_zero, sizeshift);
      break;
    }

      // 0x2xx = XXXss:
    case 0x251: // sqrt
    case 0x252: // rsqrt
    case 0x253: // rcp
      //case 0x254: // and (scalar version does not exist)
      //case 0x255: // andn
      //case 0x256: // or
      //case 0x257: // xor
    case 0x258: // add
    case 0x259: // mul
      // 0x25a, 0x25b are conversions with different form
    case 0x25c: // sub
    case 0x25d: // min
    case 0x25e: // div
    case 0x25f: // max
    case 0x2c2: // cmp (has imm byte at end for compare type)

      // 0x3xx = XXXps
    case 0x351: // sqrt
    case 0x352: // rsqrt
    case 0x353: // rcp
    case 0x354: // and
    case 0x355: // andn
    case 0x356: // or
    case 0x357: // xor
    case 0x358: // add
    case 0x359: // mul
      // 0x35a, 0x25b are conversions with different form
    case 0x35c: // sub
    case 0x35d: // min
    case 0x35e: // div
    case 0x35f: // max
    case 0x3c2: // cmp (has imm byte at end for compare type)

      // 0x4xx = XXXsd
    case 0x451: // sqrt
    case 0x452: // rsqrt
    case 0x453: // rcp
      //case 0x454: // and (scalar version does not exist)
      //case 0x455: // andn
      //case 0x456: // or
      //case 0x457: // xor
    case 0x458: // add
    case 0x459: // mul
      // 0x45a, 0x25b are conversions with different form
    case 0x45c: // sub
    case 0x45d: // min
    case 0x45e: // div
    case 0x45f: // max
    case 0x4c2: // cmp (has imm byte at end for compare type)

      // 0x5xx = XXXpd
    case 0x551: // sqrt
    case 0x552: // rsqrt
    case 0x553: // rcp
    case 0x554: // and
    case 0x555: // andn
    case 0x556: // or
    case 0x557: // xor
    case 0x558: // add
    case 0x559: // mul
      // 0x55a, 0x25b are conversions with different form
    case 0x55c: // sub
    case 0x55d: // min
    case 0x55e: // div
    case 0x55f: 
    case 0x5c2: { // cmp (has imm byte at end for compare type)
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();

      bool cmp = (lowbits(op, 8) == 0xc2);
      DecodedOperand imm;
      imm.imm.imm = 0;
      if (cmp) {
        // cmpXX has imm8 at end to specify 3 bits of compare type:
        DECODE(iform, imm, b_mode);
        CheckInvalid();
      }

      int destreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];

      // XXXss: 0x2xx 00
      // XXXps: 0x3xx 01
      // XXXsd: 0x4xx 10
      // XXXpd: 0x5xx 11

      byte sizetype = (op >> 8) - 2; // put into 0x{2-5}00 -> 2-5 range, then set to 0-3 range
      bool packed = bit(sizetype, 0);
      bool dp = bit(sizetype, 1);

      static const byte opcode_to_uop[16] = {OP_nop, OP_sqrtf, OP_rsqrtf, OP_rcpf, OP_and, OP_andnot, OP_or, OP_xor, OP_addf, OP_mulf, OP_nop, OP_nop, OP_subf, OP_minf, OP_divf, OP_maxf};

      int uop = (lowbits(op, 8) == 0xc2) ? OP_cmpf : opcode_to_uop[lowbits(op, 4)];

      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        rareg = REG_temp0;
        operand_load(REG_temp0, ra, OP_ld, 1);
        if (packed) {
          ra.mem.offset += 8;
          operand_load(REG_temp1, ra, OP_ld, 1);
        }
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      TransOp lowop(uop, rdreg+0, rdreg+0, rareg+0, REG_zero, isclass(uop, OPCLASS_LOGIC) ? 3 : sizetype);
      lowop.cond = imm.imm.imm;
      this << lowop;

      if (packed) {
        TransOp highop(uop, rdreg+1, rdreg+1, rareg+1, REG_zero, isclass(uop, OPCLASS_LOGIC) ? 3 : sizetype);
        highop.cond = imm.imm.imm;
        this << highop;
      }
      break;
    }

    case 0x22a: { // cvtsi2ss with W32 or W64 source
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, v_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        ra.mem.size = (rex.mode64) ? 3 : 2;
        operand_load(REG_temp0, ra, OP_ld, 1);
        rareg = REG_temp0;
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      this << TransOp((rex.mode64) ? OP_cvtf_q2s_ins : OP_cvtf_i2s_ins, rdreg, rdreg, rareg, REG_zero, 3);
      break;
    }

    case 0x42a: { // cvtsi2sd with W32 or W64 source
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, v_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        ra.mem.size = (rex.mode64) ? 3 : 2;
        operand_load(REG_temp0, ra, OP_ld, 1);
        rareg = REG_temp0;
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      this << TransOp((rex.mode64) ? OP_cvtf_q2d : OP_cvtf_i2d_lo, rdreg, rareg, REG_zero, REG_zero, 3);
      break;
    }

    case 0x2e6: // cvtdq2pd
    case 0x52a: { // cvtpi2pd
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        ra.mem.size = (rex.mode64) ? 3 : 2;
        operand_load(REG_temp0, ra, OP_ld, 1);
        rareg = REG_temp0;
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      this << TransOp(OP_cvtf_i2d_lo, rdreg+0, rareg, REG_zero, REG_zero, 3);
      this << TransOp(OP_cvtf_i2d_hi, rdreg+1, rareg, REG_zero, REG_zero, 3);
      break;
    }

    case 0x35b: { // cvtdq2ps
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        operand_load(REG_temp0, ra, OP_ld, 1);
        ra.mem.offset += 8;
        operand_load(REG_temp1, ra, OP_ld, 1);
        rareg = REG_temp0;
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      this << TransOp(OP_cvtf_i2s_p, rdreg+0, rareg+0, REG_zero, REG_zero, 3);
      this << TransOp(OP_cvtf_i2s_p, rdreg+1, rareg+1, REG_zero, REG_zero, 3);
      break;
    }

    case 0x4e6: // cvtpd2dq
    case 0x5e6: { // cvttpd2dq
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        operand_load(REG_temp0, ra, OP_ld, 1);
        ra.mem.offset += 8;
        operand_load(REG_temp1, ra, OP_ld, 1);
        rareg = REG_temp0;
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      this << TransOp(OP_cvtf_d2i_p, rdreg+0, rareg+1, rareg+0, REG_zero, ((op >> 8) == 5));
      this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3);
      break;
    }

      // cvtpd2pi has mmx target: skip for now

    case 0x55a: { // cvtpd2ps
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        operand_load(REG_temp0, ra, OP_ld, 1);
        ra.mem.offset += 8;
        operand_load(REG_temp1, ra, OP_ld, 1);
        rareg = REG_temp0;
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      this << TransOp(OP_cvtf_d2s_p, rdreg+0, rareg+1, rareg+0, REG_zero, 3);
      this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3);
      break;
    }

    case 0x32a: { // cvtpi2ps
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        operand_load(REG_temp0, ra, OP_ld, 1);
        ra.mem.offset += 8;
        operand_load(REG_temp1, ra, OP_ld, 1);
        rareg = REG_temp0;
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      this << TransOp(OP_cvtf_i2s_p, rdreg+0, rareg+0, REG_zero, REG_zero, 3);
      this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3);
      break;
    }

    case 0x55b: // cvtps2dq
    case 0x25b: { // cvttps2dq
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        operand_load(REG_temp0, ra, OP_ld, 1);
        ra.mem.offset += 8;
        operand_load(REG_temp1, ra, OP_ld, 1);
        rareg = REG_temp0;
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      this << TransOp(OP_cvtf_s2i_p, rdreg+0, rareg+0, REG_zero, REG_zero, ((op >> 8) == 2));
      this << TransOp(OP_cvtf_s2i_p, rdreg+1, rareg+1, REG_zero, REG_zero, ((op >> 8) == 2));
      break;
    }

      // cvtps2pi/cvttps2pi: uses mmx so ignore for now

    case 0x42d: // cvtsd2si
    case 0x42c: { // cvttsd2si
      DECODE(gform, rd, v_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        operand_load(REG_temp0, ra, OP_ld, 1);
        rareg = REG_temp0;
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      this << TransOp((rex.mode64) ? OP_cvtf_d2q : OP_cvtf_d2i, rdreg, rareg, REG_zero, REG_zero, (lowbits(op, 8) == 0x2c));
      break;
    }

    case 0x22d: // cvtss2si
    case 0x22c: { // cvttss2si
      DECODE(gform, rd, v_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        operand_load(REG_temp0, ra, OP_ld, 1);
        rareg = REG_temp0;
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      this << TransOp((rex.mode64) ? OP_cvtf_s2q : OP_cvtf_s2i, rdreg, rareg, REG_zero, REG_zero, (lowbits(op, 8) == 0x2c));
      break;
    }

    case 0x25a: { // cvtss2sd
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        operand_load(REG_temp0, ra, OP_ld, 1);
        rareg = REG_temp0;
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      this << TransOp(OP_cvtf_s2d_lo, rdreg, rareg, REG_zero, REG_zero, 3);
      break;
    }

    case 0x35a: { // cvtps2pd
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        operand_load(REG_temp0, ra, OP_ld, 1);
        rareg = REG_temp0;
        ra.mem.offset += 8;
        operand_load(REG_temp1, ra, OP_ld, 1);
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      this << TransOp(OP_cvtf_s2d_lo, rdreg+0, rareg, REG_zero, REG_zero, 3);
      this << TransOp(OP_cvtf_s2d_lo, rdreg+1, rareg, REG_zero, REG_zero, 3);
      break;
    }

    case 0x45a: { // cvtsd2ss
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        operand_load(REG_temp0, ra, OP_ld, 1);
        rareg = REG_temp0;
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      this << TransOp(OP_cvtf_d2s_ins, rdreg, rdreg, rareg, REG_zero, 3);
      break;
    }

    case 0x328: // movaps load 
    case 0x528: // movapd load
    case 0x310: // movups load
    case 0x510: { // movupd load
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];

      if (ra.type == OPTYPE_MEM) {
        // Load
        operand_load(rdreg+0, ra, OP_ld, 1);
        ra.mem.offset += 8;
        operand_load(rdreg+1, ra, OP_ld, 1);
      } else {
        // Move
        int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
        this << TransOp(OP_mov, rdreg+0, REG_zero, rareg+0, REG_zero, 3);
        this << TransOp(OP_mov, rdreg+1, REG_zero, rareg+1, REG_zero, 3);
      }
      break;
    }

    case 0x329: // movaps store
    case 0x529: // movapd store
    case 0x311: // movups store
    case 0x511: { // movupd store
      DECODE(eform, rd, x_mode);
      DECODE(gform, ra, x_mode);
      CheckInvalid();
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      if (rd.type == OPTYPE_MEM) {
        // Store
        result_store(rareg+0, REG_temp0, rd);
        rd.mem.offset += 8;
        result_store(rareg+1, REG_temp1, rd);
      } else {
        // Move
        int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
        this << TransOp(OP_mov, rdreg+0, REG_zero, rareg+0, REG_zero, 3);
        this << TransOp(OP_mov, rdreg+1, REG_zero, rareg+1, REG_zero, 3);
      }
      break;
    };

    case 0x210: // movss load
    case 0x410: { // movsd load
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      bool isdouble = ((op >> 8) == 0x4);
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      if (ra.type == OPTYPE_MEM) {
        // Load
        ra.mem.size = (isdouble) ? 3 : 2;
        operand_load(rdreg+0, ra, OP_ld, 1);
        this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3); // zero high 64 bits
      } else {
        int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
        // Strange semantics: iff the source operand is a register, insert into low 32 bits only; leave high 32 bits and bits 64-127 alone
        this << TransOp((isdouble) ? OP_mov : OP_movl, rdreg, (isdouble) ? REG_zero : rdreg, rareg, REG_zero, 3);
      }
      break;
    }

    case 0x211: // movss store
    case 0x411: { // movsd store
      DECODE(eform, rd, x_mode);
      DECODE(gform, ra, x_mode);
      CheckInvalid();
      bool isdouble = ((op >> 8) == 0x4);
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      if (rd.type == OPTYPE_MEM) {
        // Store
        rd.mem.size = (isdouble) ? 3 : 2;
        result_store(rareg, REG_temp0, rd);
      } else {
        // Register to register
        int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
        // Strange semantics: iff the source operand is a register, insert into low 32 bits only; leave high 32 bits and bits 64-127 alone
        this << TransOp((isdouble) ? OP_mov : OP_movl, rdreg, (isdouble) ? REG_zero : rdreg, rareg, REG_zero, 3);
      }
      break;
    }

      /*
        0x2xx   0xf3  OPpd
        0x3xx   none  OPps
        0x4xx   0xf2  OPsd
        0x5xx   0x66  OPpd
      */

    case 0x32f: // comiss
    case 0x32e: // ucomiss
    case 0x52f: // comisd
    case 0x52e: { // ucomisd
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg;

      if (ra.type == OPTYPE_MEM) {
        operand_load(REG_temp0, ra, OP_ld, 1);
        rareg = REG_temp0;
      } else {
        rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      }

      int sizecode;
      switch (op) {
      case 0x32f: sizecode = 0; break;
      case 0x32e: sizecode = 1; break;
      case 0x52f: sizecode = 2; break;
      case 0x52e: sizecode = 3; break;
      }

      //
      // comisX and ucomisX set {zf pf cf} according to the comparison,
      // and always set {of sf af} to zero.
      //
      this << TransOp(OP_cmpccf, REG_temp0, rdreg, rareg, REG_zero, sizecode, 0, 0, FLAGS_DEFAULT_ALU);
      break;
    };

    case 0x516: // movhpd load
    case 0x316: // movhps load or movlhps
    case 0x512: // movlpd load
    case 0x312: { // movlps load or movhlps
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      if (ra.type == OPTYPE_MEM) {
        // movhpd/movhps/movlpd/movlps
        operand_load(rdreg + ((lowbits(op, 8) == 0x16) ? 1 : 0), ra, OP_ld, 1);
      } else {
        // movlhps/movhlps
        int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
        switch (op) {
        case 0x312: // movhlps
          this << TransOp(OP_mov, rdreg, REG_zero, rareg+1, REG_zero, 3); break;
        case 0x316: // movlhps
          this << TransOp(OP_mov, rdreg+1, REG_zero, rareg, REG_zero, 3); break;
        }
      }
      break;
    }

    case 0x517: // movhpd store
    case 0x317: // movhps store
    case 0x513: // movlpd store
    case 0x313: { // movlps store
      DECODE(eform, rd, x_mode);
      DECODE(gform, ra, x_mode);
      CheckInvalid();
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      if (rd.type != OPTYPE_MEM) MakeInvalid();
      result_store(rareg + ((lowbits(op, 8) == 0x17) ? 1 : 0), REG_temp0, rd);
      break;
    }

      /*
        0x2xx   0xf3  OPpd
        0x3xx   none  OPps
        0x4xx   0xf2  OPsd
        0x5xx   0x66  OPpd

      */

    case 0x514: // unpcklpd
    case 0x515: { // unpckhpd
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      if (ra.type == OPTYPE_MEM) {
        switch (op) {
        case 0x514: // unpcklpd
          operand_load(rdreg+1, ra, OP_ld, 1); break;
        case 0x515: // unpckhpd
          this << TransOp(OP_mov, rdreg+0, REG_zero, rdreg+1, REG_zero, 3);
          ra.mem.offset += 8;
          operand_load(rdreg+1, ra, OP_ld, 1); break;
        }
      } else {
        int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
        switch (op) {
        case 0x514: // unpcklpd
          this << TransOp(OP_mov, rdreg+1, REG_zero, rareg+0, REG_zero, 3); break;
        case 0x515: // unpckhpd
          this << TransOp(OP_mov, rdreg+0, REG_zero, rdreg+1, REG_zero, 3);
          this << TransOp(OP_mov, rdreg+1, REG_zero, rareg+1, REG_zero, 3); break;
        }
      }
      break;
    }

    case 0x1c3: {
      // movnti
      DECODE(eform, rd, v_mode);
      DECODE(gform, ra, v_mode);
      CheckInvalid();
      move_reg_or_mem(rd, ra);
      break;
    }

      /*
        0x2xx   0xf3  OPpd
        0x3xx   none  OPps
        0x4xx   0xf2  OPsd
        0x5xx   0x66  OPpd

      */

    case 0x56e: { // movd xmm,rm32/rm64
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, v_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      if (ra.type == OPTYPE_MEM) {
        // Load
        operand_load(rdreg+0, ra, OP_ld, 1);
        this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3); // zero high 64 bits
      } else {
        int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
        int rashift = reginfo[ra.reg.reg].sizeshift;
        this << TransOp(OP_mov, rdreg+0, REG_zero, rareg, REG_zero, rashift);
        this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3); // zero high 64 bits
      }
      break;
    }

    case 0x57e: { // movd rm32/rm64,xmm
      DECODE(eform, rd, v_mode);
      DECODE(gform, ra, x_mode);
      CheckInvalid();
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      if (rd.type == OPTYPE_MEM) {
        result_store(rareg, REG_temp0, rd);
      } else {
        int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
        int rdshift = reginfo[rd.reg.reg].sizeshift;
        this << TransOp(OP_mov, rdreg, (rdshift < 3) ? rdreg : REG_zero, rareg, REG_zero, rdshift);
      }
      break;
    }

    case 0x27e: { // movq xmm,xmmlo|mem64 with zero extension
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      CheckInvalid();
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      if (ra.type == OPTYPE_MEM) {
        // Load
        operand_load(rdreg+0, ra, OP_ld, 1);
        this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3); // zero high 64 bits
      } else {
        // Move from xmm to xmm
        int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
        this << TransOp(OP_mov, rdreg+0, REG_zero, rareg, REG_zero, 3);
        this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3); // zero high 64 bits
      }
      break;
    }

    case 0x5d6: { // movd xmmlo|mem64,xmm with zero extension
      DECODE(eform, rd, v_mode);
      DECODE(gform, ra, x_mode);
      CheckInvalid();
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      if (rd.type == OPTYPE_MEM) {
        result_store(rareg, REG_temp0, rd);
      } else {
        int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
        this << TransOp(OP_mov, rdreg, REG_zero, rareg, REG_zero, 3);
        this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3); // zero high 64 bits
      }
      break;
    }

    case 0x1ae: {
      // fxsave fxrstor ldmxcsr stmxcsr (inv) lfence mfence sfence
      switch (modrm.reg) {
      case 2: { // ldmxcsr
        //++MTY TODO
        this << TransOp(OP_nop, REG_temp0, REG_zero, REG_zero, REG_zero, 3);
        break;
      }
      case 3: { // stmxcsr
        //++MTY TODO
        this << TransOp(OP_nop, REG_temp0, REG_zero, REG_zero, REG_zero, 3);
        break;
      }
      case 5: // lfence
      case 6: // mfence
      case 7: { // sfence
        this << TransOp(OP_nop, REG_temp0, REG_zero, REG_zero, REG_zero, 3);
        break;
      }
      default:
        MakeInvalid();
        break;
      }
      break;
    }

    case 0x137: { // 0f 37: PTL undocumented opcode
      microcode_assist(ASSIST_PTLCALL, ripstart, rip);      
      end_of_block = 1;
      break;
    }
      //case 0x314: // unpcklps
      //case 0x315: // unpckhps
    default: {
      MakeInvalid();
      break;
    }
    } // switch

    user_insn_count++;

    assert(!invalid);

    if (end_of_block) {
      // Block ended with a branch: close the uop and exit
      lastop();
      return false;
    } else {
      // Block did not end with a branch: do we have more room for another x86 insn?
      if (((MAXBBLEN - bb.count) < MAX_TRANSOPS_PER_USER_INSN) 
          || ((rip - ripstart) >= MAX_USER_INSN_BB_BYTES)) {
        if (DEBUG) logfile << "Basic block ", (void*)bb.rip, " too long: cutting at ", bb.count, " transops", endl;
        // bb.rip_taken and bb.rip_not_taken were already filled out for the last instruction.
        if (!last_flags_update_was_atomic)
          this << TransOp(OP_collcc, REG_temp0, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
        TransOp transop(OP_bru, REG_rip, REG_zero, REG_zero, REG_zero, 3);
        transop.riptaken = (W64)rip;
        transop.ripseq = (W64)rip;
        bb.rip_taken = bb.rip_not_taken = (W64)rip;
        this << transop;
        lastop();
        return false;
      } else {
        lastop();
        return true;
      }
    }
#undef DECODE
  }
};

using namespace TranslateX86;

ostream& printflags(ostream& os, W64 flags) {
  os << "0x", hexstring(flags, 32), " = [";

  for (int i = (FLAG_COUNT-1); i >= 0; i--) {
    if (bit(flags, i)) os << " ", x86_flag_names[i]; else os << " -";
  }
  os << " ] ";
  return os;
}

BasicBlock* translate_basic_block(void* rip) {
  bool DEBUG = analyze_in_detail();

  if (DEBUG) logfile << "Translating ", (void*)rip, " at ", total_user_insns_committed, " commits", endl, flush;

  translate_timer.start();

  TraceDecoder trans;
  trans.reset((W64)rip);

  for (;;) {
    //if (DEBUG) logfile << "rip ", (void*)trans.rip, ", relrip = ", (void*)(trans.rip - trans.bb.rip), endl, flush;
    if (!trans.translate()) break;
  }

  BasicBlock* bb = trans.bb.clone();

  if (DEBUG) {
    logfile << "=====================================================================", endl;
    logfile << *bb, endl;
    logfile << "End of basic block: rip ", (void*)trans.bb.rip, " -> taken rip 0x", hexstring(trans.bb.rip_taken, 64), ", not taken rip 0x", hexstring(trans.bb.rip_not_taken, 64), endl;
  }

  translate_timer.stop();
  return bb;
}

void init_translate() { }
