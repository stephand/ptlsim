//
// PTLsim: Cycle Accurate x86-64 Simulator
// Decoder for complex instructions
//
// Copyright 1999-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <decode.h>

template <typename T> void assist_div(Context& ctx) {
  Waddr rax = ctx.commitarf[REG_rax]; Waddr rdx = ctx.commitarf[REG_rdx];
  asm("div %[divisor];" : "+a" (rax), "+d" (rdx) : [divisor] "q" ((T)ctx.commitarf[REG_ar1]));
  ctx.commitarf[REG_rax] = rax; ctx.commitarf[REG_rdx] = rdx;
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
}

template <typename T> void assist_idiv(Context& ctx) {
  Waddr rax = ctx.commitarf[REG_rax]; Waddr rdx = ctx.commitarf[REG_rdx];
  asm("idiv %[divisor];" : "+a" (rax), "+d" (rdx) : [divisor] "q" ((T)ctx.commitarf[REG_ar1]));
  ctx.commitarf[REG_rax] = rax; ctx.commitarf[REG_rdx] = rdx;
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
}

// Not possible in 64-bit mode
#ifndef __x86_64__
template <> void assist_div<W64>(Context& ctx) { assert(false); }
template <> void assist_idiv<W64>(Context& ctx) { assert(false); }
#endif

template void assist_div<byte>(Context& ctx);
template void assist_div<W16>(Context& ctx);
template void assist_div<W32>(Context& ctx);
template void assist_div<W64>(Context& ctx);

template void assist_idiv<byte>(Context& ctx);
template void assist_idiv<W16>(Context& ctx);
template void assist_idiv<W32>(Context& ctx);
template void assist_idiv<W64>(Context& ctx);

void assist_int(Context& ctx) {
  byte intid = ctx.commitarf[REG_ar1];
#ifdef PTLSIM_HYPERVISOR
  // The returned rip is nextrip for explicit intN instructions:
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
  ctx.propagate_x86_exception(intid, 0);
#else
  if (intid == 0x80) {
    handle_syscall_32bit(SYSCALL_SEMANTICS_INT80);
  } else {
    logfile << "Unknown int 0x", hexstring(intid, 8), "; aborting", endl, flush;
    abort();
  }
#endif
}

#ifdef PTLSIM_HYPERVISOR
extern void handle_xen_hypercall_assist(Context& ctx);

extern void handle_syscall_assist(Context& ctx);
#endif

void assist_syscall(Context& ctx) {
#ifdef PTLSIM_HYPERVISOR
  //
  // SYSCALL has two distinct sets of semantics on Xen x86-64.
  //
  // When executed from user mode, it's a normal system call
  // in the Linux sense, and Xen just relays control back
  // to the guest domain's kernel.
  //
  // When executed from kernel mode, it's interpreted as a
  // hypercall into Xen itself.
  //

  if (ctx.kernel_mode) {
    handle_xen_hypercall_assist(ctx);
  } else {
    handle_syscall_assist(ctx);
  }
#else
  if (ctx.use64) {
#ifdef __x86_64__
    handle_syscall_64bit();
#endif
  } else {
    handle_syscall_32bit(SYSCALL_SEMANTICS_SYSCALL);
  }
#endif
  // REG_rip is filled out for us
}

void assist_sysenter(Context& ctx) {
#ifdef PTLSIM_HYPERVISOR
  //++MTY TODO
  cerr << "assist_sysenter()", endl, flush;
  abort();
#else
  handle_syscall_32bit(SYSCALL_SEMANTICS_SYSENTER);
#endif
  // REG_rip is filled out for us
}

//
// For compatibility reasons, we now cheat and pretend to be a Pentium 4 Northwood CPU here.
// Intel's C++ compiler insists on running on a genuine Intel CPU or it intentionally runs
// incorrect or sub-optimal code. Intel has been harshly criticized for this anti-competitive 
// practice. If you want to report the original PTLsim CPUID, uncomment the lines below.
//
//static const char cpuid_vendor[12+1] = "GenuineIntel";
//static const char cpuid_description[48+1] = "PTLsim Cycle Accurate x86-64 Simulator Model    ";

static const char cpuid_vendor[12+1] = "PTLsimCPUx64";
static const char cpuid_description[48+1] = "PTLsim Cycle Accurate x86-64 Simulator Model    ";


void assist_cpuid(Context& ctx) {
  W64& rax = ctx.commitarf[REG_rax];
  W64& rbx = ctx.commitarf[REG_rbx];
  W64& rcx = ctx.commitarf[REG_rcx];
  W64& rdx = ctx.commitarf[REG_rdx];

  W32 func = rax;
  if (logable(4)) {
    logfile << "assist_cpuid: func 0x", hexstring(func, 32), " called from ",
      (void*)(Waddr)ctx.commitarf[REG_selfrip], ":", endl;
  }

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
  case 1: {
    // Model and capability information
    // PTLsim pretends to be a standard Pentium 4 Northwood processor;
    // these values are taken from such a chip (by running cpuid)
    rax = 0x00000f29; // model
    rbx = 0x0002080b; // other info
    rcx = 0x00004400; // Intel-specific features (no SSE3 bit set)
    rdx = 0xbfebfbff; // features
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

  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
}

//
// Pop from stack into flags register, with checking for reserved bits
//
void assist_popf(Context& ctx) {
  W32 flags = ctx.commitarf[REG_ar1];
  ctx.internal_eflags = flags & ~(FLAG_ZAPS|FLAG_CF|FLAG_OF);
  ctx.commitarf[REG_flags] = flags & (FLAG_ZAPS|FLAG_CF|FLAG_OF);
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];

  // Update internal flags too (only update non-standard flags in internal_flags_bits):
  // Equivalent to these uops:
  // this << TransOp(OP_and, REG_temp1, REG_temp0, REG_imm, REG_zero, 2, ~(FLAG_ZAPS|FLAG_CF|FLAG_OF));
  // TransOp stp(OP_st, REG_mem, REG_ctx, REG_imm, REG_temp1, 2, offsetof(Context, internal_eflags)); stp.internal = 1; this << stp;
  // this << TransOp(OP_movrcc, REG_temp0, REG_zero, REG_temp0, REG_zero, 3, 0, 0, FLAGS_DEFAULT_ALU);
}

//
// CLD and STD must be barrier assists since a new RIPVirtPhys
// context key may be active after the direction flag is altered.
//
void assist_cld(Context& ctx) {
  ctx.internal_eflags &= ~FLAG_DF;
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];  
}

void assist_std(Context& ctx) {
  ctx.internal_eflags |= FLAG_DF;
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];  
}

//
// PTL calls
//
extern void assist_ptlcall(Context& ctx);

void assist_write_segreg(Context& ctx) {
  W16 selector = ctx.commitarf[REG_ar1];
  byte segid = ctx.commitarf[REG_ar2];

  int exception = ctx.write_segreg(segid, selector);

  if unlikely (exception) {
    ctx.commitarf[REG_rip] = ctx.commitarf[REG_selfrip];
    ctx.propagate_x86_exception(exception, selector);
    return;
  }

  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
}

void assist_ldmxcsr(Context& ctx) {
  //
  // LDMXCSR needs to flush the pipeline since future FP instructions will
  // depend on its value and can't be issued out of order w.r.t the mxcsr.
  //
  W32 mxcsr = (W32)ctx.commitarf[REG_ar1];

  // Top bit of mxcsr archreg doubles as direction flag and other misc flags: preserve it
  ctx.mxcsr = (ctx.mxcsr & 0xffffffff00000000ULL) | mxcsr;

  // We can't have exceptions going on inside PTLsim: virtualize this feature in uopimpl code
  // Everything else will be used by real SSE insns inside uopimpls. 
  mxcsr |= MXCSR_EXCEPTION_DISABLE_MASK;
  x86_set_mxcsr(mxcsr);

  //
  // Technically all FP uops should update the sticky exception bits in the mxcsr
  // if marked as such (i.e. non-x87). Presently we don't do this, so hopefully
  // no code checks for exception conditions in this manner. Otherwise each FP
  // uopimpl would need to update a speculative version of the mxcsr.
  //
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
}

void assist_fxsave(Context& ctx) {
  FXSAVEStruct state;

  ctx.fxsave(state);

  Waddr target = ctx.commitarf[REG_ar1];

  PageFaultErrorCode pfec;
  Waddr faultaddr;
  int bytes = ctx.copy_to_user(target, &state, sizeof(state), pfec, faultaddr);

  if (bytes < sizeof(state)) {
    ctx.commitarf[REG_rip] = ctx.commitarf[REG_selfrip];
    ctx.propagate_x86_exception(EXCEPTION_x86_page_fault, pfec, faultaddr);
    return;
  }
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
}

void assist_wrmsr(Context& ctx) {
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_selfrip];

#ifdef PTLSIM_HYPERVISOR
  if (ctx.kernel_mode) {
    abort();
  } else {
    ctx.propagate_x86_exception(EXCEPTION_x86_gp_fault);
  }
#else
  ctx.propagate_x86_exception(EXCEPTION_x86_invalid_opcode);
#endif
}

void assist_rdmsr(Context& ctx) {
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_selfrip];

#ifdef PTLSIM_HYPERVISOR
  if (ctx.kernel_mode) {
    W32 msr = ctx.commitarf[REG_rcx];
    W64 rc = 0;
    bool invalid = 0;
    switch (msr) {
    case 0xc0000100:
      rc = ctx.seg[SEGID_FS].base; break;
    case 0xc0000101:
      rc = ctx.seg[SEGID_GS].base; break;
    case 0xc0000102:
      rc = ctx.swapgs_base; break;
    default:
      invalid = 1; break;
    }
    if (invalid) {
      ctx.propagate_x86_exception(EXCEPTION_x86_gp_fault);
    } else {
      ctx.commitarf[REG_rdx] = HI32(rc);
      ctx.commitarf[REG_rax] = LO32(rc);
      ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
    }
  } else {
    ctx.propagate_x86_exception(EXCEPTION_x86_gp_fault);
  }
#else
  ctx.propagate_x86_exception(EXCEPTION_x86_invalid_opcode);
#endif
}

void assist_wrcr(Context& ctx) {
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_selfrip];
  ctx.propagate_x86_exception(EXCEPTION_x86_invalid_opcode);
}

void assist_rdcr(Context& ctx) {
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_selfrip];
  ctx.propagate_x86_exception(EXCEPTION_x86_invalid_opcode);
}

void assist_iret16(Context& ctx) {
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_selfrip];
  ctx.propagate_x86_exception(EXCEPTION_x86_invalid_opcode);
}

void assist_iret32(Context& ctx) {
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_selfrip];
  ctx.propagate_x86_exception(EXCEPTION_x86_invalid_opcode);
}

void assist_iret64(Context& ctx) {
#ifdef PTLSIM_HYPERVISOR
  struct IRETStackFrame {
    W64 rip, cs, rflags, rsp, ss;
  };

  IRETStackFrame frame;

  PageFaultErrorCode pfec;
  Waddr faultaddr;

  ctx.commitarf[REG_rip] = ctx.commitarf[REG_selfrip];
  int n = ctx.copy_from_user(&frame, (Waddr)ctx.commitarf[REG_rsp], sizeof(frame), pfec, faultaddr);
  if (n != sizeof(frame)) {
    ctx.propagate_x86_exception(EXCEPTION_x86_page_fault, pfec, faultaddr);
    return;
  }

  int exception;

  if (exception = ctx.write_segreg(SEGID_SS, frame.ss)) {
    ctx.propagate_x86_exception(exception, frame.ss & 0xfff8);
    return;
  }

  if (exception = ctx.write_segreg(SEGID_CS, frame.cs)) {
    ctx.propagate_x86_exception(exception, frame.cs & 0xfff8);
    return;
  }

  ctx.commitarf[REG_rip] = frame.rip;
  ctx.commitarf[REG_rsp] = frame.rsp;
  ctx.internal_eflags = frame.rflags & ~(FLAG_ZAPS|FLAG_CF|FLAG_OF);
  ctx.commitarf[REG_flags] = frame.rflags & (FLAG_ZAPS|FLAG_CF|FLAG_OF);
#else
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_selfrip];
  ctx.propagate_x86_exception(EXCEPTION_x86_invalid_opcode);
#endif
}

bool TraceDecoder::decode_complex() {
  DecodedOperand rd;
  DecodedOperand ra;

  switch (op) {
 
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

  case 0x64 ... 0x67: {
    // invalid (prefixes)
    MakeInvalid();
    break;
  }

  case 0x6c ... 0x6f: {
    // insb/insw/outsb/outsw: not supported
    MakeInvalid();
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

      bool moveonly = (!rdhigh && !rahigh);

      int maskctl1 = 
        (rdhigh && !rahigh) ? MaskControlInfo(56, 8, 56) : // insert high byte
        (!rdhigh && rahigh) ? MaskControlInfo(0, 8, 8) : // extract high byte
        (rdhigh && rahigh) ? MaskControlInfo(56, 8, 0) : // move between high bytes
        MaskControlInfo(0, 64, 0); // straight move (but cannot synthesize from mask uop)

      int maskctl2 = 
        (rdhigh && !rahigh) ? MaskControlInfo(0, 8, 8) : // extract high byte
        (!rdhigh && rahigh) ? MaskControlInfo(56, 8, 56) : // insert high byte
        (rdhigh && rahigh) ? MaskControlInfo(56, 8, 0) : // move between high bytes
        MaskControlInfo(0, 64, 0); // straight move (but cannot synthesize from mask uop)

      if (moveonly) {
        this << TransOp(OP_mov, rdreg, rdreg, rareg, REG_zero, sizeshift);
        this << TransOp(OP_mov, rareg, rareg, REG_temp0, REG_zero, sizeshift);
      } else {
        this << TransOp(OP_maskb, rdreg, rdreg, rareg, REG_imm, 3, 0, maskctl1);
        this << TransOp(OP_maskb, rareg, rareg, REG_temp0, REG_imm, 3, 0, maskctl2);
      }
    } else {
      if (rahigh)
        this << TransOp(OP_maskb, REG_temp7, REG_zero, rareg, REG_imm, 3, 0, MaskControlInfo(0, 8, 8));
      else this << TransOp(OP_mov, REG_temp7, REG_zero, rareg, REG_zero, 3);

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
        if (reginfo[rd.reg.reg].hibyte)
          this << TransOp(OP_maskb, destreg, destreg, REG_temp0, REG_imm, 3, 0, MaskControlInfo(56, 8, 56));
        else this << TransOp(OP_mov, destreg, destreg, REG_temp0, REG_zero, sizeshift);
      }

      //
      // st [mem] = t0
      //
      result_store(REG_temp7, REG_temp0, rd);
    }
    break;
  }

  case 0x8c: {
    // mov Ev,segreg
    DECODE(eform, rd, v_mode);
    DECODE(gform, ra, v_mode);
    CheckInvalid();
    ra.type = OPTYPE_IMM;
    ra.imm.imm = 0x63;
    move_reg_or_mem(rd, ra, REG_temp7);
    break;
  }

  case 0x8e: {
    // mov segreg,Ev
    DECODE(gform, rd, w_mode);
    DECODE(eform, ra, w_mode);
    CheckInvalid();

    // Same encoding as order in SEGID_xxx: ES CS SS DS FS GS - - (last two are invalid)
    if (modrm.reg >= 6) MakeInvalid();

    int rareg = (ra.type == OPTYPE_MEM) ? REG_temp0 : arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    if (ra.type == OPTYPE_MEM) operand_load(REG_temp0, ra);

    this << TransOp(OP_mov, REG_ar1, REG_zero, rareg, REG_zero, 3);
    immediate(REG_ar2, 3, modrm.reg);

    microcode_assist(ASSIST_WRITE_SEGREG, ripstart, rip);
    end_of_block = 1;
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
    int sizeshift = (opsize_prefix) ? 1 : ((use64) ? 3 : 2);
    int size = (1 << sizeshift);
    CheckInvalid();

    if (last_flags_update_was_atomic) {
      this << TransOp(OP_movccr, REG_temp0, REG_zero, REG_zf, REG_zero, 3);
    } else {
      this << TransOp(OP_collcc, REG_temp0, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
      this << TransOp(OP_movccr, REG_temp0, REG_zero, REG_temp0, REG_zero, 3);
    }

    TransOp ldp(OP_ld, REG_temp1, REG_ctx, REG_imm, REG_zero, 2, offsetof(Context, internal_eflags)); ldp.internal = 1; this << ldp;
    this << TransOp(OP_or, REG_temp1, REG_temp1, REG_temp0, REG_zero, 2); // merge in standard flags

    this << TransOp(OP_sub, REG_rsp, REG_rsp, REG_imm, REG_zero, 3, size);
    this << TransOp(OP_st, REG_mem, REG_rsp, REG_zero, REG_temp1, sizeshift);

    break;
  }

  case 0x9d: {
    // popfw/popfd/popfq
    int sizeshift = (opsize_prefix) ? 1 : ((use64) ? 3 : 2);
    int size = (1 << sizeshift);
    CheckInvalid();

    this << TransOp(OP_ld, REG_ar1, REG_rsp, REG_zero, REG_zero, sizeshift);
    this << TransOp(OP_add, REG_rsp, REG_rsp, REG_imm, REG_zero, 3, size);

    microcode_assist(ASSIST_POPF, ripstart, rip);
    end_of_block = 1;
    break;
  }

  case 0xfc: { // cld
    CheckInvalid();
    microcode_assist(ASSIST_CLD, ripstart, rip);
    end_of_block = 1;
    break;
  }

  case 0xfd: { // std
    CheckInvalid();
    microcode_assist(ASSIST_STD, ripstart, rip);
    end_of_block = 1;
    break;
  }

  case 0xa4 ... 0xa5:
  case 0xa6 ... 0xa7:
  case 0xaa ... 0xab:
  case 0xac ... 0xad:
  case 0xae ... 0xaf: {
    W64 rep = (prefixes & (PFX_REPNZ|PFX_REPZ));
    int sizeshift = (!bit(op, 0)) ? 0 : (rex.mode64) ? 3 : opsize_prefix ? 1 : 2;
    int addrsizeshift = (use64 ? (addrsize_prefix ? 2 : 3) : (addrsize_prefix ? 1 : 2));

    CheckInvalid();

    // only actually code if it is the very first insn in the block!
    // otherwise emit a branch:
    if (rep && ((Waddr)ripstart != (Waddr)bb.rip)) {
      if (!last_flags_update_was_atomic) 
        this << TransOp(OP_collcc, REG_temp0, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);
      TransOp br(OP_bru, REG_rip, REG_zero, REG_zero, REG_zero, 3);
      br.riptaken = (Waddr)ripstart;
      br.ripseq = (Waddr)ripstart;
      this << br;
      end_of_block = 1;
    } else {
      // This is the very first x86 insn in the block, so translate it as a loop!
      if (rep) {
        TransOp chk(OP_chk_sub, REG_temp0, REG_rcx, REG_zero, REG_imm, addrsizeshift, 0, (Waddr)rip);
        chk.cond = COND_ne; // make sure rcx is not equal to zero
        chk.memid = EXCEPTION_SkipBlock; // type of exception to raise
        this << chk;
        bb.repblock = 1;
      }
      int increment = (1 << sizeshift);
      if (dirflag) increment = -increment;

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

        this << TransOp(OP_ld,     REG_temp0, REG_rsi,    REG_zero,  REG_zero,  sizeshift);
        this << TransOp(OP_st,     REG_mem,   REG_rdi,    REG_zero,  REG_temp0, sizeshift);
        this << TransOp(OP_add,    REG_rsi,   REG_rsi,    REG_imm,   REG_zero,  addrsizeshift, increment);
        this << TransOp(OP_add,    REG_rdi,   REG_rdi,    REG_imm,   REG_zero,  addrsizeshift, increment);
        if (rep) {
          TransOp sub(OP_sub,  REG_rcx,   REG_rcx,    REG_imm,   REG_zero, addrsizeshift, 1, 0, SETFLAG_ZF);
          sub.nouserflags = 1; // it still generates flags, but does not rename the user flags
          this << sub;
          TransOp br(OP_br, REG_rip, REG_rcx, REG_zero, REG_zero, addrsizeshift);
          br.cond = COND_ne; // repeat while nonzero
          br.riptaken = (Waddr)ripstart;
          br.ripseq = (Waddr)rip;
          this << br;
        }
        break;
      }
      case 0xa6: case 0xa7: {
        // cmps
        this << TransOp(OP_ld,   REG_temp0, REG_rsi,    REG_zero,  REG_zero,  sizeshift);
        this << TransOp(OP_ld,   REG_temp1, REG_rdi,    REG_zero,  REG_zero,  sizeshift);
        this << TransOp(OP_add,  REG_rsi,   REG_rsi,    REG_imm,   REG_zero,  addrsizeshift, increment);
        this << TransOp(OP_add,  REG_rdi,   REG_rdi,    REG_imm,   REG_zero,  addrsizeshift, increment);
        this << TransOp(OP_sub,  REG_temp2, REG_temp0,  REG_temp1, REG_zero,  sizeshift, 0, 0, FLAGS_DEFAULT_ALU);

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

          TransOp sub(OP_sub,  REG_rcx,   REG_rcx,    REG_imm,   REG_zero, addrsizeshift, 1, 0, SETFLAG_ZF);     // sub     rcx = rcx,1 [zf internal]
          sub.nouserflags = 1; // it still generates flags, but does not rename the user flags
          this << sub;
          TransOp orxf((rep == PFX_REPZ) ? OP_ornotcc : OP_orcc, REG_temp0, REG_rcx, REG_temp2, REG_zero, (use64 ? 3 : 2), 0, 0, FLAGS_DEFAULT_ALU);
          orxf.nouserflags = 1;
          this << orxf;
          if (!last_flags_update_was_atomic) 
            this << TransOp(OP_collcc, REG_temp5, REG_temp2, REG_temp2, REG_temp2, 3);
          TransOp br(OP_br, REG_rip, REG_temp0, REG_zero, REG_zero, 3);
          br.cond = COND_ne; // repeat while nonzero
          br.riptaken = (Waddr)ripstart;
          br.ripseq = (Waddr)rip;
          this << br;
        }

        break;
      }
      case 0xaa: case 0xab: {
        // stos
        if (rep) assert(rep == PFX_REPZ); // only rep is allowed for movs and rep == repz here
        this << TransOp(OP_st,   REG_mem,   REG_rdi,    REG_zero,  REG_rax, sizeshift);
        this << TransOp(OP_add,  REG_rdi,   REG_rdi,    REG_imm,   REG_zero, addrsizeshift, increment);
        if (rep) {
          TransOp sub(OP_sub,  REG_rcx,   REG_rcx,    REG_imm,   REG_zero, addrsizeshift, 1, 0, SETFLAG_ZF);     // sub     rcx = rcx,1 [zf internal]
          sub.nouserflags = 1; // it still generates flags, but does not rename the user flags
          this << sub;
          TransOp br(OP_br, REG_rip, REG_rcx, REG_zero, REG_zero, 3);
          br.cond = COND_ne; // repeat while nonzero
          br.riptaken = (Waddr)ripstart;
          br.ripseq = (Waddr)rip;
          this << br;
        }
        break;
      }
      case 0xac ... 0xad: {
        // lods
        if (rep) assert(rep == PFX_REPZ); // only rep is allowed for movs and rep == repz here

        if (sizeshift >= 2) {
          this << TransOp(OP_ld,   REG_rax,   REG_rsi,    REG_zero,  REG_zero, sizeshift);
        } else {
          this << TransOp(OP_ld,   REG_temp0, REG_rsi,    REG_zero,  REG_zero, sizeshift);
          this << TransOp(OP_mov,  REG_rax,   REG_rax,    REG_temp0, REG_zero, sizeshift);
        }

        this << TransOp(OP_add,  REG_rsi,   REG_rsi,    REG_imm,   REG_zero, addrsizeshift, increment);

        if (rep) {
          TransOp sub(OP_sub,  REG_rcx,   REG_rcx,    REG_imm,   REG_zero, addrsizeshift, 1, 0, SETFLAG_ZF);     // sub     rcx = rcx,1 [zf internal]
          sub.nouserflags = 1; // it still generates flags, but does not rename the user flags
          this << sub;
          TransOp br(OP_br, REG_rip, REG_rcx, REG_zero, REG_zero, 3);
          br.cond = COND_ne; // repeat while nonzero
          br.riptaken = (Waddr)ripstart;
          br.ripseq = (Waddr)rip;
          this << br;
        }
        break;
      }
      case 0xae: case 0xaf: {
        // scas
        this << TransOp(OP_ld,   REG_temp1, REG_rdi,    REG_zero,  REG_zero, sizeshift);           // ldSZ    t1 = [rdi]
        this << TransOp(OP_add,  REG_rdi,   REG_rdi,    REG_imm,   REG_zero, addrsizeshift, increment);
        this << TransOp(OP_sub,  REG_temp2, REG_temp1,  REG_rax,   REG_zero, sizeshift, 0, 0, FLAGS_DEFAULT_ALU); // sub    t2 = t1,rax (zco)

        if (rep) {
          TransOp sub(OP_sub,  REG_rcx,   REG_rcx,    REG_imm,   REG_zero, addrsizeshift, 1, 0, SETFLAG_ZF);     // sub     rcx = rcx,1 [zf internal]
          sub.nouserflags = 1; // it still generates flags, but does not rename the user flags
          this << sub;
          TransOp orxf((rep == PFX_REPZ) ? OP_ornotcc : OP_orcc, REG_temp0, REG_rcx, REG_temp2, REG_zero, 3, 0, 0, FLAGS_DEFAULT_ALU);
          orxf.nouserflags = 1;
          this << orxf;
          if (!last_flags_update_was_atomic) 
            this << TransOp(OP_collcc, REG_temp5, REG_temp2, REG_temp2, REG_temp2, 3);
          TransOp br(OP_br, REG_rip, REG_temp0, REG_zero, REG_zero, 3);
          br.cond = COND_ne; // repeat while nonzero
          br.riptaken = (Waddr)ripstart;
          br.ripseq = (Waddr)rip;
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

  case 0xc4 ... 0xc5: {
    // les lds (not supported)
    MakeInvalid();
    break;
  }

  case 0xca ... 0xcb: {
    // ret far, with and without pop count (not supported)
    MakeInvalid();
    break;
  }

  case 0xcc: {
    // INT3 (breakpoint)
    CheckInvalid();
    immediate(REG_ar1, 3, 0);
    microcode_assist(ASSIST_INT, ripstart, rip);
    end_of_block = 1;
    break;
  }

  case 0xcd: {
    // int imm8
    DECODE(iform, ra, b_mode);
    CheckInvalid();
    immediate(REG_ar1, 0, ra.imm.imm & 0xff);
    microcode_assist(ASSIST_INT, ripstart, rip);
    end_of_block = 1;
    break;
  }

  case 0xce: {
    // INTO
    // Check OF with chk.no and raise SkipBlock exception;
    // otherwise terminate with ASSIST_INT.
    MakeInvalid();
    break;
  }

  case 0xcf: {
    // IRET
    int assistid = (use64) ? (opsize_prefix ? ASSIST_IRET32 : ASSIST_IRET64) : (opsize_prefix ? ASSIST_IRET16 : ASSIST_IRET32);
    microcode_assist(assistid, ripstart, rip);
    end_of_block = 1;
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

  case 0xd8 ... 0xdf: {
    // x87 legacy FP
    // already handled as 0x6xx pseudo-opcodes

    MakeInvalid();
    break;
  }

  case 0xe0 ... 0xe2: {
    // 0xe0 loopnz
    // 0xe1 loopz
    // 0xe2 loop
    DECODE(iform, ra, b_mode);
    CheckInvalid();

    int sizeshift = (rex.mode64) ? (addrsize_prefix ? 2 : 3) : (addrsize_prefix ? 1 : 2);

    TransOp testop(OP_and, REG_temp1, REG_rcx, REG_rcx, REG_zero, sizeshift, 0, 0, FLAGS_DEFAULT_ALU);
    testop.nouserflags = 1;
    this << testop;

    // ornotcc: raflags | (~rbflags)
    if ((op == 0xe0) | (op == 0xe1)) {
      TransOp mergeop((op == 0xe0) ? OP_ornotcc : OP_orcc, REG_temp1, REG_temp1, REG_zf, REG_zero, 3, 0, 0, FLAGS_DEFAULT_ALU);
      mergeop.nouserflags = 1;
      this << mergeop;
    }

    TransOp transop(OP_br, REG_rip, REG_temp1, REG_zero, REG_zero, 3, 0);
    transop.cond = COND_e;
    transop.riptaken = (Waddr)rip + ra.imm.imm;
    transop.ripseq = (Waddr)rip;
    bb.rip_taken = (Waddr)rip + ra.imm.imm;
    bb.rip_not_taken = (Waddr)rip;
    this << transop;
    end_of_block = true;
    break;
  };

  case 0xe3: {
    // jcxz
    // near conditional branches with 8-bit displacement:
    DECODE(iform, ra, b_mode);
    CheckInvalid();

    int sizeshift = (use64) ? (opsize_prefix ? 2 : 3) : (opsize_prefix ? 1 : 2);

    TransOp testop(OP_and, REG_temp1, REG_rcx, REG_rcx, REG_zero, sizeshift, 0, 0, FLAGS_DEFAULT_ALU);
    testop.nouserflags = 1;
    this << testop;

    if (!last_flags_update_was_atomic)
      this << TransOp(OP_collcc, REG_temp0, REG_zf, REG_cf, REG_of, 3, 0, 0, FLAGS_DEFAULT_ALU);

    TransOp transop(OP_br, REG_rip, REG_temp1, REG_zero, REG_zero, 3, 0);
    transop.cond = COND_e;
    transop.riptaken = (Waddr)rip + ra.imm.imm;
    transop.ripseq = (Waddr)rip;
    bb.rip_taken = (Waddr)rip + ra.imm.imm;
    bb.rip_not_taken = (Waddr)rip;
    this << transop;
    end_of_block = true;
    break;
  }

  case 0xe4 ... 0xe7: {
    // inb/inw/outb/outw imm8/imm16: NOT SUPPORTED
    MakeInvalid();
    assert(false);
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
    //++MTY TODO: this should be trapped by hypervisor to properly do idle time
    CheckInvalid();
    this << TransOp(OP_nop, REG_temp0, REG_zero, REG_zero, REG_zero, 3);
    break;
  }

    //
    // NOTE: Some forms of this are handled by the fast decoder:
    //
  case 0xf6 ... 0xf7: {
    // GRP3b and GRP3S
    DECODE(eform, rd, (op & 1) ? v_mode : b_mode);
    CheckInvalid();

    switch (modrm.reg) {
    case 0 ... 3: // test, (inv), not, neg
      // These are handled by the fast decoder!
      abort();
      break;
      //
      // NOTE: gcc does not synthesize these forms of imul since they target both %rdx:%rax.
      // However, it DOES use idiv in this form, so we need to implement it. Probably a microcode
      // callout would be appropriate here: first get the operand into some known register,
      // then encode a microcode callout.
      //
    case 4:
    case 5: {
      // mul (4), imul (5)
      int srcreg;

      if (rd.type == OPTYPE_REG) {
        srcreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      } else {
        ra.type = OPTYPE_REG;
        ra.reg.reg = 0; // not used
        move_reg_or_mem(ra, rd, REG_temp4);
        srcreg = REG_temp4;
      }

      int size = (rd.type == OPTYPE_REG) ? reginfo[rd.reg.reg].sizeshift : rd.mem.size;

      int highop = (modrm.reg == 4) ? OP_mulhu : OP_mulh;

      if (size == 0) {
        // ax <- al * src
        this << TransOp(OP_mov,  REG_temp0, REG_zero, srcreg, REG_zero, 3);
        this << TransOp(highop, REG_temp1, REG_rax, REG_temp0, REG_zero, size, 0, 0, SETFLAG_CF|SETFLAG_OF);
        this << TransOp(OP_mull, REG_rax, REG_rax, REG_temp0, REG_zero, size);
        // insert high byte
        this << TransOp(OP_maskb, REG_rax, REG_rax, REG_temp1, REG_imm, 3, 0, MaskControlInfo(56, 8, 56));
      } else {
        // dx:ax = ax * src
        // edx:eax = eax * src
        // rdx:rax = rax * src
        this << TransOp(OP_mov,  REG_temp0, REG_zero, srcreg, REG_zero, 3);
        this << TransOp(highop, REG_rdx, REG_rax, REG_temp0, REG_zero, size, 0, 0, SETFLAG_CF|SETFLAG_OF);
        this << TransOp(OP_mull, REG_rax, REG_rax, REG_temp0, REG_zero, size);
      }
      break;
    }
    default:
      // 6, 7
      ra.type = OPTYPE_REG;
      ra.reg.reg = 0; // not used
      move_reg_or_mem(ra, rd, REG_ar1);

      int subop_and_size_to_assist_idx[4][4] = {
        {ASSIST_DIV8,  ASSIST_DIV16,  ASSIST_DIV32,  ASSIST_DIV64},
        {ASSIST_IDIV8, ASSIST_IDIV16, ASSIST_IDIV32, ASSIST_IDIV64}
      };

      int size = (rd.type == OPTYPE_REG) ? reginfo[rd.reg.reg].sizeshift : rd.mem.size;

      microcode_assist(subop_and_size_to_assist_idx[modrm.reg - 6][size], ripstart, rip);
      end_of_block = 1;
    }
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

  case 0x120: { // mov reg,crN
    DECODE(eform, rd, v_mode);
    DECODE(gform, ra, v_mode);
#ifdef PTLSIM_HYPERVISOR
    if (rd.type != OPTYPE_REG) MakeInvalid();
    CheckInvalid();

    int offset;

    switch (modrm.reg) {
    case 0: offset = offsetof(Context, cr0); break;
    case 1: offset = offsetof(Context, cr1); break;
    case 2: offset = offsetof(Context, cr2); break;
    case 3: offset = offsetof(Context, cr3); break;
    case 4: offset = offsetof(Context, cr4); break;
    case 5: offset = offsetof(Context, cr5); break;
    case 6: offset = offsetof(Context, cr6); break;
    case 7: offset = offsetof(Context, cr7); break;
    default: MakeInvalid();
    }

    TransOp ldp(OP_ld, arch_pseudo_reg_to_arch_reg[rd.reg.reg], REG_ctx, REG_imm, REG_zero, 3, offset); ldp.internal = 1; this << ldp;
#else
    MakeInvalid();
#endif
    break;
  }

  case 0x132: { // rdmsr
    microcode_assist(ASSIST_RDMSR, ripstart, rip);
    end_of_block = 1;
    break;
  };

  case 0x130: { // wrmsr
    microcode_assist(ASSIST_WRMSR, ripstart, rip);
    end_of_block = 1;
    break;
  };

  case 0x1a3: // bt ra,rb     101 00 011
  case 0x1ab: // bts ra,rb    101 01 011
  case 0x1b3: // btr ra,rb    101 10 011
  case 0x1bb: { // btc ra,rb  101 11 011
    // Fast decoder handles only reg forms
    DECODE(eform, rd, v_mode);
    DECODE(gform, ra, v_mode);
    CheckInvalid();

    static const byte x86_to_uop[4] = {OP_bt, OP_bts, OP_btr, OP_btc};
    int opcode = x86_to_uop[bits(op, 3, 2)];

    if (rd.type == OPTYPE_REG) {
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];

      // bt has no output - just flags:
      this << TransOp(opcode, (opcode == OP_bt) ? REG_temp0 : rdreg, rdreg, rareg, REG_zero, 3, 0, 0, SETFLAG_CF);
      break;
    } else {
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];

      rd.mem.size = (use64 ? (addrsize_prefix ? 2 : 3) : (addrsize_prefix ? 1 : 2));
      address_generate_and_load_or_store(REG_temp1, REG_zero, rd, OP_add, 0, 0, true);

      this << TransOp(OP_sar, REG_temp2, rareg, REG_imm, REG_zero, 3, 3); // byte index
      this << TransOp(OP_ld, REG_temp0, REG_temp1, REG_temp2, REG_zero, 0);
      this << TransOp(opcode, REG_temp0, REG_temp0, rareg, REG_zero, 0, 0, 0, SETFLAG_CF);

      if (opcode != OP_bt) {
        this << TransOp(OP_st, REG_mem, REG_temp1, REG_temp2, REG_temp0, 0);
      }

      break;
    }
  }

  case 0x1ba: { // bt|btc|btr|bts mem,imm
    // Fast decoder handles only reg forms
    DECODE(eform, rd, v_mode);
    DECODE(iform, ra, b_mode);
    if (modrm.reg < 4) MakeInvalid();
    CheckInvalid();

    static const byte x86_to_uop[4] = {OP_bt, OP_bts, OP_btr, OP_btc};
    int opcode = x86_to_uop[lowbits(modrm.reg, 2)];

    if (rd.type == OPTYPE_REG) {
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];

      // bt has no output - just flags:
      this << TransOp(opcode, (opcode == OP_bt) ? REG_temp0 : rdreg, rdreg, REG_imm, REG_zero, 3, ra.imm.imm, 0, SETFLAG_CF);
      break;
    } else {
      rd.mem.size = (use64 ? (addrsize_prefix ? 2 : 3) : (addrsize_prefix ? 1 : 2));
      address_generate_and_load_or_store(REG_temp1, REG_zero, rd, OP_add, 0, 0, true);

      this << TransOp(OP_ld, REG_temp0, REG_temp1, REG_imm, REG_zero, 0, ra.imm.imm >> 3);
      this << TransOp(opcode, REG_temp0, REG_temp0, REG_imm, REG_zero, 0, lowbits(ra.imm.imm, 3), 0, SETFLAG_CF);

      if (opcode != OP_bt) {
        this << TransOp(OP_st, REG_mem, REG_temp1, REG_imm, REG_temp0, 0, ra.imm.imm >> 3);
      }

      break;
    }
  }

  case 0x1a4 ... 0x1a5: // shld rd,[imm|cl]
  case 0x1ac ... 0x1ad: { // shrd rd,[imm|cl]
    DECODE(eform, rd, v_mode);
    DECODE(gform, ra, v_mode);

    bool left = (op == 0x1a4 || op == 0x1a5);

    bool immform = (bit(op, 0) == 0);
    DecodedOperand rimm;
    rimm.imm.imm = 0;
    if (immform) DECODE(iform, rimm, b_mode);
    CheckInvalid();

    int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];

    if (rd.type == OPTYPE_MEM) operand_load(REG_temp4, rd);
    int rdreg = (rd.type == OPTYPE_MEM) ? REG_temp4 : arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rdsize = (rd.type == OPTYPE_MEM) ? rd.mem.size : reginfo[rd.reg.reg].sizeshift;

    byte imm = lowbits(rimm.imm.imm, 3 + rdsize);

    if (immform & (imm == 0)) {
      // No action and no flags update
      this << TransOp(OP_nop,   REG_temp0, REG_zero,  REG_zero,  REG_zero, 0);
      break;
    }
    
    if (!immform) {
      if (left) {
        //
        // Build mask: (58 = 64-6, 52 = 64-12)
        //
        // Example (shift left count 3):
        //
        // In:  d7 d6 d5 d4 d3 d2 d1 d0   a7 a6 a5 a4 a3 a2 a1 a0
        //      d4 d3 d2 d1 d0 -- -- -- | << c
        //      >>> 64-c                | -- -- -- -- -- a7 a6 a5
        //
        // Therefore: mask (rd << c), rs, [ms=0, mc=c, ds=64-c]
        //   ms = 0
        //   mc = c
        //   ds = 64-c
        //

        this << TransOp(OP_and,   REG_temp0, REG_rcx,   REG_imm,   REG_zero, 3, bitmask(3 + rdsize));
        this << TransOp(OP_mov,   REG_temp2, REG_zero,  REG_imm,   REG_zero, 0, (1 << rdsize) * 8); // load inverse count (e.g. 64 - c)
        this << TransOp(OP_sub,   REG_temp2, REG_temp2, REG_temp0, REG_zero, 0); // load inverse count (e.g. 64 - c)
        // Form [ 64-c | c ]
        this << TransOp(OP_maskb, REG_temp1, REG_temp0, REG_temp2, REG_imm,  3, 0, MaskControlInfo(58, 6, 58));
        // Form [ 64-c | c | 0 ]
        this << TransOp(OP_shl,   REG_temp1, REG_temp1, REG_imm,   REG_zero, 3, 6);
      } else {
        //
        // Build mask: (58 = 64-6, 52 = 64-12)
        // and   t0 = c,sizemask
        // maskq t1 = t0,t0,[ms=58, mc=6, ds=58]       // build 0|c|c
        // maskq t1 = t1,t0,[ms=52, mc=6, ds=52]       // build c|c|c
        //
        this << TransOp(OP_and,   REG_temp0, REG_rcx,   REG_imm,   REG_zero, 3, bitmask(3 + rdsize));
        this << TransOp(OP_maskb, REG_temp1, REG_temp0, REG_temp0, REG_imm,  3, 0, MaskControlInfo(58, 6, 58));
        this << TransOp(OP_maskb, REG_temp1, REG_temp1, REG_temp0, REG_imm,  3, 0, MaskControlInfo(52, 6, 52));
      }
    }

    //
    // Collect the old flags here in case the shift count was zero:
    //
    if (!immform) this << TransOp(OP_collcc,REG_temp2, REG_zf,    REG_cf,    REG_of,   3, 0, 0, FLAGS_DEFAULT_ALU);

    //
    // To simplify the microcode construction of the shrd/shld instructions,
    // the following sequence may be used:
    //
    // shrd rd,rs:
    //
    // shr  t = rd,c          
    //      t.cf = rd[c-1] last bit shifted out
    //      t.of = rd[63]  or whatever rd's original sign bit position was
    // mask rd = t,rs,[ms=c, mc=c, ds=c]
    //      rd.cf = t.cf  inherited from t
    //      rd.of = (out.sf != t.of) i.e. did the sign bit change?
    //
    // shld rd,rs:
    //
    // shl  t = rd,c          
    //      t.cf = rd[64-c] last bit shifted out
    //      t.of = rd[63]   or whatever rd's original sign bit position was
    // mask rd = t,rs,[ms=0, mc=c, ds=64-c]
    //      rd.cf = t.cf  inherited from t
    //      rd.of = (out.sf != t.of) i.e. did the sign bit change?
    //

    int shiftreg = (immform) ? REG_imm : REG_temp0;
    int maskreg = (immform) ? REG_imm : REG_temp1;
    int opcode = (left) ? OP_shl : OP_shr;
    this << TransOp(opcode,   rdreg,     rdreg,     shiftreg,  REG_zero,  rdsize, imm, 0, FLAGS_DEFAULT_ALU);
    W64 maskctl = (left) ? MaskControlInfo(0, imm, ((1 << rdsize)*8) - imm) : MaskControlInfo(imm, imm, imm);
    this << TransOp(OP_mask,  rdreg,     rdreg,     rareg,     maskreg,   rdsize, 0, maskctl, FLAGS_DEFAULT_ALU);

    if (rd.type == OPTYPE_MEM) result_store(rdreg, REG_temp5, rd);

    //
    // Account for no flag changes if zero shift:
    // sub   t0 = t0,t0
    // sel.e t0 = rd,t2,t0      [zco] (t2 = original flags)
    //
    if (!immform) {
      this << TransOp(OP_and,   REG_temp0, REG_temp0, REG_temp0, REG_zero,  0,      0, 0, FLAGS_DEFAULT_ALU);
      TransOp selop  (OP_sel,   REG_temp0, rdreg,     REG_temp2, REG_temp0, 3,      0, 0, FLAGS_DEFAULT_ALU);
      selop.cond = COND_e; this << selop;
    }
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

    TransOp selmem(OP_sel, REG_temp2, REG_temp0, rareg, REG_temp1, sizeshift);
    selmem.cond = COND_e;
    this << selmem;

    TransOp selreg(OP_sel, REG_rax, REG_rax, REG_temp0, REG_temp1, sizeshift);
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

  case 0x1c3: {
    // movnti
    DECODE(eform, rd, v_mode);
    DECODE(gform, ra, v_mode);
    CheckInvalid();
    move_reg_or_mem(rd, ra);
    break;
  }

  case 0x1ae: {
    // fxsave fxrstor ldmxcsr stmxcsr (inv) lfence mfence sfence
    switch (modrm.reg) {
    case 0: { // fxsave
      DECODE(eform, ra, q_mode);
      CheckInvalid();

      // Get effective address into sr2
      int basereg = arch_pseudo_reg_to_arch_reg[ra.mem.basereg];
      int indexreg = arch_pseudo_reg_to_arch_reg[ra.mem.indexreg];
      basereg = bias_by_segreg(basereg);
      TransOp addop(OP_adda, REG_ar1, basereg, REG_imm, indexreg, (use64) ? 3 : 2, ra.mem.offset);
      addop.extshift = ra.mem.scale;
      this << addop;

      microcode_assist(ASSIST_FXSAVE, ripstart, rip);
      end_of_block = 1;
      break;
    }
    case 2: { // ldmxcsr
      DECODE(eform, ra, d_mode);
      CheckInvalid();

      ra.type = OPTYPE_REG;
      ra.reg.reg = 0; // get the requested mxcsr into sr2
      move_reg_or_mem(ra, rd, REG_ar1);
      //
      // LDMXCSR needs to flush the pipeline since future FP instructions will
      // depend on its value and can't be issued out of order w.r.t the mxcsr.
      //
      microcode_assist(ASSIST_LDMXCSR, ripstart, rip);
      end_of_block = 1;
      break;
    }
    case 3: { // stmxcsr
      DECODE(eform, rd, d_mode);
      CheckInvalid();

      TransOp ldp(OP_ld, REG_temp1, REG_ctx, REG_imm, REG_zero, 1, offsetof(Context, mxcsr)); ldp.internal = 1; this << ldp;
      result_store(REG_temp1, REG_temp0, rd);
      break;
    }
    case 5: // lfence
    case 6: // mfence
    case 7: { // sfence
      CheckInvalid();
      this << TransOp(OP_nop, REG_temp0, REG_zero, REG_zero, REG_zero, 3);
      break;
    }
    default:
      MakeInvalid();
      break;
    }
    break;
  }

  case 0x105: {
    // syscall
    // Saves return address into %rcx and jumps to MSR_LSTAR
    CheckInvalid();
    immediate(REG_rcx, 3, (Waddr)rip);
    microcode_assist(ASSIST_SYSCALL, ripstart, rip);
    end_of_block = 1;
    break;
  }

  case 0x134: {
    // sysenter
    //
    // Technically, sysenter does not save anything (even the return address)
    // but we do not have the information the kernel has about the fixed %eip
    // to return to, so we have to pretend:
    //
    CheckInvalid();
    microcode_assist(ASSIST_SYSENTER, ripstart, rip);
    end_of_block = 1;
    break;
  }

  case 0x131: {
    // rdtsc: put result into %edx:%eax
    CheckInvalid();
    TransOp ldp1(OP_ld, REG_rdx, REG_zero, REG_imm, REG_zero, 3, (Waddr)&sim_cycle); ldp1.internal = 1; this << ldp1;
#ifdef PTLSIM_HYPERVISOR
    TransOp ldp2(OP_ld, REG_temp0, REG_ctx, REG_imm, REG_zero, 3, offsetof(Context, base_tsc)); ldp2.internal = 1; this << ldp2;
    this << TransOp(OP_add, REG_rdx, REG_rdx, REG_temp0, REG_zero, 3);
#endif
    this << TransOp(OP_mov, REG_rax, REG_zero, REG_rdx, REG_zero, 2);
    this << TransOp(OP_shr, REG_rdx, REG_rdx, REG_imm, REG_zero, 3, 32);
    break;
  }

  case 0x1a2: {
    // cpuid: update %rax,%rbx,%rcx,%rdx
    CheckInvalid();
    microcode_assist(ASSIST_CPUID, ripstart, rip);
    end_of_block = 1;
    break;
  }

  case 0x137: { // 0f 37: PTL undocumented opcode
    CheckInvalid();
    microcode_assist(ASSIST_PTLCALL, ripstart, rip);      
    end_of_block = 1;
    break;
  }

  default: {
    MakeInvalid();
    break;
  }
  }

  return true;
}
