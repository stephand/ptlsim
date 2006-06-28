//
// PTLsim: Cycle Accurate x86-64 Simulator
// Functions common to both PTLmon and core PTLxen
//
// Copyright 2005-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <ptlxen.h>

void Context::restorefrom(const vcpu_guest_context& ctx) {
  commitarf[REG_rax] = ctx.user_regs.rax;
  commitarf[REG_rcx] = ctx.user_regs.rcx;
  commitarf[REG_rdx] = ctx.user_regs.rdx;
  commitarf[REG_rbx] = ctx.user_regs.rbx;
  commitarf[REG_rsp] = ctx.user_regs.rsp;
  commitarf[REG_rbp] = ctx.user_regs.rbp;
  commitarf[REG_rsi] = ctx.user_regs.rsi;
  commitarf[REG_rdi] = ctx.user_regs.rdi;
  commitarf[REG_r8] = ctx.user_regs.r8;
  commitarf[REG_r9] = ctx.user_regs.r9;
  commitarf[REG_r10] = ctx.user_regs.r10;
  commitarf[REG_r11] = ctx.user_regs.r11;
  commitarf[REG_r12] = ctx.user_regs.r12;
  commitarf[REG_r13] = ctx.user_regs.r13;
  commitarf[REG_r14] = ctx.user_regs.r14;
  commitarf[REG_r15] = ctx.user_regs.r15;

  commitarf[REG_rip] = ctx.user_regs.rip;
  commitarf[REG_flags] = ctx.user_regs.eflags;

  exception_type = ctx.user_regs.entry_vector;
  error_code = ctx.user_regs.error_code;

  kernel_mode = ((ctx.flags & VGCF_IN_KERNEL) != 0);
  i387_valid = ((ctx.flags & VGCF_I387_VALID) != 0);
  failsafe_disables_events = ((ctx.flags & VGCF_failsafe_disables_events) != 0);
  syscall_disables_events = ((ctx.flags & VGCF_syscall_disables_events) != 0);

  // use32, use64 updated below

  foreach (i, lengthof(ctx.trap_ctxt)) {
    const trap_info& ti = ctx.trap_ctxt[i];
    TrapTarget& tt = idt[ti.vector];
    tt.cs = ti.cs;
    tt.rip = ti.address;
    tt.cpl = lowbits(ti.flags, 2);
    tt.maskevents = bit(ti.flags, 2);
  }

  ldtvirt = ctx.ldt_base;
  ldtsize = ctx.ldt_ents;
  foreach (i, lengthof(gdtpages)) gdtpages[i] = ctx.gdt_frames[i];
  gdtsize = ctx.gdt_ents;

  kernel_ss = ctx.kernel_ss;
  kernel_sp = ctx.kernel_sp;
  cr0 = ctx.ctrlreg[0];
  cr1 = ctx.ctrlreg[1];
  cr2 = ctx.ctrlreg[2];
  cr3 = ctx.ctrlreg[3];
  cr4 = ctx.ctrlreg[4];
  cr5 = ctx.ctrlreg[5];
  cr6 = ctx.ctrlreg[6];
  cr7 = ctx.ctrlreg[7];

  dr0 = ctx.debugreg[0];
  dr1 = ctx.debugreg[1];
  dr2 = ctx.debugreg[2];
  dr3 = ctx.debugreg[3];
  dr4 = ctx.debugreg[4];
  dr5 = ctx.debugreg[5];
  dr6 = ctx.debugreg[6];
  dr7 = ctx.debugreg[7];

  saved_upcall_mask = ctx.user_regs.saved_upcall_mask;
  event_callback_rip = ctx.event_callback_eip;
  failsafe_callback_rip = ctx.failsafe_callback_eip;
  syscall_rip = ctx.syscall_callback_eip;
  vm_assist = ctx.vm_assist;

  fs_base = ctx.fs_base;
  gs_base_kernel = ctx.gs_base_kernel;
  gs_base_user = ctx.gs_base_user;

  seg[SEGID_CS].selector = ctx.user_regs.cs;
  seg[SEGID_SS].selector = ctx.user_regs.ss;
  seg[SEGID_DS].selector = ctx.user_regs.ds;
  seg[SEGID_ES].selector = ctx.user_regs.es;
  seg[SEGID_FS].selector = ctx.user_regs.fs;
  seg[SEGID_GS].selector = ctx.user_regs.gs;

  fxrstor(*(const FXSAVEStruct*)&ctx.fpu_ctxt);
}

void Context::saveto(vcpu_guest_context& ctx) {
  ctx.user_regs.rax = commitarf[REG_rax];
  ctx.user_regs.rcx = commitarf[REG_rcx];
  ctx.user_regs.rdx = commitarf[REG_rdx];
  ctx.user_regs.rbx = commitarf[REG_rbx];
  ctx.user_regs.rsp = commitarf[REG_rsp];
  ctx.user_regs.rbp = commitarf[REG_rbp];
  ctx.user_regs.rsi = commitarf[REG_rsi];
  ctx.user_regs.rdi = commitarf[REG_rdi];
  ctx.user_regs.r8 = commitarf[REG_r8];
  ctx.user_regs.r9 = commitarf[REG_r9];
  ctx.user_regs.r10 = commitarf[REG_r10];
  ctx.user_regs.r11 = commitarf[REG_r11];
  ctx.user_regs.r12 = commitarf[REG_r12];
  ctx.user_regs.r13 = commitarf[REG_r13];
  ctx.user_regs.r14 = commitarf[REG_r14];
  ctx.user_regs.r15 = commitarf[REG_r15];

  ctx.user_regs.rip = commitarf[REG_rip];
  ctx.user_regs.eflags = commitarf[REG_flags];

  ctx.user_regs.entry_vector = exception_type;
  ctx.user_regs.error_code = error_code;

  ctx.flags = 0;
  if (kernel_mode) ctx.flags |= VGCF_IN_KERNEL;
  if (i387_valid) ctx.flags |= VGCF_I387_VALID;
  if (failsafe_disables_events) ctx.flags |= VGCF_failsafe_disables_events;
  if (syscall_disables_events) ctx.flags |= VGCF_syscall_disables_events;

  // use32, use64 implied by CS descriptor

  setzero(ctx.trap_ctxt);
  foreach (i, lengthof(ctx.trap_ctxt)) {
    const TrapTarget& tt = idt[i];
    trap_info& ti = ctx.trap_ctxt[i];
    ti.vector = i;
    ti.cs = tt.cs;
    ti.address = tt.rip;
    ti.flags = tt.cpl | (tt.maskevents << 2);
  }

  ctx.ldt_base = ldtvirt;
  ctx.ldt_ents = ldtsize;
  foreach (i, lengthof(gdtpages)) ctx.gdt_frames[i] = gdtpages[i];
  ctx.gdt_ents = gdtsize;

  ctx.kernel_ss = kernel_ss;
  ctx.kernel_sp = kernel_sp;
  ctx.ctrlreg[0] = cr0;
  ctx.ctrlreg[1] = cr1;
  ctx.ctrlreg[2] = cr2;
  ctx.ctrlreg[3] = cr3;
  ctx.ctrlreg[4] = cr4;
  ctx.ctrlreg[5] = cr5;
  ctx.ctrlreg[6] = cr6;
  ctx.ctrlreg[7] = cr7;

  ctx.debugreg[0] = dr0;
  ctx.debugreg[1] = dr1;
  ctx.debugreg[2] = dr2;
  ctx.debugreg[3] = dr3;
  ctx.debugreg[4] = dr4;
  ctx.debugreg[5] = dr5;
  ctx.debugreg[6] = dr6;
  ctx.debugreg[7] = dr7;

  ctx.user_regs.saved_upcall_mask = saved_upcall_mask;
  ctx.event_callback_eip = event_callback_rip;
  ctx.failsafe_callback_eip = failsafe_callback_rip;
  ctx.syscall_callback_eip = syscall_rip;
  ctx.vm_assist = vm_assist;

  ctx.fs_base = fs_base;
  ctx.gs_base_kernel = gs_base_kernel;
  ctx.gs_base_user = gs_base_user;

  ctx.user_regs.cs = seg[SEGID_CS].selector;
  ctx.user_regs.ss = seg[SEGID_SS].selector;
  ctx.user_regs.ds = seg[SEGID_DS].selector;
  ctx.user_regs.es = seg[SEGID_ES].selector;
  ctx.user_regs.fs = seg[SEGID_FS].selector;
  ctx.user_regs.gs = seg[SEGID_GS].selector;

  fxsave(*(FXSAVEStruct*)&ctx.fpu_ctxt);
}

ostream& operator <<(ostream& os, const LongModeLevel1PTE& pte) {
  if (pte.p) {
    os << ((pte.rw) ? "wrt " : "-   ");
    os << ((pte.us) ? "sup " : "-   ");
    os << ((pte.nx) ? "nx  " : "-   ");
    os << ((pte.a) ? "acc " : "-   ");
    os << ((pte.d) ? "dty " : "-   ");
    os << ((pte.pat) ? "pat " : "-   ");
    os << ((pte.pwt) ? "wt  " : "-   ");
    os << ((pte.pcd) ? "cd  " : "-   ");
    os << ((pte.g) ? "gbl " : "-   ");
    os << " phys 0x", hexstring((W64)pte.phys << 12, 40), " mfn ", intstring(pte.phys, 10);
  } else {
    os << "(not present)";
  }
  return os;
}

ostream& operator <<(ostream& os, const LongModeLevel2PTE& pte) {
  if (pte.p) {
    os << ((pte.rw) ? "wrt " : "-   ");
    os << ((pte.us) ? "sup " : "-   ");
    os << ((pte.nx) ? "nx  " : "-   ");
    os << ((pte.a) ? "acc " : "-   ");
    os << "    ";
    os << "    ";
    os << ((pte.pwt) ? "wt  " : "-   ");
    os << ((pte.pcd) ? "cd  " : "-   ");
    os << ((pte.psz) ? "psz " : "-   ");
    os << " next 0x", hexstring((W64)pte.next << 12, 40), " mfn ", intstring(pte.next, 10);
  } else {
    os << "(not present)";
  }
  return os;
}

ostream& operator <<(ostream& os, const LongModeLevel3PTE& pte) {
  if (pte.p) {
    os << ((pte.rw) ? "wrt " : "-   ");
    os << ((pte.us) ? "sup " : "-   ");
    os << ((pte.nx) ? "nx  " : "-   ");
    os << ((pte.a) ? "acc " : "-   ");
    os << "    ";
    os << "    ";
    os << ((pte.pwt) ? "wt  " : "-   ");
    os << ((pte.pcd) ? "cd  " : "-   ");
    os << "    ";
    os << " next 0x", hexstring((W64)pte.next << 12, 40), " mfn ", intstring(pte.next, 10);
  } else {
    os << "(not present)";
  }
  return os;
}

ostream& operator <<(ostream& os, const LongModeLevel4PTE& pte) {
  if (pte.p) {
    os << ((pte.rw) ? "wrt " : "-   ");
    os << ((pte.us) ? "sup " : "-   ");
    os << ((pte.nx) ? "nx  " : "-   ");
    os << ((pte.a) ? "acc " : "-   ");
    os << "    ";
    os << "    ";
    os << ((pte.pwt) ? "wt  " : "-   ");
    os << ((pte.pcd) ? "cd  " : "-   ");
    os << "    ";
    os << " next 0x", hexstring((W64)pte.next << 12, 40), " mfn ", intstring(pte.next, 10);
  } else {
    os << "(not present)";
  }
  return os;
}

ostream& print_page_table(ostream& os, LongModeLevel1PTE* ptes, W64 baseaddr) {
  VirtAddr virt(baseaddr);

  virt.lm.offset = 0;
  virt.lm.level1 = 0;

  foreach (i, 512) {
    virt.lm.level1 = i;
    os << "        ", hexstring(virt, 64), " -> ", ptes[i], endl;
  }

  return os;
}

const char* PageFrameType::names[] = {"normal", "L1", "L2", "L3", "L4", "(5)", "(6)", "invalid"};

/*
ostream& operator <<(ostream& os, const cpu_user_regs_t& regs) {
  os << "  State Registers:", endl;
  os << "    rip ", hexstring(regs.rip, 64), "  flg ", hexstring(regs.rflags, 64), endl;
  os << "  Integer Registers:", endl;
  os << "    rax ", hexstring(regs.rax, 64), "  rcx ", hexstring(regs.rcx, 64), "  rdx ", hexstring(regs.rdx, 64),  " rbx ", hexstring(regs.rbx, 64), endl;
  os << "    rsp ", hexstring(regs.rsp, 64), "  rbp ", hexstring(regs.rbp, 64), "  rsi ", hexstring(regs.rsi, 64),  " rdi ", hexstring(regs.rdi, 64), endl;
  os << "    r8  ", hexstring(regs.r8, 64),  "  rbp ", hexstring(regs.r9, 64),  "  r10 ", hexstring(regs.r10, 64),  " r11 ", hexstring(regs.r11, 64), endl;
  os << "    r12 ", hexstring(regs.r12, 64), "  r13 ", hexstring(regs.r13, 64), "  r14 ", hexstring(regs.r14, 64),  " r15 ", hexstring(regs.r15, 64), endl;
  os << "  Segment Registers:", endl;
  os << "    cs  ", hexstring(regs.cs, 16), "  ds ", hexstring(regs.ds, 16), "  ss ", hexstring(regs.ss, 16), "  es ", hexstring(regs.es, 16), "  fs ", hexstring(regs.fs, 16), "  gs ", hexstring(regs.gs, 16), endl;
  os << "  Other Registers:", endl;
  os << "    err ", hexstring(regs.error_code, 32), "  evc ", hexstring(regs.entry_vector, 32), "  saved_upcall_mask ", hexstring(regs.saved_upcall_mask, 8), endl;
  return os;
}

ostream& operator <<(ostream& os, const vcpu_guest_context_t& ctx) {
  os << ctx.user_regs;
  os << "  Debug Registers:", endl;
  os << "    dr0 ", hexstring(ctx.debugreg[0], 64), "  dr1 ", hexstring(ctx.debugreg[1], 64), "  dr2 ", hexstring(ctx.debugreg[2], 64),  "  dr3 ", hexstring(ctx.debugreg[3], 64), endl;
  os << "    dr4 ", hexstring(ctx.debugreg[4], 64), "  dr5 ", hexstring(ctx.debugreg[5], 64), "  dr6 ", hexstring(ctx.debugreg[6], 64),  "  dr7 ", hexstring(ctx.debugreg[7], 64), endl;
  os << "  Control Registers:", endl;
  os << "    cr0 ", hexstring(ctx.ctrlreg[0], 64), "  cr1 ", hexstring(ctx.ctrlreg[1], 64), "  cr2 ", hexstring(ctx.ctrlreg[2], 64),  "  cr3 ", hexstring(ctx.ctrlreg[3], 64), endl;
  os << "    cr4 ", hexstring(ctx.ctrlreg[4], 64), "  cr5 ", hexstring(ctx.ctrlreg[5], 64), "  cr6 ", hexstring(ctx.ctrlreg[6], 64),  "  cr7 ", hexstring(ctx.ctrlreg[7], 64), endl;
  os << "    kss ", hexstring(ctx.kernel_ss, 64), "  ksp ", hexstring(ctx.kernel_sp, 64), "  vma ", hexstring(ctx.vm_assist, 64),  "  flg ", hexstring(ctx.flags, 64), endl;
  os << "  Segment Registers:", endl;
  os << "    ldt ", hexstring(ctx.ldt_base, 64), "  ld# ", hexstring(ctx.ldt_ents, 64), "  gd# ", hexstring(ctx.gdt_ents, 64), endl;
  os << "    gdt mfns"; foreach (i, 16) { os << " ", ctx.gdt_frames[i]; } os << endl;
  os << "    fsB ", hexstring(ctx.fs_base, 64), "  gsB ", hexstring(ctx.gs_base_user, 64), "  gkB ", hexstring(ctx.gs_base_kernel, 64), endl;
  os << "  Callbacks:", endl;
  os << "    event_callback_rip    ", hexstring(ctx.event_callback_eip, 64), endl;
  os << "    failsafe_callback_rip ", hexstring(ctx.failsafe_callback_eip, 64), endl;
  os << "    syscall_callback_rip  ", hexstring(ctx.syscall_callback_eip, 64), endl;
  return os;
}
*/
