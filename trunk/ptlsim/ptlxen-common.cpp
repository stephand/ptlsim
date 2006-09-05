//
// PTLsim: Cycle Accurate x86-64 Simulator
// Functions common to both PTLmon and PTLxen core
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
  commitarf[REG_flags] = ctx.user_regs.eflags & (FLAG_ZAPS|FLAG_CF|FLAG_OF);
  internal_eflags = ctx.user_regs.eflags & ~(FLAG_ZAPS|FLAG_CF|FLAG_OF);

  x86_exception = ctx.user_regs.entry_vector;
  error_code = ctx.user_regs.error_code;

  kernel_mode = ((ctx.flags & VGCF_IN_KERNEL) != 0);
  kernel_in_syscall = ((ctx.flags & VGCF_IN_SYSCALL) != 0);
  i387_valid = ((ctx.flags & VGCF_I387_VALID) != 0);
  failsafe_disables_events = ((ctx.flags & VGCF_failsafe_disables_events) != 0);
  syscall_disables_events = ((ctx.flags & VGCF_syscall_disables_events) != 0);

  // use32, use64 updated below

  foreach (i, lengthof(ctx.trap_ctxt)) {
    const trap_info& ti = ctx.trap_ctxt[i];
    TrapTarget& tt = idt[ti.vector];
    tt.cs = ti.cs >> 3;
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

  user_runstate = null;

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

  //
  // VIRQs must be rebound by the guest:
  //
  foreach (i, NR_VIRQS) virq_to_port[i] = -1;

  running = 1;
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
  ctx.user_regs.eflags = 
    (commitarf[REG_flags] & (FLAG_ZAPS|FLAG_CF|FLAG_OF)) |
    (internal_eflags & ~(FLAG_ZAPS|FLAG_CF|FLAG_OF));
  ctx.user_regs.eflags = (ctx.user_regs.eflags & ~FLAG_IOPL) | ((kernel_mode ? 1 : 3) << 12);

  ctx.user_regs.entry_vector = x86_exception;
  ctx.user_regs.error_code = error_code;

  ctx.flags = 0;
  if (kernel_mode) ctx.flags |= VGCF_IN_KERNEL;
  if (kernel_in_syscall) ctx.flags |= VGCF_IN_SYSCALL;
  if (i387_valid) ctx.flags |= VGCF_I387_VALID;
  if (failsafe_disables_events) ctx.flags |= VGCF_failsafe_disables_events;
  if (syscall_disables_events) ctx.flags |= VGCF_syscall_disables_events;

  // use32, use64 implied by CS descriptor

  setzero(ctx.trap_ctxt);
  foreach (i, lengthof(ctx.trap_ctxt)) {
    const TrapTarget& tt = idt[i];
    trap_info& ti = ctx.trap_ctxt[i];
    ti.vector = i;
    ti.cs = (tt.cs << 3) | 3;
    ti.address = signext64(tt.rip, 48);
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

ostream& operator <<(ostream& os, const Level1PTE& pte) {
  if (pte.p) {
    os << ((pte.rw) ? "wrt " : "-   ");
    os << ((pte.us) ? "u+s " : "sup ");
    os << ((pte.nx) ? "nx  " : "exe ");
    os << ((pte.a) ? "acc " : "-   ");
    os << ((pte.d) ? "dty " : "-   ");
    os << ((pte.pat) ? "pat " : "-   ");
    os << ((pte.pwt) ? "wt  " : "-   ");
    os << ((pte.pcd) ? "cd  " : "-   ");
    os << ((pte.g) ? "gbl " : "-   ");
    os << " phys 0x", hexstring((W64)pte.mfn << 12, 40), " mfn ", intstring(pte.mfn, 10);
  } else {
    os << "(not present)";
  }
  return os;
}

ostream& operator <<(ostream& os, const Level2PTE& pte) {
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
    os << " next 0x", hexstring((W64)pte.mfn << 12, 40), " mfn ", intstring(pte.mfn, 10);
  } else {
    os << "(not present)";
  }
  return os;
}

ostream& operator <<(ostream& os, const Level3PTE& pte) {
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
    os << " next 0x", hexstring((W64)pte.mfn << 12, 40), " mfn ", intstring(pte.mfn, 10);
  } else {
    os << "(not present)";
  }
  return os;
}

ostream& operator <<(ostream& os, const Level4PTE& pte) {
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
    os << " next 0x", hexstring((W64)pte.mfn << 12, 40), " mfn ", intstring(pte.mfn, 10);
  } else {
    os << "(not present)";
  }
  return os;
}

ostream& print_page_table(ostream& os, Level1PTE* ptes, W64 baseaddr) {
  VirtAddr virt(baseaddr);

  virt.lm.offset = 0;
  virt.lm.level1 = 0;

  foreach (i, 512) {
    virt.lm.level1 = i;
    os << "        ", intstring(i, 3), ": ", hexstring(virt, 64), " -> ", ptes[i], endl;
  }

  return os;
}

const char* PageFrameType::names[] = {"normal", "L1", "L2", "L3", "L4", "(5)", "(6)", "invalid"};

ostream& operator <<(ostream& os, const shared_info& si) {
  os << "Xen Shared Info:", endl;
  foreach (i, 1) { // or MAX_VIRT_CPUS
    vcpu_info_t vcpu = si.vcpu_info[i];
    os << "  VCPU ", i, ":", endl;
    os << "    pending ", vcpu.evtchn_upcall_pending, ", mask ", vcpu.evtchn_upcall_mask, endl;
    os << "    sel     ", bitstring(vcpu.evtchn_pending_sel, 64), endl;
    os << "    cr2     ", hexstring(vcpu.arch.cr2, 64), endl;
    os << "    version ", intstring(vcpu.time.version, 64), endl;
    os << "    tsc     ", intstring(vcpu.time.tsc_timestamp, 64), endl;
    os << "    systime ", intstring(vcpu.time.system_time, 64), endl;
    os << "    tsc2sys ", intstring(vcpu.time.tsc_to_system_mul, 64), endl;
    os << "    tscshft ", intstring(vcpu.time.tsc_shift, 64), endl;
  }

  os << "  pending ", bitstring(si.evtchn_pending[0], 64), endl;
  os << "  mask    ", bitstring(si.evtchn_mask[0], 64), endl;
  os << "  wc_ver  ", intstring(si.wc_version, 64), endl;
  os << "  wc_sec  ", intstring(si.wc_sec, 64), endl;
  os << "  wc_nsec ", intstring(si.wc_nsec, 64), endl;
  os << "  max_pfn ", intstring(si.arch.max_pfn, 64), endl;
  os << "  pfn2mfn ", intstring(si.arch.pfn_to_mfn_frame_list_list, 64), endl;
  os << "  nmi     ", intstring(si.arch.nmi_reason, 64), endl;

  return os;

}

void PTLsimConfig::reset() {
  domain = (W64)(-1);
  run = 0;
  stop = 0;
  native = 0;
  kill = 0;
  pause = 0;

  core_name = "seq";

  clock_adj_factor = 1000;

  quiet = 0;
  log_filename = "logfile";
  loglevel = 0;
  start_log_at_iteration = infinity;
  start_log_at_rip = 0xffffffffffffffffULL;
  log_ptlsim_boot = 0;
  log_on_console = 0;

  stats_filename.reset();
  snapshot_cycles = infinity;
  snapshot_now.reset();

  stop_at_user_insns = infinity;
  stop_at_iteration = infinity;
  stop_at_rip = 0xffffffffffffffffULL;
  stop_at_user_insns_relative = infinity;
  insns_in_last_basic_block = 65536;
  flush_interval = infinity;
  dumpcode_filename = "test.dat";

  event_trace_record_filename.reset();
  event_trace_record_stop = 0;
  event_trace_replay_filename.reset();

  core_freq_hz = 0;
  timer_interrupt_freq_hz = 1000;
  pseudo_real_time_clock = 0;
  realtime = 0;
  mask_interrupts = 0;
  console_mfn = 0;

  perfect_cache = 0;
}

PTLsimConfig config;
ConfigurationParser<PTLsimConfig> configparser;

template <>
void ConfigurationParser<PTLsimConfig>::setup() {
  section("PTLmon Control");
  add(domain,                       "domain",               "Domain to access");

  section("Action (specify only one)");
  add(run,                          "run",                  "Run under simulation");
  add(stop,                         "stop",                 "Stop current simulation run and wait for command");
  add(native,                       "native",               "Switch to native mode");
  add(kill,                         "kill",                 "Kill PTLsim inside domain (and ptlmon), then shutdown domain");

  section("Simulation Control");

  add(core_name,                    "core",                 "Run using specified core (-core <corename>)");

  section("Logging Control");
  add(quiet,                        "quiet",                "Do not print PTLsim system information banner");
  add(log_filename,                 "logfile",              "Log filename (use /dev/fd/1 for stdout, /dev/fd/2 for stderr)");
  add(loglevel,                     "loglevel",             "Log level (0 to 99)");
  add(start_log_at_iteration,       "startlog",             "Start logging after iteration <starlog>");
  add(start_log_at_rip,             "startlogrip",          "Start logging after first translation of basic block starting at rip");
  add(log_on_console,               "consolelog",           "Replicate log file messages to console");
  add(log_ptlsim_boot,              "bootlog",              "Log PTLsim early boot and injection process (for debugging)");

  section("Statistics Database");
  add(stats_filename,               "stats",                "Statistics data store hierarchy root");
  add(snapshot_cycles,              "snapshot-cycles",      "Take statistical snapshot and reset every <snapshot> cycles");
  add(snapshot_now,                 "snapshot-now",         "Take statistical snapshot immediately, using specified name");

  section("Event Trace Recording");
  add(event_trace_record_filename,  "event-record",         "Save replayable events (interrupts, DMAs, etc) to this file");
  add(event_trace_record_stop,      "event-record-stop",    "Stop recording events");
  add(event_trace_replay_filename,  "event-replay",         "Replay events (interrupts, DMAs, etc) to this file, starting at checkpoint");

  section("Trace Stop Point");
  add(stop_at_user_insns,           "stopinsns",            "Stop after executing <stopinsns> user instructions");
  add(stop_at_iteration,            "stop",                 "Stop after <stop> cycles");
  add(stop_at_rip,                  "stoprip",              "Stop before rip <stoprip> is translated for the first time");
  add(stop_at_user_insns_relative,  "stopinsns-rel",        "Stop after executing <stopinsns-rel> user instructions relative to start of current run");
  add(insns_in_last_basic_block,    "bbinsns",              "In final basic block, only translate <bbinsns> user instructions");
  add(flush_interval,               "flushevery",           "Flush the pipeline every N committed instructions");

  section("Timers and Interrupts");
  add(core_freq_hz,                 "corefreq",             "Core clock frequency in Hz (default uses host system frequency)");
  add(timer_interrupt_freq_hz,      "timerfreq",            "Timer interrupt frequency in Hz");
  add(pseudo_real_time_clock,       "pseudo-rtc",           "Real time clock always starts at time saved in checkpoint");
  add(realtime,                     "realtime",             "Operate in real time: no time dilation (not accurate for I/O intensive workloads!)");
  add(mask_interrupts,              "maskints",             "Mask all interrupts (required for guaranteed deterministic behavior)");
  add(console_mfn,                  "console-mfn",          "Track the specified Xen console MFN");
  add(pause,                        "pause",                "Pause domain after using -native");

  section("Out of Order Core (ooocore)");
  add(perfect_cache,                "perfect-cache",        "Perfect cache performance: all loads and stores hit in L1");

  section("Miscellaneous");
  add(dumpcode_filename,            "dumpcode",             "Save page of user code at final rip to file <dumpcode>");
};

ostream& operator <<(ostream& os, const PTLsimConfig& config) {
  return configparser.print(os, config);
}

void print_banner(ostream& os) {
  utsname hostinfo;
  sys_uname(&hostinfo);

  os << "//  ", endl;
#ifdef __x86_64__
  os << "//  PTLsim: Cycle Accurate x86-64 Full System SMP/SMT Simulator", endl;
#else
  os << "//  PTLsim: Cycle Accurate x86 Full System SMP/SMT Simulator (32-bit version)", endl;
#endif
  os << "//  Copyright 1999-2006 Matt T. Yourst <yourst@yourst.com>", endl;
  os << "// ", endl;
  os << "//  Revision ", stringify(SVNREV), " (", stringify(SVNDATE), ")", endl;
  os << "//  Built ", __DATE__, " ", __TIME__, " on ", stringify(BUILDHOST), " using gcc-", 
    stringify(__GNUC__), ".", stringify(__GNUC_MINOR__), endl;
  os << "//  Running on ", hostinfo.nodename, ".", hostinfo.domainname, endl;
  os << "//  ", endl, endl;
  os << flush;
}

