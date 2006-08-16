//
// PTLsim: Cycle Accurate x86-64 Simulator
// Toplevel control and kernel interface to Xen inside the user domain
//
// Copyright 1999-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>
#include <ptlxen.h>
#include <mm.h>
#include <ptlsim.h>

//
// Global variables
//
ostream logfile;
W64 loglevel = 0;
W64 sim_cycle = 0;
W64 iterations = 0;
W64 total_uops_executed = 0;
W64 total_uops_committed = 0;
W64 total_user_insns_committed = 0;
W64 total_basic_blocks_committed = 0;

//
// Xen hypercalls
//
W64 ptlsim_hypercall_histogram[64];
W64 guest_hypercall_histogram[64];

static inline W64 do_xen_hypercall(W64 hypercall, W64 arg1, W64 arg2, W64 arg3, W64 arg4, W64 arg5, W64 arg6) {
  W64 rc;
  W64 addr = (PTLSIM_HYPERCALL_PAGE_VIRT_BASE + (hypercall * 32));
  asm volatile ("movq %[arg4],%%r10\n"
                "movq %[arg5],%%r8\n"
                "movq %[arg6],%%r9\n"
                "call %%rax\n"
                : "=a" (rc)
                : "a" (addr), "D" ((W64)(arg1)), "S" ((W64)(arg2)),
                "d" ((W64)(arg3)), [arg4] "g" ((W64)(arg4)), [arg5] "g" ((W64)(arg5)),
                [arg6] "g" ((W64)(arg6))
                : "r11", "rcx", "memory", "r8", "r10", "r9");
  return rc;
}

int HYPERVISOR_set_trap_table(trap_info_t *table) {
  return _hypercall1(int, set_trap_table, table);
}

int HYPERVISOR_mmu_update(mmu_update_t *req, int count, int *success_count, domid_t domid) {
  return _hypercall4(int, mmu_update, req, count, success_count, domid);
}

int HYPERVISOR_set_gdt(unsigned long *frame_list, int entries) {
  return _hypercall2(int, set_gdt, frame_list, entries);
}

int HYPERVISOR_stack_switch(unsigned long ss, unsigned long esp) {
  return _hypercall2(int, stack_switch, ss, esp);
}

int HYPERVISOR_set_callbacks(unsigned long event_address, unsigned long failsafe_address, unsigned long syscall_address) {
	return _hypercall3(int, set_callbacks, event_address, failsafe_address, syscall_address);
}

int HYPERVISOR_fpu_taskswitch(int set) {
	return _hypercall1(int, fpu_taskswitch, set);
}

int HYPERVISOR_sched_op_compat(int cmd, unsigned long arg) {
  return _hypercall2(int, sched_op_compat, cmd, arg);
}

int HYPERVISOR_dom0_op(dom0_op_t *dom0_op) {
  dom0_op->interface_version = DOM0_INTERFACE_VERSION;
  return _hypercall1(int, dom0_op, dom0_op);
}

int HYPERVISOR_set_debugreg(int reg, unsigned long value) {
  return _hypercall2(int, set_debugreg, reg, value);
}

unsigned long HYPERVISOR_get_debugreg(int reg) {
  return _hypercall1(unsigned long, get_debugreg, reg);
}

int HYPERVISOR_update_descriptor(unsigned long ma, unsigned long word) {
  return _hypercall2(int, update_descriptor, ma, word);
}

int HYPERVISOR_memory_op(unsigned int cmd, void *arg) {
  return _hypercall2(int, memory_op, cmd, arg);
}

int HYPERVISOR_multicall(void *call_list, int nr_calls) {
  return _hypercall2(int, multicall, call_list, nr_calls);
}

int HYPERVISOR_update_va_mapping(unsigned long va, pte_t new_val, unsigned long flags) {
  return _hypercall3(int, update_va_mapping, va, new_val, flags);
}

long HYPERVISOR_set_timer_op(u64 timeout) {
  return _hypercall1(long, set_timer_op, timeout);
}

// HYPERVISOR_event_channel_op_compat

int HYPERVISOR_xen_version(int cmd, void *arg) {
  return _hypercall2(int, xen_version, cmd, arg);
}

int HYPERVISOR_console_io(int cmd, int count, char *str) {
  return _hypercall3(int, console_io, cmd, count, str);
}

// HYPERVISOR_physdev_op_compat()

int HYPERVISOR_grant_table_op(unsigned int cmd, void *uop, unsigned int count) {
  return _hypercall3(int, grant_table_op, cmd, uop, count);
}

int HYPERVISOR_vm_assist(unsigned int cmd, unsigned int type) {
  return _hypercall2(int, vm_assist, cmd, type);
}

int HYPERVISOR_update_va_mapping_otherdomain(unsigned long va, pte_t new_val, unsigned long flags, domid_t domid) {
  return _hypercall4(int, update_va_mapping_otherdomain, va, new_val, flags, domid);
}

// iret

int HYPERVISOR_vcpu_op(int cmd, int vcpuid, void *extra_args) {
  return _hypercall3(int, vcpu_op, cmd, vcpuid, extra_args);
}

int HYPERVISOR_set_segment_base(int reg, unsigned long value) {
  return _hypercall2(int, set_segment_base, reg, value);
}

int HYPERVISOR_mmuext_op(struct mmuext_op *op, int count, int *success_count, domid_t domid) {
  return _hypercall4(int, mmuext_op, op, count, success_count, domid);
}

// acm_op

int HYPERVISOR_nmi_op(unsigned long op, void *arg) {
  return _hypercall2(int, nmi_op, op, arg);
}

int HYPERVISOR_sched_op(int cmd, void *arg) {
  return _hypercall2(int, sched_op, cmd, arg);
}

#if 0
int HYPERVISOR_callback_op(int cmd, void *arg) {
  return _hypercall2(int, callback_op, cmd, arg);
}

int HYPERVISOR_xenoprof_op(int op, unsigned long arg1, unsigned long arg2) {
  return _hypercall3(int, xenoprof_op, op, arg1, arg2);
}
#endif

int HYPERVISOR_event_channel_op(int cmd, void *arg) {
	return _hypercall2(int, event_channel_op, cmd, arg);
}

int HYPERVISOR_physdev_op(void *physdev_op) {
  return _hypercall1(int, physdev_op, physdev_op);
}

int xen_sched_block() {
	return HYPERVISOR_sched_op(SCHEDOP_block, NULL);
}

int xen_sched_yield() {
	return HYPERVISOR_sched_op(SCHEDOP_yield, NULL);
}

int xen_shutdown_domain(int reason) {
  sched_shutdown_t shutdown;
  shutdown.reason = reason;
	return HYPERVISOR_sched_op(SCHEDOP_shutdown, &reason);
}

//
// Event channels
//
#define active_evtchns(cpu,sh,idx) ((sh).evtchn_pending[idx] & ~(sh).evtchn_mask[idx])

void mask_evtchn(int port) {
  shinfo_evtchn_mask[port].atomicset();
}

void force_evtchn_callback() {
  // Xen processes pending events on every hypercall:
  (void)HYPERVISOR_xen_version(0, 0);
}

void unmask_evtchn(int port) {
  vcpu_info_t& vcpu_info = shinfo.vcpu_info[0];

  shinfo_evtchn_mask[port].atomicclear();
  
  //
  // The following is basically the equivalent of 'hw_resend_irq'. Just like
  // a real IO-APIC we 'lose the interrupt edge' if the channel is masked.
  //

  if (shinfo_evtchn_pending[port] && (!(shinfo_evtchn_pending_sel(0)[port / (sizeof(unsigned long) * 8)].atomicset()))) {
    vcpu_info.evtchn_upcall_pending = 1;
    if (!vcpu_info.evtchn_upcall_mask) force_evtchn_callback();
  }
}

static inline void cli() {
  shinfo.vcpu_info[0].evtchn_upcall_mask = 1;
	barrier();
}

static inline void sti() {
	barrier();
  vcpu_info_t& vcpu = shinfo.vcpu_info[0];
	vcpu.evtchn_upcall_mask = 0;
	barrier(); // unmask then check (avoid races)
	if (vcpu.evtchn_upcall_pending) {
    force_evtchn_callback();
  }
}

void clear_evtchn(int port) {
  shinfo_evtchn_pending[port].atomicclear();
}

bool shadow_evtchn_set_pending(unsigned int port);
int shadow_evtchn_unmask(unsigned int port);

W64 events_just_handled = 0;

bitvec<4096> always_mask_port;

void handle_event(int port) {
  // Can't use anything that makes host calls in here!
  if likely (port == bootinfo.hostcall_port) {
    // No action: will automatically unblock and return to hostcall caller
  } else if unlikely (port == bootinfo.upcall_port) {
    // Upcall: check at next iteration of main loop
  } else {
    // some user port: copy to virtualized shared info page and notify simulation loop
    if (!always_mask_port[port]) {
      events_just_handled |= (1<<port);
       if likely (!config.mask_interrupts) shadow_evtchn_set_pending(port);
    }
  }

	clear_evtchn(port);
}

asmlinkage void xen_event_callback(W64* regs) {
  u32                l1, l2;
  unsigned int   l1i, l2i, port;
  int            cpu = 0;
  vcpu_info_t& vcpu_info = shinfo.vcpu_info[cpu];

  vcpu_info.evtchn_upcall_pending = 0;
  l1 = xchg(vcpu_info.evtchn_pending_sel, 0UL);

  while (l1) {
    l1i = lsbindex(l1);
    l1 &= ~(1 << l1i);

    while ((l2 = active_evtchns(cpu, shinfo, l1i))) {
      l2i = lsbindex(l2);
      l2 &= ~(1 << l2i);
      port = (l1i * BITS_PER_LONG) + l2i;
      handle_event(port);
    }
    shinfo.evtchn_pending[l1i] = 0;
  }
}

int virq_and_vcpu_to_port[NR_VIRQS][MAX_VIRT_CPUS];
W8s port_to_vcpu[NR_EVENT_CHANNELS];

int shadow_evtchn_unmask(unsigned int port) {
  if (port >= NR_EVENT_CHANNELS) return 0;

  int vcpu_to_notify = port_to_vcpu[port];

  if (port_to_vcpu[port] < 0) {
    logfile << "unmask_evtchn: port ", port, " is not bound to any VCPU", endl;
    return 0;
  }

  // Equivalent to xen/common/event_channel.c evtchn_unmask():

  if (sshinfo_evtchn_mask[port].testclear() &&
      sshinfo_evtchn_pending[port] &&
      (!(sshinfo_evtchn_pending_sel(vcpu_to_notify)[port / (sizeof(unsigned long) * 8)].testset()))) {
    if (!xchg(sshinfo.vcpu_info[vcpu_to_notify].evtchn_upcall_pending, (byte)1)) {
      if (logable(1)) logfile << "shadow_evtchn_unmask(", port, "): event delivery: making vcpu ", vcpu_to_notify, " runnable", endl;
      return 1;
    }
  }

  return 0;
}

bool shadow_evtchn_set_pending(unsigned int port) {
  if (port >= 4096) return false;
  static const bool DEBUG = 0; // cannot be set if called from event upcall interrupt handler
  int vcpu_to_notify = port_to_vcpu[port];

  if (DEBUG) logfile << "Set pending for port ", port, " mapped to vcpu ", vcpu_to_notify, ":", endl;

  if unlikely (vcpu_to_notify < 0) {
    if (DEBUG) logfile << "  Not bound to any VCPU", endl;
    return false;
  }

  if unlikely (sshinfo_evtchn_pending[port].testset()) {
    if (DEBUG) logfile << "  Already pending", endl;
    return false;
  }

  bool masked = sshinfo_evtchn_mask[port];

  if unlikely (masked) {
    if (DEBUG) logfile << "  Event masked", endl;
    return false;
  }

  if unlikely (sshinfo_evtchn_pending_sel(vcpu_to_notify)[port / (sizeof(unsigned long) * 8)].testset()) {
    if (DEBUG) logfile << "  Event already pending in evtchn_pending_sel", endl;
    return false;
  }

  if (DEBUG) logfile << "  Mark vcpu ", vcpu_to_notify, " events pending", endl;

  if likely (!xchg(sshinfo.vcpu_info[vcpu_to_notify].evtchn_upcall_pending, (byte)1)) {
    if (DEBUG) logfile << "  Kick vcpu", endl;
    return true;
  } else {
    if (DEBUG) logfile << "  VCPU already kicked", endl;
    return false;
  }
}

//
// Host calls to PTLmon
//
W64s synchronous_host_call(const PTLsimHostCall& call, bool spin = false) {
  stringbuf sb;
  int rc;

  void* p = &bootinfo.hostreq;
  memcpy(&bootinfo.hostreq, &call, sizeof(PTLsimHostCall));
  bootinfo.hostreq.ready = 0;

  // This will clear the port if a previous upcall got out of sync:
  unmask_evtchn(bootinfo.hostcall_port);
  shinfo_evtchn_pending[bootinfo.hostcall_port] = 0;

  evtchn_send_t sendop;
  sendop.port = bootinfo.hostcall_port;
  rc = HYPERVISOR_event_channel_op(EVTCHNOP_send, &sendop);

  //
  // We need to block here since we need an event to clear the hostcall
  // pending bit. However, for switching to native mode, we should NOT
  // block, since if we race with pause() in PTLmon and lose, the domain
  // will be in the Xen "blocked" state when setvcpucontext is called
  // by PTLmon, but setvcpucontext does not save/restore the blocked
  // state. Hence the target VCPU will remain blocked forever. To avoid
  // this, we specify spin = true for these calls.
  //
  while (!bootinfo.hostreq.ready) {
    if (!spin) xen_sched_block();
  }

  assert(bootinfo.hostreq.ready);

  return bootinfo.hostreq.rc;
}

//
// Switch PTLsim to native mode by swapping in context <ctx>,
// and saving the current PTLsim context back to <ctx>.
//
// When this call returns (i.e. we switch back to simulation mode),
// <ctx> is filled with the new user context we interrupted, and
// the PTLsim register state is restored, allowing us to return
// exactly where we left off.
//
int switch_to_native(bool pause = false) {
  Context ptlctx[32];
  int rc;

  PTLsimHostCall call;
  call.op = PTLSIM_HOST_SWITCH_TO_NATIVE;
  call.ready = 0;
  call.switch_to_native.pause = pause;

  // Linux kernels expect this to be re-enabled:
	HYPERVISOR_vm_assist(VMASST_CMD_enable, VMASST_TYPE_writable_pagetables);

  rc = synchronous_host_call(call, true);
  return rc;
}

int shutdown(bool pause = false) {
  Context ptlctx[32];
  int rc;

  PTLsimHostCall call;
  call.op = PTLSIM_HOST_TERMINATE;
  call.ready = 0;
  call.terminate.pause = pause;

  // Linux kernels expect this to be re-enabled:
	HYPERVISOR_vm_assist(VMASST_CMD_enable, VMASST_TYPE_writable_pagetables);

  rc = synchronous_host_call(call, true);
  // (never returns)
  return rc;
}

//
// Get one request, blocking until one is ready
//
W64 accept_upcall(char* buf, size_t count, bool blocking = 1) {
  PTLsimHostCall call;

  call.op = PTLSIM_HOST_ACCEPT_UPCALL;
  call.ready = 0;
  call.accept_upcall.buf = xferpage;
  call.accept_upcall.count = min(count, PAGE_SIZE);
  call.accept_upcall.blocking = blocking;

  int rc = synchronous_host_call(call);
  if (rc) memcpy(buf, xferpage, min(count, PAGE_SIZE));
  return rc;
}

W64 accept_upcall_nonblocking(char* buf, size_t count) {
  return accept_upcall(buf, count, 0);
}

int complete_upcall(W64 uuid) {
  // cerr << "Complete upcall for uuid ", uuid, endl, flush;

  PTLsimHostCall call;

  call.op = PTLSIM_HOST_COMPLETE_UPCALL;
  call.ready = 0;
  call.complete_upcall.uuid = uuid;
  return synchronous_host_call(call);
}

//
// Linux-like system calls passed back to dom0 via upcall mechanism
//
#undef declare_syscall0
#undef declare_syscall1
#undef declare_syscall2
#undef declare_syscall3
#undef declare_syscall4
#undef declare_syscall5
#undef declare_syscall6

#define declare_syscall0(sysid,type,name) type name(void) { \
  return (type)synchronous_host_call(PTLsimHostCall(sysid)); }

#define declare_syscall1(sysid,type,name,type1,arg1) type name(type1 arg1) { \
  return (type)synchronous_host_call(PTLsimHostCall(sysid, (W64)arg1)); }

#define declare_syscall2(sysid,type,name,type1,arg1,type2,arg2) asmlinkage type name(type1 arg1,type2 arg2) { \
  return (type)synchronous_host_call(PTLsimHostCall(sysid, (W64)arg1, (W64)arg2)); }

#define declare_syscall3(sysid,type,name,type1,arg1,type2,arg2,type3,arg3) type name(type1 arg1,type2 arg2,type3 arg3) { \
  return (type)synchronous_host_call(PTLsimHostCall(sysid, (W64)arg1, (W64)arg2, (W64)arg3)); }

#define declare_syscall4(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) asmlinkage type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) { \
  return (type)synchronous_host_call(PTLsimHostCall(sysid, (W64)arg1, (W64)arg2, (W64)arg3, (W64)arg4)); }

#define declare_syscall5(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5) \
  type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) { \
  return (type)synchronous_host_call(PTLsimHostCall(sysid, (W64)arg1, (W64)arg2, (W64)arg3, (W64)arg4, (W64)arg5)); }

#define declare_syscall6(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5,type6,arg6) \
  type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) { \
  return (type)synchronous_host_call(PTLsimHostCall(sysid, (W64)arg1, (W64)arg2, (W64)arg3, (W64)arg4, (W64)arg5, (W64)arg6)); }

declare_syscall3(__NR_lseek, W64, sys_seek, int, fd, W64, offset, unsigned int, origin);

declare_syscall3(__NR_open, int, sys_open_thunk, const char*, pathname, int, flags, int, mode);
asmlinkage int sys_open(const char* pathname, int flags, int mode) {
  strncpy(xferpage, pathname, PAGE_SIZE);
  return sys_open_thunk(xferpage, flags, mode);
}

declare_syscall1(__NR_close, int, sys_close, int, fd);

declare_syscall3(__NR_read, ssize_t, sys_read_thunk, int, fd, void*, buf, size_t, count);
asmlinkage ssize_t sys_read(int fd, void* buf, size_t count) {
  char* p = (char*)buf;
  size_t realcount = 0;
  int rc;

  while (count) {
    rc = sys_read_thunk(fd, xferpage, min(count, PAGE_SIZE));
    if (rc < 0) return rc;
    memcpy(p, xferpage, rc);
    count -= rc;
    realcount += rc;
    p += rc;
    if (rc < PAGE_SIZE) break;
  }

  return realcount;
}

declare_syscall3(__NR_write, ssize_t, sys_write_thunk, int, fd, const void*, buf, size_t, count);

asmlinkage ssize_t sys_write(int fd, const void* buf, size_t count) {
  char* p = (char*)buf;
  size_t realcount = 0;
  int rc;

  while (count) {
    memcpy(xferpage, p, min(count, PAGE_SIZE));
    rc = sys_write_thunk(fd, xferpage, min(count, PAGE_SIZE));
    if (rc < 0) return rc;
    count -= rc;
    realcount += rc;
    p += rc;
    if (rc < PAGE_SIZE) break;
  }

  return realcount;
}

declare_syscall1(__NR_unlink, int, sys_unlink_thunk, const char*, pathname);
asmlinkage int sys_unlink(const char* pathname) {
  strncpy(xferpage, pathname, PAGE_SIZE);
  return sys_unlink_thunk(xferpage);
}

declare_syscall2(__NR_rename, int, sys_rename_thunk, const char*, oldpath, const char*, newpath);
asmlinkage int sys_rename(const char* oldpath, const char* newpath) {
  strncpy(xferpage + 0, oldpath, 2048);
  strncpy(xferpage + 2048, newpath, 2048);
  return sys_rename_thunk(xferpage + 0, xferpage + 2048);
}

declare_syscall0(__NR_getpid, pid_t, sys_getpid);
declare_syscall0(__NR_gettid, pid_t, sys_gettid);

declare_syscall1(__NR_uname, int, sys_uname_thunk, struct utsname*, buf);
asmlinkage int sys_uname(struct utsname* buf) {
  utsname* unamebuf = (utsname*)xferpage;
  int rc = sys_uname_thunk(unamebuf);
  if ((!rc) && buf) memcpy(buf, unamebuf, sizeof(utsname));
  return rc;
}

declare_syscall3(__NR_readlink, int, sys_readlink_thunk, const char*, path, char*, buf, size_t, bufsiz);
asmlinkage int sys_readlink(const char *path, char *buf, size_t bufsiz) {
  strncpy(xferpage + 0, path, 2048);
  int rc = sys_readlink_thunk(xferpage + 0, xferpage + 2048, min(bufsiz, (size_t)2048));
  if (rc >= 0) memcpy(buf, xferpage + 2048, rc);
  return rc;
}

declare_syscall2(__NR_nanosleep, int, do_nanosleep, const timespec*, req, timespec*, rem);

asmlinkage int sys_gettimeofday(struct timeval* tv, struct timezone* tz) {
  tv->tv_sec = shinfo.wc_sec;
  tv->tv_usec = shinfo.wc_nsec / 1000;
  return 0;
}

asmlinkage time_t sys_time(time_t* t) {
  W64 sec = shinfo.wc_sec;
  if (t) *t = sec;
  return sec;
}

W64 sys_nanosleep(W64 nsec) {
  timespec* reqrem = (timespec*)xferpage;

  reqrem->tv_sec = (W64)nsec / 1000000000ULL;
  reqrem->tv_nsec = (W64)nsec % 1000000000ULL;

  do_nanosleep(reqrem, reqrem+1);

  return ((W64)reqrem[1].tv_sec * 1000000000ULL) + (W64)reqrem[1].tv_nsec;
}

void* sys_mmap(void* start, size_t length, int prot, int flags, int fd, W64 offset) {
  // Not supported on the bare hardware
  return (void*)(Waddr)0xffffffffffffffffULL;
}

// This is where we end up after issuing opcode 0x0f37 (undocumented x86 PTL call opcode)
void assist_ptlcall(Context& ctx) {
  //++MTY TODO
}

void initiate_prefetch(W64 addr, int cachelevel) {
  // (dummy for now)
}

asmlinkage void assert_fail(const char *__assertion, const char *__file, unsigned int __line, const char *__function) {
  stringbuf sb;
  sb << "ptlxen: Assert ", __assertion, " failed in ", __file, ":", __line, " (", __function, ")", endl;

  logfile << sb, flush;
  cerr << sb, flush;
  asm("ud2a");
  abort();
}

//
// Page table management
//
mmu_update_t mmuqueue[1024];
int mmuqueue_count = 0;

int do_commit_page_table_updates() {
  static const bool DEBUG = 0;

  if (DEBUG) logfile << "Page table update commit of ", mmuqueue_count, " entries:", endl, flush;

  foreach (i, mmuqueue_count) {
    mmu_update_t& mmu = mmuqueue[i];
    W64 virt = mmu.ptr;

    if likely (virt_is_inside_ptlsim(mmu.ptr)) {
      mmu.ptr = ptl_virt_to_phys((void*)mmu.ptr);
    } else if likely (virt_is_inside_physmap(mmu.ptr)) {
      mmu.ptr = mapped_virt_to_phys((void*)mmu.ptr);
    } else {
      // invalid update
      mmu.ptr = 0;
    }

    if (DEBUG) logfile << "  virt 0x", hexstring(virt, 64), ", phys 0x", hexstring(mmu.ptr, 64), " (mfn ", intstring(mmu.ptr >> 12, 8), 
                 " offset ", intstring(lowbits(mmu.ptr, 12) / 8, 8), ") <= ", Level1PTE(mmu.val), endl, flush;
  }

  int update_count = 0;
  int rc = HYPERVISOR_mmu_update(mmuqueue, mmuqueue_count, &update_count, DOMID_SELF);

  if (rc) {
    logfile << "Page table update commit failed for ", mmuqueue_count, " entries (completed ", update_count, " entries):", endl, flush;
    foreach (i, mmuqueue_count) {
      logfile << "  phys 0x", hexstring(mmuqueue[i].ptr, 64), " (mfn ", intstring(mmuqueue[i].ptr >> 12, 8), 
        " offset ", intstring(lowbits(mmuqueue[i].ptr, 12) / 8, 8), ") <= ", Level1PTE(mmuqueue[i].val), endl, flush;
    }
  }

  mmuqueue_count = 0;

  return rc;
}

// Update a PTE by its physical address
template <typename T>
int update_phys_pte(Waddr dest, const T& src) {
	mmu_update_t u;
	u.ptr = dest;
	u.val = (W64)src;
  return HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF);
}

int pin_page_table_page(void* virt, int level) {
  return 0;
  assert(inrange(level, 0, 4));

  // Was it in PTLsim space?
  mfn_t mfn = ptl_virt_to_mfn(virt);
  if unlikely (mfn == INVALID_MFN) return -1;
  
  int level_to_function[5] = {MMUEXT_UNPIN_TABLE, MMUEXT_PIN_L1_TABLE, MMUEXT_PIN_L2_TABLE, MMUEXT_PIN_L3_TABLE, MMUEXT_PIN_L4_TABLE};
  int func = level_to_function[level];
  
  int rc = 0;
  mmuext_op op;
  op.cmd = func;
  op.arg1.mfn = mfn;

  int success_count = 0;
  return HYPERVISOR_mmuext_op(&op, 1, &success_count, DOMID_SELF);
}

int make_ptl_page_writable(void* virt, bool writable) {
  pfn_t pfn = ptl_virt_to_pfn(virt);
  if unlikely (pfn == INVALID_MFN) return -1;

  Level1PTE& pte = bootinfo.ptl_pagedir[pfn];
  Level1PTE temppte = pte;
  temppte.rw = writable;
  return update_ptl_pte(pte, temppte);
}

void unmap_phys_page(mfn_t mfn) {
  Level1PTE& pte = bootinfo.phys_pagedir[mfn];
  if unlikely (!pte.p) return;
  assert(update_ptl_pte(pte, Level1PTE(0)) == 0);
}

int query_pages(page_type_t* pt, int count) {
  mmuext_op op;
  op.cmd = MMUEXT_QUERY_PAGES;
  op.arg1.linear_addr = (Waddr)pt;
  op.arg2.nr_ents = count;

  int success_count = 0;
  return HYPERVISOR_mmuext_op(&op, 1, &success_count, DOMID_SELF);
}

void unmap_phys_page(mfn_t mfn);

page_type_t query_page(mfn_t mfn) {
  unmap_phys_page(mfn);

  page_type_t pt;
  pt.in.mfn = mfn;

  mmuext_op op;
  op.cmd = MMUEXT_QUERY_PAGES;
  op.arg1.linear_addr = (Waddr)&pt;
  op.arg2.nr_ents = 1;

  int success_count = 0;
  assert(HYPERVISOR_mmuext_op(&op, 1, &success_count, DOMID_SELF) == 0);

  return pt;
}

void query_page_and_print_type_info(mfn_t mfn) {
  logfile << "mfn ", mfn, ": ", query_page(mfn), endl;
}

//
// Trap and Exception Handling
//
asmlinkage {
  void divide_error();
  void debug();
  void int3();
  void overflow();
  void bounds();
  void invalid_op();
  void device_not_available();
  void coprocessor_segment_overrun();
  void invalid_tss();
  void segment_not_present();
  void stack_segment();
  void general_protection();
  void page_fault();
  void coprocessor_error();
  void simd_coprocessor_error();
  void alignment_check();
  void spurious_interrupt_bug();
  void machine_check();
};

void print_regs(ostream& os, const W64* regs) {
  foreach (i, ARCHREG_COUNT) {
    os << "  ", padstring(arch_reg_names[i], -6), " 0x", hexstring(regs[i], 64);
    if ((i % 4) == (4-1)) os << endl;
  }
}

void print_stack(ostream& os, Waddr sp) {
  W64* p = (W64*)sp;

  os << "Stack trace back from ", (void*)sp, ":", endl, flush;
  foreach (i, 64) {
    if ((i % 8) == 0) os << "  ", &p[i], ":";
    os << " ", hexstring(p[i], 64);
    if ((i % 8) == 7) os << endl;
  }
  os << flush;
}

asmlinkage void ptl_internal_trap(int trapid, const char* name, W64* regs) {
  cerr << endl;
  cerr << "PTLsim Internal Error: unhandled trap ", trapid, " (", name, "): error code ", hexstring(regs[REG_ar1], 32), endl;
  cerr << "Registers:", endl;
  print_regs(cerr, regs);
  cerr << flush;
  print_stack(cerr, regs[REG_rsp]);
  if (logfile) logfile.flush();
  cerr.flush();
  cout.flush();

  xen_shutdown_domain(SHUTDOWN_crash);
}

#define DO_ERROR(trapid, str, name) asmlinkage void do_##name(W64* regs) { ptl_internal_trap(trapid, str, regs); }

//
// These exceptions are not handled by PTLsim. If they occur
// during simulation mode, something is seriously wrong.
//
DO_ERROR(0, "divide error", divide_error);
DO_ERROR(3, "int3", int3);
DO_ERROR(4, "overflow", overflow);
DO_ERROR(5, "bounds", bounds);
DO_ERROR(6, "invalid opcode", invalid_op);
DO_ERROR(7, "device not available", device_not_available);
DO_ERROR(11, "segment not present", segment_not_present);
DO_ERROR(12, "stack segment", stack_segment);
DO_ERROR(13, "general protection", general_protection);
asmlinkage void do_page_fault(W64* regs);
DO_ERROR(16, "fpu", coprocessor_error);
DO_ERROR(19, "sse", simd_coprocessor_error);

asmlinkage void xen_event_callback_entry();
asmlinkage void divide_error_entry();
asmlinkage void int3_entry();
asmlinkage void overflow_entry();
asmlinkage void bounds_entry();
asmlinkage void invalid_op_entry();
asmlinkage void device_not_available_entry();
asmlinkage void segment_not_present_entry();
asmlinkage void stack_segment_entry();
asmlinkage void general_protection_entry();
asmlinkage void page_fault_entry();
asmlinkage void coprocessor_error_entry();
asmlinkage void simd_coprocessor_error_entry();

static trap_info_t trap_table[] = {
  {  0, 0, FLAT_KERNEL_CS, (Waddr)&divide_error_entry          },
  {  3, 0, FLAT_KERNEL_CS, (Waddr)&int3_entry                  },
  {  4, 0, FLAT_KERNEL_CS, (Waddr)&overflow_entry              },
  {  5, 0, FLAT_KERNEL_CS, (Waddr)&bounds_entry                },
  {  6, 0, FLAT_KERNEL_CS, (Waddr)&invalid_op_entry            },
  {  7, 0, FLAT_KERNEL_CS, (Waddr)&device_not_available_entry  },
  { 11, 0, FLAT_KERNEL_CS, (Waddr)&segment_not_present_entry   },
  { 12, 0, FLAT_KERNEL_CS, (Waddr)&stack_segment_entry         },
  { 13, 0, FLAT_KERNEL_CS, (Waddr)&general_protection_entry    },
  { 14, 0, FLAT_KERNEL_CS, (Waddr)&page_fault_entry            },
  { 16, 0, FLAT_KERNEL_CS, (Waddr)&coprocessor_error_entry     },
  { 19, 0, FLAT_KERNEL_CS, (Waddr)&simd_coprocessor_error_entry},
  {  0, 0, 0,              0                                   }
};

//
// Xen puts the virtualized page fault virtual address in arch.cr2
// instead of the machine's CR2 register.
//
static inline Waddr read_cr2() { return shinfo.vcpu_info[0].arch.cr2; }

static int page_fault_in_progress = 0;

ostream& operator <<(ostream& os, const page_type_t& pagetype) {
  static const char* page_type_names[] = {"none", "L1", "L2", "L3", "L4", "GDT", "LDT", "write"};
  const char* page_type_name = 
    (pagetype.out.type == PAGE_TYPE_INVALID_MFN) ? "inv" :
    (pagetype.out.type == PAGE_TYPE_INACCESSIBLE) ? "inacc" :
    (pagetype.out.type < lengthof(page_type_names)) ? page_type_names[pagetype.out.type] :
    "???";
  
  os << padstring(page_type_name, -5), " ", (pagetype.out.pinned ? "pin" : "   "), " ",
    intstring(pagetype.out.total_count, 5), " total, ", intstring(pagetype.out.type_count, 5), " by type";
  return os;
}

bool force_readonly_physmap = 0;

//
// This is required before switching back to native mode, since we may have
// read/write maps of pages that the guest kernel thinks are read-only
// everywhere; this will cause later pin operations to fail.
//
// We scan the physmap L2 page table, looking for L1 pages that were filled
// in on demand by PTLsim's page fault handler. If the present bit was set,
// we first clear the L2 PTE's present bit, then unpin the L1 page.
//
void unmap_address_space() {
  Waddr physmap_level1_pages = ceil(bootinfo.total_machine_pages, PTES_PER_PAGE) / PTES_PER_PAGE;

  int n = 0;

  if (logable(1)) logfile << "unmap_address_space: check ", physmap_level1_pages, " PTEs:", endl, flush;

  foreach (i, physmap_level1_pages) {
    Level2PTE& l2pte = bootinfo.phys_level2_pagedir[i];
    if unlikely (l2pte.p) {
      l2pte <= l2pte.P(0);
      if (logable(1)) logfile << "  update ", intstring(n, 6), ": pte ", intstring(i, 6), " <= not present", endl;
      n++;
    }
  }

  commit_page_table_updates();
}

//
// Debugging helper function to track down stray refs to a page
//
void find_all_mappings_of_mfn(mfn_t mfn) {
  // Start with an empty mapping
  unmap_address_space();

  int pagetype_bytes_allocated = bootinfo.total_machine_pages * sizeof(page_type_t);
  page_type_t* pagetypes = (page_type_t*)ptl_alloc_private_pages(pagetype_bytes_allocated);
  assert(pagetypes);

  foreach (i, bootinfo.total_machine_pages) {
    pagetypes[i].in.mfn = i;
  }

  logfile << "Finding all mappings of mfn ", mfn, ":", endl, flush;
  int rc = query_pages(pagetypes, bootinfo.total_machine_pages);
  logfile << "rc = ", rc, endl, flush;

  force_readonly_physmap = 1;

  //
  // Nothing so far - where's the refcount from?
  // Print out the page table page we're trying to pin,
  // and see if there's a problem there.
  //
  // Since it's an L4 pin attempt, maybe something
  // else other than a page table is pointing to it?
  //

  foreach (i, bootinfo.total_machine_pages) {
    const page_type_t& pt = pagetypes[i];

    if (pt.out.type == PAGE_TYPE_INACCESSIBLE) continue;

    if (inrange(pt.out.type, (byte)PAGE_TYPE_L1, (byte)PAGE_TYPE_L4)) {
      const Level1PTE* pte = (const Level1PTE*)phys_to_mapped_virt(i << 12);
      foreach (j, PTES_PER_PAGE) {
        if (pte->mfn == mfn) {
          logfile << "  Page table page mfn ", intstring(i, 6), " index ", intstring(j, 3), " references target mfn ", intstring(mfn, 6), ": ", *pte, endl;
        }
        pte++;
      }
    }
  }

  ptl_free_private_pages(pagetypes, pagetype_bytes_allocated);

  force_readonly_physmap = 0;
  unmap_address_space();
}



//
// Walk the page table tree, accumulating the relevant permissions
// as we go, according to x86 rules (specifically, p, rw, us, nx).
//
// The A (accessed) and D (dirty) bits in the returned PTE have
// special meaning. We do not actually update these bits unless
// the instruction causing the PT walk successfully commits.
// Therefore, if the returned A is *not* set, this means one or
// more PT levels need to have their A bits refreshed. If D is
// *not* set, AND the intended access is for a store, the D bits
// also need to be refreshed at the final PT level (level 2 or 1).
// This is done at commit time by page_table_acc_dirty_update().
//

Waddr xen_m2p_map_end;

Level1PTE page_table_walk(W64 rawvirt, W64 toplevel_mfn) {
  VirtAddr virt(rawvirt);

  bool acc_bit_up_to_date = 0;

  if unlikely ((rawvirt >= HYPERVISOR_VIRT_START) & (rawvirt < xen_m2p_map_end)) {
    //
    // The access is inside Xen's address space. Xen will not let us even access the
    // page table entries it injects into every top-level page table page, and we
    // cannot map M2P pages like we do other physical pages. Because Xen does not
    // allow its internal page tables to be mapped by guests at all, we have to
    // special-case these virtual addresses.
    //
    // We cheat by biasing the returned physical address such that we have
    // (HYPERVISOR_VIRT_START - PHYS_VIRT_BASE) + PHYS_VIRT_BASE == HYPERVISOR_VIRT_START
    // when other parts of PTLsim use ptl_phys_to_virt to access the memory.
    //
    const Waddr hypervisor_space_mask = (HYPERVISOR_VIRT_END - HYPERVISOR_VIRT_START)-1;
    Waddr pseudo_phys = (HYPERVISOR_VIRT_START - PHYS_VIRT_BASE) + (rawvirt & hypervisor_space_mask);

    Level1PTE pte = 0;
    pte.mfn = pseudo_phys >> 12;
    pte.p = 1;
    pte.rw = 0;
    pte.us = 1;
    pte.a = 1; // don't try to update accessed bits again
    pte.d = 0;

    return pte;
  }

  Level4PTE& level4 = ((Level4PTE*)phys_to_mapped_virt(toplevel_mfn << 12))[virt.lm.level4];
  Level1PTE final = (W64)level4;

  if unlikely (!level4.p) return final;
  acc_bit_up_to_date = level4.a;

  Level3PTE& level3 = ((Level3PTE*)phys_to_mapped_virt(level4.mfn << 12))[virt.lm.level3];
  final.accum(level3);
  if unlikely (!level3.p) return final;
  acc_bit_up_to_date &= level3.a;

  Level2PTE& level2 = ((Level2PTE*)phys_to_mapped_virt(level3.mfn << 12))[virt.lm.level2];
  final.accum(level2);
  if (unlikely(!level2.p)) return final;
  acc_bit_up_to_date &= level2.a;

  if unlikely (level2.psz) {
    final.mfn = level2.mfn;
    final.pwt = level2.pwt;
    final.pcd = level2.pcd;
    acc_bit_up_to_date &= level2.a;

    final.a = acc_bit_up_to_date;
    final.d = level2.d;

    return final;
  }

  Level1PTE& level1 = ((Level1PTE*)phys_to_mapped_virt(level2.mfn << 12))[virt.lm.level1];
  final.accum(level1);
  if unlikely (!level1.p) return final;
  acc_bit_up_to_date &= level1.a;

  final.mfn = level1.mfn;
  final.g = level1.g;
  final.pat = level1.pat;
  final.pwt = level1.pwt;
  final.pcd = level1.pcd;
  final.a = acc_bit_up_to_date;
  final.d = level1.d;

  if unlikely (final.mfn == bootinfo.shared_info_mfn) {
    final.mfn = (Waddr)ptl_virt_to_phys(&sshinfo) >> 12;
  }

  return final;
}

//
// Page table walk with debugging info:
//
Level1PTE page_table_walk_debug(W64 rawvirt, W64 toplevel_mfn, bool DEBUG) {
  ostream& os = logfile;

  VirtAddr virt(rawvirt);

  bool acc_bit_up_to_date = 0;

  if (DEBUG) os << "page_table_walk: rawvirt ", (void*)rawvirt, ", toplevel ", (void*)toplevel_mfn, endl, flush;

  if unlikely ((rawvirt >= HYPERVISOR_VIRT_START) & (rawvirt < xen_m2p_map_end)) {
    //
    // The access is inside Xen's address space. Xen will not let us even access the
    // page table entries it injects into every top-level page table page, and we
    // cannot map M2P pages like we do other physical pages. Because Xen does not
    // allow its internal page tables to be mapped by guests at all, we have to
    // special-case these virtual addresses.
    //
    // We cheat by biasing the returned physical address such that we have
    // (HYPERVISOR_VIRT_START - PHYS_VIRT_BASE) + PHYS_VIRT_BASE == HYPERVISOR_VIRT_START
    // when other parts of PTLsim use ptl_phys_to_virt to access the memory.
    //
    const Waddr hypervisor_space_mask = (HYPERVISOR_VIRT_END - HYPERVISOR_VIRT_START)-1;
    Waddr pseudo_phys = (HYPERVISOR_VIRT_START - PHYS_VIRT_BASE) + (rawvirt & hypervisor_space_mask);

    if (DEBUG) os << "page_table_walk: special case (inside M2P map): pseudo_phys ", (void*)pseudo_phys, endl, flush;

    Level1PTE pte = 0;
    pte.mfn = pseudo_phys >> 12;
    pte.p = 1;
    pte.rw = 0;
    pte.us = 1;
    pte.a = 1; // don't try to update accessed bits again
    pte.d = 0;

    return pte;
  }

  Level4PTE& level4 = ((Level4PTE*)phys_to_mapped_virt(toplevel_mfn << 12))[virt.lm.level4];
  if (DEBUG) os << "  level4 @ ", &level4, " (mfn ", ((((Waddr)&level4) & 0xffffffff) >> 12), ", entry ", virt.lm.level4, ")", endl, flush;
  Level1PTE final = (W64)level4;

  if unlikely (!level4.p) return final;
  acc_bit_up_to_date = level4.a;

  Level3PTE& level3 = ((Level3PTE*)phys_to_mapped_virt(level4.mfn << 12))[virt.lm.level3];
  if (DEBUG) os << "  level3 @ ", &level3, " (mfn ", ((((Waddr)&level3) & 0xffffffff) >> 12), ", entry ", virt.lm.level3, ")", endl, flush;
  final.accum(level3);
  if unlikely (!level3.p) return final;
  acc_bit_up_to_date &= level3.a;

  Level2PTE& level2 = ((Level2PTE*)phys_to_mapped_virt(level3.mfn << 12))[virt.lm.level2];
  if (DEBUG) os << "  level2 @ ", &level2, " (mfn ", ((((Waddr)&level2) & 0xffffffff) >> 12), ", entry ", virt.lm.level2, ")", endl, flush;
  final.accum(level2);
  if unlikely (!level2.p) return final;
  acc_bit_up_to_date &= level2.a;

  if unlikely (level2.psz) {
    final.mfn = level2.mfn;
    final.pwt = level2.pwt;
    final.pcd = level2.pcd;
    acc_bit_up_to_date &= level2.a;

    final.a = acc_bit_up_to_date;
    final.d = level2.d;

    return final;
  }

  Level1PTE& level1 = ((Level1PTE*)phys_to_mapped_virt(level2.mfn << 12))[virt.lm.level1];
  if (DEBUG) os << "  level1 @ ", &level1, " (mfn ", ((((Waddr)&level1) & 0xffffffff) >> 12), ", entry ", virt.lm.level1, ")", endl, flush;
  final.accum(level1);
  if unlikely (!level1.p) return final;
  acc_bit_up_to_date &= level1.a;

  final.mfn = level1.mfn;
  final.g = level1.g;
  final.pat = level1.pat;
  final.pwt = level1.pwt;
  final.pcd = level1.pcd;
  final.a = acc_bit_up_to_date;
  final.d = level1.d;

  if unlikely (final.mfn == bootinfo.shared_info_mfn) {
    final.mfn = (Waddr)ptl_virt_to_phys(&sshinfo) >> 12;
    if (DEBUG) os << "  Remap shinfo access from real mfn ", bootinfo.shared_info_mfn,
                 " to PTLsim virtual shinfo page mfn ", final.mfn, " (virt ", &sshinfo, ")", endl, flush;
  }

  if (DEBUG) os << "  Final PTE for virt ", (void*)(Waddr)rawvirt, ": ", final, endl, flush;

  return final;
}

//
// Walk the page table, but return the physical address of the PTE itself
// that maps the specified virtual address
//
Waddr virt_to_pte_phys_addr(W64 rawvirt, W64 toplevel_mfn) {
  static const bool DEBUG = 0;
  VirtAddr virt(rawvirt);

  if (unlikely((rawvirt >= HYPERVISOR_VIRT_START) & (rawvirt < xen_m2p_map_end))) return 0;

  Level4PTE& level4 = ((Level4PTE*)phys_to_mapped_virt(toplevel_mfn << 12))[virt.lm.level4];
  if (DEBUG) logfile << "  level4 @ ", &level4, " (mfn ", ((((Waddr)&level4) & 0xffffffff) >> 12), ", entry ", virt.lm.level4, ")", endl, flush;
  if (unlikely(!level4.p)) return 0;

  Level3PTE& level3 = ((Level3PTE*)phys_to_mapped_virt(level4.mfn << 12))[virt.lm.level3];
  if (DEBUG) logfile << "  level3 @ ", &level3, " (mfn ", ((((Waddr)&level3) & 0xffffffff) >> 12), ", entry ", virt.lm.level3, ")", endl, flush;
  if (unlikely(!level3.p)) return 0;

  Level2PTE& level2 = ((Level2PTE*)phys_to_mapped_virt(level3.mfn << 12))[virt.lm.level2];
  if (DEBUG) logfile << "  level2 @ ", &level2, " (mfn ", ((((Waddr)&level2) & 0xffffffff) >> 12), ", entry ", virt.lm.level2, ") [pte ", level2, "]", endl, flush;
  if (unlikely(!level2.p)) return 0;

  if (unlikely(level2.psz)) return ((Waddr)&level2) - PHYS_VIRT_BASE;

  Level1PTE& level1 = ((Level1PTE*)phys_to_mapped_virt(level2.mfn << 12))[virt.lm.level1];
  if (DEBUG) logfile << "  level1 @ ", &level1, " (mfn ", ((((Waddr)&level1) & 0xffffffff) >> 12), ", entry ", virt.lm.level1, ")", endl, flush;

  return ((Waddr)&level1) - PHYS_VIRT_BASE;
}

//
// Walk the specified page table tree and update the accessed
// (and optionally dirty) bits as we go.
//
// Technically this could be done transparently by just accessing
// the specified virtual address, however we still explicitly
// submit this as an update queue to the hypervisor since we need
// to keep our simulated TLBs in sync.
//
void page_table_acc_dirty_update(W64 rawvirt, W64 toplevel_mfn, const PTEUpdate& update) {
  static const bool DEBUG = 1;

  VirtAddr virt(rawvirt);

  if (unlikely((rawvirt >= HYPERVISOR_VIRT_START) & (rawvirt < xen_m2p_map_end))) return;

  //++MTY CHECKME This does not seem to be getting called.
  if (logable(5)) logfile << "Update acc/dirty bits: ", update.a, " ", update.d, " for virt ", (void*)rawvirt, endl;

  Level4PTE& level4 = ((Level4PTE*)phys_to_mapped_virt(toplevel_mfn << 12))[virt.lm.level4];
  if unlikely (!level4.p) return;
  if unlikely (!level4.a) { if (DEBUG) logfile << "level4 @ ", &level4, " <= ", level4.A(1), endl; level4 <= level4.A(1); }

  Level3PTE& level3 = ((Level3PTE*)phys_to_mapped_virt(level4.mfn << 12))[virt.lm.level3];
  if unlikely (!level3.p) return;
  if unlikely (!level3.a) { if (DEBUG) logfile << "level3 @ ", &level3, " <= ", level3.A(1), endl; level3 <= level3.A(1); }

  Level2PTE& level2 = ((Level2PTE*)phys_to_mapped_virt(level3.mfn << 12))[virt.lm.level2];
  if unlikely (!level2.p) return;
  if unlikely (!level2.a) { if (DEBUG) logfile << "level2 @ ", &level2, " <= ", level2.A(1), endl; level2 <= level2.A(1); }

  if unlikely (level2.psz) {
    if unlikely (update.d & (!level2.d)) { if (DEBUG) logfile << "level2 @ ", &level2, " <= ", level2.D(1), endl; level2 <= level2.D(1); }
    return;
  }

  Level1PTE& level1 = ((Level1PTE*)phys_to_mapped_virt(level2.mfn << 12))[virt.lm.level1];
  if unlikely (!level1.p) return;
  if unlikely (!level1.a) { if (DEBUG) logfile << "level1 @ ", &level1, " <= ", level1.A(1), endl; level1 <= level1.A(1); }
  if unlikely (update.d & (!level1.d)) { if (DEBUG) logfile << "level1 @ ", &level1, " <= ", level1.D(1), endl; level1 <= level1.D(1); }

  commit_page_table_updates();
}

//
// Force PTLsim to map the specified page
//
byte force_internal_page_fault(Waddr phys) {
  byte z;
  void* mapped = phys_to_mapped_virt(phys);
  asm volatile("movb (%[m]),%[z];" : [z] "=q" (z) : [m] "r" (mapped) : "memory");
  return z;
}

bool is_mfn_ptpage(mfn_t mfn) {
  if unlikely (mfn >= bootinfo.total_machine_pages) {
    logfile << "Invalid MFN ", mfn, " (", sim_cycle, " cycles, ", total_user_insns_committed, " commits)", endl, flush;
    abort();
  }
  Level1PTE& pte = bootinfo.phys_pagedir[mfn];

  if unlikely (!pte.p) {
    //
    // The page has never been accessed before.
    // Pretend we're reading from it so PTLsim's page fault handler
    // will fault it in for us.
    //
    force_internal_page_fault(mfn << 12);
    if (!pte.p) {
      logfile << "PTE for mfn ", mfn, " is still not present!", endl, flush;
      abort();
    }
  } else if unlikely (!pte.rw) {
    //
    // Try to promote to writable:
    //

    if likely (update_ptl_pte(pte, pte.W(1)) == 0) {
      if (logable(2)) {
        logfile << "[PTLsim Writeback Handler: promoted read-only L1 PTE for guest mfn ",
          mfn, " to writable (", sim_cycle, " cycles, ", total_user_insns_committed, " commits)", endl;
      }
    } else {
      // Could not promote: really is a pinned page table page (need mmu_update hypercall to update it)
    }
  }

  return (!pte.rw);
}

W64 storemask(Waddr physaddr, W64 data, byte bytemask) {
  W64& mem = *(W64*)phys_to_mapped_virt(physaddr);
  W64 merged = mux64(expand_8bit_to_64bit_lut[bytemask], mem, data);

  if unlikely (physaddr >> 40) {
    // Physical address is inside of PTLsim: apply directly
    mem = merged;
  } else if unlikely (is_mfn_ptpage(physaddr >> 12)) {
    // MFN is pinned: force Xen to do the store for us
    mmu_update_t u;
    u.ptr = physaddr;
    u.val = merged;
    int rc = HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF);
    if unlikely (rc) {
      logfile << "storemask: WARNING: store to physaddr ", (void*)physaddr, " <= ", Level1PTE(data), " failed with rc ", rc, endl, flush;
    }
  } else {
    mem = merged;
  }

  return data;
}

// idx must be between 0 and 8191 (i.e. 65535 >> 3)
bool Context::gdt_entry_valid(W16 idx) {
  if ((idx >= FIRST_RESERVED_GDT_ENTRY) && (idx < (FIRST_RESERVED_GDT_ENTRY + (PAGE_SIZE / sizeof(SegmentDescriptor)))))
    return true;

  return (idx < gdtsize);
}

SegmentDescriptor Context::get_gdt_entry(W16 idx) {
  // idx >>= 3; // remove GDT/LDT select bit and 2-bit DPL

  if (!idx)
    return SegmentDescriptor(0);

  if ((idx >> 9) == FIRST_RESERVED_GDT_PAGE)
    return *(const SegmentDescriptor*)((byte*)bootinfo.gdt_page + (lowbits(idx, 9) * 8));

  if (idx >= gdtsize)
    return SegmentDescriptor(0);

  mfn_t mfn = gdtpages[idx >> 9];
  return *(const SegmentDescriptor*)phys_to_mapped_virt((mfn << 12) + (lowbits(idx, 9) * 8));
}

void Context::flush_tlb() {
  // Also clear out the TLB mini-cache:
  foreach (i, lengthof(cached_pte_virt)) {
    cached_pte_virt[i] = 0xffffffffffffffffULL;
    cached_pte[i] = 0;
  }
}

int Context::write_segreg(unsigned int segid, W16 selector) {
  assert(segid < SEGID_COUNT);

  int idx = selector >> 3; // mask out the dpl bits and turn into index

  if (idx == 0) {
    //
    // It's perfectly legal to load a null selector, especially in x86-64 mode,
    // where most segments (except cs, fs, gs) are ignored.
    //
    // The processor is supposed to deliver a fault (seg_not_present or stack_fault)
    // the first time the null selector is actually used.
    //
    if (logable(4)) {
      logfile << "write_segreg(", segid, ", 0x", hexstring(selector, 16), " (idx ", idx, ")): load null segment", endl;
    }
    seg[segid].selector = 0;
    reload_segment_descriptor(segid, selector);
    return 0;
  }

  if (!gdt_entry_valid(idx)) {
    if (logable(4)) {
      logfile << "write_segreg(", segid, ", 0x", hexstring(selector, 16), " (idx ", idx, ")): gdt entry ", idx, " is invalid (gdt size? ", gdtsize, ")", endl;
    }
    return EXCEPTION_x86_gp_fault;
  }

  SegmentDescriptor desc = get_gdt_entry(idx);

  int cs_dpl = (kernel_mode) ? 0 : 3;
  if (desc.dpl < cs_dpl) {
    if (logable(4)) {
      logfile << "write_segreg(", segid, ", 0x", hexstring(selector, 16), " (idx ", idx, ")): gdt entry ", idx, " had incompatible DPL (desc dpl ", desc.dpl, " vs current dpl ", cs_dpl, ")", endl;
      logfile << "  gdt entry was: ", desc, endl;
    }
    return EXCEPTION_x86_gp_fault;
  }

  if (!desc.p) {
    if (logable(4)) {
      logfile << "write_segreg(", segid, ", 0x", hexstring(selector, 16), " (idx ", idx, ")): gdt entry ", idx, " is not present", endl;
      logfile << "  gdt entry was: ", desc, endl;
    }
    // return (segid == SEGID_SS) ? EXCEPTION_x86_stack_fault : EXCEPTION_x86_seg_not_present;
    // Technically this is supposed to be a seg not present fault, but x86-64 mode seems to signal a GP fault instead:
    return EXCEPTION_x86_gp_fault;
  }

  reload_segment_descriptor(segid, selector);

  if (logable(4)) {
    logfile << "write_segreg(", segid, ", 0x", hexstring(selector, 16), " (idx ", idx, ")): gdt entry ", idx, " validated", endl;
    logfile << "  gdt entry was: ", desc, endl;
  }

  return 0;
}

void Context::swapgs() {
  // This is equivalent to swapgs instruction:
  if (logable(4)) logfile << "  swapgs: update gsbase old ", (void*)(Waddr)seg[SEGID_GS].base, " => new ", (void*)(Waddr)swapgs_base, endl;
  W64 temp = seg[SEGID_GS].base;
  seg[SEGID_GS].base = swapgs_base;
  swapgs_base = temp;
}

void Context::reload_segment_descriptor(unsigned int segid, W16 selector) {

  SegmentDescriptorCache& s = seg[segid];

  s.selector = selector;

  switch (segid) {
  case SEGID_CS:
    s = get_gdt_entry(seg[SEGID_CS].selector >> 3);
    use32 = s.use32;
    use64 = s.use64;
    virt_addr_mask = (use64 ? 0xffffffffffffffffULL : 0x00000000ffffffffULL);
    break;
  case SEGID_SS:
  case SEGID_DS:
  case SEGID_ES:
    if (use64)
      s.flatten();
    else s = get_gdt_entry(seg[segid].selector >> 3);
    break;
  case SEGID_FS:
  case SEGID_GS:
    s = get_gdt_entry(seg[segid].selector >> 3);
    if (use64) s.limit = 0xffffffffffffffffULL;
    break;
  }
}

//
// Update for the first time after a return from native mode:
//
void Context::init() {
  flush_tlb();
  commitarf[REG_ctx] = ((Waddr)this);
  commitarf[REG_fpstack] = ((Waddr)&this->fpstack);

  reload_segment_descriptor(SEGID_CS, seg[SEGID_CS].selector);
  reload_segment_descriptor(SEGID_SS, seg[SEGID_SS].selector);
  reload_segment_descriptor(SEGID_DS, seg[SEGID_DS].selector);
  reload_segment_descriptor(SEGID_ES, seg[SEGID_ES].selector);
  reload_segment_descriptor(SEGID_FS, seg[SEGID_FS].selector);
  reload_segment_descriptor(SEGID_GS, seg[SEGID_GS].selector);

  if (use64 && (!seg[SEGID_FS].selector)) {
    seg[SEGID_FS].base = fs_base;
  }

  if (kernel_mode) {
    seg[SEGID_GS].base = gs_base_kernel;
    //++MTY CHECKME re unusual 32 bit processes that reload gs
    swapgs_base = gs_base_user;
  } else {
    // user mode
    if (use64) seg[SEGID_GS].base = gs_base_user;
    swapgs_base = gs_base_kernel;
  }
}

void* Context::check_and_translate(Waddr virtaddr, int sizeshift, bool store, bool internal, int& exception, PageFaultErrorCode& pfec, PTEUpdate& pteupdate) {
  exception = 0;
  pteupdate = 0;

  pfec = 0;

  if unlikely (lowbits(virtaddr, sizeshift)) {
    exception = EXCEPTION_UnalignedAccess;
    return null;
  }

  if unlikely (internal) {
    //
    // Directly mapped to PTL space (microcode load/store)
    // We need to patch in PTLSIM_VIRT_BASE since in 32-bit
    // mode, ctx.virt_addr_mask will chop off these bits.
    //
    return (void*)(lowbits(virtaddr, 32) | PTLSIM_VIRT_BASE);
  }

  Level1PTE pte;

  pte = virt_to_pte(virtaddr);
  
  bool page_not_present = (!pte.p);
  bool page_read_only = (store & (!pte.rw));
  bool page_kernel_only = ((!kernel_mode) & (!pte.us));

  if unlikely (page_not_present | page_read_only | page_kernel_only) {
    if (logable(4)) logfile << "virt ", (void*)virtaddr, ", mfn ", pte.mfn, ": store ", store, ", page_not_present ",
      page_not_present, ", page_kernel_only ", page_kernel_only, ", page_read_only ", page_read_only, endl;

    if unlikely (store && (!page_not_present) && (!page_kernel_only) &&
                 page_read_only && is_mfn_ptpage(pte.mfn)) {
      if (logable(4)) {
        logfile << "Page is a page table page: special semantics", endl;
      }
      //
      // This is a page table page and is technically mapped read only,
      // but the user code has attempted to store to it anyway under the
      // assumption that the hypervisor will trap the store, validate the
      // written PTE value and emulate the store as if it was to a normal
      // read-write page.
      //
      // For PTLsim use, we set the pteupdate.ptwrite bit to indicate that
      // special handling is needed. However, no exception is signalled.
      //
      pteupdate.ptwrite = 1;
    } else {
      exception = (store) ? EXCEPTION_PageFaultOnWrite : EXCEPTION_PageFaultOnRead;
      pfec.p = pte.p;
      pfec.rw = store;
      pfec.us = (!kernel_mode);
    }

    if (exception) return null;
  }

  pteupdate.a = (!pte.a);
  pteupdate.d = (store & (!pte.d));

  return pte_to_mapped_virt(virtaddr, pte);
}

int Context::copy_from_user(void* target, Waddr source, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr, bool forexec) {
  Level1PTE pte;

  int n = 0;

  pfec = 0;
  pte = virt_to_pte(source);

  if unlikely ((!pte.p) | (forexec & pte.nx) | ((!kernel_mode) & (!pte.us))) {
    faultaddr = source;
    pfec.p = pte.p;
    pfec.nx = forexec;
    pfec.us = (!kernel_mode);
    return 0;
  }

  n = min(4096 - lowbits(source, 12), (Waddr)bytes);
  memcpy(target, pte_to_mapped_virt(source, pte), n);

  PTEUpdate pteupdate = 0;
  pteupdate.a = 1;

  if unlikely (!pte.a) update_pte_acc_dirty(source, pteupdate);

  // All the bytes were on the first page
  if likely (n == bytes) return n;

  // Go on to second page, if present
  pte = virt_to_pte(source + n);
  if unlikely ((!pte.p) | (forexec & pte.nx) | ((!kernel_mode) & (!pte.us))) {
    faultaddr = source + n;
    pfec.p = pte.p;
    pfec.nx = forexec;
    pfec.us = (!kernel_mode);
    return n;
  }

  if (!pte.a) update_pte_acc_dirty(source + n, pteupdate);

  memcpy((byte*)target + n, pte_to_mapped_virt(source + n, pte), bytes - n);
  n = bytes;
  return n;
}

int Context::copy_to_user(Waddr target, void* source, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr) {
  Level1PTE pte;

  pfec = 0;
  pte = virt_to_pte(target);
  if unlikely ((!pte.p) | (!pte.rw) | ((!kernel_mode) & (!pte.us))) {
    faultaddr = target;
    pfec.p = pte.p;
    pfec.rw = 1;
    pfec.us = (!kernel_mode);
    return 0;
  }

  byte* targetlo = (byte*)pte_to_mapped_virt(target, pte);
  int nlo = min(4096 - lowbits(target, 12), (Waddr)bytes);

  PTEUpdate pteupdate = 0;
  pteupdate.a = 0;
  pteupdate.d = 1;
  if unlikely ((!pte.a) | (!pte.d)) update_pte_acc_dirty(target, pteupdate);

  // All the bytes were on the first page
  if likely (nlo == bytes) {
    memcpy(targetlo, source, nlo);
    return bytes;
  }

  // Go on to second page, if present
  pte = virt_to_pte(target + nlo);
  if unlikely ((!pte.p) | (!pte.rw) | ((!kernel_mode) & (!pte.us))) {
    faultaddr = target + nlo;
    pfec.p = pte.p;
    pfec.rw = 1;
    pfec.us = (!kernel_mode);
    return nlo;
  }

  if unlikely ((!pte.a) | (!pte.d)) update_pte_acc_dirty(target + nlo, pteupdate);

  memcpy(pte_to_mapped_virt(target + nlo, pte), (byte*)source + nlo, bytes - nlo);
  memcpy(targetlo, source, nlo);

  return bytes;
}

//
// Why we need to always track both MFNs:
// Example of ambiguity:
//
// - Pair of proceses (A and B)
// - Page 1 is mapped to mfn X in both A and B
// - Page 2 is mapped to mfn Y in A and mfn Z in B
// - BB crosses 1-to-2 page boundary at same virt addr in both A and B
// - Meaning of instruction is different depending only on those
//   bytes in page 2 (mfn Y or Z)
//

RIPVirtPhys& RIPVirtPhys::update(Context& ctx, int bytes) {
  Level1PTE pte;
  bool invalid;

  use64 = ctx.use64;
  kernel = ctx.kernel_mode;
  df = ((ctx.internal_eflags & FLAG_DF) != 0);
  padlo = 0;
  padhi = 0;

  pte = ctx.virt_to_pte(rip);
  invalid = ((!pte.p) | pte.nx | ((!ctx.kernel_mode) & (!pte.us)));
  mfnlo = (invalid) ? INVALID : pte.mfn;
  mfnhi = mfnlo;

  int page_crossing = ((lowbits(rip, 12) + (bytes-1)) >> 12);

  //
  // Since table lookups only know the RIP of the target and not
  // its size, we don't know if there is a page crossing. Hence,
  // we always assume there is. BB translation (case above) may
  // be more optimized, only doing this if the pages are truly
  // different.
  //
  //++MTY TODO:
  // If BBs are terminated at the first insn to cross a page,
  // technically we could get away with only checking if the
  // byte at rip + (15-1) would hit the next page.
  //

  if unlikely (page_crossing) {
    pte = ctx.virt_to_pte(rip + (bytes-1));
    invalid = ((!pte.p) | pte.nx | ((!ctx.kernel_mode) & (!pte.us)));
    mfnhi = (invalid) ? INVALID : pte.mfn;
  }

  return *this;
}

//
// Unmap an entire tree of physical pages rooted
// at the specified L4 mfn. This must be done
// before passing a pin hypercall or new_baseptr
// hypercall up to Xen. We may have read/write
// refs to some of these pages, which are currently
// normal pages (updated by the guest kernel) but
// which will become read-only page table pages
// once Xen tries to pin the entire tree. We only
// need to unmap L4/L3/L2 pages; L1 pages (i.e.
// the actual data pages) are not relevant.
// 
// Only those pages with read/write mappings are 
// unmapped. Levels 4/3/2 of the page table are
// recursively traversed and unmapped from the leaves
// on up, so we do not accidentally touch a page and
// re-map it on our way back to the root.
//
static const bool debug_unmap_phys_page_tree = 1;

inline void unmap_level1_page_tree(mfn_t mfn) {
  // No need to unmap actual leaf physical pages - those are just data pages
  Level1PTE& physpte = bootinfo.phys_pagedir[mfn];
  if unlikely (debug_unmap_phys_page_tree & logable(1)) logfile << "        L1: mfn ", intstring(mfn, 8), ((physpte.p & physpte.rw) ? " (unmap)" : ""), endl;
  if unlikely (physpte.p & physpte.rw) physpte <= physpte.P(0);
}

inline void unmap_level2_page_tree(mfn_t mfn) {
  Level2PTE* ptes = (Level2PTE*)phys_to_mapped_virt(mfn << 12);
  foreach (i, PTES_PER_PAGE) if unlikely (ptes[i].p) unmap_level1_page_tree(ptes[i].mfn);
  Level1PTE& physpte = bootinfo.phys_pagedir[mfn];
  if unlikely (debug_unmap_phys_page_tree & logable(1)) logfile << "      L2: mfn ", intstring(mfn, 8), ((physpte.p & physpte.rw) ? " (unmap)" : ""), endl;
  if unlikely (physpte.p & physpte.rw) physpte <= physpte.P(0);
}

void unmap_level3_page_tree(mfn_t mfn) {
  Level3PTE* ptes = (Level3PTE*)phys_to_mapped_virt(mfn << 12);
  foreach (i, PTES_PER_PAGE) if unlikely (ptes[i].p) unmap_level2_page_tree(ptes[i].mfn);
  Level1PTE& physpte = bootinfo.phys_pagedir[mfn];
  if unlikely (debug_unmap_phys_page_tree & logable(1)) logfile << "    L3: mfn ", intstring(mfn, 8), ((physpte.p & physpte.rw) ? " (unmap)" : ""), endl;
  if unlikely (physpte.p & physpte.rw) physpte <= physpte.P(0);
}

void unmap_level4_page_tree(mfn_t mfn) {
  Level4PTE* ptes = (Level4PTE*)phys_to_mapped_virt(mfn << 12);
  foreach (i, PTES_PER_PAGE) if unlikely (ptes[i].p) unmap_level3_page_tree(ptes[i].mfn);
  Level1PTE& physpte = bootinfo.phys_pagedir[mfn];
  if unlikely (debug_unmap_phys_page_tree & logable(1)) logfile << "  L4: mfn ", intstring(mfn, 8), ((physpte.p & physpte.rw) ? " (unmap)" : ""), endl;
  if unlikely (physpte.p & physpte.rw) physpte <= physpte.P(0);
}

void unmap_phys_page_tree(mfn_t root) {
  if (logable(1)) logfile << "Unmapping page tree starting at root mfn ", root, endl;
  unmap_level4_page_tree(root);
  commit_page_table_updates();
}

void smc_setdirty_internal(Level1PTE& pte, bool dirty) {
  if (logable(5)) logfile << "smc_setdirty_internal(", &pte, " [", pte, "], dirty ", dirty, ")", endl, flush;
  assert(update_ptl_pte(pte, pte.D(dirty)) == 0);
}

Level4PTE ptlsim_pml4_entry;
Level4PTE physmap_pml4_entry;

//
// Build page tables for the 1:1 mapping of physical memory.
//
// Since we don't know which pages a domain can access until later,
// and the accessibility may change at any time, we only build levels
// L2 and L3, but leave L1 to be constructed on demand (we still do
// allocate L1, we just don't fill it).
//
// On return, PML4 slot 508 (0xfffffe0000000000) should be set to
// ptl_virt_to_mfn(bootinfo.phys_level3_pagedir).
//
void build_physmap_page_tables() {
  static const bool DEBUG = 0;

  if (DEBUG) cerr << "Building physical page map for ", bootinfo.total_machine_pages, " pages (",
    (pages_to_kb(bootinfo.total_machine_pages) / 1024), " MB)", " of memory:", endl, flush;

  Waddr physmap_level1_page_count = ceil(bootinfo.total_machine_pages, PTES_PER_PAGE) / PTES_PER_PAGE;

  bootinfo.phys_pagedir = (Level1PTE*)ptl_alloc_private_pages(physmap_level1_page_count * PAGE_SIZE);
  memset(bootinfo.phys_pagedir, 0, physmap_level1_page_count * PAGE_SIZE);

  if (DEBUG) cerr << "  L1 page table at virt ", (void*)bootinfo.phys_pagedir, " (", bootinfo.total_machine_pages, " entries, ",
    physmap_level1_page_count, " pages, ", (bootinfo.total_machine_pages * sizeof(Level1PTE)), " bytes)", endl, flush;

  //
  // Construct L2 page tables, pointing to fill-on-demand L1 tables:
  //
  Waddr physmap_level2_page_count = ceil(physmap_level1_page_count, PTES_PER_PAGE) / PTES_PER_PAGE;
  bootinfo.phys_level2_pagedir = (Level2PTE*)ptl_alloc_private_pages(physmap_level2_page_count * PAGE_SIZE);

  if (DEBUG) cerr << "  L2 page table at virt ", (void*)bootinfo.phys_level2_pagedir, " (", physmap_level1_page_count, " entries, ",
    physmap_level2_page_count, " pages, ", (physmap_level1_page_count * sizeof(Level1PTE)), " bytes)", endl, flush;

  foreach (i, physmap_level1_page_count) {
    struct Level2PTE& pte = bootinfo.phys_level2_pagedir[i];
    pte = 0;
    pte.p = 1;  // let PTLsim fill it in on demand
    pte.rw = 1; // sub-pages are writable unless overridden
    pte.us = 1; // both user and supervisor (PTLsim itself will check protections)
    pte.a = 1;  // accessed
    pte.mfn = ptl_virt_to_mfn(bootinfo.phys_pagedir + (i * PTES_PER_PAGE));

    // cerr << "    Slot ", intstring(i, 6), " = ", pte, endl, flush;
    pte.p = 0;
  }

  // Clear out leftover slots: we may not care, but Xen will complain:
  if ((physmap_level1_page_count & (PTES_PER_PAGE-1)) > 0) {
    foreach (i, PTES_PER_PAGE - (physmap_level1_page_count & (PTES_PER_PAGE-1))) {
      // cerr << "    Slot ", intstring(physmap_level1_page_count + i, 6), " is left over", endl, flush;
      bootinfo.phys_level2_pagedir[physmap_level1_page_count + i] = 0;
    }
  }

  //
  // Construct L3 page table (just one page covers 2^39 bit phys addr space):
  //
  assert(physmap_level2_page_count < PTES_PER_PAGE);
  bootinfo.phys_level3_pagedir = (Level3PTE*)ptl_alloc_private_page();

  if (DEBUG) cerr << "  L3 page table at virt ", (void*)bootinfo.phys_level3_pagedir, " (", physmap_level2_page_count, " entries, ",
    1, " pages, ", (physmap_level2_page_count * sizeof(Level1PTE)), " bytes)", endl, flush;

  foreach (i, physmap_level2_page_count) {
    struct Level3PTE& pte = bootinfo.phys_level3_pagedir[i];
    pte = 0;
    pte.p = 1;  // pre-filled
    pte.rw = 1; // sub-pages are writable unless overridden
    pte.us = 1; // both user and supervisor (PTLsim itself will check protections)
    pte.a = 1;  // accessed

    // Link back to L2 tables:
    Level2PTE* ptvirt = bootinfo.phys_level2_pagedir + (i * PTES_PER_PAGE);
    pte.mfn = ptl_virt_to_mfn(ptvirt);
    // cerr << "    Slot ", intstring(i, 6), " = ", pte, endl, flush;
    assert(make_ptl_page_writable(ptvirt, false) == 0);
    // assert(pin_page_table_page(ptvirt, 2) == 0);
  }

  // Clear out leftover slots: we may not care, but Xen will complain:
  if ((physmap_level2_page_count & (PTES_PER_PAGE-1)) > 0) {
    foreach (i, PTES_PER_PAGE - physmap_level2_page_count) {
      // cerr << "    Slot ", intstring(physmap_level2_page_count + i, 6), " is left over", endl;
      bootinfo.phys_level3_pagedir[physmap_level2_page_count + i] = 0;
    }
  }

  //
  // Remap and pin L3 page
  //
  Level3PTE* ptvirt = bootinfo.phys_level3_pagedir;
  if (DEBUG) cerr << "  Final L3 page table page at virt ", bootinfo.phys_level3_pagedir,
    " (mfn ", ptl_virt_to_mfn(bootinfo.phys_level3_pagedir), ")", endl, flush;
  assert(make_ptl_page_writable(ptvirt, false) == 0);
  // assert(pin_page_table_page(ptvirt, 3) == 0);

  //
  // Build physmap PML4 entry 508:
  //
  physmap_pml4_entry = 0;
  physmap_pml4_entry.p = 1;
  physmap_pml4_entry.rw = 1;
  physmap_pml4_entry.us = 1;
  physmap_pml4_entry.a = 1;
  physmap_pml4_entry.mfn = ptl_virt_to_mfn(bootinfo.phys_level3_pagedir);

  //
  // Build PTLsim PML4 entry 510:
  //
  ptlsim_pml4_entry = 0;
  ptlsim_pml4_entry.p = 1;
  ptlsim_pml4_entry.rw = 1;
  ptlsim_pml4_entry.us = 1;
  ptlsim_pml4_entry.a = 1;
  ptlsim_pml4_entry.mfn = ptl_virt_to_mfn(bootinfo.ptl_level3_map);
}

//
// Inject the PTLsim toplevel page table entries (PML 510 and PML 508)
// into the specified user mfn. The page must already be pinned; this
// function is called right before loading.
//
void inject_ptlsim_into_toplevel(mfn_t mfn, bool force = false) {
  int rc;

  Level4PTE* top = (Level4PTE*)phys_to_mapped_virt(mfn << 12);
  int ptlsim_slot = VirtAddr(PTLSIM_VIRT_BASE).lm.level4;
  int physmap_slot = VirtAddr(PHYS_VIRT_BASE).lm.level4;
#if 0
  cerr << "Inject PTLsim PML4 entries into top mfn ", mfn, " (at virt ", top, "):", endl;
  cerr << "  top[", ptlsim_slot, "] = ", ptlsim_pml4_entry, endl;
  cerr << "  top[", physmap_slot, "] = ", physmap_pml4_entry, endl, flush;
#endif
  bool needs_ptlsim_slot_update = true;
  bool needs_physmap_slot_update = true;

  if (!force) {
    needs_ptlsim_slot_update = (top[ptlsim_slot] != ptlsim_pml4_entry);
    needs_physmap_slot_update = (top[physmap_slot] != physmap_pml4_entry);
  }

  if (needs_ptlsim_slot_update)
    assert(update_phys_pte((mfn << 12) + (ptlsim_slot * 8), ptlsim_pml4_entry) == 0);

  if (needs_physmap_slot_update)
    assert(update_phys_pte((mfn << 12) + (physmap_slot * 8), physmap_pml4_entry) == 0);
}

//
// Set the real page table on the PTLsim primary VCPU.
//
// This automatically calls inject_ptlsim_into_toplevel(mfn)
// to make sure we have a seamless transition. The page must
// already be pinned on behalf of the guest.
//
void switch_page_table(mfn_t mfn) {
  //return;

  inject_ptlsim_into_toplevel(mfn);

  mmuext_op op;
  op.cmd = MMUEXT_NEW_BASEPTR;
  op.arg1.mfn = mfn;

  int success_count = 0;
  assert(HYPERVISOR_mmuext_op(&op, 1, &success_count, DOMID_SELF) == 0);
}

ostream& print_page_table_with_types(ostream& os, Level1PTE* ptes) {
  page_type_t pagetypes[512];
  foreach (i, 512) {
    pagetypes[i].in.mfn = ptes[i].mfn;
  }

  assert(query_pages(pagetypes, lengthof(pagetypes)) == 0);

  foreach (i, 512) {
    os << "        ", intstring(i, 3), ": ", ptes[i], " type ", pagetypes[i], endl;
  }

  return os;
}

inline W32 get_eflags() {
  W64 eflags;
  asm volatile("pushfq; popq %[eflags]" : [eflags] "=r" (eflags) : : "memory");
  return eflags;
}

// The returned %rsp is advisory only!
static inline void* get_rsp() {
  W64 rsp;
  asm volatile("mov %%rsp,%[out]" : [out] "=rm" (rsp));
  return (void*)rsp;
}

static inline mfn_t get_cr3_mfn() {
  Waddr cr3;
  asm volatile("mov %%cr3,%[out]" : [out] "=r" (cr3));
  return (cr3 >> 12);
}

//
// Page fault handling logic:
//
// By default, PTLsim maps physical pages as writable the first time
// they are referenced. Since we call unmap_address_space() before
// passing through any hypercalls that could collide with our now
// removed writable mappings, this is not a problem.
//
// If Xen refuses to update the physmap PTE with a writable mapping,
// this means some live page table is pinning it to read-only. In
// this case, for loads at least, we simply make it a read only
// mapping, which is always allowed.
//
asmlinkage void do_page_fault(W64* regs) {
  static const bool force_page_fault_logging = 0;
  int rc;
  Waddr faultaddr = read_cr2();
  //
  // If we are already handling a page fault, and got another one
  // that means we faulted in pagetable walk. Continuing here would cause
  // a recursive fault.
  //
  PageFaultErrorCode pfec = regs[REG_ar1];

  if unlikely (page_fault_in_progress) {
    cerr << "PTLsim Internal Error: recursive page fault @ rip ", (void*)regs[REG_rip], " while accessing ", (void*)faultaddr, " (error code ", pfec, ")", endl, flush;
    cerr << "Registers:", endl;
    print_regs(cerr, regs);
    print_stack(cerr, regs[REG_rsp]);
    cerr.flush();
    logfile.flush();
    xen_shutdown_domain(SHUTDOWN_crash);
  }

  page_fault_in_progress = 1;

  if likely (inrange(faultaddr, PHYS_VIRT_BASE, (PHYS_VIRT_BASE + ((Waddr)bootinfo.total_machine_pages * PAGE_SIZE) - 1))) {
    mfn_t mfn = (faultaddr - (Waddr)PHYS_VIRT_BASE) >> 12;
    int level2_slot_index = mfn / PTES_PER_PAGE;
    Level2PTE& l2pte = bootinfo.phys_level2_pagedir[level2_slot_index];
    Level1PTE& l1pte = bootinfo.phys_pagedir[mfn];

    if unlikely (!l2pte.p) {
      //
      // Level 2 PTE was not present: either this is the first
      // access or it was fast cleared by unmap_address_space().
      // In any case, re-establish it after clearing any old
      // PTEs from the corresponding L1 page.
      //
      Level1PTE* l1page = floorptr(&l1pte, PAGE_SIZE);
      assert(make_ptl_page_writable(l1page, 1) == 0);
      ptl_zero_private_page(l1page);
      assert(make_ptl_page_writable(l1page, 0) == 0);

      assert(update_ptl_pte(l2pte, l2pte.P(1)) == 0);

      if (logable(2) | force_page_fault_logging) {
        logfile << "[PTLsim Page Fault Handler from rip ", (void*)regs[REG_rip], "] ",
          (void*)faultaddr, ": added L2 PTE slot ", level2_slot_index, " (L1 mfn ",
          l2pte.mfn, ") to PTLsim physmap", endl;
      }
    }

    //
    // Page was not present: try to map the page read-write
    //
    Level1PTE pte = 0;
    pte.p = 1;
    pte.rw = 1;
    pte.us = 1;
    pte.mfn = mfn;
    
    rc = (force_readonly_physmap) ? -EINVAL : update_ptl_pte(l1pte, pte);

    if unlikely (rc) {
      //
      // It's a special page and must be marked read-only:
      //
      pte.rw = 0;
      rc = update_ptl_pte(l1pte, pte);
      
      if (rc) {
        logfile << "ERROR: Cannot map mfn ", mfn, " (for virt ", (void*)faultaddr, ") into the address space (requested from rip ", (void*)regs[REG_rip], "). Does it belong to the domain?", endl;
        logfile << "Stopped at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits", endl;
        logfile << flush;
        cerr << flush;
        xen_shutdown_domain(SHUTDOWN_crash);
      }

      if (logable(2) | force_page_fault_logging) logfile << "[PTLsim Page Fault Handler from rip ", (void*)regs[REG_rip], "] ", (void*)faultaddr, ": added read-only L1 PTE for guest mfn ", mfn, " (", sim_cycle, " cycles, ", total_user_insns_committed, " commits)", endl;
    } else {
      if (logable(2) | force_page_fault_logging) logfile << "[PTLsim Page Fault Handler from rip ", (void*)regs[REG_rip], "] ", (void*)faultaddr, ": added L1 PTE for guest mfn ", mfn, " (", sim_cycle, " cycles, ", total_user_insns_committed, " commits)", endl;
    }
  } else {
    cerr << "PTLsim Internal Error: page fault @ rip ", (void*)regs[REG_rip], " while accessing ", (void*)faultaddr, " (error code ", pfec, "); rsp ", get_rsp(), endl;
    cerr << "Registers:", endl;
    print_regs(cerr, regs);
    print_stack(cerr, regs[REG_rsp]);
    cerr.flush();
    logfile.flush();
    xen_shutdown_domain(SHUTDOWN_crash);
    asm("ud2a");
  }

  page_fault_in_progress = 0;
}

//
// Handle Xen hypercall, invoked by running the SYSCALL
// instruction in kernel mode. SYSCALL from user mode
// is handled elsewhere.
//
static const char* hypercall_names[] = {
  "set_trap_table", "mmu_update", "set_gdt", "stack_switch", "set_callbacks", "fpu_taskswitch", "sched_op_compat", "dom0_op",
  "set_debugreg", "get_debugreg", "update_descriptor", "11", "memory_op", "multicall", "update_va_mapping", "set_timer_op",
  "event_channel_op_compat", "xen_version", "console_io", "physdev_op_compat", "grant_table_op", "vm_assist", "update_va_mapping_otherdomain", "iret",
  "vcpu_op", "set_segment_base", "mmuext_op", "acm_op", "nmi_op", "sched_op", "callback_op", "xenoprof_op",
  "event_channel_op", "physdev_op"
};


#ifdef __x86_64__
#define GUEST_KERNEL_RPL 3
#else
#define GUEST_KERNEL_RPL 1
#endif

// Fix up the RPL of a guest segment selector
static inline W16 fixup_guest_stack_selector(W16 sel) {
  return ((sel & 3) >= GUEST_KERNEL_RPL) ? sel : ((sel & ~3) | GUEST_KERNEL_RPL);
}

void update_time();

W64 timer_interrupt_period_in_cycles = infinity;
W64 timer_interrupt_last_sent_at_cycle = 0;

int handle_xen_hypercall(Context& ctx, int hypercallid, W64 arg1, W64 arg2, W64 arg3, W64 arg4, W64 arg5, W64 arg6) {
  //
  // x86-64 hypercall conventions:
  //
  // Hypercall ID in %rax
  // Return address in %rcx (SYSCALL microcode puts it there)
  // Args in %rdi %rsi %rdx %r10 %r8 %r9 (identical to Linux syscall interface)
  // (see arch/x86/domain.c)
  //
  // Normal x86-64 userspace ABI:
  //
  // Callee must preserve: rbx rsp rbp r12 r13 r14 r15
  // Args passed in:       rdi rsi rdx rcx r8 r9        (syscalls replace rcx with r10 since processor overwrites rcx)
  // Available:            rax r10 r11
  //

  static const bool force_hypercall_logging = 0;
  bool debug = logable(1) | force_hypercall_logging;

  if (debug) {
    logfile << "hypercall: ", hypercallid, " (", ((hypercallid < lengthof(hypercall_names)) ? hypercall_names[hypercallid] : "???"), 
      ") on vcpu ", ctx.vcpuid, " from ", (void*)ctx.commitarf[REG_rip], " ", flush;
    // Get real return address from stack, above push of %rcx and %r11
    void* real_retaddr;
    int stackn = ctx.copy_from_user(&real_retaddr, (ctx.commitarf[REG_rsp] + 8*2), 8);
    logfile << "real ret addr "; if (stackn) logfile << real_retaddr; else logfile << "<unknown>";
    logfile << " args (", (void*)arg1, ", ", (void*)arg2, ", ", (void*)arg3, ", ", (void*)arg4, ", ",
      (void*)arg5, ", ", (void*)arg6, ") at cycle ", iterations, " (", total_user_insns_committed, " commits)", endl, flush;
  }

  W64s rc;

  PageFaultErrorCode pfec;
  Waddr faultaddr;

  switch (hypercallid) {
  case __HYPERVISOR_set_trap_table: {
    struct trap_info trap_ctxt[256];
    if (arg1) {
      int n = ctx.copy_from_user(trap_ctxt, arg1, sizeof(trap_ctxt), pfec, faultaddr);
      rc = -EFAULT;
      if (n != sizeof(trap_ctxt)) break;
    } else {
      setzero(trap_ctxt);
    }

    setzero(ctx.idt);

    foreach (i, 256) {
      const trap_info& ti = trap_ctxt[i];
      TrapTarget& tt = ctx.idt[ti.vector];
      tt.cs = ti.cs >> 3;
      tt.rip = ti.address;
      tt.cpl = lowbits(ti.flags, 2);
      tt.maskevents = bit(ti.flags, 2);
    }

    rc = 0;
    break;
  }

  case __HYPERVISOR_mmu_update: {
    mmu_update_t* reqp = (mmu_update_t*)arg1;
    Waddr count = arg2;

    mmu_update_t req;

    int total_updates = 0;
    foreach (i, count) {
      int n = ctx.copy_from_user(&req, (Waddr)&reqp[i], sizeof(mmu_update_t), pfec, faultaddr);
      if (n < sizeof(mmu_update_t)) break;
      mfn_t mfn = req.ptr >> 12;
      if (mfn >= bootinfo.total_machine_pages) {
        if (debug) logfile << "  mfn out of range (", bootinfo.total_machine_pages, ")", endl, flush;
        continue;
      }

      //
      // If we're updating an L4/L3/L2 page and the new PTE data specifies
      // a page we currently have mapped read/write, we must unmap it first
      // since Xen will not let the page table page reference it otherwise.
      //
      // The actual mfn we're modifying must already be a page table page;
      // hence we would only have a read only mapping of it anyway.
      //

      Level1PTE newpte(req.val);
      if (newpte.p) unmap_phys_page(newpte.mfn);

      if (debug) logfile << "hypercall: mmu_update: mfn ", mfn, " + ", (void*)(Waddr)lowbits(req.ptr, 12), " (entry ", (lowbits(req.ptr, 12) >> 3), ") <= ", (Level1PTE)req.val, endl, flush;

      int update_count;
      rc = HYPERVISOR_mmu_update(&req, 1, &update_count, arg4);
      total_updates += update_count;
      if (rc) break;
    }

    ctx.flush_tlb();
    ctx.copy_to_user(arg3, &total_updates, sizeof(int), pfec, faultaddr);
    break;
  }

    // __HYPERVISOR_set_gdt only needed during boot

  case __HYPERVISOR_stack_switch: {
    arg1 = fixup_guest_stack_selector(arg1);
    ctx.kernel_ss = arg1;
    ctx.kernel_sp = arg2;
    rc = 0;
    break;
  }

    // __HYPERVISOR_set_callbacks only needed during boot

  case __HYPERVISOR_fpu_taskswitch: {
    ctx.cr0.ts = arg1;
    rc = 0;
    break;
  };

    // __HYPERVISOR_sched_op_compat deprecated

    // __HYPERVISOR_dom0_op not needed in domU

    // __HYPERVISOR_set_debugreg can be done later

    // __HYPERVISOR_get_debugreg can be done later

  case __HYPERVISOR_update_descriptor: {
    //
    // Update a single descriptor. We just pass this down to Xen
    // since we can always refresh PTLsim's descriptor cache
    // when the segment is explicitly reloaded.
    //
    Waddr physaddr = arg1;
    W64 desc = arg2;

    rc = HYPERVISOR_update_descriptor(physaddr, desc);
    break;
  };

    // __HYPERVISOR_memory_op needed only during boot

    // __HYPERVISOR_multicall handled elsewhere

  case __HYPERVISOR_update_va_mapping: {
    Waddr va = arg1;
    Waddr ptephys = virt_to_pte_phys_addr(va, ctx.cr3 >> 12);
    if (!ptephys) {
      if (debug) logfile << "hypercall: update_va_mapping: va ", (void*)va, " using toplevel mfn ", (ctx.cr3 >> 12), ": cannot resolve PTE address", endl, flush;
      rc = -EINVAL;
      break;
    }

    Waddr flags = arg3;

    if (debug) logfile << "hypercall: update_va_mapping: va ", (void*)va, " using toplevel mfn ", (ctx.cr3 >> 12),
      " -> pte @ phys ", (void*)ptephys, ") <= ", Level1PTE(arg2), ", flags ", (void*)(Waddr)flags,
      " (flushtype ", (flags & UVMF_FLUSHTYPE_MASK), ")", endl, flush;

    if (flags & ~UVMF_FLUSHTYPE_MASK) {
      Waddr* flush_bitmap_ptr = (Waddr*)(flags & ~UVMF_FLUSHTYPE_MASK);
      // pointer was specified: get it and thunk the address
      Waddr flush_bitmap;
      if (ctx.copy_from_user(&flush_bitmap, (Waddr)flush_bitmap_ptr, sizeof(flush_bitmap)) != sizeof(flush_bitmap)) {
        if (debug) logfile << "hypercall: update_va_mapping: va ", (void*)va, "; flush bitmap ptr ", flush_bitmap_ptr, " not accessible", endl, flush;
        rc = -EFAULT;
        break;
      }
      flags = (((Waddr)&flush_bitmap) & ~UVMF_FLUSHTYPE_MASK) | (flags & UVMF_FLUSHTYPE_MASK);
      if (debug) logfile << "Copied flush bitmap ", bitstring(flush_bitmap, 64, true), "; new flags ", hexstring(flags, 64), endl, flush;
    }

    int targetmfn = Level1PTE(arg2).mfn;

    if (debug) logfile << "  Old PTE: ", *(Level1PTE*)phys_to_mapped_virt(ptephys), endl, flush;

    rc = HYPERVISOR_update_va_mapping(va, arg2, arg3);
    /*
    // Can also be converted to an mmu_update call if we don't have PTLsim in the same
    // address space as the guest. Currently this is not necessary:
    mmu_update_t u;
    u.ptr = ptephys;
    u.val = arg2;
    rc = HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF);
    */

    if (debug) logfile << "  New PTE: ", *(Level1PTE*)phys_to_mapped_virt(ptephys), " (rc ", rc, ")", endl, flush;

    if (flags & UVMF_FLUSHTYPE_MASK) {
      foreach (i, bootinfo.vcpu_count) {
        contextof(i).flush_tlb_virt(va);
      }
    }

    break;
  }

  case __HYPERVISOR_set_timer_op: {
    if (arg1) {
      update_time();
      W64 trigger_nsecs_since_boot = arg1;
      W64 trigger_cycles_since_boot = (W64)((double)trigger_nsecs_since_boot / ctx.sys_time_cycles_to_nsec_coeff);
      W64 trigger_cycles_in_future = trigger_cycles_since_boot - (ctx.base_tsc + sim_cycle);

      ctx.timer_cycle = trigger_cycles_since_boot;

      //
      // For some reason Linux does not properly compute the next
      // timer system time nsec value; it sometimes specifies
      // times in the past.
      //
      // Therefore, force this to be a fixed timer interrupt period.
      //
      ctx.timer_cycle = ctx.base_tsc + sim_cycle + timer_interrupt_period_in_cycles;

      if (debug) logfile << "hypercall: set_timer_op: timeout ", trigger_nsecs_since_boot, " nsec since boot = ", 
        ctx.timer_cycle, " cycles since boot (", trigger_cycles_in_future, " cycles in future = ",
        (trigger_nsecs_since_boot - sshinfo.vcpu_info[0].time.system_time), " nsec in future)", endl;
    } else {
      ctx.timer_cycle = infinity;
      if (debug) logfile << "hypercall: set_timer_op: cancel timer", endl;
    }
    rc = 0;
    break;
  }

    // __HYPERVISOR_event_channel_op_compat deprecated

  case __HYPERVISOR_xen_version: {
    // NOTE: xen_version is sometimes used as a no-op call just to get pending events processed
    static const int struct_sizes[] = {
      0, // XENVER_version
      sizeof(xen_extraversion_t),
      sizeof(xen_compile_info_t),
      sizeof(xen_capabilities_info_t),
      sizeof(xen_changeset_info_t),
      sizeof(xen_platform_parameters_t),
      sizeof(xen_feature_info_t)
    };

    if (arg1 >= lengthof(struct_sizes)) { rc = -EINVAL; break; }

    // biggest structure is 1024 bytes (xen_capabilities_info_t) but use a full page just to be safe:
    char buf[4096];
    int n = struct_sizes[arg1];

    if (n && (ctx.copy_from_user(buf, arg2, n, pfec, faultaddr) != n)) { rc = -EFAULT; break; }

    rc = HYPERVISOR_xen_version(arg1, buf);

    ctx.copy_to_user(arg1, buf, n, pfec, faultaddr);

    break;
  }

    // __HYPERVISOR_console_io not needed in domU

    // __HYPERVISOR_physdev_op_compat deprecated

  case __HYPERVISOR_grant_table_op: {
    foreach (i, arg3) {
#define getreq(type) type req; if (ctx.copy_from_user(&req, (Waddr)arg2, sizeof(type), pfec, faultaddr) != sizeof(type)) { rc = -EFAULT; break; }
#define putreq(type) ctx.copy_to_user((Waddr)arg2, &req, sizeof(type), pfec, faultaddr)
      switch (arg1) {
        //
        //++MTY TODO:
        // map_grant_ref and unmap_grant_ref have a flag that says GNTMAP_contains_pte
        // which tells Xen to update the specified PTE to map the granted page.
        // However, Linux does not use this flag; instead, Xen internally generates
        // the PTE address for us based on the current page table root. Since PTLsim
        // has its own page table in effect, we need to do the virt->PTE-to-modify mapping
        // ourselves, replace the host_addr field and add in the GNTMAP_contains_pte flag.
        //
        //++MTY NOTE: This is no longer required since we cohabitate the same virtual
        // address space as the real page table base at all times.
        //
      case GNTTABOP_map_grant_ref: {
        getreq(gnttab_map_grant_ref);
        if (debug) logfile << "GNTTABOP_map_grant_ref(host_addr ", (void*)(Waddr)req.host_addr, ", flags ", req.flags,
          ", ref ", req.ref, ", dom ", req.dom, ")", endl;
        if (debug) logfile << "map_grant_ref is not supported yet!", endl;
        abort();
      }
      case GNTTABOP_unmap_grant_ref: {
        getreq(gnttab_map_grant_ref);
        if (debug) logfile << "GNTTABOP_unmap_grant_ref(host_addr ", (void*)(Waddr)req.host_addr,
          ", dev_bus_addr ", (void*)(Waddr)req.dev_bus_addr, ", handle ", (void*)(Waddr)req.handle, ")", endl, flush;
        if (debug) logfile << "unmap_grant_ref is not supported yet!", endl;
        abort();
      }
      case GNTTABOP_setup_table: {
        getreq(gnttab_setup_table);
        unsigned long* orig_frame_list = req.frame_list.p;
        unsigned long frames[4]; // on x86 and x86-64, NR_GRANT_FRAMES is always 1<<2 == 4
        int framecount = min(req.nr_frames, (W32)lengthof(frames));
        req.frame_list.p = frames;
        if (debug) logfile << "GNTTABOP_setup_table(dom ", req.dom, ", nr_frames ", req.nr_frames, ", frame_list ", orig_frame_list, ")", endl, flush;
        rc = HYPERVISOR_grant_table_op(GNTTABOP_setup_table, &req, 1);
        req.frame_list.p = orig_frame_list;
        if (debug) { logfile << "  Frames:"; foreach (i, framecount) { logfile << " ", frames[i]; }; logfile << ", status ", req.status, endl, flush; }
        assert(ctx.copy_to_user((Waddr)orig_frame_list, &frames, framecount * sizeof(unsigned long), pfec, faultaddr) == (framecount * sizeof(unsigned long)));
        putreq(gnttab_setup_table);
        arg2 += sizeof(req);
        break;
      }
      case GNTTABOP_transfer: {
        getreq(gnttab_transfer);
        ctx.flush_tlb();
        if (debug) logfile << "GNTTABOP_transfer(mfn ", req.mfn, ", domid ", req.domid, ", ref ", req.ref, ")", endl, flush;
        unmap_phys_page(req.mfn);
        rc = HYPERVISOR_grant_table_op(GNTTABOP_transfer, &req, 1);
        putreq(gnttab_transfer);
        arg2 += sizeof(req);
        break;
      }
      default: {
        if (debug) logfile << "hypercall: grant_table_op: unknown op ", arg1, endl, flush;
        rc = -EINVAL;
        abort();
        break;
      }
      }

      if (rc) break;
    }

    break;
  }

    // __HYPERVISOR_vm_assist not generally needed on x86-64

    // __HYPERVISOR_update_va_mapping_otherdomain not needed in domU

    // __HYPERVISOR_iret handled separately

  case __HYPERVISOR_vcpu_op: {
    switch (arg1) {
    case VCPUOP_register_runstate_memory_area: {
      vcpu_register_runstate_memory_area req;
      if (ctx.copy_from_user(&req, (Waddr)arg3, sizeof(req), pfec, faultaddr) != sizeof(req)) { rc = -EFAULT; break; }
      if (arg2 >= bootinfo.vcpu_count) { rc = -EINVAL; break; }
      if (debug) logfile << "hypercall: vcpu_op: register_runstate_memory_area: registered virt ", req.addr.v, " for runstate info on vcpu ", arg2, endl, flush;
      // Since this is virtual, we need to check it every time we "reschedule" the VCPU:
      contextof(arg2).user_runstate = (RunstateInfo*)req.addr.v;

      //
      // This is a virtual address not currently mapped by PTLsim:
      // Xen will get a silent fault (ignored) every time it tries to
      // update this data until it returns to the guest in which
      // this address is valid.
      //
      // Therefore, we don't set it until we switch to native mode.
      //
      break;
    }
    default:
      if (debug) logfile << "hypercall: vcpu_op ", arg1, " not implemented!", endl, flush;
      abort();
    }

    break;
  }

  case __HYPERVISOR_set_segment_base: {
    rc = 0;
    switch (arg1) {
    case SEGBASE_FS:
      ctx.fs_base = arg2;
      ctx.seg[SEGID_FS].base = arg2;
      break;
    case SEGBASE_GS_USER:
      ctx.gs_base_user = arg2;
      //
      // Update the MSR so the new user base gets restored
      // when we do an iret from the kernel code that made
      // this hypercall.
      //
      ctx.swapgs_base = arg2;
      break;
    case SEGBASE_GS_KERNEL:
      ctx.gs_base_kernel = arg2;
      ctx.seg[SEGID_GS].base = arg2;
      break;
    case SEGBASE_GS_USER_SEL: {
      //
      // Technically this only takes effect when we switch back
      // to user mode, but the selector must be in place anyway.
      // See the Xen code for do_set_segment_base() for the
      // swapgs; mov %k0,%gs; swapgs; hack they have to use.
      //
      ctx.swapgs();
      int exception = ctx.write_segreg(SEGID_GS, arg2);
      ctx.swapgs(); // put it back in the base to restore for user mode
      rc = (exception) ? -EINVAL : 0;
      break;
    }
    default:
      if (debug) logfile << "hypercall: set_segment_base: unknown segment id ", arg1, endl;
      abort();
    }

    break;
  }

  case __HYPERVISOR_mmuext_op: {
    mmuext_op_t* reqp = (mmuext_op_t*)arg1;
    Waddr count = arg2;

    mmuext_op_t req;

    int total_updates = 0;
    foreach (i, count) {
      int n = ctx.copy_from_user(&req, (Waddr)&reqp[i], sizeof(mmuext_op_t), pfec, faultaddr);
      if (n < sizeof(mmuext_op_t)) break;

      switch (req.cmd) {
      case MMUEXT_PIN_L1_TABLE:
      case MMUEXT_PIN_L2_TABLE:
      case MMUEXT_PIN_L3_TABLE:
      case MMUEXT_PIN_L4_TABLE:
      case MMUEXT_UNPIN_TABLE: {
        mfn_t mfn = req.arg1.mfn;
        if (mfn >= bootinfo.total_machine_pages) continue;

        //
        // Unmap the requisite pages from our physmap since we may be making them read only.
        // It will be remapped by the PTLsim page fault handler on demand.
        //
        const Level1PTE* pinptes = (Level1PTE*)phys_to_mapped_virt(mfn << 12);
        Level1PTE pte0 = pinptes[0];

        if (debug) logfile << "hypercall: mmuext_op: map/unmap mfn ", mfn, " (pin/unpin operation ", req.cmd, ")", endl, flush;

        if (req.cmd != MMUEXT_UNPIN_TABLE) {
          // Unmapping only required when pinning, not unpinning
          // It's actually more efficient to just unmap everything:
          // constant time (1 L2 page scan) for systems with only a
          // few GB of physical memory:
          // (slower) unmap_phys_page_tree(mfn);
          unmap_address_space();
        }

        int update_count = 0;
        rc = HYPERVISOR_mmuext_op(&req, 1, &update_count, arg4);

        if (rc) {
          logfile << "  mmuext_op rc was ", rc, endl, flush;
          page_type_t pagetype = query_page(mfn);
          logfile << "Page type for mfn ", mfn, ": ", pagetype, endl, flush;
          abort(); // so we don't overflow xen dmesg
          unmap_address_space();
          find_all_mappings_of_mfn(mfn);
          logfile << "Actual page to pin (mfn ", mfn, "): ", endl, flush;
          print_page_table_with_types(logfile, (Level1PTE*)phys_to_mapped_virt(mfn << 12));
        }

        total_updates += update_count;
        break;
      }
      case MMUEXT_NEW_BASEPTR: {
        if (debug) logfile << "hypercall: mmuext_op: new kernel baseptr is mfn ",
          req.arg1.mfn, " on vcpu ", ctx.vcpuid, ")", endl, flush;
        unmap_phys_page(req.arg1.mfn);
        ctx.kernel_ptbase_mfn = req.arg1.mfn;
        ctx.cr3 = ctx.kernel_ptbase_mfn << 12;
        ctx.flush_tlb();
        switch_page_table(ctx.kernel_ptbase_mfn);
        total_updates++;
        rc = 0;
        break;
      }
      case MMUEXT_TLB_FLUSH_LOCAL:
      case MMUEXT_INVLPG_LOCAL: {
        bool single = (req.cmd == MMUEXT_INVLPG_LOCAL);
        if (debug) logfile << "hypercall: mmuext_op: ", (single ? "invlpg" : "flush"), " local (vcpu ", ctx.vcpuid, ") @ ",
          (void*)(Waddr)req.arg1.linear_addr, endl, flush;
        if (single)
          ctx.flush_tlb_virt(req.arg1.linear_addr);
        else ctx.flush_tlb();
        total_updates++;
        rc = 0;
        break;
      }
      case MMUEXT_TLB_FLUSH_MULTI:
      case MMUEXT_INVLPG_MULTI: {
        Waddr vcpumask;
        int n = ctx.copy_from_user(&vcpumask, (Waddr)req.arg2.vcpumask, sizeof(vcpumask), pfec, faultaddr);
        if (n != sizeof(vcpumask)) { rc = -EFAULT; break; }
        bool single = (req.cmd == MMUEXT_INVLPG_MULTI);
        if (debug) logfile << "hypercall: mmuext_op: ", (single ? "invlpg" : "flush"), " multi (mask ", 
          bitstring(vcpumask, bootinfo.vcpu_count), " @ ", (void*)(Waddr)req.arg1.linear_addr, endl, flush;
        if (single) {
          foreach (i, bootinfo.vcpu_count) {
            if (bit(vcpumask, i)) contextof(i).flush_tlb_virt(req.arg1.linear_addr);
          }
        } else {
          foreach (i, bootinfo.vcpu_count) {
            if (bit(vcpumask, i)) contextof(i).flush_tlb();
          }
        }
        total_updates++;
        rc = 0;
        break;
      }
      case MMUEXT_TLB_FLUSH_ALL:
      case MMUEXT_INVLPG_ALL: {
        bool single = (req.cmd == MMUEXT_INVLPG_ALL);
        if (debug) logfile << "hypercall: mmuext_op: ", (single ? "invlpg" : "flush"), " all @ ",
          (void*)(Waddr)req.arg1.linear_addr, endl, flush;
        if (single) {
          foreach (i, bootinfo.vcpu_count) contextof(i).flush_tlb_virt(req.arg1.linear_addr);
        } else {
          foreach (i, bootinfo.vcpu_count) contextof(i).flush_tlb();
        }
        total_updates++;
        rc = 0;
        break;
      }
      case MMUEXT_FLUSH_CACHE: {
        if (debug) logfile << "hypercall: mmuext_op: flush_cache on vcpu ", ctx.vcpuid, endl, flush;
        total_updates++;
        rc = 0;
        break;
      }
      case MMUEXT_SET_LDT: {
        ctx.ldtvirt = req.arg1.linear_addr;
        ctx.ldtsize = req.arg2.nr_ents;

        if (debug) logfile << "hypercall: mmuext_op: set_ldt to virt ", (void*)(Waddr)ctx.ldtvirt, " with ",
          ctx.ldtsize, " entries on vcpu ", ctx.vcpuid, endl, flush;

        total_updates++;
        rc = 0;
        break;
      }
      case MMUEXT_NEW_USER_BASEPTR: { // (x86-64 only)
        if (debug) logfile << "hypercall: mmuext_op: new user baseptr is mfn ",
          req.arg1.mfn, " on vcpu ", ctx.vcpuid, ")", endl, flush;
        ctx.user_ptbase_mfn = req.arg1.mfn;
        //
        // Since PTLsim runs in kernel mode at all times, we can pass this request
        // through to Xen so the guest domain gets the correct base pointer on return
        // to native mode.
        //
        // In simulation, we do not switch ctx.cr3 = ctx.user_cr3 until we return to
        // userspace (with iret hypercall).
        //
        int update_count = 0;
        rc = HYPERVISOR_mmuext_op(&req, 1, &update_count, arg4);
        total_updates++;
        break;
      }
      default:
        if (debug) logfile << "hypercall: mmuext_op: unknown op ", req.cmd, endl, flush;
        rc = -EINVAL;
        abort();
        break;
      }

      if (rc) break;
    }
    break;
  }

    // __HYPERVISOR_acm_op not needed for now

    // __HYPERVISOR_nmi_op not needed in domU

  case __HYPERVISOR_sched_op: {
    switch (arg1) {
    case SCHEDOP_yield: {
      // Take no action: under PTLsim, the guest VCPU appears to run continuously
      if (debug) logfile << "hypercall: sched_op: yield VCPU ", ctx.vcpuid, endl, flush;
      break;
    }
    case SCHEDOP_block: {
      //
      // Block the VCPU. The specified core model is responsible for checking
      // ctx.running and if zero, no instructions will be dispatched from that
      // hardware thread or core. However, inject_events() must still be called
      // so it will unblock when an interrupt arrives.
      //
      // Xen implicitly unmasks events when we do this. 
      // 
      if (debug) logfile << "hypercall: sched_op: blocking VCPU ", ctx.vcpuid, endl, flush;
      ctx.change_runstate(RUNSTATE_blocked);
      sshinfo.vcpu_info[ctx.vcpuid].evtchn_upcall_mask = 0;
      break;
    }
    default: {
      abort();
      rc = -EINVAL;
    }
    }
    break;
  };

    // __HYPERVISOR_callback_op needed only during boot

    // __HYPERVISOR_xenoprof_op not needed for now

  case __HYPERVISOR_event_channel_op: {
#undef doreq
#define doreq(type) case EVTCHNOP_##type: { getreq(evtchn_##type); rc = HYPERVISOR_event_channel_op(arg1, &req); putreq(evtchn_##type); break; }

    switch (arg1) {
    case EVTCHNOP_alloc_unbound: {
      getreq(evtchn_alloc_unbound);
      rc = HYPERVISOR_event_channel_op(arg1, &req);
      if (debug) logfile << "hypercall: evtchn_alloc_unbound {dom = ", req.dom, ", remote_dom = ", req.remote_dom, "} => {port = ", req.port, "}", ", rc ", rc, endl;
      putreq(evtchn_alloc_unbound);
      break;
    }
    case EVTCHNOP_bind_interdomain: {
      getreq(evtchn_bind_interdomain);
      rc = HYPERVISOR_event_channel_op(arg1, &req);
      if (debug) logfile << "hypercall: evtchn_bind_interdomain {remote_dom = ", req.remote_dom, ", remote_port = ", req.remote_port, "} => {local_port = ", req.local_port, "}", ", rc ", rc, endl;
      putreq(evtchn_bind_interdomain);
      break;
    }
    case EVTCHNOP_bind_virq: {
      //
      // PTLsim needs to monitor attempts to bind the VIRQ_TIMER interrupt so we can
      // correctly deliver internal timer events at the appropriate rate.
      //
      getreq(evtchn_bind_virq);
      rc = HYPERVISOR_event_channel_op(arg1, &req);

      if (debug) logfile << "hypercall: evtchn_bind_virq {virq = ", req.virq, ", vcpu = ", req.vcpu, "} => {port = ", req.port, "}", ", rc ", rc, endl;

      if (rc == 0) {
        assert(req.vcpu < bootinfo.vcpu_count);
        assert(req.virq < lengthof(contextof(req.vcpu).virq_to_port));
        contextof(req.vcpu).virq_to_port[req.virq] = req.port;
        assert(req.port < NR_EVENT_CHANNELS);
        port_to_vcpu[req.port] = req.vcpu;
        // PTLsim generates its own timer interrupts
        if (req.virq == VIRQ_TIMER) {
          if (debug) logfile << "Assigned timer VIRQ ", req.virq, " on VCPU ", req.vcpu, " to port ", req.port, endl;
          mask_evtchn(req.port);
          always_mask_port[req.port] = 1;
        }
      }
      putreq(evtchn_bind_virq);
      break;
    }
    case EVTCHNOP_bind_ipi: {
      getreq(evtchn_bind_ipi);
      rc = HYPERVISOR_event_channel_op(arg1, &req);
      if (debug) logfile << "hypercall: evtchn_bind_ipi {vcpu = ", req.vcpu, "} => {port = ", req.port, "}", ", rc ", rc, endl;
      if (rc == 0) port_to_vcpu[req.port] = req.vcpu;
      putreq(evtchn_bind_ipi);
      break;
    }
    case EVTCHNOP_close: {
      getreq(evtchn_close);
      rc = HYPERVISOR_event_channel_op(arg1, &req);
      if (debug) logfile << "hypercall: evtchn_close {port = ", req.port, "}", ", rc ", rc, endl;
      putreq(evtchn_close);
      break;
    }
    case EVTCHNOP_send: {
      getreq(evtchn_send);
      rc = HYPERVISOR_event_channel_op(arg1, &req);
      if (debug) logfile << "hypercall: evtchn_send {port = ", req.port, "}", ", rc ", rc, endl;
      putreq(evtchn_send);
      break;
    }
    case EVTCHNOP_status: {
      getreq(evtchn_status);
      rc = HYPERVISOR_event_channel_op(arg1, &req);
      if (debug) logfile << "hypercall: evtchn_status {...}", ", rc ", rc, endl;
      putreq(evtchn_status);
      break;
    }
    case EVTCHNOP_bind_vcpu: {
      getreq(evtchn_bind_vcpu);
      rc = HYPERVISOR_event_channel_op(arg1, &req);
      if (debug) logfile << "hypercall: evtchn_bind_vcpu {port = ", req.port, ", vcpu = ", req.vcpu, "}", ", rc ", rc, endl;
      if (rc == 0) port_to_vcpu[req.port] = req.vcpu;
      putreq(evtchn_bind_vcpu);
      break;
    }
    case EVTCHNOP_unmask: {
      //
      // Unmask is special since we need to redirect it to our
      // virtual shinfo page, and potentially simulate an upcall.
      //
      getreq(evtchn_unmask);
      if (debug) logfile << "hypercall: evtchn_unmask {port = ", req.port, "}, rc ", rc, endl;
      shadow_evtchn_unmask(req.port);
      rc = 0;
      putreq(evtchn_unmask);
      break;
    }
    default:
      abort();
    }

    break;
  }

    // __HYPERVISOR_physdev_op not needed in domU

  default:
    if (debug) logfile << "Cannot handle hypercall ", hypercallid, "!", endl, flush;
    abort();
  }

  if (debug) logfile << "  Returning rc ", rc, endl, flush;

  return rc;
}

static inline ostream& operator <<(ostream& os, const iret_context& iretctx) {
  os << "cs:rip ", (void*)iretctx.cs, ":", (void*)iretctx.rip,
    ", ss:rsp ", (void*)iretctx.ss, ":", (void*)iretctx.rsp,
    ", rflags ", (void*)iretctx.rflags, ", rax ", (void*)iretctx.rax,
    ", r11 ", (void*)iretctx.r11, ", rcx ", (void*)iretctx.rcx,
    ", xen flags ", (void*)iretctx.flags;
  return os;
}

void handle_xen_hypercall_assist(Context& ctx) {
  //
  // x86-64 hypercall conventions:
  //
  // Hypercall ID in %rax
  // Return address in %rcx (SYSCALL microcode puts it there)
  // Args in %rdi %rsi %rdx %r10 %r8 %r9 (identical to Linux syscall interface)
  // (see arch/x86/domain.c)
  //

  // SYSCALL x86 insn microcode puts return address in %rcx
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_rcx];

  W64 hypercallid = ctx.commitarf[REG_rax];
  W64 arg1 = ctx.commitarf[REG_rdi];
  W64 arg2 = ctx.commitarf[REG_rsi];
  W64 arg3 = ctx.commitarf[REG_rdx];
  W64 arg4 = ctx.commitarf[REG_r10];
  W64 arg5 = ctx.commitarf[REG_r8];
  W64 arg6 = ctx.commitarf[REG_r9];

  if (hypercallid == __HYPERVISOR_multicall) {
    Waddr reqp = arg1;
    int reqcount = arg2;

    foreach (i, reqcount) {
      multicall_entry req;
      Waddr faultaddr;
      PageFaultErrorCode pfec;

      if (ctx.copy_from_user(&req, reqp, sizeof(req), pfec, faultaddr) != sizeof(req)) {
        ctx.commitarf[REG_rax] = (W64)(-EFAULT);
        return;
      }

      req.result = handle_xen_hypercall(ctx, req.op, req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5]);

      ctx.copy_to_user(reqp, &req, sizeof(req), pfec, faultaddr);
      
      reqp += sizeof(req);
    }
    ctx.commitarf[REG_rax] = 0;
  } else if (hypercallid == __HYPERVISOR_iret) {
    iret_context iretctx;
    PageFaultErrorCode pfec;
    Waddr faultaddr;
    if (ctx.copy_from_user(&iretctx, ctx.commitarf[REG_rsp], sizeof(iretctx), pfec, faultaddr) != sizeof(iretctx)) { abort(); }

    if (logable(2)) logfile << "IRET from rip ", (void*)(Waddr)ctx.commitarf[REG_rip], ": iretctx @ ", (void*)(Waddr)ctx.commitarf[REG_rsp], " = ", iretctx, " (", sim_cycle, " cycles, ", total_user_insns_committed, " commits)", endl, flush;

    if likely ((iretctx.cs & 3) == 3) {
      // Returning to user mode: toggle_guest_mode(v)
      assert(ctx.kernel_mode);
      iretctx.rflags = (iretctx.rflags & ~FLAG_IOPL) | (0x3 << 12);
      ctx.kernel_mode = 0;
      ctx.cr3 = ctx.user_ptbase_mfn << 12;
      ctx.flush_tlb();
      if (logable(4)) logfile << "  Switch back to user mode @ cr3 mfn ", (ctx.cr3 >> 12), endl;
      ctx.swapgs();
    }

    ctx.commitarf[REG_rip] = iretctx.rip;
    ctx.reload_segment_descriptor(SEGID_CS, iretctx.cs | 3);
    // Set IF and IOPL=3 in flags
    ctx.internal_eflags = (iretctx.rflags & ~(FLAG_IOPL|FLAG_VM)) | FLAG_IF;
    ctx.commitarf[REG_flags] = ctx.internal_eflags & (FLAG_ZAPS|FLAG_CF|FLAG_OF);
    ctx.commitarf[REG_rsp] = iretctx.rsp;
    ctx.reload_segment_descriptor(SEGID_SS, iretctx.ss | 3);
    //
    //++MTY CHECKME if returning from 64-bit kernel to 32-bit userspace,
    // the base and limit semantics of DS/ES/FS/GS must now be enforced.
    // This is unclear if the segments must be manually reloaded; it seems
    // at least Linux does this anyway.
    //

    if (!(iretctx.flags & VGCF_IN_SYSCALL)) {
      if (logable(4)) logfile << "  Restore as interrupt, not system call", endl;
      ctx.x86_exception = 0;
      ctx.commitarf[REG_r11] = iretctx.r11;
      ctx.commitarf[REG_rcx] = iretctx.rcx;
    } else {
      if (logable(4)) logfile << "  Restore as system call", endl;
    }

    // Restore upcall mask from supplied EFLAGS.IF.
    sshinfo.vcpu_info[ctx.vcpuid].evtchn_upcall_mask = !(iretctx.rflags & FLAG_IF);
    if (logable(4)) logfile << "  Restore evtchn upcall mask to ", (!(iretctx.rflags & FLAG_IF)), endl;

    ctx.commitarf[REG_rax] = iretctx.rax;

  } else {
    int rc = handle_xen_hypercall(ctx, hypercallid, arg1, arg2, arg3, arg4, arg5, arg6);
    ctx.commitarf[REG_rax] = rc;
  }

  if likely (hypercallid <= lengthof(guest_hypercall_histogram)) guest_hypercall_histogram[hypercallid]++;

  if (ctx.check_events()) {
    if (logable(4)) logfile << "Events pending on vcpu ", ctx.vcpuid, " after hypercall", endl;
    ctx.event_upcall();
  }
}

//
// SYSCALL/SYSRET target MSR
//
struct STARmsr {
  W64 syscall_target_32bit:32, syscall_cs:16, sysret_cs:16;
  RawDataAccessors(STARmsr, W64);
};

// Xen GDT (used by syscall/sysret):
enum {
  HYPERVISOR_RESERVED = 0,
  HYPERVISOR_CS32 = 0xe008, // ring 0 code, 32-bit
  HYPERVISOR_CS64 = 0xe010, // ring 0 code, 64-bit
  HYPERVISOR_DS32 = 0xe018, // ring 0 data
  GUEST_CS32      = 0xe023, // ring 3 code, 32-bit
  GUEST_DS        = 0xe02b, // ring 3 data
  GUEST_CS64      = 0xe033  // ring 3 code, 64-bit
};

enum {
  TBF_EXCEPTION          = 1,
  TBF_EXCEPTION_ERRCODE  = 2,
  TBF_INTERRUPT          = 8,
  TBF_FAILSAFE           = 16
};

static inline bool push_on_kernel_stack(Context& ctx, Waddr& p, Waddr data) {
  PageFaultErrorCode pfec;
  Waddr faultaddr;
  p -= sizeof(data);
  bool ok = (ctx.copy_to_user((Waddr)p, &data, sizeof(data), pfec, faultaddr) == sizeof(data));
  if (logable(4)) logfile << "  [", (void*)(Waddr)p, "] 0x", hexstring(data, 64), (ok ? "" : " (error)"), endl;
  return ok;
}

//
// This is the simplified equivalent of the assembly language 
// create_bounce_frame() function in xen/arch/x86/x86_64/entry.S.
//
// Like much of Xen's internals, the stack frame format passed
// to the guest OS is undocumented. We use push_on_kernel_stack
// everywhere a stack frame word is pushed.
//
bool Context::create_bounce_frame(W16 target_cs, Waddr target_rip, int action) {
  // Save old regs

  // If in kernel context already, push new frame at existing rsp:
  Waddr frame = (kernel_mode) ? commitarf[REG_rsp] : kernel_sp;
  Waddr origframe = frame;

  if (logable(2)) logfile << "Create bounce frame from ", (kernel_mode ? "kernel" : "user"), " rip ", 
    (void*)(Waddr)commitarf[REG_rip], " to kernel rip ", (void*)(Waddr)target_rip,
    " at rsp ", (void*)(Waddr)frame, endl;

  bool from_kernel_mode = kernel_mode;

  W16 guest_cs;

  if unlikely (from_kernel_mode) {
    // If in kernel mode, set cs.dpl = 0 so we know where we were called from:
    guest_cs = (seg[SEGID_CS].selector & 0xfffc);
  } else {
    // Called from user mode: switch to kernel mode
    // Push new frame at registered guest-OS stack base.
    kernel_mode = 1;
    kernel_in_syscall = 1;
    guest_cs = seg[SEGID_CS].selector;
    // Load kernel cr3 so we can copy in frame below
    cr3 = kernel_ptbase_mfn << 12;
    if (logable(4)) logfile << "  Load kernel page table @ cr3 mfn ", (cr3 >> 12), endl;
    flush_tlb();

    if (logable(4)) logfile << "  Switching to kernel mode (new kernel ptbase mfn ", (cr3 >> 12), ")", endl;
  }

  frame = floor(frame, 16);

  bool ok = 1;

  if (logable(4)) logfile << "  Pushing rip | (cs, upmask) | rflags | rsp | ss:", endl;

  ok &= push_on_kernel_stack(*this, frame, seg[SEGID_SS].selector);
  ok &= push_on_kernel_stack(*this, frame, commitarf[REG_rsp]);

  byte& upcallmask = sshinfo.vcpu_info[vcpuid].evtchn_upcall_mask;

  // Prepare flags to be saved:
  W64 saved_flags = 
    (commitarf[REG_flags] & (FLAG_ZAPS|FLAG_CF|FLAG_OF)) |
    (internal_eflags & ~(FLAG_ZAPS|FLAG_CF|FLAG_OF));
  saved_upcall_mask = upcallmask;
  W64 cs_and_upcallmask = ((W64)upcallmask << 32) | (W64)guest_cs;
  assignbit(saved_flags, log2(FLAG_IF), !upcallmask);

  // Update flags for handler:
  upcallmask = ((action & TBF_INTERRUPT) != 0);
  assignbit(internal_eflags, log2(FLAG_IF), !upcallmask);

  if (logable(4)) logfile << "  Set upcallmask = 0x", hexstring(upcallmask, 8), endl;

  ok &= push_on_kernel_stack(*this, frame, saved_flags);
  ok &= push_on_kernel_stack(*this, frame, cs_and_upcallmask);
  ok &= push_on_kernel_stack(*this, frame, commitarf[REG_rip]);

  if unlikely (action & TBF_EXCEPTION_ERRCODE) {
    if (logable(4)) logfile << "  Pushing error_code:", endl;
    ok &= push_on_kernel_stack(*this, frame, error_code);
  }

  if unlikely (action & TBF_FAILSAFE) {
    if (logable(4)) logfile << "  Pushing ds | es | fs | gs:", endl;
    ok &= push_on_kernel_stack(*this, frame, seg[SEGID_GS].selector);
    ok &= push_on_kernel_stack(*this, frame, seg[SEGID_FS].selector);
    ok &= push_on_kernel_stack(*this, frame, seg[SEGID_ES].selector);
    ok &= push_on_kernel_stack(*this, frame, seg[SEGID_DS].selector);
  }

  if (logable(4)) logfile << "  Pushing rcx | r11:", endl;
  ok &= push_on_kernel_stack(*this, frame, commitarf[REG_r11]);
  ok &= push_on_kernel_stack(*this, frame, commitarf[REG_rcx]);

  // Fault while constructing bounce frame: return and call failsafe callback
  if unlikely (!ok) return false;

  commitarf[REG_rsp] = frame;

  if unlikely (from_kernel_mode) {
    seg[SEGID_CS].selector &= 0xfffc; // clear DPL to virtual ring 0 so guest knows where interrupt came from
  } else {
    // Set up for 64-bit ring3 kernel:
    reload_segment_descriptor(SEGID_CS, target_cs);
    reload_segment_descriptor(SEGID_SS, kernel_ss);
    // (x86-64 does not use DS or ES in 64-bit mode)
    // Leave %fs alone
    swapgs();  // put kernel gs base into effect
  }

  if (logable(4)) logfile << "  Adjusted CS and SS", endl;

  commitarf[REG_rip] = target_rip;

  x86_exception = 256; // TRAP_syscall
  // IA32 Ref. Vol. 3: TF, VM, RF and NT flags are cleared on trap.
  internal_eflags &= ~(FLAG_TF|FLAG_VM|FLAG_RF|FLAG_NT|FLAG_IOPL);
  internal_eflags |= (1 << 12); // virtual IOPL = 1 (kernel)

  if (logable(4)) {
    logfile << "  Done creating bounce frame at rsp ", (void*)(Waddr)commitarf[REG_rsp], 
      " to rip ", (void*)(Waddr)commitarf[REG_rip],  endl;
  }

  return true;
}

//
// NOTE: exception is one of EXCEPTION_x86_xxx, NOT an internal PTL exception number
//
void Context::propagate_x86_exception(byte exception, W32 errorcode, Waddr virtaddr) {
  assert(exception < lengthof(idt));

  if (logable(2)) {
    logfile << "Exception ", exception, " (x86 ", x86_exception_names[exception], ") at rip ", (void*)commitarf[REG_rip], ": error code ";
    if likely (exception == EXCEPTION_x86_page_fault) {
      logfile << PageFaultErrorCode(errorcode), " (", (void*)(Waddr)errorcode, ") @ virtaddr ", (void*)virtaddr;
    } else {
      logfile << "0x", hexstring(errorcode, 32);
    }
    logfile << " (", total_user_insns_committed, " user commits, ", sim_cycle, " cycles)", endl, flush;
  }

  x86_exception = exception;
  error_code = errorcode;

  // Clear DPL bits for everything but page fault error code format
  if unlikely (exception != EXCEPTION_x86_page_fault) errorcode &= 0xfff8;

  if likely (exception == EXCEPTION_x86_page_fault) {
    cr2 = virtaddr;
    sshinfo.vcpu_info[vcpuid].arch.cr2 = virtaddr;
  }

  // Avoid recursion on FPU state lazy save/restore (equivalent to clts)
  if unlikely (exception == EXCEPTION_x86_fpu_not_avail) cr0.ts = 0;

  const TrapTarget& tt = idt[exception];
  int flags = TBF_EXCEPTION | (tt.maskevents ? TBF_INTERRUPT : 0);

  // Only [tss, seg, stack, gp, page, align] have the error code field
  static const byte x86_exception_has_error_code[EXCEPTION_x86_count] = {_,_,_,_,_,_,_,_,_,_,1,1,1,1,1,_,_,1,_,_};

  bool uses_errcode = (exception < EXCEPTION_x86_count) && x86_exception_has_error_code[exception];
  if (uses_errcode) flags = flags | TBF_EXCEPTION_ERRCODE;

  assert(create_bounce_frame((tt.cs << 3) | 3, signext64(tt.rip, 48), flags));
}

void handle_syscall_assist(Context& ctx) {
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_rcx]; // microcode stub puts return address in rcx

  int action = (ctx.syscall_disables_events) ? TBF_INTERRUPT : 0;
  ctx.create_bounce_frame(GUEST_CS64, ctx.syscall_rip, action);
}

//
// Update time fields (tsc_timestamp, system_time, tsc_to_system_mul, tsc_shift) in shinfo
//
struct RealTimeInfo {
  W64 wc_sec;
  W64 wc_nsec;
};

RealTimeInfo initial_realtime_info;

//
// Initialize times after switching to simulation mode.
//
// It is expected that the guest kernel is just coming out of
// sleep mode and will re-init all VIRQs, etc. for us.
//

W64 get_core_freq_hz(const vcpu_time_info_t& timeinfo) {
  W64 core_freq_hz = ((1000000000ULL << 32) / timeinfo.tsc_to_system_mul);

  if (timeinfo.tsc_shift >= 0)
    core_freq_hz >>= timeinfo.tsc_shift;
  else core_freq_hz <<= -timeinfo.tsc_shift;

  return core_freq_hz;
}

void init_virqs() {
  logfile << "Calibrate internal time conversions:", endl;

  foreach (i, bootinfo.vcpu_count) {
    Context& ctx = contextof(i);

    vcpu_time_info_t& timeinfo = sshinfo.vcpu_info[ctx.vcpuid].time;

    if (config.pseudo_real_time_clock) {
      timeinfo.tsc_timestamp = 0;
      timeinfo.system_time = 0;
    }

    ctx.core_freq_hz = get_core_freq_hz(timeinfo);

    ctx.sys_time_cycles_to_nsec_coeff = 1. / ((double)ctx.core_freq_hz / 1000000000.);
    ctx.base_tsc = timeinfo.tsc_timestamp;

    ctx.timer_cycle = infinity;
    ctx.poll_timer_cycle = infinity;

    logfile << "  VCPU ", i, " has recorded core frequency ", (ctx.core_freq_hz / 1000000), " MHz", endl;

    RunstateInfo& runstate = ctx.runstate;
    runstate.state = RUNSTATE_running;
    runstate.state_entry_time = (W64)(ctx.base_tsc * ctx.sys_time_cycles_to_nsec_coeff);
    setzero(runstate.time);
    ctx.running = 1;
  }

  if (config.pseudo_real_time_clock) {
    initial_realtime_info.wc_sec = sshinfo.wc_sec;
    initial_realtime_info.wc_nsec = sshinfo.wc_nsec;
  } else {
    initial_realtime_info.wc_sec = 0;
    initial_realtime_info.wc_nsec = 0;
  }

  double timer_period_sec = 1. / ((double)config.timer_interrupt_freq_hz);
  timer_interrupt_period_in_cycles = contextof(0).core_freq_hz / config.timer_interrupt_freq_hz;
  timer_interrupt_last_sent_at_cycle = 0;

  memset(port_to_vcpu, 0, sizeof(port_to_vcpu)); // by default, route to vcpu 0

  logfile << "  Timer VIRQ ", VIRQ_TIMER, " will be delivered every 1/", config.timer_interrupt_freq_hz,
    " sec = every ", timer_interrupt_period_in_cycles, " cycles", endl;

  always_mask_port.reset();

  // Let PTLsim see all events even if the guest masks them...
  setzero(shinfo.evtchn_mask);

  if (logable(1)) {
    logfile << "Current shared info:", endl, shinfo, endl;
    logfile << "Current shadow shared info:", endl, sshinfo, endl;
  }
}

//
// Update time info in shinfo page for each VCPU.
// This should be called before virq 
//
void update_time() {
  if (logable(5)) {
    logfile << "Update virtual real time at cycle ", sim_cycle, " (", total_user_insns_committed, " commits):", endl;
    logfile << "  Global simulation TSC:              ", intstring(sim_cycle, 20), endl;
  }

  foreach (i, bootinfo.vcpu_count) {
    Context& ctx = contextof(i);
    vcpu_time_info_t& timeinfo = sshinfo.vcpu_info[ctx.vcpuid].time;
    timeinfo.tsc_timestamp = ctx.base_tsc + sim_cycle;
    timeinfo.system_time = (config.realtime) ? shinfo.vcpu_info[0].time.system_time : (W64)(timeinfo.tsc_timestamp * ctx.sys_time_cycles_to_nsec_coeff);
    timeinfo.version &= ~1ULL; // bit 0 == 0 means update all done
    if (logable(5)) logfile << "  VCPU ", i, " base TSC:                    ", intstring(ctx.base_tsc, 20), endl;
  }

  W64 initial_nsecs_since_epoch;
  W64 nsecs_since_boot;
  W64 nsecs_since_epoch;

  if likely (config.realtime) {
    sshinfo.wc_sec = shinfo.wc_sec;
    sshinfo.wc_nsec = shinfo.wc_nsec;
  } else {
    // Simulated time dilation
    initial_nsecs_since_epoch = (initial_realtime_info.wc_sec * 1000000000ULL) +
      initial_realtime_info.wc_nsec;
    nsecs_since_boot = sshinfo.vcpu_info[0].time.system_time;
    nsecs_since_epoch = initial_nsecs_since_epoch + nsecs_since_boot;
    
    sshinfo.wc_sec = nsecs_since_epoch / 1000000000ULL;
    sshinfo.wc_nsec = nsecs_since_epoch % 1000000000ULL;
  }

  if (logable(5)) {
    logfile << "Wallclock time:", endl;
    logfile << "  Nanoseconds since boot:             ", intstring(nsecs_since_boot, 20), endl;
    logfile << "  Nanoseconds since epoch:            ", intstring(nsecs_since_epoch, 20), endl;
    logfile << "  Seconds since epoch:                ", intstring(sshinfo.wc_sec, 20), endl;
    logfile << "  Nanoseconds added on:               ", intstring(sshinfo.wc_nsec, 20), endl;
    logfile << flush;
  }
}

//
// Inject events from the event replay queue.
// Returns true if an upcall is needed.
//
// The caller should call ctx.check_events()
// and possibly ctx.event_upcall() on each
// VCPU to actually process the events.
//
// Cores should call inject_events() every
// cycle, as well as after any assist.
//

bool Context::change_runstate(int newstate) {
  if (runstate.state == newstate) return false;

  update_time();
  W64 current_time_nsec = sshinfo.vcpu_info[vcpuid].time.system_time;
  W64 delta_nsec = current_time_nsec - runstate.state_entry_time;
  runstate.time[runstate.state] += delta_nsec;

  if (logable(1)) logfile << "change_vcpu_runstate at cycle ", sim_cycle, " (vcpu ", vcpuid, "): change state ", runstate.state,
    " -> ", newstate, " (delta nsec ", delta_nsec, ")", endl;

  runstate.state_entry_time = current_time_nsec;
  runstate.state = newstate;

  running = (newstate == RUNSTATE_running);

  if likely (user_runstate) {
    int n = copy_to_user((Waddr)user_runstate, &runstate, sizeof(vcpu_runstate_info_t));
    if unlikely (n != sizeof(vcpu_runstate_info_t)) {
      if (logable(1)) logfile << "change_vcpu_runstate: warning: only copied ", n,
        " bytes to mapped runstate pointer ", user_runstate, endl;
    }
  }

  return true;
}

bool deliver_timer_interrupt_to_vcpu(int vcpuid, bool forced) {
  Context& ctx = contextof(vcpuid);

  int port = ctx.virq_to_port[VIRQ_TIMER];

  if unlikely (port < 0) return false;
  if (logable(1)) {
    logfile << "Deliver ", ((forced) ? "forced" : "periodic"), " timer interrupt to VCPU ", vcpuid,
    " on port ", port, " at abs cycle ", (sim_cycle + ctx.base_tsc), " (rel cycle ", sim_cycle, ")", endl;
    logfile << "  Masked? ", sshinfo.vcpu_info[vcpuid].evtchn_upcall_mask, ", pending? ", 
      sshinfo.vcpu_info[vcpuid].evtchn_upcall_pending, ", state? ", ctx.runstate.state, " (running? ", ctx.running, ")", endl;
  }
  shadow_evtchn_set_pending(port);
  return ctx.check_events();
}

W64 inject_counter = 0;

int inject_events() {
  //
  // Process events by polling: we are CPU-bound anyway
  // and this allows us to have more control over forwarding
  // events to the guest.
  //
  if unlikely (xchg(shinfo.vcpu_info[0].evtchn_upcall_pending, (byte)0)) {
    xen_event_callback(0);
  }

  W64 evmask;
  if unlikely (evmask = xchg(events_just_handled, 0ULL)) {
    logfile << "Just got external events: ", bitstring(evmask, 64, true), endl;
    logfile << "cycle ", sim_cycle, ": sshinfo.evtchn_pending ", bitstring(sshinfo.evtchn_pending[0], 32, true), endl;
    logfile << "cycle ", sim_cycle, ": sshinfo.evtchn_mask    ", bitstring(sshinfo.evtchn_mask[0], 32, true), endl;
    logfile << "cycle ", sim_cycle, ": vcpu pending ", sshinfo.vcpu_info[0].evtchn_upcall_pending, ", mask ", sshinfo.vcpu_info[0].evtchn_upcall_mask, endl;
    logfile.flush();
  }

  W64 delta = sim_cycle - timer_interrupt_last_sent_at_cycle;

  bool needs_upcall = false;

  if unlikely (delta >= timer_interrupt_period_in_cycles) {
    timer_interrupt_last_sent_at_cycle = sim_cycle;
    update_time();

    foreach (i, bootinfo.vcpu_count) {
      needs_upcall |= deliver_timer_interrupt_to_vcpu(i, false);
    }
  }

  foreach (i, bootinfo.vcpu_count) {
    Context& ctx = contextof(i);
    if unlikely ((ctx.base_tsc + sim_cycle) >= ctx.timer_cycle) {
      ctx.timer_cycle = infinity;
      needs_upcall |= deliver_timer_interrupt_to_vcpu(i, true);
    }
    needs_upcall |= ctx.check_events();
  }

  return needs_upcall;
}

//
// Check the specified VCPU for pending events.
//
bool Context::check_events() const {
  const vcpu_info_t& vcpuinfo = sshinfo.vcpu_info[vcpuid];

  return ((!vcpuinfo.evtchn_upcall_mask) && vcpuinfo.evtchn_upcall_pending);
}

//
// If any events are pending and unmasked (i.e. check_events())
// returns true, redirect execution to the upcall handler.
//
bool Context::event_upcall() {
  if (!check_events()) return false;
  change_runstate(RUNSTATE_running);
  create_bounce_frame(GUEST_CS64, event_callback_rip, TBF_INTERRUPT);
  return true;
}

struct DescriptorTablePointer {
  W16 bytes;
  W64 virtaddr;
} packedstruct;

ostream& operator <<(ostream& os, const DescriptorTablePointer& dtp) {
  return os << (void*)(Waddr)dtp.virtaddr, ", limit ", dtp.bytes, " (", (void*)(Waddr)dtp.bytes, ")";
}

static inline void sgdt(DescriptorTablePointer& p) {
  setzero(p);
  asm volatile("sgdt %[p]" : [p] "=m" (p) : : "memory");
}

static inline void sidt(DescriptorTablePointer& p) {
  setzero(p);
  asm volatile("sidt %[p]" : [p] "=m" (p) : : "memory");
}

static inline void sldt(W16& selector) {
  selector = 0;
  asm volatile("sldt %[selector]" : [selector] "=m" (selector) : : "memory");
}

static inline void load_fs(W16 selector) {
  asm volatile("mov %[selector],%%fs" : : [selector] "r" (selector) : "memory");
}

static inline void load_gs(W16 selector) {
  asm volatile("mov %[selector],%%fs" : : [selector] "r" (selector) : "memory");
}


// Just big enough to have more than one word; rely on having no bounds checks:
typedef bitvec<65> infinite_bitvec_t;

infinite_bitvec_t* ptlsim_mfn_bitmap = null;

void backup_and_reopen_logfile() {
  if (config.log_filename) {
    if (logfile) logfile.close();
    stringbuf oldname;
    oldname << config.log_filename, ".backup"; // assert fails here
    sys_unlink(oldname);
    sys_rename(config.log_filename, oldname);
    logfile.open(config.log_filename);
  }
}

static inline void ptlsim_init_fail(W64 marker) {
  asm("mov %[marker],%%rax\n"
      "ud2a\n" : : [marker] "r" (marker));
}

extern Waddr xen_m2p_map_end;

void ptlsim_init() {
  stringbuf sb;
  int rc;

  byte startup_log_buffer[65536];
  memset(startup_log_buffer, 0, sizeof(startup_log_buffer));
  bootinfo.startup_log_buffer = startup_log_buffer;
  bootinfo.startup_log_buffer_tail = 0;
  bootinfo.startup_log_buffer_size = lengthof(startup_log_buffer);

  //
  // Initialize the page pools and memory management
  //
  ptl_mm_init(bootinfo.heap_start, bootinfo.heap_end);

  //
  // We need this to clear the TS bit in CR0: otherwise any
  // modifications to the FPU or SSE context will create a
  // device-not-available exception.
  //
  HYPERVISOR_fpu_taskswitch(0);

  //
  // Connect to the host call port the monitor set up for us:
  //
  evtchn_bind_interdomain_t bindreq;
  bindreq.remote_dom = 0; // dom0
  bindreq.remote_port = bootinfo.monitor_hostcall_port;
  rc = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain, &bindreq);

  if (rc < 0) ptlsim_init_fail(3);

  bootinfo.hostcall_port = bindreq.local_port;

  bindreq.remote_dom = 0; // dom0
  bindreq.remote_port = bootinfo.monitor_upcall_port;
  rc = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain, &bindreq);
  if (rc < 0) ptlsim_init_fail(4);

  bootinfo.upcall_port = bindreq.local_port;

  rc = HYPERVISOR_set_callbacks((Waddr)xen_event_callback_entry, 0, 0);
  if (rc < 0) ptlsim_init_fail(5);

  //
  // Set up our trap table
  //
  rc = HYPERVISOR_set_trap_table(trap_table);
  if (rc < 0) ptlsim_init_fail(6);

  //
  // PTLsim must be explicitly aware of which pages are page table pages;
  // we can't get sloppy here or Xen may silently disconnect dirty pages
  // for revalidation. Since we directly walk page tables, we will think
  // the guest itself did this, and erroneous exceptions will ensue.
  //
	rc = HYPERVISOR_vm_assist(VMASST_CMD_disable, VMASST_TYPE_writable_pagetables);
  if (rc < 0) ptlsim_init_fail(7);

  //
  // Make page at base of stack read-only (guard against overflows):
  //
  make_ptl_page_writable((byte*)bootinfo.stack_top - bootinfo.stack_size, 0);

  //
  // Enable upcalls
  //
  // We leave events disabled most of the time, since
  // sched_block atomically enables events anyway.
  //
  cli();
  clear_evtchn(bootinfo.hostcall_port);
  clear_evtchn(bootinfo.upcall_port);
  barrier();
  unmask_evtchn(bootinfo.hostcall_port);
  unmask_evtchn(bootinfo.upcall_port);

  //
  // From this point forward, we can make hostcalls to PTLmon
  //

  //
  // Call all C++ constructors
  //
  call_global_constuctors();

  //
  // Set up the bitmap of which MFNs belong to PTLsim itself
  //
  int bytes_required = ceil(bootinfo.total_machine_pages, 8) / 8;

  xen_m2p_map_end = HYPERVISOR_VIRT_START + (bootinfo.total_machine_pages * sizeof(Waddr));

  ptlsim_mfn_bitmap = (infinite_bitvec_t*)ptl_alloc_private_pages(bytes_required);
  memset(ptlsim_mfn_bitmap, 0, bytes_required);

  foreach (i, bootinfo.mfn_count) {
    mfn_t mfn = bootinfo.ptl_pagedir[i].mfn;
    assert(mfn < bootinfo.total_machine_pages);
    (*ptlsim_mfn_bitmap)[mfn] = 1;
  }

  //
  // Copy GDT template page from hypervisor
  //
  bootinfo.gdt_page = ptl_alloc_private_page();
  bootinfo.gdt_mfn = ptl_virt_to_mfn(bootinfo.gdt_page);

  mmuext_op_t mmuextop;  
  mmuextop.cmd = MMUEXT_GET_GDT_TEMPLATE;
  mmuextop.arg1.linear_addr = (unsigned long)bootinfo.gdt_page;
  mmuextop.arg2.nr_ents = PAGE_SIZE;
  int opcount = 1;
  assert(HYPERVISOR_mmuext_op(&mmuextop, opcount, &opcount, DOMID_SELF) == 0);
  if (rc < 0) ptlsim_init_fail(6);

  //
  // Bring up the rest of the PTLsim subsystems:
  //
  config.reset();
  configparser.setup();

  init_uops();
  init_translate();

  //
  // Build the physical memory map page tables, inject
  // PTLsim into the virtual address space of the guest
  // domain, then switch to this page table base.
  //
  build_physmap_page_tables();
  inject_ptlsim_into_toplevel(bootinfo.toplevel_page_table_mfn, true);
  switch_page_table(contextof(0).cr3 >> 12);

  //
  // Initialize the non-trivial parts of the VCPU contexts.
  // This must go AFTER physical memory is accessible since
  // we're refilling descriptor caches and TLBs here.
  //
  foreach (i, bootinfo.vcpu_count) {
    Context& ctx = contextof(i);
    ctx.vcpuid = i;
    ctx.init();
  }

  // Tell PTLmon we're now up and running
  bootinfo.ptlsim_state = PTLSIM_STATE_RUNNING;
}

void print_meminfo_line(ostream& os, const char* name, W64 pages) {
  os << "  ", padstring(name, -20), intstring(pages, 10), " pages, ", intstring(pages_to_kb(pages), 10), " KB", endl;
}

void print_sysinfo(ostream& os) {
  xen_capabilities_info_t xen_caps = "";
  xen_platform_parameters_t xen_params;

  HYPERVISOR_xen_version(XENVER_platform_parameters, &xen_params);
  HYPERVISOR_xen_version(XENVER_capabilities, &xen_caps);

  Waddr xen_hypervisor_start_va = xen_params.virt_start;

  os << "System Information:", endl;
  os << "  Running on hypervisor version ", xen_caps, endl;
  os << "  Xen is mapped at virtual address ", (void*)(Waddr)xen_hypervisor_start_va, endl;
  os << "  PTLsim is running across ", bootinfo.vcpu_count, " VCPUs:", endl;

  foreach (i, bootinfo.vcpu_count) {
    const vcpu_time_info_t& timeinfo = shinfo.vcpu_info[i].time;
    os << "    VCPU ", i, ": ", (get_core_freq_hz(timeinfo) / 1000000), " MHz", endl;
  }

  os << "Memory Layout:", endl;
  print_meminfo_line(os, "System:",          bootinfo.total_machine_pages);
  print_meminfo_line(os, "Domain:",          bootinfo.max_pages);
  print_meminfo_line(os, "PTLsim reserved:", bootinfo.mfn_count);
  print_meminfo_line(os, "Page Tables:",     bootinfo.mfn_count - bootinfo.avail_mfn_count);
  print_meminfo_line(os, "PTLsim image:",    ((Waddr)bootinfo.heap_start - PTLSIM_VIRT_BASE) / 4096);
  print_meminfo_line(os, "Heap:",            ((Waddr)bootinfo.heap_end - (Waddr)bootinfo.heap_start) / 4096);
  print_meminfo_line(os, "Stack:",           bootinfo.stack_size / 4096);
  os << "Interfaces:", endl;
  os << "  Shared info mfn:    ", intstring(bootinfo.shared_info_mfn, 10), endl;
  os << "  Shadow shinfo mfn:  ", intstring(ptl_virt_to_mfn(&sshinfo), 10), endl;
  os << "  Start info mfn:     ", intstring(bootinfo.start_info_mfn, 10), endl;
  os << "  Store mfn;          ", intstring(bootinfo.store_mfn, 10), ", event channel ", intstring(bootinfo.store_evtchn, 4), endl;
  os << "  Console mfn:        ", intstring(bootinfo.console_mfn, 10), ", event channel ", intstring(bootinfo.console_evtchn, 4), endl;
  os << "  PTLsim hostcall:    ", padstring("", 10), "  event channel ", intstring(bootinfo.hostcall_port, 4), endl;
  os << "  PTLsim upcall:      ", padstring("", 10), "  event channel ", intstring(bootinfo.upcall_port, 4), endl;

  os << endl;
}

stringbuf current_log_filename;

W64 handle_upcall(PTLsimConfig& config, bool blocking = true) {
  // This needs to be static because string parameters point into here:
  static char reqstr[4096];
  static bool first_time = true;

  int rc;
  logfile << "PTLsim: waiting for request (", (blocking ? "blocking" : "non-blocking"), ")...", endl, flush;

  W64 requuid = accept_upcall(reqstr, sizeof(reqstr), blocking);
  if (!requuid) return 0;

  logfile << "PTLsim: processing request '", reqstr, "' with uuid ", requuid, endl, flush;

  int lastarg = configparser.parse(config, reqstr);
  
  //
  // Fix up parameter defaults:
  //
  if ((config.start_log_at_iteration == infinity) && (config.loglevel > 0))
    config.start_log_at_iteration = 0;

  if (config.log_filename.size() && (config.log_filename != current_log_filename)) {
    // Can also use "-logfile /dev/fd/1" to send to stdout (or /dev/fd/2 for stderr):
    backup_and_reopen_logfile();
    current_log_filename = config.log_filename;
  }

  logfile.setchain((config.log_on_console) ? &cout : null);

  if (first_time) {
    if (!config.quiet) {
      print_banner(cerr);
      print_sysinfo(cerr);

      cerr << "PTLsim is now waiting for a command.", endl, flush;
    }
    print_banner(logfile);
    print_sysinfo(logfile);
    cerr << flush;
    logfile << config;
    logfile.flush();
    first_time = false;
  }
  
  if (config.run) {
    if (config.native) logfile << "Warning: when specifying -run, cannot also specify -native", endl, flush;
    // act on it
  }
  
  if (config.native) {
    if (config.run) {
      logfile << "Warning: when specifying -native, cannot also specify -run", endl, flush;
    }
  }

  return requuid;
}

W64 handle_upcall_nonblocking(PTLsimConfig& config) {
  return handle_upcall(config, false);
}

bool check_for_async_sim_break() {
  if (bootinfo.queued_upcall_count) {
    W64 requuid = handle_upcall(config);
    complete_upcall(requuid);

    if (config.native | config.pause | config.kill) {
      logfile << "Requested exit from simulation loop", endl, flush;
      return true;
    }
  }

  return false;
}

bool simulate(const char* corename) {
  logfile << "Switching to simulation core '", corename, "'...", endl, flush;
  logfile << "Stopping after ", config.stop_at_user_insns, " commits", endl, flush;

  sim_cycle = 0;

  init_virqs();
  update_time();

  /*
  Waddr physmap_level1_page_count = ceil(bootinfo.total_machine_pages, PTES_PER_PAGE) / PTES_PER_PAGE;
  logfile << "Pages comprising PTLsim physmap L1 pagedir (", physmap_level1_page_count, " L1 pages):", endl;
  foreach (i, physmap_level1_page_count) {
    if ((i % 8) == 0) logfile << " ";
    logfile << " ", bootinfo.phys_level2_pagedir[i].mfn;
    if ((i % 8) == 7) logfile << endl;
  }
  logfile << endl, flush;
  */

  sequential_core_toplevel_loop();

  logfile << "Hypercall usage:", endl;
  logfile << "  ", padstring("Hypercall", -40), " ", padstring("Total", 10), " ", padstring("Guest", 10), endl;
  foreach (i, lengthof(hypercall_names)) {
    logfile << "  ", padstring(hypercall_names[i], -40), " ",
      intstring(ptlsim_hypercall_histogram[i], 10), " ", intstring(guest_hypercall_histogram[i], 10), endl;
  }

#if 0
  //
  // Debugging support code, to crash domain at specific point
  //

  Waddr patch_entry = 0xffffffff8xxxxxxx;
  //Waddr patch_entry = signext64(contextof(0).idt[EXCEPTION_x86_page_fault].rip, 48);

  byte trigger_code[] = {0x0f, 0x0b}; // ud2a

  PageFaultErrorCode pfec;
  Waddr faultaddr;
  W64 oldcr3 = contextof(0).cr3;
  contextof(0).cr3 = (contextof(0).kernel_ptbase_mfn << 12);
  int n = contextof(0).copy_to_user(patch_entry, &trigger_code, sizeof(trigger_code), pfec, faultaddr);

  logfile << "Copied ", n, " bytes to patch entry rip ", (void*)patch_entry, endl, flush;

  contextof(0).cr3 = oldcr3;

  /*
  // Force Xen to directly handle the exception:
  contextof(0).idt[EXCEPTION_x86_page_fault].rip = 0;
  contextof(0).idt[EXCEPTION_x86_page_fault].cs = 0;
  contextof(0).idt[EXCEPTION_x86_invalid_opcode].rip = 0;
  contextof(0).idt[EXCEPTION_x86_invalid_opcode].cs = 0;
  contextof(0).idt[EXCEPTION_x86_gp_fault].rip = 0;
  contextof(0).idt[EXCEPTION_x86_gp_fault].cs = 0;
  contextof(0).idt[EXCEPTION_x86_seg_not_present].rip = 0;
  contextof(0).idt[EXCEPTION_x86_seg_not_present].cs = 0;

  contextof(0).failsafe_callback_rip = 0;
  */
#endif

  if (config.dumpcode_filename.set()) {
    byte insnbuf[256];
    PageFaultErrorCode pfec;
    Waddr faultaddr;
    Waddr rip = contextof(0).commitarf[REG_rip];
    int n = contextof(0).copy_from_user(insnbuf, rip, sizeof(insnbuf), pfec, faultaddr);
    logfile << "Saving ", n, " bytes from rip ", (void*)rip, " to ", config.dumpcode_filename, endl, flush;
    ostream(config.dumpcode_filename).write(insnbuf, n);
  }

  unmap_address_space();

  return 0;
}

int main(int argc, char** argv) {
  ptlsim_init();

  bool first_time = true;

  for (;;) {
    W64 requuid = handle_upcall(config);

    if (config.run) {
      config.run = 0;
      simulate(config.core_name);
    }

    complete_upcall(requuid);

    if (config.native) {
      bool pause = config.pause;
      bool kill = config.kill;
      config.native = 0;
      config.pause = 0;
      config.kill = 0;
      logfile << "Switching to native (pause? ", pause, ", kill? ", kill, ")...", endl, flush;
      logfile << "Final context:", endl, contextof(0), flush;
      logfile << "Final shared info page:", endl, sshinfo, endl, flush;

      foreach (i, bootinfo.vcpu_count) {
        Context& ctx = contextof(i);
        if (ctx.user_runstate) {
          vcpu_register_runstate_memory_area req;
          req.addr.v = (vcpu_runstate_info_t*)ctx.user_runstate;
          int rc = HYPERVISOR_vcpu_op(VCPUOP_register_runstate_memory_area, i, &req);
          logfile << "Re-register vcpu ", i, " memory mapped runstate @ ", ctx.user_runstate, " => rc ", rc, endl;
        }
      }

      unmap_address_space();

      logfile << "Done!", endl;
      logfile << flush;

      if (kill)
        shutdown(pause);
      else switch_to_native(pause);

      foreach (i, bootinfo.vcpu_count) {
        Context& ctx = contextof(i);
        ctx.vcpuid = i;
        ctx.init();
      }
    
      logfile << "Returned from switch to native: now back in sim", endl, flush;
    }
  }

  // We should never get here!
  abort();
  return 0;
}
