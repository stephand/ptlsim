//
// PTLsim: Cycle Accurate x86-64 Simulator
// Toplevel control and kernel interface to Xen inside the user domain
//
// Copyright 1999-2008 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>
#include <ptlxen.h>
#include <mm.h>
#include <ptlsim.h>
#include <stats.h>

#define __INSIDE_PTLSIM__
#include <ptlcalls.h>


//
// Xen hypercalls
//

#define __STR(x) #x
#define STR(x) __STR(x)

#define _hypercall0(type, name)			\
({						\
	long __res;				\
  ptlsim_hypercall_histogram[__HYPERVISOR_##name]++; \
	asm volatile (				\
		"call hypercall_page + ("STR(__HYPERVISOR_##name)" * 32)"\
		: "=a" (__res)			\
		:				\
		: "memory" );			\
	(type)__res;				\
})

#define _hypercall1(type, name, a1)				\
({								\
	long __res, __ign1;					\
  ptlsim_hypercall_histogram[__HYPERVISOR_##name]++; \
	asm volatile (						\
		"call hypercall_page + ("STR(__HYPERVISOR_##name)" * 32)"\
		: "=a" (__res), "=D" (__ign1)			\
		: "1" ((long)(a1))				\
		: "memory" );					\
	(type)__res;						\
})

#define _hypercall2(type, name, a1, a2)				\
({								\
	long __res, __ign1, __ign2;				\
  ptlsim_hypercall_histogram[__HYPERVISOR_##name]++; \
	asm volatile (						\
		"call hypercall_page + ("STR(__HYPERVISOR_##name)" * 32)"\
		: "=a" (__res), "=D" (__ign1), "=S" (__ign2)	\
		: "1" ((long)(a1)), "2" ((long)(a2))		\
		: "memory" );					\
	(type)__res;						\
})

#define _hypercall3(type, name, a1, a2, a3)			\
({								\
	long __res, __ign1, __ign2, __ign3;			\
  ptlsim_hypercall_histogram[__HYPERVISOR_##name]++; \
	asm volatile (						\
		"call hypercall_page + ("STR(__HYPERVISOR_##name)" * 32)"\
		: "=a" (__res), "=D" (__ign1), "=S" (__ign2), 	\
		"=d" (__ign3)					\
		: "1" ((long)(a1)), "2" ((long)(a2)),		\
		"3" ((long)(a3))				\
		: "memory" );					\
	(type)__res;						\
})

#define _hypercall4(type, name, a1, a2, a3, a4)			\
({								\
	long __res, __ign1, __ign2, __ign3;			\
  ptlsim_hypercall_histogram[__HYPERVISOR_##name]++; \
	asm volatile (						\
		"movq %7,%%r10; "				\
		"call hypercall_page + ("STR(__HYPERVISOR_##name)" * 32)"\
		: "=a" (__res), "=D" (__ign1), "=S" (__ign2),	\
		"=d" (__ign3)					\
		: "1" ((long)(a1)), "2" ((long)(a2)),		\
		"3" ((long)(a3)), "g" ((long)(a4))		\
		: "memory", "r10" );				\
	(type)__res;						\
})

#define _hypercall5(type, name, a1, a2, a3, a4, a5)		\
({								\
	long __res, __ign1, __ign2, __ign3;			\
  ptlsim_hypercall_histogram[__HYPERVISOR_##name]++; \
	asm volatile (						\
		"movq %7,%%r10; movq %8,%%r8; "			\
		"call hypercall_page + ("STR(__HYPERVISOR_##name)" * 32)"\
		: "=a" (__res), "=D" (__ign1), "=S" (__ign2),	\
		"=d" (__ign3)					\
		: "1" ((long)(a1)), "2" ((long)(a2)),		\
		"3" ((long)(a3)), "g" ((long)(a4)),		\
		"g" ((long)(a5))				\
		: "memory", "r10", "r8" );			\
	(type)__res;						\
})

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

int HYPERVISOR_domctl_op(xen_domctl_t *domctl_op) {
  domctl_op->interface_version = XEN_DOMCTL_INTERFACE_VERSION;
  return _hypercall1(int, domctl, domctl_op);
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

long HYPERVISOR_set_timer_op(u64 abs_nsecs) {
  return _hypercall1(long, set_timer_op, abs_nsecs);
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

int HYPERVISOR_callback_op(int cmd, void *arg) {
  return _hypercall2(int, callback_op, cmd, arg);
}

int HYPERVISOR_xenoprof_op(int op, void *arg) {
	return _hypercall2(int, xenoprof_op, op, arg);
}

int HYPERVISOR_event_channel_op(int cmd, void *arg) {
	return _hypercall2(int, event_channel_op, cmd, arg);
}

int HYPERVISOR_physdev_op(int cmd, void *arg) {
  return _hypercall2(int, physdev_op, cmd, arg);
}

int xen_sched_block() {
	return HYPERVISOR_sched_op(SCHEDOP_block, NULL);
}

int xen_sched_yield() {
	return HYPERVISOR_sched_op(SCHEDOP_yield, NULL);
}

int xen_sched_timer(u64 nsecs) {
  nsecs += shinfo.vcpu_info[0].time.system_time;
  HYPERVISOR_set_timer_op(nsecs);
  return 0;
}

int xen_sched_poll(int port, u64 nsecs) {
  evtchn_port_t ports[1];
  ports[0] = port;

  sched_poll_t op;
  op.ports.p = ports;
  op.nr_ports = 1;
  op.timeout = shinfo.vcpu_info[0].time.system_time + nsecs;

  return HYPERVISOR_sched_op(SCHEDOP_poll, &op);
}

int xen_shutdown_domain(int reason) {
  sched_shutdown_t shutdown;
  shutdown.reason = reason;
	return HYPERVISOR_sched_op(SCHEDOP_shutdown, &reason);
}

int current_vcpuid() {
  W64 rsp = (W64)get_rsp();
  W64 pervcpu = (W64)bootinfo.per_vcpu_stack_base;
  int vcpuid = 0;
  bool is_secondary_stack = inrange(rsp, pervcpu, (pervcpu + (PAGE_SIZE * MAX_CONTEXTS) - 1));
  if (is_secondary_stack) vcpuid = ((rsp - pervcpu) >> 12);
  return vcpuid;
}

W64 early_boot_log_seqid = 0;

void early_boot_log(const void* data, int length) {
  const char* p = (const char*)data;
  char* log_buffer_base = (char*)(PTLSIM_VIRT_BASE + (PTLSIM_LOGBUF_PAGE_PFN * PAGE_SIZE));

  bootinfo.logbuf_spinlock.acquire();

  early_boot_log_seqid++;
  stringbuf sb; sb.reset(); sb << early_boot_log_seqid, ": ";
  int n = strlen((char*)sb);

  foreach (i, n) {
    log_buffer_base[bootinfo.logbuf_tail] = ((char*)(sb))[i];
    bootinfo.logbuf_tail = (bootinfo.logbuf_tail + 1) % PTLSIM_LOGBUF_SIZE;
  }

  foreach (i, length) {
    log_buffer_base[bootinfo.logbuf_tail] = p[i];
    bootinfo.logbuf_tail = (bootinfo.logbuf_tail + 1) % PTLSIM_LOGBUF_SIZE;
  }

  bootinfo.logbuf_spinlock.release();
}

//
// Host calls to PTLmon
//
W64 hostreq_calls = 0;
W64 hostreq_spins = 0;

W64s synchronous_host_call(const PTLsimHostCall& call, bool spin, bool ignorerc) {
  int vcpuid = current_vcpuid();
  if (vcpuid != 0) asm volatile("int3");

  stringbuf sb;
  int rc;
  hostreq_calls++;

  memcpy(&bootinfo.hostreq, &call, sizeof(PTLsimHostCall));
  bootinfo.hostreq.ready = 0;

  unmask_evtchn(bootinfo.hostcall_port);
  if likely (real_timer_port[vcpuid] >= 0) unmask_evtchn(real_timer_port[vcpuid]);
  sti();

  evtchn_send_t sendop;
  sendop.port = bootinfo.hostcall_port;
  rc = HYPERVISOR_event_channel_op(EVTCHNOP_send, &sendop);

  if (ignorerc) return 0;

  //
  // We need to block here since we need an event to clear the hostcall
  // pending bit. However, for switching to native mode, we should NOT
  // block, since if we race with pause() in PTLmon and lose, the domain
  // will be in the Xen "blocked" state when setvcpucontext is called
  // by PTLmon, but setvcpucontext does not save/restore the blocked
  // state. Hence the target VCPU will remain blocked forever. To avoid
  // this, we specify spin = true for these calls.
  //

  barrier();

  while (!bootinfo.hostreq.ready) {
    barrier();
    if unlikely (!spin) {
      hostreq_spins++;
      xen_sched_block();
    }
    barrier();
  }

  assert(bootinfo.hostreq.ready);

  return bootinfo.hostreq.rc;
}

void enable_breakout_insn() {
  vcpu_breakout_insn_action_t breakout;
  breakout.flags = BREAKOUT_NOTIFY_PORT | BREAKOUT_PAUSE_DOMAIN;
  breakout.insn[0] = 0x0f;
  breakout.insn[1] = 0x37;
  breakout.insn_length = 2;
  breakout.notify_port = bootinfo.breakout_port;

  foreach (i, contextcount) {
    int rc = HYPERVISOR_vcpu_op(VCPUOP_set_breakout_insn_action, i, &breakout);
    logfile << "  Enabled breakout insn on vcpu ", i, " -> port ", breakout.notify_port, " (rc ", rc, ")", endl, flush;
  }
}

void disable_breakout_insn() {
  vcpu_breakout_insn_action_t breakout;
  setzero(breakout);

  foreach (i, contextcount) {
    int rc = HYPERVISOR_vcpu_op(VCPUOP_set_breakout_insn_action, i, &breakout);
    logfile << "  Disabled breakout insn on vcpu ", i, " -> port ", breakout.notify_port, " (rc ", rc, ")", endl, flush;
  }
};

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
  flush_stats();
  logfile.flush();
  cerr.flush();

  //
  // Switch back to the PTLsim root page table before going native,
  // so the monitor saves that as the cr3 value to restore when
  // we context switch back into PTLsim later on.
  //
  // If we do not do this, the guest kernel may try to reuse
  // the current cr3 mfn as a data page, and hence it will be
  // invalid if we try to use it as our root later on.
  //
  // switch_page_table(bootinfo.toplevel_page_table_mfn);
  enable_breakout_insn();

  // Linux kernels expect this to be re-enabled:
	HYPERVISOR_vm_assist(VMASST_CMD_enable, VMASST_TYPE_writable_pagetables);

  virtualize_time_for_native_mode();

  PTLsimHostCall call;
  call.op = PTLSIM_HOST_SWITCH_TO_NATIVE;
  call.ready = 0;
  call.switch_to_native.pause = pause;

  flush_cache();
  flush_tlb();

  perfctrs_start();
  int rc = synchronous_host_call(call, true);
  perfctrs_stop();

  HYPERVISOR_vm_assist(VMASST_CMD_disable, VMASST_TYPE_writable_pagetables);

  return rc;
}

//
// Shutdown PTLsim and the domain
//
int shutdown(int reason) {
  if (reason != SHUTDOWN_crash) shutdown_subsystems();
  flush_stats();
  logfile.close();
  cerr.close();

  PTLsimHostCall call;
  call.op = PTLSIM_HOST_SHUTDOWN;
  call.ready = 0;
  call.shutdown.reason = reason;

  // Linux kernels expect this to be re-enabled:
	HYPERVISOR_vm_assist(VMASST_CMD_enable, VMASST_TYPE_writable_pagetables);

  int rc = synchronous_host_call(call, false, true);
  xen_shutdown_domain(reason);
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
  call.accept_upcall.length = min(count, size_t(PTLSIM_XFER_PAGES_SIZE));
  call.accept_upcall.blocking = blocking;

  int rc = synchronous_host_call(call);
  if (rc) {
    count = min(count, size_t(PTLSIM_XFER_PAGES_SIZE-1));
    memcpy(buf, xferpage, count);
    buf[count] = 0;

    cerr << "Processing ", buf, endl, flush;
  }
  return rc;
}

W64 accept_upcall_nonblocking(char* buf, size_t count) {
  return accept_upcall(buf, count, 0);
}

//
// Complete a request and notify any blocked waiters
//
int complete_upcall(W64 uuid) {
  // cerr << "Complete upcall for uuid ", uuid, endl, flush;

  PTLsimHostCall call;

  call.op = PTLSIM_HOST_COMPLETE_UPCALL;
  call.ready = 0;
  call.complete_upcall.uuid = uuid;
  return synchronous_host_call(call);
}

//
// Inject an upcall into the monitor for later readout
//
W64 inject_upcall(const char* buf, size_t count, bool flushing) {
  if (flushing) {
    PTLsimHostCall call;
    logfile << "inject_upcall: flushing upcall queue...", endl, flush;
    call.op = PTLSIM_HOST_FLUSH_UPCALL_QUEUE;
    call.flush_upcall_queue.uuid_limit = 0;
    int n = synchronous_host_call(call);
    logfile << "inject_upcall: Flushed ", n, " pending commands", endl, flush;

    //
    // check_for_async_sim_break() will check bootinfo.abort_request
    // on the next pass through, and stop the run if we just flushed
    // the queue.
    //
    bootinfo.abort_request = 1;
  }

  PTLsimHostCall call;
  logfile << "inject_upcall: '", buf, "'", endl, flush;

  count = min(count, size_t(PTLSIM_XFER_PAGES_SIZE));
  memcpy(xferpage, buf, count);

  call.op = PTLSIM_HOST_INJECT_UPCALL;
  call.ready = 0;
  call.inject_upcall.buf = xferpage;
  call.inject_upcall.length = min(count, size_t(PTLSIM_XFER_PAGES_SIZE));
  call.inject_upcall.flush = 0;

  return synchronous_host_call(call);
}

//
// Linux-like system calls passed back to PTLmon via hostcall mechanism
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
  strncpy(xferpage, pathname, PTLSIM_XFER_PAGES_SIZE);
  return sys_open_thunk(xferpage, flags, mode);
}

declare_syscall1(__NR_close, int, sys_close, int, fd);

declare_syscall3(__NR_read, ssize_t, sys_read_thunk, int, fd, void*, buf, size_t, count);
asmlinkage ssize_t sys_read(int fd, void* buf, size_t count) {
  char* p = (char*)buf;
  size_t realcount = 0;
  int rc;

  while (count) {
    rc = sys_read_thunk(fd, xferpage, min(count, size_t(PTLSIM_XFER_PAGES_SIZE)));
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
    size_t n = min(count, size_t(PTLSIM_XFER_PAGES_SIZE));
    memcpy(xferpage, p, n);
    rc = sys_write_thunk(fd, xferpage, n);
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
  strncpy(xferpage, pathname, PTLSIM_XFER_PAGES_SIZE);
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
  foreach (i, 256) {
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
  if (logfile) {
    logfile << "PTLsim Internal Error: unhandled trap ", trapid, " (", name, "): error code ", hexstring(regs[REG_ar1], 32), endl;
    logfile << "Registers:", endl;
    print_regs(logfile, regs);
    print_stack(logfile, regs[REG_rsp]);
    logfile << flush;
  }
  logfile.close();
  cerr.flush();
  cout.flush();

  shutdown(SHUTDOWN_crash);
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

bool lowlevel_init_done = 0;

asmlinkage void assert_fail(const char *__assertion, const char *__file, unsigned int __line, const char *__function) {
  // use two stringbufs to avoid allocating any memory:
  stringbuf sb1, sb2;
  sb1 << endl, "Assert ", __assertion, " failed in ", __file, ":", __line, " (", __function, ") from ", getcaller();
  sb2 << " at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits, ", iterations, " iterations", endl;

  if (!lowlevel_init_done) {
    sys_write(2, sb1, strlen(sb1));
    sys_write(2, sb2, strlen(sb2));
    asm("mov %[ra],%%rax; ud2a;" : : [ra] "r" (getcaller()));
  }

  cerr << sb1, sb2, flush;

  if (logfile) {
    logfile << sb1, sb2, flush;
    PTLsimMachine* machine = PTLsimMachine::getcurrent();
    if (machine) machine->dump_state(logfile);
    logfile.close();
  }

  // Make sure the ring buffer is flushed too:
  ptl_mm_flush_logging();
  cerr.flush();
  cout.flush();

  // Force crash here:
  asm("ud2a");
  for (;;) { }
}

//
// Tracking of cycles and instructions in each mode
//

W64 cycles_at_last_mode_switch = 0;
W64 insns_at_last_mode_switch = 0;

void reset_mode_switch_delta_cycles_and_insns(W64& delta_cycles, W64& delta_insns) {
  delta_cycles = (sim_cycle - cycles_at_last_mode_switch);
  delta_insns = (total_user_insns_committed - insns_at_last_mode_switch);
  cycles_at_last_mode_switch = sim_cycle;
  insns_at_last_mode_switch = total_user_insns_committed;
}

void update_pre_run_stats() {
  cycles_at_last_mode_switch = sim_cycle;
  insns_at_last_mode_switch = total_user_insns_committed;
}

//
// x86 Specific Functions
//

// idx must be between 0 and 8191 (i.e. 65535 >> 3)
bool Context::gdt_entry_valid(W16 idx) {
  if ((idx >= FIRST_RESERVED_GDT_ENTRY) && (idx < (FIRST_RESERVED_GDT_ENTRY + (PAGE_SIZE / sizeof(SegmentDescriptor)))))
    return true;

  return (idx < gdtsize);
}

void* gdt_page;
mfn_t gdt_mfn;

SegmentDescriptor Context::get_gdt_entry(W16 idx) {
  if (!idx)
    return SegmentDescriptor(0);

  if ((idx >> 9) == FIRST_RESERVED_GDT_PAGE)
    return *(const SegmentDescriptor*)((byte*)gdt_page + (lowbits(idx, 9) * 8));

  if (idx >= gdtsize)
    return SegmentDescriptor(0);

  mfn_t mfn = gdtpages[idx >> 9];
  return *(const SegmentDescriptor*)phys_to_mapped_virt((mfn << 12) + (lowbits(idx, 9) * 8));
}

void Context::flush_tlb(bool propagate_flush_to_model) {
  if (logable(5)) logfile << "[vcpu ", vcpuid, "] flush_tlb() called from ", getcaller(), endl;

  foreach (i, lengthof(cached_pte_virt)) {
    cached_pte_virt[i] = 0xffffffffffffffffULL;
    cached_pte[i] = 0;
  }

  if unlikely (!propagate_flush_to_model) return;

  PTLsimMachine* machine = PTLsimMachine::getcurrent();
  if likely (machine) machine->flush_tlb(*this);
}

void Context::flush_tlb_virt(Waddr virtaddr, bool propagate_flush_to_model) {
  if (logable(5)) logfile << "[vcpu ", vcpuid, "] flush_tlb(", (void*)virtaddr, ") called from ", getcaller(), endl;

  int slot = lowbits(virtaddr >> 12, log2(PTE_CACHE_SIZE));
  if (cached_pte_virt[slot] == floor(virtaddr, PAGE_SIZE)) {
    cached_pte_virt[slot] = 0xffffffffffffffffULL;
    cached_pte[slot] = 0;
  }

  if unlikely (!propagate_flush_to_model) return;
  
  PTLsimMachine* machine = PTLsimMachine::getcurrent();
  if likely (machine) machine->flush_tlb_virt(*this, virtaddr);
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
    // Technically this is supposed to be a seg not present fault, but K8 in x86-64 mode seems to signal a GP fault instead:
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
    swapgs_base = gs_base_user;
  } else {
    // user mode
    if (use64) seg[SEGID_GS].base = gs_base_user;
    swapgs_base = gs_base_kernel;
  }

  // Extended Feature Enable Register (EFER MSR):
  efer = 0;
  efer.sce = 1;
  efer.lme = 1;
  efer.lma = 1;
  efer.nxe = 1;
  efer.ffxsr = 1;

  // Bring the state representations back in sync
  //SD NOTE: This is likely an ugly hack.
  if (running && (runstate.state == RUNSTATE_blocked)) {
    if (logable(1)) logfile << "[vcpu ", vcpuid, "] Faking a proper runstate transition to mark the VCPU running.", endl;
    running = false;
    change_runstate(RUNSTATE_running); // Will set running back to true;
  }
}

//
// Hypercalls
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
    logfile << "[vcpu ", ctx.vcpuid, "] hypercall (", hypercallid, ") from ";
    // Get real return address from stack, above push of %rcx and %r11
    void* real_retaddr;
    int stackn = ctx.copy_from_user(&real_retaddr, (ctx.commitarf[REG_rsp] + 8*2), 8);
    if (stackn) logfile << real_retaddr; else logfile << "<unknown>";
    logfile << " at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits: ";
    // Target hypercall will print rest of line 
  }

  W64s rc;

#define getreq(type) type req; if (ctx.copy_from_user(&req, (Waddr)arg2, sizeof(type)) != sizeof(type)) { rc = -EFAULT; break; }
#define putreq(type) ctx.copy_to_user((Waddr)arg2, &req, sizeof(type))

  switch (hypercallid) {
  case __HYPERVISOR_set_trap_table: {
    struct trap_info trap_ctxt[256];
    if (arg1) {
      int n = ctx.copy_from_user(trap_ctxt, arg1, sizeof(trap_ctxt));
      rc = -EFAULT;
      if (n != sizeof(trap_ctxt)) break;
    } else {
      setzero(trap_ctxt);
    }

    setzero(ctx.idt);

    if (debug) {
      logfile << "set_trap_table(", (void*)arg1, "):", endl;
    }

    foreach (i, 256) {
      const trap_info& ti = trap_ctxt[i];
      if (!ti.address) break;

      TrapTarget& tt = ctx.idt[ti.vector];
      tt.cs = ti.cs >> 3;
      tt.rip = ti.address;
      tt.cpl = lowbits(ti.flags, 2);
      tt.maskevents = bit(ti.flags, 2);

      if (logable(1) | force_hypercall_logging) {
        logfile << "  Trap 0x", hexstring(ti.vector, 8), " = ", hexstring(tt.cs << 3, 16),
          ":", hexstring(tt.rip, 64), " cpl ", tt.cpl, (tt.maskevents ? " (mask events)" : ""), endl;
      }
    }

    rc = 0;
    break;
  }

  case __HYPERVISOR_mmu_update: {
    rc = handle_mmu_update_hypercall(ctx, (mmu_update_t*)arg1, arg2, (int*)arg3, arg4, debug);
    break;
  }

  case __HYPERVISOR_set_gdt: {
    unsigned int entries = arg2;
    unsigned int pages = ceil(entries, 512) / 512;
    unsigned long mfns[16];

    int n = ctx.copy_from_user(&mfns, arg1, sizeof(unsigned long) * pages);
    if unlikely (n != (sizeof(unsigned long) * pages)) {
      rc = -EFAULT;
      break;
    }

    foreach (i, pages) {
      unmap_phys_page(mfns[i]);
    }

    rc = HYPERVISOR_set_gdt(mfns, entries);

    if (debug) {
      logfile << "set_gdt: ", entries, " entries in ", pages, " pages:";
      foreach (i, pages) { logfile << " ", mfns[i]; }
      logfile << "; rc ", rc, endl;
    }

    ctx.gdtsize = entries;
    foreach (i, pages) ctx.gdtpages[i] = mfns[i];
    ctx.flush_tlb();

    break;
  }

  case __HYPERVISOR_stack_switch: {
    arg1 = fixup_guest_stack_selector(arg1);
    ctx.kernel_ss = arg1;
    ctx.kernel_sp = arg2;
    if (debug) logfile << "stack_switch: ", (void*)ctx.kernel_ss, ":", (void*)ctx.kernel_sp, endl;
    rc = 0;
    break;
  }

  case __HYPERVISOR_set_callbacks: {
    ctx.event_callback_rip = arg1;
    ctx.failsafe_callback_rip = arg2;
    ctx.syscall_rip = arg3;
    ctx.syscall_disables_events = 0;
    ctx.failsafe_disables_events = 1;
    logfile << "set_callbacks: (event ", (void*)ctx.event_callback_rip, ", failsafe ",
      (void*)ctx.failsafe_callback_rip, ", syscall ", (void*)ctx.syscall_rip, ")", endl;
    rc = 0;
    break;
  };

  case __HYPERVISOR_fpu_taskswitch: {
    ctx.cr0.ts = arg1;
    if (debug) logfile << "fpu_taskswitch: TS = ", ctx.cr0.ts, endl;
    rc = 0;
    break;
  };

    // __HYPERVISOR_sched_op_compat deprecated

    // __HYPERVISOR_dom0_op not needed in domU

  case __HYPERVISOR_set_debugreg: {
    logfile << "set_debugreg: dr", arg1, " = 0x", hexstring(arg2, 64), endl;
    if (inrange((int)arg1, 0, 7)) {
      switch (arg1) {
      case 0: ctx.dr0 = arg2; break;
      case 1: ctx.dr1 = arg2; break;
      case 2: ctx.dr2 = arg2; break;
      case 3: ctx.dr3 = arg2; break;
      case 4: ctx.dr4 = arg2; break;
      case 5: ctx.dr5 = arg2; break;
      case 6: ctx.dr6 = arg2; break;
      case 7: ctx.dr7 = arg2; break;
      }
      rc = 0;
    } else {
      rc = -EINVAL;
    }
    break;
  }

  case __HYPERVISOR_get_debugreg: {
    if (inrange((int)arg1, 0, 7)) {
      switch (arg1) {
      case 0: rc = ctx.dr0; break;
      case 1: rc = ctx.dr1; break;
      case 2: rc = ctx.dr2; break;
      case 3: rc = ctx.dr3; break;
      case 4: rc = ctx.dr4; break;
      case 5: rc = ctx.dr5; break;
      case 6: rc = ctx.dr6; break;
      case 7: rc = ctx.dr7; break;
      }
    } else {
      rc = -EINVAL;
    }
    logfile << "get_debugreg: dr", arg1, " = 0x", hexstring(rc, 64), endl;
    break;
  }

  case __HYPERVISOR_update_descriptor: {
    //
    // Update a single descriptor. We just pass this down to Xen
    // since we can always refresh PTLsim's descriptor cache
    // when the segment is explicitly reloaded.
    //
    Waddr physaddr = arg1;
    W64 desc = arg2;

    if (debug) logfile << "update_descriptor: physaddr ", (void*)arg1, " (mfn ", (arg1 >> 12), ", entry ", (lowbits(arg1, 12) / 8), ") = 0x", hexstring(desc, 64), endl;
    rc = HYPERVISOR_update_descriptor(physaddr, desc);
    break;
  };

  case __HYPERVISOR_memory_op: {
    rc = handle_memory_op_hypercall(ctx, arg1, (void*)arg2, debug);
    break;
  };

    // __HYPERVISOR_multicall handled elsewhere

  case __HYPERVISOR_update_va_mapping: {
    rc = handle_update_va_mapping_hypercall(ctx, arg1, arg2, arg3, debug);
    break;
  }

  case __HYPERVISOR_set_timer_op: {
    rc = handle_set_timer_op_hypercall(ctx, arg1, debug);
    break;
  }

  case __HYPERVISOR_event_channel_op_compat: {
    uint32_t op;
    rc = -EFAULT;
    if (ctx.copy_from_user(&op, (Waddr)arg1, sizeof(op)) == sizeof(op)) {
      rc = handle_event_channel_op_hypercall(ctx, op, (void*)(arg1 + sizeof(op)), debug);
    }
    break;
  }

  case __HYPERVISOR_xen_version: {
    // NOTE: xen_version is sometimes used as a no-op call just to get pending events processed

    if (debug) logfile << "xen_version: type ", arg1, " => buf ", (void*)arg2, endl;

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

    if (n && (ctx.copy_from_user(buf, arg2, n) != n)) { rc = -EFAULT; break; }

    rc = HYPERVISOR_xen_version(arg1, buf);

    ctx.copy_to_user(arg1, buf, n);

    break;
  }

  case __HYPERVISOR_console_io: {
    switch (arg1) {
    case CONSOLEIO_write: {
      if (debug) logfile << "console_io (write): write ", arg2, " bytes at ", (void*)(Waddr)arg3, endl, flush;
      logfile << "Console output (", arg2, " bytes):", endl, flush;
      // logfile.write((void*)arg3, arg2); (page tables may not be set up yet)
      logfile << flush;
      rc = arg2;
      break;
    }
    case CONSOLEIO_read: {
      if (debug) logfile << "console_io (read): read ", arg2, " bytes into ", (void*)(Waddr)arg3, endl, flush;
      rc = 0;
      break;
    }
    default:
      assert(false);
    }
    break;
  }

  case __HYPERVISOR_physdev_op_compat: {
    getreq(physdev_op_t);
    if (debug) logfile << "physdev_op (operation ", req.cmd, "): ignored", endl;
    rc = 0;
    break;
  }

  case __HYPERVISOR_grant_table_op: {
    rc = handle_grant_table_op_hypercall(ctx, arg1, (byte*)arg2, arg3, debug);
    break;
  }

  case __HYPERVISOR_vm_assist: {
    if (debug) logfile << "vm_assist (subcall ", arg1, ") = value ", arg2, endl;
    // Writable pagetables are always supported by PTLsim (this is the only relevant assist type)
    break;
  }

    // __HYPERVISOR_update_va_mapping_otherdomain not needed in domU

    // __HYPERVISOR_iret handled separately

  case __HYPERVISOR_vcpu_op: {
    rc = handle_vcpu_op_hypercall(ctx, arg1, arg2, arg3, debug);
    break;
  }

  case __HYPERVISOR_set_segment_base: {
    rc = 0;
    switch (arg1) {
    case SEGBASE_FS:
      if (debug) logfile << "set_segment_base: kernel_fs = ", (void*)arg2, endl;
      ctx.fs_base = arg2;
      ctx.seg[SEGID_FS].base = arg2;
      break;
    case SEGBASE_GS_USER:
      if (debug) logfile << "set_segment_base: user_gs = ", (void*)arg2, endl;
      ctx.gs_base_user = arg2;
      //
      // Update the MSR so the new user base gets restored
      // when we do an iret from the kernel code that made
      // this hypercall.
      //
      ctx.swapgs_base = arg2;
      break;
    case SEGBASE_GS_KERNEL:
      if (debug) logfile << "set_segment_base: kernel_gs = ", (void*)arg2, endl;
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
      if (debug) logfile << "set_segment_base: user_gs_sel = ", (void*)arg2, endl;
      int exception = ctx.write_segreg(SEGID_GS, arg2);
      ctx.swapgs(); // put it back in the base to restore for user mode
      rc = (exception) ? -EINVAL : 0;
      break;
    }
    default:
      if (debug) logfile << "set_segment_base: unknown segment id ", arg1, endl;
      assert(false);
    }

    break;
  }

  case __HYPERVISOR_mmuext_op: {
    rc = handle_mmuext_op_hypercall(ctx, (mmuext_op_t*)arg1, arg2, (int*)arg3, arg4, debug);
    break;
  }

    // __HYPERVISOR_acm_op not needed for now

  case __HYPERVISOR_nmi_op: {
    // not supported outside dom0
    if (debug) logfile << "nmi_op: not supported", endl;
    rc = -EINVAL;
    break;
  }

  case __HYPERVISOR_sched_op: {
    rc = handle_sched_op_hypercall(ctx, arg1, (void*)arg2, debug);
    break;
  };

  case __HYPERVISOR_callback_op: {
    switch (arg1) {
    case CALLBACKOP_register: {
      getreq(callback_register_t);
      bool disable_events = ((req.flags & CALLBACKF_mask_events) != 0);
      switch (req.type) {
      case CALLBACKTYPE_event:
        if (debug) logfile << "callback_op: set event callback to ", (void*)(Waddr)req.address, endl;
        ctx.event_callback_rip = req.address;
        break;
      case CALLBACKTYPE_syscall:
        if (debug) logfile << "callback_op: set syscall callback to ", 
                     (void*)(Waddr)req.address, " (disable events? ", disable_events, ")", endl;
        ctx.syscall_rip = req.address;
        ctx.syscall_disables_events = disable_events;
        break;
      case CALLBACKTYPE_failsafe:
        if (debug) logfile << "callback_op: set failsafe callback to ", 
                     (void*)(Waddr)req.address, " (disable events? ", disable_events, ")", endl;
        ctx.failsafe_callback_rip = req.address;
        ctx.failsafe_disables_events = disable_events;
        break;
      case CALLBACKTYPE_nmi:
        if (debug) logfile << "callback_op: set nmi callback to ", 
                     (void*)(Waddr)req.address, " (disable events? ", disable_events, ")", endl;
        // We don't have NMIs in PTLsim - dom0 handles that
        break;
      default:
        logfile << "callback_op: set unknown callback ", req.type, " to ", 
          (void*)(Waddr)req.address, " (disable events? ", disable_events, ")", endl;
        assert(false);
        break;
      }
      rc = 0;
      break;
    }
    default:
      assert(false);
      rc = -EINVAL;
    }
    break;
  };

    // __HYPERVISOR_xenoprof_op not needed for now

  case __HYPERVISOR_event_channel_op: {
    rc = handle_event_channel_op_hypercall(ctx, arg1, (void*)arg2, debug);
    break;
  }

  case __HYPERVISOR_physdev_op: {
    switch (arg1) {
    case PHYSDEVOP_set_iopl: {
      if (debug) logfile << "physdev_op (set_iopl): ignored", endl;
      // Even domU's try to get iopl 1; just ignore it: they don't have any physical devices anyway
      rc = 0;
      break;
    }
    default:
      rc = -EINVAL;
      assert(false);
    }
    break;
  }

  default:
    if (debug) logfile << "Cannot handle hypercall ", hypercallid, "!", endl, flush;
    assert(false);
  }

  // if (debug) logfile << "  Returning rc ", rc, endl, flush;
  if (debug) logfile.flush();

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

      if (ctx.copy_from_user(&req, reqp, sizeof(req)) != sizeof(req)) {
        ctx.commitarf[REG_rax] = (W64)(-EFAULT);
        return;
      }

      req.result = handle_xen_hypercall(ctx, req.op, req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5]);

      ctx.copy_to_user(reqp, &req, sizeof(req));
      
      reqp += sizeof(req);
    }
    ctx.commitarf[REG_rax] = 0;
  } else if (hypercallid == __HYPERVISOR_iret) {
    iret_context iretctx;
    if (ctx.copy_from_user(&iretctx, ctx.commitarf[REG_rsp], sizeof(iretctx)) != sizeof(iretctx)) { assert(false); }

    if (logable(2)) {
      logfile << "[vcpu ", ctx.vcpuid, "] IRET from rip ", (void*)(Waddr)ctx.commitarf[REG_rip], ": iretctx @ ",
        (void*)(Waddr)ctx.commitarf[REG_rsp], " = ", iretctx, " (", sim_cycle, " cycles, ",
        total_user_insns_committed, " commits)", endl, flush;
    }

    bool return_to_user_mode = ((iretctx.cs & 3) == 3);

    if likely (return_to_user_mode) {
      // Returning to user mode: toggle_guest_mode(v)
      assert(ctx.kernel_mode);
      iretctx.rflags = (iretctx.rflags & ~FLAG_IOPL) | (0x3 << 12);
      ctx.kernel_mode = 0;
      ctx.cr3 = ctx.user_ptbase_mfn << 12;
      ctx.flush_tlb();
      // switch_page_table(ctx.cr3 >> 12);
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

    if likely (return_to_user_mode) {
      W64 delta_cycles, delta_insns;
      W64 prev_cycles_at_last_mode_switch = cycles_at_last_mode_switch;
      W64 prev_insns_at_last_mode_switch = insns_at_last_mode_switch;
      reset_mode_switch_delta_cycles_and_insns(delta_cycles, delta_insns);

      if (logable(2)) {
        logfile << "[vcpu ", ctx.vcpuid, "] Switch to ", (ctx.use64 ? "user64" : "user32"), " mode at ",
          sim_cycle, " cycles, ", total_user_insns_committed, " insns", " (previous mode ", "kernel64",
          ": abs ", prev_cycles_at_last_mode_switch, " cycles, ", prev_insns_at_last_mode_switch, " insns; ",
          "delta ", delta_cycles, " cycles, ", delta_insns, " insns)", endl;
      }

      stats.external.cycles_in_mode.kernel64 += delta_cycles;
      stats.external.insns_in_mode.kernel64 += delta_insns;
    }
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
  p -= sizeof(data);
  bool ok = (ctx.copy_to_user((Waddr)p, &data, sizeof(data)) == sizeof(data));
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
  if likely (!kernel_mode) {
    //
    // Switch from user mode to kernel mode
    //
    W64 delta_cycles, delta_insns;
    W64 prev_cycles_at_last_mode_switch = cycles_at_last_mode_switch;
    W64 prev_insns_at_last_mode_switch = insns_at_last_mode_switch;
    reset_mode_switch_delta_cycles_and_insns(delta_cycles, delta_insns);

    if (logable(2)) {
      logfile << "[vcpu ", vcpuid, "] Switch to kernel64 mode at ", sim_cycle, " cycles, ", total_user_insns_committed, " insns",
        " (previous mode ", (use64 ? "user64" : "user32"), ": abs ", prev_cycles_at_last_mode_switch, " cycles, ",
        prev_insns_at_last_mode_switch, " insns; ", "delta ", delta_cycles, " cycles, ", delta_insns, " insns)", endl;
    }

    if likely (use64) {
      stats.external.cycles_in_mode.user64 += delta_cycles;
      stats.external.insns_in_mode.user64 += delta_insns;
    } else {
      stats.external.cycles_in_mode.user32 += delta_cycles;
      stats.external.insns_in_mode.user32 += delta_insns;
    }
  }

  // If in kernel context already, push new frame at existing rsp:
  Waddr frame = (kernel_mode) ? commitarf[REG_rsp] : kernel_sp;
  Waddr origframe = frame;

  if (logable(2)) logfile << "[vcpu ", vcpuid, "] Create bounce frame from ", (kernel_mode ? "kernel" : "user"), " rip ", 
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
    // switch_page_table(cr3 >> 12);
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
  // force_logging_enabled();

  assert(exception < lengthof(idt));

  stats.external.traps[exception]++;

  RIPVirtPhys rvp(commitarf[REG_rip]);
  rvp.update(*this);

  if (logable(2)) {
    logfile << "[vcpu ", vcpuid, "] Exception ", exception, " (x86 ", x86_exception_names[exception], ") at rip ", (RIPVirtPhys)rvp, ": error code ";
    if likely (exception == EXCEPTION_x86_page_fault) {
      logfile << PageFaultErrorCode(errorcode), " (", (void*)(Waddr)errorcode, ") @ virtaddr ", (void*)virtaddr;
      //logfile << "Offending 
    } else {
      logfile << "0x", hexstring(errorcode, 32);
    }
    logfile << " (", total_user_insns_committed, " user commits, ", sim_cycle, " cycles, ", iterations, " iterations)", endl, flush;
  }

  x86_exception = exception;
  error_code = errorcode;

  // Clear DPL bits for everything but page fault error code format
  if unlikely (exception != EXCEPTION_x86_page_fault) errorcode &= 0xfff8;

  if likely (exception == EXCEPTION_x86_page_fault) {
    cr2 = virtaddr;
    sshinfo.vcpu_info[vcpuid].arch.cr2 = virtaddr;
    flush_tlb_virt(virtaddr);
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

  // PTLsimMachine::getcurrent()->dump_state(logfile);
  // assert(false);
}

void handle_syscall_assist(Context& ctx) {
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_rcx]; // microcode stub puts return address in rcx

  if (logable(1)) {
    logfile << "[vcpu ", ctx.vcpuid, "] syscall from ", (void*)ctx.commitarf[REG_rip], ": ", ctx.commitarf[REG_rax], " args (",
      (void*)ctx.commitarf[REG_rdi], ", ",
      (void*)ctx.commitarf[REG_rsi], ", ",
      (void*)ctx.commitarf[REG_rdx], ", ",
      (void*)ctx.commitarf[REG_r10], ", ",
      (void*)ctx.commitarf[REG_r8], ", ",
      (void*)ctx.commitarf[REG_r9], ")", endl;
  }

  //
  // Print useful information about system calls as they are made.
  // This only works when the guest OS is Linux and the program is 64 bit.
  //
  if (ctx.use64) {
    switch (ctx.commitarf[REG_rax]) {
    case __NR_execve: {
      char filename[256];
      int n = ctx.copy_from_user(filename, ctx.commitarf[REG_rdi], sizeof(filename)-1);
      assert(inrange(n, 0, int(sizeof(filename)-1)));
      filename[n] = 0;
      logfile << "syscall: execve('", filename, "', ...)", endl;
      break;
    }
    }
  }

  int action = (ctx.syscall_disables_events) ? TBF_INTERRUPT : 0;
  ctx.create_bounce_frame(GUEST_CS64, ctx.syscall_rip, action);
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

static inline void ptlsim_init_fail(W64 marker) {
  asm("mov %[marker],%%rax\n"
      "ud2a\n" : : [marker] "r" (marker));
}

extern Waddr xen_m2p_map_end;

void collect_sysinfo(PTLsimStats& stats) {
  collect_common_sysinfo(stats);

  xen_capabilities_info_t xen_caps = "";
  HYPERVISOR_xen_version(XENVER_capabilities, &xen_caps);
#define strput(x, y) (strncpy((x), (y), sizeof(x)))
  strput(stats.simulator.run.hypervisor_version, xen_caps);
}

void wait_for_secondary_vcpus();

int cpu_type = CPU_TYPE_UNKNOWN;

//
// Bring up PTLsim subsystems on the bare hardware,
// using only Xen hypercalls until we can establish
// the channel to PTLmon in domain 0. 
//

void ptlsim_init() {
  int rc;

  //
  // Capture initial timing information
  //
  capture_initial_timestamps();

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
  bindreq.remote_dom = 0;
  bindreq.remote_port = bootinfo.monitor_hostcall_port;
  rc = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain, &bindreq);
  if (rc < 0) ptlsim_init_fail(3);

  bootinfo.hostcall_port = bindreq.local_port;

  bindreq.remote_dom = 0;
  bindreq.remote_port = bootinfo.monitor_upcall_port;
  rc = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain, &bindreq);
  if (rc < 0) ptlsim_init_fail(4);
  bootinfo.upcall_port = bindreq.local_port;

  bindreq.remote_dom = 0;
  bindreq.remote_port = bootinfo.monitor_breakout_port;
  rc = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain, &bindreq);
  if (rc < 0) ptlsim_init_fail(5);
  bootinfo.breakout_port = bindreq.local_port;

  rc = HYPERVISOR_set_callbacks((Waddr)xen_event_callback_entry, 0, 0);
  if (rc < 0) ptlsim_init_fail(6);

  //
  // Set up our trap table
  //
  rc = HYPERVISOR_set_trap_table(trap_table);
  if (rc < 0) ptlsim_init_fail(7);

  //
  // PTLsim must be explicitly aware of which pages are page table pages;
  // we can't get sloppy here or Xen may silently disconnect dirty pages
  // for revalidation. Since we directly walk page tables, we will think
  // the guest itself did this, and erroneous exceptions will ensue.
  //
	rc = HYPERVISOR_vm_assist(VMASST_CMD_disable, VMASST_TYPE_writable_pagetables);
  if (rc < 0) ptlsim_init_fail(8);

  //
  // Enable upcalls
  //
  clear_evtchn(bootinfo.hostcall_port);
  clear_evtchn(bootinfo.upcall_port);
  barrier();
  //
  // Unmask everything: we want to see all interrupts so we can
  // pass them through to the guest.
  //
  setzero(shinfo.evtchn_mask);
  unmask_evtchn(bootinfo.hostcall_port);
  unmask_evtchn(bootinfo.upcall_port);
  sti();

  //
  // Make all pages below the boot page inaccessible, so we can trap null pointers
  //
  foreach (i, PTLSIM_BOOT_PAGE_PFN) {
    update_ptl_virt((void*)(PTLSIM_VIRT_BASE + (i * PAGE_SIZE)), 0);
  }

  //
  // Make page at base of stack read-only (guard against overflows):
  //
  make_ptl_page_writable((byte*)bootinfo.stack_top - bootinfo.stack_size, 0);

  //
  // Determine CPU type
  //
  cpu_type = get_cpu_type();

  //
  // Initialize the page pools and memory management
  //
  ptl_mm_init(bootinfo.heap_start, bootinfo.heap_end);

  //
  // From this point forward, we can make hostcalls to PTLmon
  //
  events_init();

  //
  // Call all C++ constructors
  //
  call_global_constuctors();
  lowlevel_init_done = 1;

  //
  // Set up the bitmap of which MFNs belong to PTLsim itself
  //
  int bytes_required = ceil(bootinfo.total_machine_pages, 8) / 8;

  xen_m2p_map_end = HYPERVISOR_VIRT_START + (bootinfo.total_machine_pages * sizeof(Waddr));

  ptlsim_mfn_bitmap = (infinite_bitvec_t*)ptl_mm_try_alloc_private_pages(bytes_required);
  memset(ptlsim_mfn_bitmap, 0, bytes_required);

  foreach (i, bootinfo.mfn_count) {
    mfn_t mfn = bootinfo.ptl_pagedir[i].mfn;
    assert(mfn < bootinfo.total_machine_pages);
    (*ptlsim_mfn_bitmap)[mfn] = 1;
  }

  //
  // Copy GDT template page from hypervisor
  //
  gdt_page = ptl_mm_try_alloc_private_page();
  gdt_mfn = ptl_virt_to_mfn(gdt_page);

  mmuext_op_t mmuextop;  
  mmuextop.cmd = MMUEXT_GET_GDT_TEMPLATE;
  mmuextop.arg1.linear_addr = (unsigned long)gdt_page;
  mmuextop.arg2.nr_ents = PAGE_SIZE;
  int opcount = 1;
  assert(HYPERVISOR_mmuext_op(&mmuextop, opcount, &opcount, DOMID_SELF) == 0);
  if (rc < 0) ptlsim_init_fail(6);

  //
  // Bring up the rest of the PTLsim subsystems:
  //
  config.reset();
  configparser.setup();

  //
  // Wait for ptlmon to properly convert the context
  //
  while (!bootinfo.context_spinlock) { xen_sched_yield(); barrier(); }

  //
  // Build the physical memory map page tables, inject
  // PTLsim into the virtual address space of the guest
  // domain, then switch to this page table base.
  //
  build_physmap_page_tables();

  inject_ptlsim_into_toplevel(get_cr3_mfn());

  init_uops();
  init_decode();

  //
  // Initialize the non-trivial parts of the VCPU contexts.
  // This must go AFTER physical memory is accessible since
  // we're refilling descriptor caches and TLBs here.
  //
  CycleTimer::gethz();
  foreach (i, contextcount) {
    Context& ctx = contextof(i);
    ctx.vcpuid = i;
    ctx.init();
  }

  collect_sysinfo(stats);

  // Bring up secondary processors
  wait_for_secondary_vcpus();

  // Tell PTLmon we're now up and running
  bootinfo.ptlsim_state = PTLSIM_STATE_RUNNING;
}

//
// Secondary VCPUs spin on bits in this bitmap (waiting
// for a '1' bit) until the primary VCPU initializes.
//
// This starts at bit 0 == '1' since vcpu0 immediately
// starts on bootup.
//
W64 vcpu_startup_signal_bitmap = 1;

//
// Secondary VCPUs atomically set bits in this bitmap
// as they come on line. VCPU0 only reads this bitmap;
// it never writes it.
//
W64 vcpu_startup_complete_bitmap = 1;

void prep_secondary_vcpu_context(int vcpuid, Context& ptlctx) {
  bool DEBUG = 0;

  setzero(ptlctx);
  ptlctx.cr3 = (bootinfo.toplevel_page_table_mfn << log2(PAGE_SIZE));
  ptlctx.kernel_ptbase_mfn = ptlctx.cr3 >> 12;
  ptlctx.user_ptbase_mfn = ptlctx.cr3 >> 12;
  ptlctx.kernel_mode = 1;
  ptlctx.seg[SEGID_CS].selector = FLAT_KERNEL_CS;
  ptlctx.seg[SEGID_DS].selector = FLAT_KERNEL_DS;
  ptlctx.seg[SEGID_SS].selector = FLAT_KERNEL_SS;
  ptlctx.seg[SEGID_ES].selector = FLAT_KERNEL_DS;
  ptlctx.seg[SEGID_FS].selector = 0;
  ptlctx.seg[SEGID_GS].selector = 0;
  ptlctx.commitarf[REG_flags] = 0; // interrupts initially off
  ptlctx.saved_upcall_mask = 1;
  
  W64 per_vcpu_sp = W64(bootinfo.per_vcpu_stack_base) + (vcpuid * 4096) + 4096;
  ptlctx.commitarf[REG_rsp] = (vcpuid > 0) ? per_vcpu_sp : (W64)bootinfo.stack_top;
  ptlctx.commitarf[REG_rip] = PTLSIM_ENTRYPOINT_RIP;
  // start info in %rdi (arg[0]):
  ptlctx.commitarf[REG_rdi] = W64(getbootinfo());
  // vcpuid is passed in rsi so we know whether or not we're the primary VCPU:
  ptlctx.commitarf[REG_rsi] = vcpuid;

  if (DEBUG) {
    cerr << "Configure secondary VCPU ", vcpuid, " with stack at ",
      (void*)ptlctx.commitarf[REG_rsp], ", cr3 mfn ", ptlctx.kernel_ptbase_mfn, endl;
  }
}

void bring_up_secondary_vcpu(int vcpuid) {
  int rc = 0;
  logfile << "Bringing up VCPU ", vcpuid, " into PTLsim redirector thread:", endl, flush;

  //
  // At this point we also need to configure the real VCPU
  // on which PTLsim will run its interrupt redirector.
  //
  Context ptlctx;
  vcpu_guest_context xenctx;
  
  setzero(xenctx);
  prep_secondary_vcpu_context(vcpuid, ptlctx);
  ptlctx.saveto(xenctx);
  rc = HYPERVISOR_vcpu_op(VCPUOP_initialise, vcpuid, &xenctx);
  if likely (rc >= 0) {
    logfile << "  Initialized secondary VCPU ", vcpuid, " to run PTLsim interrupt redirector thread (rc ", rc, ")", endl;
  } else {
    logfile << "  Secondary VCPU ", vcpuid, " was already initialized (rc ", rc, ")", endl;
  }

  if likely (!HYPERVISOR_vcpu_op(VCPUOP_is_up, vcpuid, null)) {
    rc = HYPERVISOR_vcpu_op(VCPUOP_up, vcpuid, null);
    logfile << "  Xen brought up VCPU ", vcpuid, " with rc = ", rc, endl;
    assert(rc == 0);
  }

  setbit(vcpu_startup_signal_bitmap, vcpuid);
  barrier();

  logfile << "  Waiting for VCPU ", vcpuid, " to reach redirector barrier", endl, flush;

  while (!bit(vcpu_startup_complete_bitmap, vcpuid)) {
    xen_sched_yield();
    barrier();
  }

  logfile << "  VCPU ", vcpuid, " is running", endl, flush;
}

void wait_for_secondary_vcpus() {
  //
  // Determine which VCPUs are already running
  // at boot or injection time, then wait for
  // them to synchronize on the PTLsim interrupt
  // redirector loop.
  //
  foreach (i, contextcount) {
    bool up = HYPERVISOR_vcpu_op(VCPUOP_is_up, i, null);
    if (up) bring_up_secondary_vcpu(i);
  }
}

//
// This is where all secondary VCPUs (i.e. other than vcpu0)
// start up after boot. We wait in a spin loop until vcpu0
// brings up all subsystems, then enter event slave mode.
//
asmlinkage void secondary_vcpu_startup(int vcpuid) {
  while (!bit(vcpu_startup_signal_bitmap, vcpuid)) { barrier(); }

  HYPERVISOR_fpu_taskswitch(0);

  int rc = HYPERVISOR_set_callbacks((Waddr)xen_event_callback_entry, 0, 0);
  if (rc < 0) ptlsim_init_fail(20);

  x86_locked_bts(vcpu_startup_complete_bitmap, W64(vcpuid));
  sti();

  for (;;) {
    xen_sched_block();
    barrier();
  }
}

//
// Resume all subsystems after returning from native mode
//
void resume_from_native() {
  capture_initial_timestamps();

	HYPERVISOR_vm_assist(VMASST_CMD_disable, VMASST_TYPE_writable_pagetables);
  HYPERVISOR_fpu_taskswitch(0);
  disable_breakout_insn();

  //
  // Enable upcalls
  //
  clear_evtchn(bootinfo.hostcall_port);
  clear_evtchn(bootinfo.upcall_port);
  barrier();

  //
  // Unmask everything: we want to see all interrupts so we can
  // pass them through to the guest.
  //
  setzero(shinfo.evtchn_mask);
  unmask_evtchn(bootinfo.hostcall_port);
  unmask_evtchn(bootinfo.upcall_port);
  sti();

  inject_ptlsim_into_toplevel(get_cr3_mfn());

  //
  // Flush the basic block cache, since code pages could
  // have been modified in native mode and we have no way
  // of knowing about this.
  //
  bbcache.flush();
  //
  // Initialize the non-trivial parts of the VCPU contexts.
  // This must go AFTER physical memory is accessible since
  // we're refilling descriptor caches and TLBs here.
  //
  foreach (i, contextcount) {
    Context& ctx = contextof(i);
    ctx.vcpuid = i;
    ctx.init();
  }

  //
  // We may have some new VCPUs that were brought online
  // during native mode:
  //

  wait_for_secondary_vcpus();
}

void print_meminfo_line(ostream& os, const char* name, W64 pages) {
  os << "  ", padstring(name, -20), intstring(pages, 10), " pages, ", intstring(pages_to_kb(pages), 10), " KB", endl;
}

void print_sysinfo(ostream& os) {
  xen_platform_parameters_t xen_params;
  HYPERVISOR_xen_version(XENVER_platform_parameters, &xen_params);
  Waddr xen_hypervisor_start_va = xen_params.virt_start;

  os << "System Information:", endl;
  os << "  Running on hypervisor version ", stats.simulator.run.hypervisor_version, endl;
  os << "  Xen is mapped at virtual address ", (void*)(Waddr)xen_hypervisor_start_va, endl;
  os << "  PTLsim is running across ", contextcount, " VCPUs:", endl;

  const vcpu_time_info_t& timeinfo = shinfo.vcpu_info[0].time;
  os << "  Physical CPU type: ", get_cpu_type_name(cpu_type), endl;
  os << "  VCPU 0 core frequency: ", (get_core_freq_hz(timeinfo) / 1000000), " MHz", endl;
  os << "  Physical CPU affinity for all VCPUs:";
  if (bootinfo.phys_cpu_affinity == bitmask(32)) {
    os << " all", endl;
  } else {
    foreach (i, 64) {
      if (bit(bootinfo.phys_cpu_affinity, i)) os << ' ', i;
    }
    os << endl;
  }

  os << "Memory Layout:", endl;
  print_meminfo_line(os, "System:",          bootinfo.total_machine_pages);
  print_meminfo_line(os, "Domain:",          bootinfo.max_pages);
  print_meminfo_line(os, "PTLsim reserved:", bootinfo.mfn_count);
  print_meminfo_line(os, "Page Tables:",     bootinfo.mfn_count - bootinfo.avail_mfn_count);
  print_meminfo_line(os, "PTLsim image:",    ((Waddr)bootinfo.heap_start - PTLSIM_VIRT_BASE) / 4096);
  print_meminfo_line(os, "Heap:",            ((Waddr)bootinfo.heap_end - (Waddr)bootinfo.heap_start) / 4096);
  print_meminfo_line(os, "Stacks:",          bootinfo.stack_size / 4096);
  os << "Interfaces:", endl;
  os << "  PTLsim page table:  ", intstring(bootinfo.toplevel_page_table_mfn, 10), endl;
  os << "  Shared info mfn:    ", intstring(bootinfo.shared_info_mfn, 10), endl;
  os << "  Shadow shinfo mfn:  ", intstring(ptl_virt_to_mfn(&sshinfo), 10), endl;
  os << "  PTLsim hostcall:    ", padstring("", 10), "  event channel ", intstring(bootinfo.hostcall_port, 4), endl;
  os << "  PTLsim upcall:      ", padstring("", 10), "  event channel ", intstring(bootinfo.upcall_port, 4), endl;
  os << endl;
}

//
// Handle an upcall request and reconfigure PTLsim
//
W64 handle_upcall(PTLsimConfig& config, bool blocking = true) {
  // This needs to be static because string parameters point into here:
  static char reqstr[4096];

  int rc;
  logfile << "PTLsim: waiting for request (", (blocking ? "blocking" : "non-blocking"), ")...", endl, flush;
  cerr << "Waiting for request...", endl, flush;

  W64 requuid = accept_upcall(reqstr, sizeof(reqstr), blocking);
  if (!requuid) return 0;

  logfile << "PTLsim: processing request '", reqstr, "' with uuid ", requuid, endl, flush;

  int lastarg = configparser.parse(config, reqstr);

  handle_config_change(config);

  return requuid;
}

W64 handle_upcall_nonblocking(PTLsimConfig& config) {
  return handle_upcall(config, false);
}

//
// Inject a specific upcall into PTLsim itself, for instance in response
// to assist-driven shutdown requests or after a return from native mode.
//
W64 handle_forced_upcall(PTLsimConfig& config, char* reqstr) {
  int lastarg = configparser.parse(config, reqstr);
  handle_config_change(config);
  return 0;
}

int assist_requested_break = 0;
stringbuf assist_requested_break_command;

//
// Check if an async user-supplied event should stop the
// current simulation run.
//
// It also takes regular stats snapshots if requested.
//
// NOTE: This function is on the critical path since it is
// called every cycle by the selected core. Keep it fast!
//
bool check_for_async_sim_break() {
  if unlikely (bootinfo.abort_request) {
    bootinfo.abort_request = 0;

    if unlikely (config.native | config.stop | config.kill) {
      logfile << "Requested exit from simulation loop", endl, flush;
    }
    return true;
  }

  if unlikely ((sim_cycle >= config.stop_at_cycle) |
               (iterations >= config.stop_at_iteration) |
               (total_user_insns_committed >= config.stop_at_user_insns)) {
    logfile << "Stopping simulation loop at specified limits (", iterations, " iterations, ", total_user_insns_committed, " commits)", endl;
    return true;
  }

  return false;
}

char ptlcall_buf[4096];

int ptlcall_while_in_native = 0;

W64 marker_sequence_number = 0;

// This is where we end up after issuing opcode 0x0f37 (undocumented x86 ptlcall opcode)
void assist_ptlcall(Context& ctx) {
  W64 op = ctx.commitarf[REG_rax];
  W64 arg1 = ctx.commitarf[REG_rcx];
  W64 arg2 = ctx.commitarf[REG_rdx];
  W64 arg3 = ctx.commitarf[REG_rsi];
  W64 arg4 = ctx.commitarf[REG_rdi];

  logfile << "VCPU ", ctx.vcpuid, " performed ptlcall ", ctx.commitarf[REG_rax], 
    " (", (void*)arg1, ", ", (void*)arg2, ", ", (void*)arg3, ", ", (void*)arg4, "):", endl, flush;

  W64s rc = 0;

  switch (op) {
  case PTLCALL_VERSION: {
    logfile << "PTLcall PTLCALL_VERSION: called from native mode? ", ptlcall_while_in_native, endl;
    // const char* c = (ptlcall_while_in_native) ? "-native" : "-run";
    // ptlcall_while_in_native = 0;
    // inject_upcall(c, strlen(c), 1);
    rc = PTLCALL_STATUS_PTLSIM_ACTIVE;
    break;
  }
  case PTLCALL_MARKER: {
    logfile << "PTLcall PTLCALL_MARKER on vcpu ", ctx.vcpuid, ":", endl;
    logfile << "  seqid:                    ", intstring(marker_sequence_number, 20), endl;
    logfile << "  rip:                        0x", hexstring(ctx.commitarf[REG_rip], 64), endl;
    logfile << "  marker:                   ", intstring(arg1, 20), endl;
    logfile << "  tsc:                      ", intstring(sim_cycle, 20), endl;
    logfile << "  pmc0:                     ", intstring(0, 20), endl;
    logfile << "  pmc1:                     ", intstring(0, 20), endl;
    logfile << "  retired_insn_count:       ", intstring(total_user_insns_committed, 20), endl;
    logfile << "  unhalted_cycle_count:     ", intstring(unhalted_cycle_count, 20), endl;
    logfile << "  unhalted_ref_cycle_count: ", intstring(unhalted_cycle_count, 20), endl;

    stringbuf markername;
    markername << "marker-seq-", marker_sequence_number, "-tag-", arg1;
    capture_stats_snapshot(markername);

    marker_sequence_number++;

    if unlikely (marker_sequence_number == config.stop_at_marker_hits) {
      logfile << "Stopping after marker was hit ", marker_sequence_number, " times", endl;
      cerr << "Stopping after marker was hit ", marker_sequence_number, " times", endl;
      bootinfo.abort_request = 1;
    }

    if unlikely (arg1 == config.stop_at_marker) {
      logfile << "Stopping after marker ", arg1, endl;
      cerr << "Stopping after marker ", arg1, endl;
      bootinfo.abort_request = 1;
    }

    ctx.commitarf[REG_rdx] = unhalted_cycle_count;
    ctx.commitarf[REG_rcx] = sim_cycle;
    ctx.commitarf[REG_rdi] = 0; // (pmc0)
    ctx.commitarf[REG_rsi] = 0; // (pmc1)
    rc = total_user_insns_committed;
    break;
  }
  case PTLCALL_ENQUEUE: {
    unsigned int count = arg2;

    char* buf = (char*)ptl_mm_alloc_private_page();
    assert(buf);

    foreach (i, count) {
      PTLsimCommandDescriptor desc;
      if (ctx.copy_from_user(&desc, arg1, sizeof(PTLsimCommandDescriptor)) != sizeof(PTLsimCommandDescriptor)) {
        logfile << "  Warning: cannot copy from user descriptor at ", (void*)arg1, endl, flush;
        rc = -EFAULT;
        break;
      }

      unsigned int length = min(desc.length, W64(4095));
      int n = ctx.copy_from_user(buf, (Waddr)desc.command, length);
      if (n != length) {
        logfile << "  Warning: cannot copy ", n, "-byte command from pointer ", (void*)desc.command, " (user descriptor #", i, ")", endl, flush;
        rc = -EFAULT;
        break;
      }

      assert(n < 4096);
      buf[n] = 0;

      W64 uuid = inject_upcall(buf, n, (i > 0) ? 0 : arg3);
      arg1 += sizeof(PTLsimCommandDescriptor);
    }

    ptl_mm_free_private_page(buf);

    rc = 0;
    break;
  }
  default: {
    rc = -ENOSYS;
    break;
  }
  }

  ptlcall_while_in_native = 0;
  ctx.commitarf[REG_rax] = rc;
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
}

void process_native_upcall() {
  //
  // Scan through the contexts and see if any have just executed
  // the ptlcall instruction. It's possible that more than one
  // VCPU just executed a ptlcall instruction, in case multiple
  // VCPUs raced through the upcall point. Process the pending
  // command on each of these VCPUs in order of vcpuids.
  //
  foreach (i, contextcount) {
    Context& ctx = contextof(i);

    W16 opcode;
    if (ctx.copy_from_user(&opcode, ctx.commitarf[REG_rip], sizeof(opcode)) != sizeof(opcode)) continue;

    logfile << "Copy from rip ", (void*)(ctx.commitarf[REG_rip]), " => 0x", bytemaskstring((byte*)&opcode, 0xffff, 2), endl, flush;

    if (opcode != 0x370f) continue;

    logfile << "VCPU ", i, " is stopped at rip ", (void*)ctx.commitarf[REG_rip], " on ptlctl opcode:", endl;

    ctx.commitarf[REG_selfrip] = ctx.commitarf[REG_rip];
    ctx.commitarf[REG_nextrip] = ctx.commitarf[REG_selfrip] + 2;
    ptlcall_while_in_native = 1;
    assist_ptlcall(ctx);
  }
}

//
// Toplevel PTLsim/X function: called by ptlsim_preinit_entry
// in lowlevel-64bit-xen.S.
//

int main(int argc, char** argv) {
  ptlsim_init();
  print_banner(cerr, stats);
  assert(sizeof(PTLsimMonitorInfo) <= PAGE_SIZE);

  bool time_init_done = 0;
  bool skip_dequeue_upcall = 0;

  for (;;) {
    W64 requuid = 0;
    if (!skip_dequeue_upcall) requuid = handle_upcall(config);
    skip_dequeue_upcall = 0;

    if (!time_init_done) {
      time_init_done = 1;
      time_and_virq_resume();
      perfctrs_init();
    }

    bool run = xchg(config.run, false);
    bool stop = xchg(config.stop, false);
    bool native = xchg(config.native, false);
    bool kill = xchg(config.kill, false);

    if unlikely (run && (contextcount > MAX_SIMULATED_VCPUS)) {
      run = 0;
      stringbuf sb;
      sb << endl;
      sb << "ERROR: this domain has ", contextcount, " VCPUs, but PTLsim was compiled with a limit of ", MAX_SIMULATED_VCPUS, " VCPUs", endl;
      sb << "You must increase MAX_SIMULATED_VCPUs and recompile to support this configuration.", endl, endl;
      cerr << sb;
      if (logfile) logfile << sb;
    }

    if unlikely (config.force_native && run) {
      logfile << "Warning: -force-native in effect, so ignoring request to do simulation run", endl, flush;
      run = 0;
      native = 1;
    }

    if (run) {
      update_pre_run_stats();
      update_time();
      bootinfo.abort_request = 0;
      simulate(config.core_name);
      capture_stats_snapshot("final");
      flush_stats();
      unmap_address_space();

      if (config.kill_after_run) kill = 1;
    }

    complete_upcall(requuid);

    if (native) {
      logfile << "Switching to native (pause? ", config.pause, ")...", endl, flush;
      logfile << "Final context:", endl;
      foreach (i, contextcount) {
        logfile << "VCPU ", i, ":", endl;
        logfile << contextof(i);
      }
      logfile << "Final shared info page:", endl, sshinfo, endl, flush;

      logfile << "Done!", endl;
      logfile << flush;

      bool pause = config.pause;
      config.pause = 0;

      unmap_address_space();

      //
      // Go native
      //
      switch_to_native(pause);

      //
      // We're back from native mode.
      //
      // Reinitialize anything that could have changed while we were out of the loop.
      //
      perfctrs_dump(logfile);
      resume_from_native();
      time_init_done = 0;

      logfile << "Returned from switch to native: now back in sim", endl, flush;
      cerr << "Returned from switch to native: now back in sim", endl, flush;
      foreach (i, contextcount) {
        logfile << "VCPU ", i, ":", endl;
        logfile << contextof(i), endl;
      }
      logfile << sshinfo, endl, flush;

      process_native_upcall();
    } else if (kill) {
      logfile << "Killing PTLsim...", endl, flush;
      shutdown(SHUTDOWN_poweroff);
    }
  }

  // We should never get here!
  assert(false);
  return 0;
}
