//
// PTLsim: Cycle Accurate x86-64 Simulator
// Xen interface inside the user domain
//
// Copyright 2005-2006 Matt T. Yourst <yourst@yourst.com>
//

/*

  Log levels:

  0: minimal (start and stop of simulation runs only)
  1: hypercalls / syscalls, etc.
  4: basic blocks and major events
  5: all instructions


*/

#include <globals.h>
#include <superstl.h>
#include <ptlxen.h>
#include <mm.h>
#include <ptlsim.h>

void early_printk(const char* p);

#ifdef __i386__
struct pt_regs {
	long ebx;
	long ecx;
	long edx;
	long esi;
	long edi;
	long ebp;
	long eax;
	int  xds;
	int  xes;
	long orig_eax;
	long eip;
	int  xcs;
	long eflags;
	long esp;
	int  xss;
};

ostream& operator <<(ostream& os, const pt_regs& regs) {
  os << "  eip ", hexstring(regs.eip, 32), "  flg ", hexstring(regs.eflags, 32), "  oax ", hexstring(regs.orig_eax, 32), endl;
  os << "  eax ", hexstring(regs.eax, 32), "  ecx ", hexstring(regs.ecx, 32), "  edx ", hexstring(regs.edx, 32), "  ebx ", hexstring(regs.ebx, 32), endl;
  os << "  esp ", hexstring(regs.esp, 32), "  ebp ", hexstring(regs.ebp, 32), "  esi ", hexstring(regs.esi, 32), "  edi ", hexstring(regs.edi, 32), endl;
  os << "  cs  ", hexstring(regs.xcs, 16), "  ds  ", hexstring(regs.xds, 16), "  ss  ", hexstring(regs.xss, 16), "  es  ", hexstring(regs.xds, 16), endl;
  return os;
}
#elif __x86_64__

struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
/* arguments: non interrupts/non tracing syscalls only save upto here*/
 	unsigned long r11;
	unsigned long r10;	
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_rax;
/* end of arguments */ 	
/* cpu exception frame or undefined */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags; 
	unsigned long rsp; 
	unsigned long ss;
/* top of stack page */ 
};

ostream& operator <<(ostream& os, const pt_regs& regs) {
  os << "  rip ", hexstring(regs.rip, 64), "  flg ", hexstring(regs.eflags, 64), "  oax ", hexstring(regs.orig_rax, 64), endl;
  os << "  rax ", hexstring(regs.rax, 64), "  rcx ", hexstring(regs.rcx, 64), "  rdx ", hexstring(regs.rdx, 64), "  rbx ", hexstring(regs.rbx, 64), endl;
  os << "  rsp ", hexstring(regs.rsp, 64), "  rbp ", hexstring(regs.rbp, 64), "  rsi ", hexstring(regs.rsi, 64), "  rdi ", hexstring(regs.rdi, 64), endl;
  os << "  r8  ", hexstring(regs.r8,  64), "  r9  ", hexstring(regs.r9,  64), "  r10 ", hexstring(regs.r10, 64), "  r11 ", hexstring(regs.r11, 64), endl;
  os << "  r12 ", hexstring(regs.r12, 64), "  r13 ", hexstring(regs.r13, 64), "  r14 ", hexstring(regs.r14, 64), "  r15 ", hexstring(regs.r15, 64), endl;
  os << "  cs  ", hexstring(regs.cs,  16), "  ss  ", hexstring(regs.ss,  16), endl;
  return os;
}
#endif

//
// Xen hypercalls
//

#define __STR(x) #x
#define STR(x) __STR(x)

#define _hypercall0(type, name)			\
({						\
	long __res;				\
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

  //
  // x86-64 hypercall conventions:
  //
  // Hypercall ID in %rax
  // Return address in %rcx (SYSCALL microcode puts it there)
  // Args in %rdi %rsi %rdx %r10 %r8 %r9 (identical to Linux syscall interface)
  // (see arch/x86/domain.c)
  //

/*
  Normal x86-64 userspace ABI:

  Callee must preserve: rbx rsp rbp r12 r13 r14 r15
  Args passed in:       rdi rsi rdx rcx r8 r9        (syscalls replace rcx with r10 since processor overwrites rcx)
  Available:            rax r10 r11
*/

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

W64 got_upcall = 0;

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
    //early_printk("unmask_evtchn: forcing evtchn callback\n");
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
	if (vcpu.evtchn_upcall_pending) force_evtchn_callback();
}

void clear_evtchn(int port) {
  shinfo_evtchn_pending[port].atomicclear();
}

inline W32 get_eflags() {
  W64 eflags;
  asm volatile("pushfq; popq %[eflags]" : [eflags] "=r" (eflags) : : "memory");
  return eflags;
}

inline W64 get_cr3() {
  W64 cr3;
  asm volatile("mov %%cr3,%[cr3]" : [cr3] "=r" (cr3));
  return cr3;
}

bool shadow_evtchn_set_pending(unsigned int port);
int shadow_evtchn_unmask(unsigned int port);

void handle_event(int port, struct pt_regs* regs) {
  //stringbuf sb; sb << "handle_event(port ", port, ")", endl; early_printk(sb);

  // Can't use anything that makes host calls in here!
  if (port == bootinfo.upcall_port) {
    // Upcall 
    //handle_ptlsim_upcall(bootinfo.upcall);
    //bootinfo.upcall.op = PTLSIM_UPCALL_NOP;
  } else if (port == bootinfo.hostcall_port) {
    // No action: will automatically unblock and return to hostcall caller
  } else {
    // some user port: copy to virtualized shared info page and notify simulation loop
    // shadow_evtchn_set_pending(port);
  }

	clear_evtchn(port);
}

extern "C" void xen_event_callback(struct pt_regs* regs) {
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
      port = (l1i << 5) + l2i; //++MTY on x86-64, shouldn't this be l1i << 6 (i.e. 64-bit per chunk)? apparently not...
      handle_event(port, regs);
    }
  }
}

W64s synchronous_host_call(const PTLsimHostCall& call) {
  stringbuf sb;
  int rc;

  void* p = &bootinfo.hostreq;
  memcpy(&bootinfo.hostreq, &call, sizeof(PTLsimHostCall));
  bootinfo.hostreq.ready = 0;

  unmask_evtchn(bootinfo.hostcall_port);

#if 0
  early_printk("Doing synchronous_host_call...\n");
  sb.reset(); sb << "  Req:      ", 
                "call ", bootinfo.hostreq.syscall.syscallid, ", args ",
                bootinfo.hostreq.syscall.arg1, " ",
                bootinfo.hostreq.syscall.arg2, " ",
                bootinfo.hostreq.syscall.arg3, " ",
                bootinfo.hostreq.syscall.arg4, " ",
                bootinfo.hostreq.syscall.arg5, " ",
                bootinfo.hostreq.syscall.arg6, endl; early_printk(sb);
#endif

  evtchn_send_t sendop;
  sendop.port = bootinfo.hostcall_port;
  rc = HYPERVISOR_event_channel_op(EVTCHNOP_send, &sendop);

  while (!bootinfo.hostreq.ready) {
    xen_sched_block();
  }

  assert(bootinfo.hostreq.ready);

  return bootinfo.hostreq.rc;
}

//
// Switch PTLsim to native mode by swapping in context <ctx>,
// and saving the current PTLsim within ptlmon.
//
// When this call returns (i.e. we switch back to simulation mode),
// <ctx> is filled with the new user context we interrupted, and
// the PTLsim register state is restored, allowing us to return
// exactly where we left off.
//
// NOTE: If there are multiple VCPUs in this VM, ctx is actually
// an *array* of contexts, one per VCPU.
//
int switch_to_native(Context* ctx, bool pause = false) {
  Context ptlctx[32];
  int rc;

  PTLsimHostCall call;
  call.op = PTLSIM_HOST_SWITCH_TO_NATIVE;
  call.ready = 0;
  call.switch_to_native.guestctx = ctx;
  call.switch_to_native.ptlctx = ptlctx;
  call.switch_to_native.pause = pause;

  rc = synchronous_host_call(call);
  return rc;
}

int shutdown(Context* ctx, bool pause = false) {
  Context ptlctx[32];
  int rc;

  PTLsimHostCall call;
  call.op = PTLSIM_HOST_TERMINATE;
  call.ready = 0;
  call.terminate.guestctx = ctx;
  call.terminate.ptlctx = ptlctx;
  call.terminate.pause = pause;

  rc = synchronous_host_call(call);
  // (never returns)
  return rc;
}

int query_pages(PageFrameType* pft, int count) {
  PTLsimHostCall call;
  call.op = PTLSIM_HOST_QUERY_PAGES;
  call.ready = 0;
  call.querypages.pft = pft;
  call.querypages.count = count;

  return synchronous_host_call(call);
}

//
// Get one request, blocking until one is ready
//
W64 accept_upcall(char* buf, size_t count, bool blocking = 1) {
  PTLsimHostCall call;

  call.op = PTLSIM_HOST_ACCEPT_UPCALL;
  call.ready = 0;
  call.accept_upcall.buf = buf;
  call.accept_upcall.count = count;
  call.accept_upcall.blocking = blocking;

  return synchronous_host_call(call);
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

#ifdef __x86_64__

declare_syscall3(__NR_lseek, W64, sys_seek, int, fd, W64, offset, unsigned int, origin);

#else

declare_syscall5(__NR__llseek, int, sys_llseek, unsigned int, fd, unsigned long, hi, unsigned long, lo, loff_t*, res, unsigned int, whence);

W64 sys_seek(int fd, W64 offset, unsigned int origin) {
  loff_t newoffs;
  int rc = sys_llseek(fd, HI32(offset), LO32(offset), &newoffs, origin);
  return (rc < 0) ? rc : newoffs;
}

#endif

declare_syscall3(__NR_open, int, sys_open, const char*, pathname, int, flags, int, mode);
declare_syscall1(__NR_close, int, sys_close, int, fd);
declare_syscall3(__NR_read, ssize_t, sys_read, int, fd, void*, buf, size_t, count);
declare_syscall3(__NR_write, ssize_t, sys_write, int, fd, const void*, buf, size_t, count);
declare_syscall1(__NR_unlink, int, sys_unlink, const char*, pathname);
declare_syscall2(__NR_rename, int, sys_rename, const char*, oldpath, const char*, newpath);

declare_syscall1(__NR_exit, void, sys_exit, int, code);
declare_syscall1(__NR_brk, void*, sys_brk, void*, p);
declare_syscall0(__NR_fork, pid_t, sys_fork);
declare_syscall3(__NR_execve, int, sys_execve, const char*, filename, const char**, argv, const char**, envp);

declare_syscall0(__NR_getpid, pid_t, sys_getpid);
declare_syscall0(__NR_gettid, pid_t, sys_gettid);
declare_syscall1(__NR_uname, int, sys_uname, struct utsname*, buf);
declare_syscall3(__NR_readlink, int, sys_readlink, const char*, path, char*, buf, size_t, bufsiz);

declare_syscall4(__NR_rt_sigaction, long, sys_rt_sigaction, int, sig, const struct sigaction*, act, struct sigaction*, oldact, size_t, sigsetsize);

declare_syscall4(__NR_wait4, pid_t, sys_wait4, pid_t, pid, int*, status, int, options, struct rusage*, rusage);

declare_syscall2(__NR_getrlimit, int, sys_getrlimit, int, resource, struct rlimit*, rlim);

declare_syscall2(__NR_nanosleep, int, do_nanosleep, const timespec*, req, timespec*, rem);

declare_syscall2(__NR_gettimeofday, int, sys_gettimeofday, struct timeval*, tv, struct timezone*, tz);
declare_syscall1(__NR_time, time_t, sys_time, time_t*, t);

W64 sys_nanosleep(W64 nsec) {
  timespec req;
  timespec rem;

  req.tv_sec = (W64)nsec / 1000000000ULL;
  req.tv_nsec = (W64)nsec % 1000000000ULL;

  do_nanosleep(&req, &rem);

  return ((W64)rem.tv_sec * 1000000000ULL) + (W64)rem.tv_nsec;
}

void* sys_mmap(void* start, size_t length, int prot, int flags, int fd, W64 offset) {
  // Not supported on the bare hardware
  return (void*)(Waddr)0xffffffffffffffffULL;
}

ostream logfile;
W64 loglevel = 0;
W64 sim_cycle = 0;
W64 user_insn_commits = 0;
W64 iterations = 0;
W64 total_uops_executed = 0;
W64 total_uops_committed = 0;
W64 total_user_insns_committed = 0;
W64 total_basic_blocks_committed = 0;
//char* dumpcode_filename = null;

// This is where we end up after issuing opcode 0x0f37 (undocumented x86 PTL call opcode)
void assist_ptlcall(Context& ctx) {
  //ctx.commitarf[REG_rax] = handle_ptlcall(ctx.commitarf[REG_sr1], ctx.commitarf[REG_rdi], ctx.commitarf[REG_rsi], ctx.commitarf[REG_rdx], ctx.commitarf[REG_rcx], ctx.commitarf[REG_r8], ctx.commitarf[REG_r9]);
}

void initiate_prefetch(W64 addr, int cachelevel) {
  // (dummy for now)
}

extern "C" void assert_fail(const char *__assertion, const char *__file, unsigned int __line, const char *__function) {
  stringbuf sb;
  sb << "ptlxen: Assert ", __assertion, " failed in ", __file, ":", __line, " (", __function, ")", endl;

  cerr << sb, flush;
  asm("int3");
  abort();
}

void early_printk(const char* p) {
  if (!bootinfo.startup_log_buffer_size) return;
  int count = min((int)strlen(p), bootinfo.startup_log_buffer_size);

  foreach (i, count) {
    bootinfo.startup_log_buffer[bootinfo.startup_log_buffer_tail] = p[i];
    bootinfo.startup_log_buffer_tail = (bootinfo.startup_log_buffer_tail + 1) & (bootinfo.startup_log_buffer_size - 1);
  }
}

extern "C" void xen_event_callback_entry();

// Just big enough to have more than one word; rely on having no bounds checks:
typedef bitvec<65> infinite_bitvec_t;

infinite_bitvec_t* ptlsim_mfn_bitmap = null;

// Update a PTE entry within PTLsim:
template <typename T>
int update_ptl_pte(T& dest, const T& src) {
	mmu_update_t u;
	u.ptr = (W64)ptl_virt_to_phys(&dest);
	u.val = (W64)src;
  return HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF);
}

void smc_setdirty_internal(Level1PTE& pte, bool dirty) {
  Level1PTE newpte = pte;
  newpte.d = dirty;
  update_ptl_pte(pte, newpte);
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
  static const bool DEBUG = 0;

  VirtAddr virt(rawvirt);

  bool acc_bit_up_to_date = 0;

  if (DEBUG) logfile << "page_table_walk: rawvirt ", (void*)rawvirt, ", toplevel ", (void*)toplevel_mfn, endl, flush;

  if (unlikely((rawvirt >= HYPERVISOR_VIRT_START) & (rawvirt < xen_m2p_map_end))) {
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

    if (DEBUG) logfile << "page_table_walk: special case (inside M2P map): pseudo_phys ", (void*)pseudo_phys, endl, flush;

    Level1PTE pte = 0;
    pte.phys = pseudo_phys >> 12;
    pte.p = 1;
    pte.rw = 0;
    pte.us = 1;
    pte.a = 1; // don't try to update accessed bits again
    pte.d = 0;

    return pte;
  }

  Level4PTE& level4 = ((Level4PTE*)(PHYS_VIRT_BASE + (toplevel_mfn << 12)))[virt.lm.level4];
  if (DEBUG) logfile << "  level4 @ ", &level4, " (mfn ", ((((Waddr)&level4) & 0xffffffff) >> 12), ", entry ", virt.lm.level4, ")", endl, flush;
  Level1PTE final = (W64)level4;

  if (unlikely(!level4.p)) return final;
  acc_bit_up_to_date = level4.a;

  Level3PTE& level3 = ((Level3PTE*)(PHYS_VIRT_BASE + (level4.next << 12)))[virt.lm.level3];
  if (DEBUG) logfile << "  level3 @ ", &level3, " (mfn ", ((((Waddr)&level3) & 0xffffffff) >> 12), ", entry ", virt.lm.level3, ")", endl, flush;
  final.accum(level3);
  if (unlikely(!level3.p)) return final;
  acc_bit_up_to_date &= level3.a;

  Level2PTE& level2 = ((Level2PTE*)(PHYS_VIRT_BASE + (level3.next << 12)))[virt.lm.level2];
  if (DEBUG) logfile << "  level2 @ ", &level2, " (mfn ", ((((Waddr)&level2) & 0xffffffff) >> 12), ", entry ", virt.lm.level2, ")", endl, flush;
  final.accum(level2);
  if (unlikely(!level2.p)) return final;
  acc_bit_up_to_date &= level2.a;

  if (unlikely(level2.psz)) {
    final.phys = level2.next;
    final.pwt = level2.pwt;
    final.pcd = level2.pcd;
    acc_bit_up_to_date &= level2.a;

    final.a = acc_bit_up_to_date;
    final.d = level2.d;

    return final;
  }

  Level1PTE& level1 = ((Level1PTE*)(PHYS_VIRT_BASE + (level2.next << 12)))[virt.lm.level1];
  if (DEBUG) logfile << "  level1 @ ", &level1, " (mfn ", ((((Waddr)&level1) & 0xffffffff) >> 12), ", entry ", virt.lm.level1, ")", endl, flush;
  final.accum(level1);
  if (unlikely(!level1.p)) return final;
  acc_bit_up_to_date &= level1.a;

  final.phys = level1.phys;
  final.g = level1.g;
  final.pat = level1.pat;
  final.pwt = level1.pwt;
  final.pcd = level1.pcd;
  final.a = acc_bit_up_to_date;
  final.d = level1.d;

  if (final.phys == bootinfo.shared_info_mfn) {
    final.phys = (Waddr)ptl_virt_to_phys(bootinfo.shadow_shinfo) >> 12;
    if (DEBUG) logfile << "  Remap shinfo access from real mfn ", bootinfo.shared_info_mfn,
                 " to PTLsim virtual shinfo page mfn ", final.phys, " (virt ", bootinfo.shadow_shinfo, ")", endl, flush;
  }

  if (DEBUG) logfile << "  Final PTE for virt ", (void*)(Waddr)rawvirt, ": ", final, endl, flush;

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

  Level4PTE& level4 = ((Level4PTE*)(PHYS_VIRT_BASE + (toplevel_mfn << 12)))[virt.lm.level4];
  if (DEBUG) logfile << "  level4 @ ", &level4, " (mfn ", ((((Waddr)&level4) & 0xffffffff) >> 12), ", entry ", virt.lm.level4, ")", endl, flush;
  if (unlikely(!level4.p)) return 0;

  Level3PTE& level3 = ((Level3PTE*)(PHYS_VIRT_BASE + (level4.next << 12)))[virt.lm.level3];
  if (DEBUG) logfile << "  level3 @ ", &level3, " (mfn ", ((((Waddr)&level3) & 0xffffffff) >> 12), ", entry ", virt.lm.level3, ")", endl, flush;
  if (unlikely(!level3.p)) return 0;

  Level2PTE& level2 = ((Level2PTE*)(PHYS_VIRT_BASE + (level3.next << 12)))[virt.lm.level2];
  if (DEBUG) logfile << "  level2 @ ", &level2, " (mfn ", ((((Waddr)&level2) & 0xffffffff) >> 12), ", entry ", virt.lm.level2, ") [pte ", level2, "]", endl, flush;
  if (unlikely(!level2.p)) return 0;

  if (unlikely(level2.psz)) return ((Waddr)&level2) - PHYS_VIRT_BASE;

  Level1PTE& level1 = ((Level1PTE*)(PHYS_VIRT_BASE + (level2.next << 12)))[virt.lm.level1];
  if (DEBUG) logfile << "  level1 @ ", &level1, " (mfn ", ((((Waddr)&level1) & 0xffffffff) >> 12), ", entry ", virt.lm.level1, ")", endl, flush;

  return ((Waddr)&level1) - PHYS_VIRT_BASE;
}

void page_table_acc_dirty_update(W64 rawvirt, W64 toplevel_mfn, const PTEUpdate& update) {
  VirtAddr virt(rawvirt);

  if (unlikely((rawvirt >= HYPERVISOR_VIRT_START) & (rawvirt < xen_m2p_map_end))) return;

  Level4PTE& level4 = ((Level4PTE*)(PHYS_VIRT_BASE + (toplevel_mfn << 12)))[virt.lm.level4];
  Level1PTE final = (W64)level4;
  if (!level4.p) return;
  if (!level4.a) level4.a = 1;

  Level3PTE& level3 = ((Level3PTE*)(PHYS_VIRT_BASE + (level4.next << 12)))[virt.lm.level3];
  if (!level3.p) return;
  if (!level3.a) level3.a = 1;

  Level2PTE& level2 = ((Level2PTE*)(PHYS_VIRT_BASE + (level3.next << 12)))[virt.lm.level2];
  if (!level2.p) return;
  if (!level2.a) level2.a = 1;

  if (level2.psz) {
    if (update.d) level2.d = 1;
    return;
  }

  Level1PTE& level1 = ((Level1PTE*)(PHYS_VIRT_BASE + (level2.next << 12)))[virt.lm.level1];
  if (!level1.p) return;
  if (!level1.a) level1.a = 1;
  if (update.d) level1.d = 1;
}

byte force_internal_page_fault(Waddr phys) {
  byte z;
  void* mapped = phys_to_mapped_virt(phys);
  asm volatile("movb (%[m]),%[z];" : [z] "=q" (z) : [m] "r" (mapped) : "memory");
  return z;
}

bool is_mfn_ptpage(Waddr mfn) {
  if unlikely (mfn >= bootinfo.total_machine_pages) return false;
  Level1PTE& pte = bootinfo.phys_pagedir[mfn];

  if (!pte.p) {
    //
    // The page has never been accessed before.
    // Pretend we're reading from it so PTLsim's page fault handler
    // will fault it in for us.
    //
    /*
    void* phys_of_page = phys_to_mapped_virt(mfn << 12);
    logfile << "Following ptes down to ", phys_of_page, ":", endl, flush;
    void* pte_phys_addr = (void*)(Waddr)virt_to_pte_phys_addr((W64)phys_of_page, get_cr3() >> 12);
    logfile << "Attempt to fault in mfn ", mfn, " [pte was at phys ", flush,
      pte_phys_addr,
      " vs phys_pagedir[mfn] at ", flush, ptl_virt_to_phys(&pte), "]...", endl, flush;
    */

    force_internal_page_fault(mfn << 12);
    if (!pte.p) {
      logfile << "PTE for mfn ", mfn, " is still not present!", endl, flush;
      assert(false);
    }
  }

  return (!pte.rw);
}

W64 storemask(Waddr physaddr, W64 data, byte bytemask) {
  W64& mem = *(W64*)phys_to_mapped_virt(physaddr);
  W64 result = mux64(expand_8bit_to_64bit_lut[bytemask], mem, data);

  if (is_mfn_ptpage(physaddr >> 12)) {
    mmu_update_t u;
    u.ptr = physaddr;
    u.val = data;
    HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF);    
  } else {
    mem = result;
  }

  return data;
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
    // Directly mapped to PTL space:
    return (void*)virtaddr;
  }

  Level1PTE pte;

  pte = virt_to_pte(virtaddr);
  
  bool page_not_present = (!pte.p);
  bool page_read_only = (store & (!pte.rw));
  bool page_kernel_only = ((!kernel_mode) & (!pte.us));

  if unlikely (page_not_present | page_read_only | page_kernel_only) {
    if (logable(4)) logfile << "virt ", (void*)virtaddr, ", mfn ", pte.phys, ": store ", store, ", page_not_present ",
      page_not_present, ", page_kernel_only ", page_kernel_only, ", page_read_only ", page_read_only, endl;

    if unlikely (store && (!page_not_present) && (!page_kernel_only) &&
                 page_read_only && is_mfn_ptpage(pte.phys)) {
      if (logable(4)) logfile << "Page is a page table page: special semantics", endl;
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
  mfnlo = (invalid) ? INVALID : pte.phys;
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
    mfnhi = (invalid) ? INVALID : pte.phys;
  }

  return *this;
}

void prep_address_space() {
  int bytes_required = ceil(bootinfo.total_machine_pages, 8) / 8;

  xen_m2p_map_end = HYPERVISOR_VIRT_START + (bootinfo.total_machine_pages * sizeof(Waddr));

  ptlsim_mfn_bitmap = (infinite_bitvec_t*)ptl_alloc_private_pages(bytes_required);
  memset(ptlsim_mfn_bitmap, 0, bytes_required);

  foreach (i, bootinfo.mfn_count) {
    mfn_t mfn = bootinfo.ptl_pagedir[i].phys;
    assert(mfn < bootinfo.total_machine_pages);
    (*ptlsim_mfn_bitmap)[mfn] = 1;
  }
}

static SegmentDescriptor invalid_gdt_entry;

static SegmentDescriptor null_gdt_entry;

static SegmentDescriptor flat_gdt_entry;

  // idx must be between 0 and 8191 (i.e. 65535 >> 3)
bool Context::gdt_entry_valid(W16 idx) {
  if ((idx >= FIRST_RESERVED_GDT_ENTRY) && (idx < (FIRST_RESERVED_GDT_ENTRY + (PAGE_SIZE / sizeof(SegmentDescriptor)))))
    return true;

  return (idx < gdtsize);
}

const SegmentDescriptor& Context::get_gdt_entry(W16 idx) {
  // idx >>= 3; // remove GDT/LDT select bit and 2-bit DPL

  if (!idx)
    return null_gdt_entry;

  if ((idx >> 9) == FIRST_RESERVED_GDT_PAGE)
    return *(const SegmentDescriptor*)((byte*)bootinfo.gdt_page + (lowbits(idx, 9) * 8));

  if (idx >= gdtsize)
    return invalid_gdt_entry;

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
  commitarf[REG_ctx] = (Waddr)this;
  commitarf[REG_fpstack] = (Waddr)&this->fpstack;

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

int pin_page_table_page(void* virt, int level) {
  assert(inrange(level, 0, 4));

  // Was it in PTLsim space?
  mfn_t mfn = ptl_virt_to_mfn(virt);

  if (mfn == INVALID_MFN) return -1;
  
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
  if (pfn == INVALID_MFN) return -1;

  Level1PTE& pte = bootinfo.ptl_pagedir[pfn];
  Level1PTE temppte = pte;
  temppte.rw = writable;
  return update_ptl_pte(pte, temppte);
}

void unmap_phys_page(mfn_t mfn) {
  Level1PTE& pte = bootinfo.phys_pagedir[mfn];
  Level1PTE temppte = pte;
  temppte.p = 0;
  update_ptl_pte(pte, temppte);
}

//
// Trap and Exception Handling
//
extern "C" {
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

void print_stack(ostream& os, Waddr sp) {
  W64* p = (W64*)sp;

  os << "Stack trace back from ", sp, ":", endl, flush;
  foreach (i, 256) {
    if ((i % 8) == 0) os << "  ", &p[i], ":";
    os << " ", hexstring(p[i], 64);
    if ((i % 8) == 7) os << endl;
  }
  os << flush;
}

static void do_trap(int trapnr, const char* str, struct pt_regs* regs, unsigned long error_code) {
  cerr << endl;
  cerr << "PTLsim Internal Error: unhandled trap ", trapnr, " (", str, "): error code ", hexstring(error_code, 32), endl;
  cerr << "Registers:", endl;
  cerr << *regs;
  print_stack(cerr, regs->rsp);
  if (logfile) logfile.flush();
  cerr.flush();
  cout.flush();

  xen_shutdown_domain(SHUTDOWN_crash);
}

#define DO_ERROR(trapnr, str, name) \
extern "C" void do_##name(struct pt_regs * regs, unsigned long error_code) { do_trap(trapnr, str, regs, error_code); }

//
// These exceptions are not handled by PTLsim. If they occur
// during simulation mode, there is something seriously wrong.
//
DO_ERROR(0, "divide error", divide_error);
DO_ERROR(3, "int3", int3);
DO_ERROR(4, "overflow", overflow);
DO_ERROR(5, "bounds", bounds);
DO_ERROR(6, "invalid operand", invalid_op);
DO_ERROR(7, "device not available", device_not_available);
DO_ERROR(9, "coprocessor segment overrun", coprocessor_segment_overrun);
DO_ERROR(10, "invalid TSS", invalid_tss);
DO_ERROR(11, "segment not present", segment_not_present);
DO_ERROR(12, "stack segment", stack_segment);
DO_ERROR(13, "general protection", general_protection);
DO_ERROR(16, "fpu", coprocessor_error);
DO_ERROR(17, "alignment check", alignment_check);
DO_ERROR(18, "machine check", machine_check);
DO_ERROR(19, "sse", simd_coprocessor_error);

static inline Waddr read_cr2() { return shinfo.vcpu_info[0].arch.cr2; }

//
// ++MTY IMPORTANT: when we emulate a page fault, we can't just set the virtual CR2.
// Instead, we also set it in sshinfo.arch.cr2 = <value> - THIS is where the OS
// reads it from (shadow shared info page), since mov to-from-cr2 is privileged.
//
// sshinfo.vcpu_info[ctx.vcpuid].arch.cr2 = virtaddr;
//

static int page_fault_in_progress = 0;

extern "C" void do_page_fault(struct pt_regs* regs, unsigned long error_code) {
  int rc;
  Waddr faultaddr = read_cr2();
  //
  // If we are already handling a page fault, and got another one
  // that means we faulted in pagetable walk. Continuing here would cause
  // a recursive fault.
  //
  if (page_fault_in_progress) {
    cerr << "PTLsim Internal Error: recursive page fault @ rip ", (void*)regs->rip, " while accessing ", (void*)faultaddr, " (error code ", (void*)(Waddr)error_code, ")", endl, flush;
    cerr << "Registers:", endl;
    cerr << *regs, endl;
    print_stack(cerr, regs->rsp);
    xen_shutdown_domain(SHUTDOWN_crash);
  }

  page_fault_in_progress = 1;

  if (inrange(faultaddr, (Waddr)PHYS_VIRT_BASE, (Waddr)(((PHYS_VIRT_BASE + bootinfo.total_machine_pages) * PAGE_SIZE) - 1))) {
    mfn_t mfn = (faultaddr - (Waddr)PHYS_VIRT_BASE) >> 12;
    // cerr << "Mapping previously unmapped physical mfn ", mfn, "...", endl, flush;

    int level2_slot_index = mfn / PTES_PER_PAGE;
    // cerr << "Level 2 slot index: ", level2_slot_index, endl, flush;

    Level2PTE& l2pte = bootinfo.phys_level2_pagedir[level2_slot_index];

    Level1PTE& l1pte = bootinfo.phys_pagedir[mfn];

    if (!l2pte.p) {
      Level1PTE* l1page = floorptr(&l1pte, PAGE_SIZE);

      // logfile << "Unpin L1 page table page at ", l1page, " (mfn ", ptl_virt_to_mfn(l1page), ")", "...", endl, flush;
      // logfile << "Current value at start of page: ", l1page[0], endl, flush;

      pin_page_table_page(l1page, 0); // (may not even be pinned yet)
      assert(make_ptl_page_writable(l1page, 1) == 0);
      ptl_zero_private_page(l1page);
      assert(make_ptl_page_writable(l1page, 0) == 0);
      assert(pin_page_table_page(l1page, 1) == 0);

      // logfile << "Marking L2 PTE ", level2_slot_index, " (for L1 mfn ", l2pte.next, ")", " present...", endl, flush;
      Level2PTE l2temp = l2pte;
      l2temp.p = 1;
      assert(update_ptl_pte(l2pte, l2temp) == 0);

      if (logable(1)) logfile << "[PTLsim Page Fault Handler] ", (void*)faultaddr, ": added L2 PTE ", level2_slot_index, " (L1 mfn ", l2pte.next, ") to PTLsim physmap", endl;
    }

    Level1PTE pte = 0;
    pte.p = 1;
    pte.rw = 1; // assume it's read/write first
    pte.us = 1;
    pte.phys = mfn;

    rc = update_ptl_pte(l1pte, pte);

    if (rc) {
      // It's a special page and must be marked read-only:
      pte.rw = 0;
      rc = update_ptl_pte(l1pte, pte);

      if (rc) {
        cerr << "ERROR: Cannot map mfn ", mfn, " (for virt ", (void*)faultaddr, ") into the address space! Does it belong to the domain?", endl, flush;
        abort();
      }

      if (logable(1)) logfile << "[PTLsim Page Fault Handler] ", (void*)faultaddr, ": added read-only L1 PTE at ", &l1pte, " for guest mfn ", mfn, endl;
    } else {
      if (logable(1)) logfile << "[PTLsim Page Fault Handler] ", (void*)faultaddr, ": added L1 PTE at ", &l1pte, " for guest mfn ", mfn, endl;
    }
  } else {
    cerr << "PTLsim Internal Error: page fault @ rip ", (void*)regs->rip, " while accessing ", (void*)faultaddr, " (error code ", (void*)(Waddr)error_code, ")", endl;
    cerr << "Registers:", endl;
    cerr << *regs, endl;
    print_stack(cerr, regs->rsp);
    abort();
  }

  // Return
  page_fault_in_progress = 0;
}

extern "C" void do_debug(struct pt_regs* regs) {
#define TF_MASK 0x100
  regs->eflags &= ~TF_MASK;
  do_trap(EXCEPTION_x86_debug, "debug", regs, 0);
}

extern "C" void do_spurious_interrupt_bug(struct pt_regs* regs) { }

/*
 * Submit a virtual IDT to the hypervisor. This consists of tuples
 * (interrupt vector, privilege ring, CS:EIP of handler).
 * The 'privilege ring' field specifies the least-privileged ring that
 * can trap to that vector using a software-interrupt instruction (INT).
 */
static trap_info_t trap_table[] = {
  {  0, 0, FLAT_KERNEL_CS, (Waddr)&divide_error                },
  {  1, 0, FLAT_KERNEL_CS, (Waddr)&debug                       },
  {  3, 3, FLAT_KERNEL_CS, (Waddr)&int3                        },
  {  4, 3, FLAT_KERNEL_CS, (Waddr)&overflow                    },
  {  5, 3, FLAT_KERNEL_CS, (Waddr)&bounds                      },
  {  6, 0, FLAT_KERNEL_CS, (Waddr)&invalid_op                  },
  {  7, 0, FLAT_KERNEL_CS, (Waddr)&device_not_available        },
  {  9, 0, FLAT_KERNEL_CS, (Waddr)&coprocessor_segment_overrun },
  { 10, 0, FLAT_KERNEL_CS, (Waddr)&invalid_tss                 },
  { 11, 0, FLAT_KERNEL_CS, (Waddr)&segment_not_present         },
  { 12, 0, FLAT_KERNEL_CS, (Waddr)&stack_segment               },
  { 13, 0, FLAT_KERNEL_CS, (Waddr)&general_protection          },
  { 14, 0, FLAT_KERNEL_CS, (Waddr)&page_fault                  },
  { 15, 0, FLAT_KERNEL_CS, (Waddr)&spurious_interrupt_bug      },
  { 16, 0, FLAT_KERNEL_CS, (Waddr)&coprocessor_error           },
  { 17, 0, FLAT_KERNEL_CS, (Waddr)&alignment_check             },
  { 19, 0, FLAT_KERNEL_CS, (Waddr)&simd_coprocessor_error      },
  {  0, 0, 0,              0                                   }
};

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
	mmu_update_t* updates = (mmu_update_t*)ptl_alloc_private_pages(physmap_level1_pages * sizeof(mmu_update_t));
  mmuext_op_t* unpins = (mmuext_op_t*)ptl_alloc_private_pages(physmap_level1_pages * sizeof(mmuext_op_t));

  int n = 0;

  logfile << "unmap_address_space: check ", physmap_level1_pages, " PTEs:", endl, flush;

  foreach (i, physmap_level1_pages) {
    Level2PTE& l2pte = bootinfo.phys_level2_pagedir[i];
    if (l2pte.p) {
      assert(n < physmap_level1_pages);
      updates[n].ptr = (W64)ptl_virt_to_phys(&l2pte);
      Level2PTE newpte = l2pte;
      newpte.p = 0;
      updates[n].val = newpte;

      unpins[n].cmd = MMUEXT_UNPIN_TABLE;
      unpins[n].arg1.mfn = newpte.next;
      logfile << "  update ", intstring(n, 6), ": pte ", intstring(i, 6), " <= ", (Level2PTE)newpte, endl;
      n++;
    }
  }

  logfile << flush;

  int update_count;
  int rc;

  update_count = 0;
  rc = HYPERVISOR_mmu_update(updates, n, &update_count, DOMID_SELF);

  logfile << "  mmu_update: updated ", update_count, " out of ", n, " L2 PTEs (rc ", rc, ")", endl, flush;

  update_count = 0;
  rc = HYPERVISOR_mmuext_op(unpins, n, &update_count, DOMID_SELF);
  logfile << "  mmuext_unpin: updated ", update_count, " out of ", n, " L2 PTEs (rc ", rc, ")", endl, flush;

	ptl_free_private_pages(updates, physmap_level1_pages * sizeof(mmu_update_t));
  ptl_free_private_pages(unpins, physmap_level1_pages * sizeof(mmuext_op_t));
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
    // vcpu_mark_events_pending(v);

    if (!xchg(sshinfo.vcpu_info[vcpu_to_notify].evtchn_upcall_pending, (byte)1)) {
      logfile << "shadow_evtchn_unmask(", port, "): event delivery: making vcpu ", vcpu_to_notify, " runnable", endl;
      // vcpu_kick(v);
      return 1;
    }
  }

  return 0;
}

bool shadow_evtchn_set_pending(unsigned int port) {
  int vcpu_to_notify = port_to_vcpu[port];

  logfile << "Set pending for port ", port, " mapped to vcpu ", vcpu_to_notify, ":", endl;

  if unlikely (vcpu_to_notify < 0) {
    logfile << "  Not bound to any VCPU", endl;
    return false;
  }

  if unlikely (sshinfo_evtchn_pending[port].testset()) {
    logfile << "  Already pending", endl;
    return false;
  }

  bool masked = sshinfo_evtchn_mask[port];

  if unlikely (masked) {
    logfile << "  Event masked", endl;
    return false;
  }

  if unlikely (sshinfo_evtchn_pending_sel(vcpu_to_notify)[port / (sizeof(unsigned long) * 8)].testset()) {
    logfile << "  Event already pending in evtchn_pending_sel", endl;
    return false;
  }

  logfile << "  Mark vcpu ", vcpu_to_notify, " events pending", endl;

  // ++MTY Do we have to check if any VCPU is polling too?

  if likely (!xchg(sshinfo.vcpu_info[vcpu_to_notify].evtchn_upcall_pending, (byte)1)) {
    logfile << "  Kick vcpu", endl;
    return true;
  } else {
    logfile << "  VCPU already kicked", endl;
    return false;
  }
}

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

  logfile << "hypercall: ", hypercallid, " (", ((hypercallid < lengthof(hypercall_names)) ? hypercall_names[hypercallid] : "???"), 
    ") on vcpu ", ctx.vcpuid, " from ", (void*)ctx.commitarf[REG_rip], " args (", (void*)arg1, ", ", (void*)arg2, ", ", (void*)arg3, ", ", (void*)arg4, ", ",
    (void*)arg5, ", ", (void*)arg6, ") at cycle ", iterations, " (", total_user_insns_committed, " commits)", endl, flush;

  W64 rc;

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
      if (mfn >= bootinfo.total_machine_pages) continue;

      logfile << "hypercall: mmu_update: mfn ", mfn, " + ", (void*)(Waddr)lowbits(req.ptr, 12), " (entry ", (lowbits(req.ptr, 12) >> 3), ") <= ", (Level1PTE)req.val, endl, flush;

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
    //
    //++MTY TODO: All commits to FPU or SSE state MUST check the TS flag in CR0.
    // If TS is set, the processor must take a device_not_available exception!
    //
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
    //
    // This is just a simplified version of mmu_update, using the current page table base.
    // We need to emulate it since PTLsim has its own page tables in effect.
    //
    Waddr va = arg1;
    Waddr ptephys = virt_to_pte_phys_addr(va, ctx.cr3 >> 12);
    if (!ptephys) {
      logfile << "hypercall: update_va_mapping: va ", (void*)va, " using toplevel mfn ", (ctx.cr3 >> 12), ": cannot resolve PTE address", endl, flush;
      rc = -EINVAL;
      break;
    }

    mmu_update_t u;
    u.ptr = ptephys;
    u.val = arg2;
    rc = HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF);

    Waddr flags = arg3;

    logfile << "hypercall: update_va_mapping: va ", (void*)va, " using toplevel mfn ", (ctx.cr3 >> 12),
      " -> pte @ phys ", (void*)ptephys, ") <= ", Level1PTE(arg2), ", flags ", (void*)(Waddr)flags,
      " (flushtype ", (flags & UVMF_FLUSHTYPE_MASK), ") => rc ", rc, endl, flush;

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

      logfile << "hypercall: set_timer_op: timeout ", trigger_nsecs_since_boot, " nsec since boot = ", 
        ctx.timer_cycle, " cycles since boot (", trigger_cycles_in_future, " cycles in future = ",
        (trigger_nsecs_since_boot - sshinfo.vcpu_info[0].time.system_time), " nsec in future)", endl;
    } else {
      ctx.timer_cycle = infinity;
      logfile << "hypercall: set_timer_op: cancel timer", endl;
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
      case GNTTABOP_map_grant_ref: {
        getreq(gnttab_map_grant_ref);
        logfile << "GNTTABOP_map_grant_ref(host_addr ", (void*)(Waddr)req.host_addr, ", flags ", req.flags,
          ", ref ", req.ref, ", dom ", req.dom, ")", endl;
        logfile << "map_grant_ref is not supported yet!", endl;
        abort();
      }
      case GNTTABOP_unmap_grant_ref: {
        getreq(gnttab_map_grant_ref);
        logfile << "GNTTABOP_unmap_grant_ref(host_addr ", (void*)(Waddr)req.host_addr,
          ", dev_bus_addr ", (void*)(Waddr)req.dev_bus_addr, ", handle ", (void*)(Waddr)req.handle, ")", endl, flush;
        logfile << "unmap_grant_ref is not supported yet!", endl;
        abort();
      }
      case GNTTABOP_setup_table: {
        getreq(gnttab_setup_table);
        unsigned long* orig_frame_list = req.frame_list.p;
        unsigned long frames[4]; // on x86 and x86-64, NR_GRANT_FRAMES is always 1<<2 == 4
        int framecount = min(req.nr_frames, (W32)lengthof(frames));
        req.frame_list.p = frames;
        logfile << "GNTTABOP_setup_table(dom ", req.dom, ", nr_frames ", req.nr_frames, ", frame_list ", orig_frame_list, ")", endl, flush;
        rc = HYPERVISOR_grant_table_op(GNTTABOP_setup_table, &req, 1);
        req.frame_list.p = orig_frame_list;
        logfile << "  Frames:"; foreach (i, framecount) { logfile << " ", frames[i]; }; logfile << ", status ", req.status, endl, flush;
        assert(ctx.copy_to_user((Waddr)orig_frame_list, &frames, framecount * sizeof(unsigned long), pfec, faultaddr) == (framecount * sizeof(unsigned long)));
        putreq(gnttab_setup_table);
        arg2 += sizeof(req);
        break;
      }
      case GNTTABOP_transfer: {
        getreq(gnttab_transfer);
        ctx.flush_tlb();
        logfile << "GNTTABOP_transfer(mfn ", req.mfn, ", domid ", req.domid, ", ref ", req.ref, ")", endl, flush;
        unmap_phys_page(req.mfn);
        rc = HYPERVISOR_grant_table_op(GNTTABOP_transfer, &req, 1);
        putreq(gnttab_transfer);
        arg2 += sizeof(req);
        break;
      }
      default: {
        logfile << "hypercall: grant_table_op: unknown op ", arg1, endl, flush;
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
      logfile << "hypercall: vcpu_op: register_runstate_memory_area: registered virt ", req.addr.v, " for runstate info on vcpu ", arg2, endl, flush;
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
      logfile << "hypercall: vcpu_op ", arg1, " not implemented!", endl, flush;
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
      logfile << "hypercall: set_segment_base: unknown segment id ", arg1, endl;
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
        mfn_t mfn = req.arg1.mfn >> 12;
        if (mfn >= bootinfo.total_machine_pages) continue;

        //
        // Unmap the requisite pages from our physmap since we may be making them read only.
        // It will be remapped by the PTLsim page fault handler on demand.
        //
        unmap_phys_page(mfn);
        logfile << "hypercall: mmuext_op: unmap mfn ", mfn, " (pin/unpin operation ", req.cmd, ")", endl, flush;

        int update_count = 0;
        rc = HYPERVISOR_mmuext_op(&req, 1, &update_count, arg4);
        total_updates += update_count;
        break;
      }
      case MMUEXT_NEW_BASEPTR: {
        logfile << "hypercall: mmuext_op: new kernel baseptr is mfn ",
          req.arg1.mfn, " on vcpu ", ctx.vcpuid, ")", endl, flush;
        ctx.kernel_ptbase_mfn = req.arg1.mfn;
        ctx.cr3 = ctx.kernel_ptbase_mfn << 12;
        ctx.flush_tlb();
        total_updates++;
        rc = 0;
        break;
      }
      case MMUEXT_TLB_FLUSH_LOCAL:
      case MMUEXT_INVLPG_LOCAL: {
        bool single = (req.cmd == MMUEXT_INVLPG_LOCAL);
        logfile << "hypercall: mmuext_op: ", (single ? "invlpg" : "flush"), " local (vcpu ", ctx.vcpuid, ") @ ",
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
        logfile << "hypercall: mmuext_op: ", (single ? "invlpg" : "flush"), " multi (mask ", 
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
        logfile << "hypercall: mmuext_op: ", (single ? "invlpg" : "flush"), " all @ ",
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
        logfile << "hypercall: mmuext_op: flush_cache on vcpu ", ctx.vcpuid, endl, flush;
        total_updates++;
        rc = 0;
        break;
      }
      case MMUEXT_SET_LDT: {
        ctx.ldtvirt = req.arg1.linear_addr;
        ctx.ldtsize = req.arg2.nr_ents;

        logfile << "hypercall: mmuext_op: set_ldt to virt ", (void*)(Waddr)ctx.ldtvirt, " with ",
          ctx.ldtsize, " entries on vcpu ", ctx.vcpuid, endl, flush;

        total_updates++;
        rc = 0;
        break;
      }
      case MMUEXT_NEW_USER_BASEPTR: { // (x86-64 only)
        logfile << "hypercall: mmuext_op: new user baseptr is mfn ",
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
        logfile << "hypercall: mmuext_op: unknown op ", req.cmd, endl, flush;
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
      logfile << "hypercall: sched_op: yield VCPU ", ctx.vcpuid, endl, flush;
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
      logfile << "hypercall: sched_op: blocking VCPU ", ctx.vcpuid, endl, flush;
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
      doreq(alloc_unbound);
      doreq(bind_interdomain);
      doreq(bind_pirq);
      doreq(bind_ipi);
      doreq(close);
      doreq(send);
      doreq(status);
      doreq(bind_vcpu);
    case EVTCHNOP_bind_virq: {
      //
      // PTLsim needs to monitor attempts to bind the VIRQ_TIMER interrupt so we can
      // correctly deliver internal timer events at the appropriate rate.
      //
      getreq(evtchn_bind_virq);
      rc = HYPERVISOR_event_channel_op(arg1, &req);
      if (rc == 0) {
        logfile << "EVTCHNOP_bind_virq: bound virq ", req.virq, " on vcpu ", req.vcpu, " -> port ", req.port, endl, flush;
        assert(req.vcpu < bootinfo.vcpu_count);
        assert(req.virq < lengthof(contextof(req.vcpu).virq_to_port));
        contextof(req.vcpu).virq_to_port[req.virq] = req.port;
        assert(req.port < NR_EVENT_CHANNELS);
        port_to_vcpu[req.port] = req.vcpu;
      }
      putreq(evtchn_bind_virq);
      break;
    }
    case EVTCHNOP_unmask: {
      //
      // Unmask is special since we need to redirect it to our
      // virtual shinfo page, and potentially simulate an upcall.
      //
      getreq(evtchn_unmask);
      logfile << "hypercall: event_channel_op: unmask port ", req.port, endl;
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
    logfile << "Cannot handle hypercall ", hypercallid, "!", endl, flush;
    abort();
  }

  logfile << "  Returning rc ", rc, endl, flush;

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
        ctx.commitarf[REG_rax] = -EFAULT;
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

    if (logable(2)) logfile << "IRET from rip ", (void*)(Waddr)ctx.commitarf[REG_rip], ": iretctx @ ", (void*)(Waddr)ctx.commitarf[REG_rsp], " = ", iretctx, endl;

    if ((iretctx.cs & 3) == 3) {
      // Returning to user mode: toggle_guest_mode(v)
      assert(ctx.kernel_mode);
      ctx.kernel_mode = 0;
      ctx.cr3 = ctx.user_ptbase_mfn << 12;
      ctx.flush_tlb();
      if (logable(4)) logfile << "  Switch back to user mode @ cr3 mfn ", (ctx.cr3 >> 12), endl;
      ctx.swapgs();
    }

    ctx.commitarf[REG_rip] = iretctx.rip;
    ctx.reload_segment_descriptor(SEGID_CS, iretctx.cs | 3);
    ctx.commitarf[REG_flags] = (iretctx.rflags & ~(FLAG_IOPL|FLAG_VM)) | FLAG_IF;
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
  W64 saved_flags = commitarf[REG_flags];
  saved_upcall_mask = upcallmask;
  W64 cs_and_upcallmask = ((W64)upcallmask << 32) | (W64)guest_cs;
  assignbit(saved_flags, log2(FLAG_IF), !upcallmask);

  // Update flags for handler:
  upcallmask = ((action & TBF_INTERRUPT) != 0);
  assignbit(commitarf[REG_flags], log2(FLAG_IF), !upcallmask);

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
  commitarf[REG_flags] &= ~(FLAG_TF|FLAG_VM|FLAG_RF|FLAG_NT);

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

  if (logable(2)|1) {
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

    const vcpu_time_info_t& timeinfo = sshinfo.vcpu_info[ctx.vcpuid].time;

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

  initial_realtime_info.wc_sec = sshinfo.wc_sec;
  initial_realtime_info.wc_nsec = sshinfo.wc_nsec;

  double timer_period_sec = 1. / ((double)config.timer_interrupt_freq_hz);
  timer_interrupt_period_in_cycles = contextof(0).core_freq_hz / config.timer_interrupt_freq_hz;
  timer_interrupt_last_sent_at_cycle = 0;

  memset(port_to_vcpu, 0xff, sizeof(port_to_vcpu));

  logfile << "  Timer VIRQ ", VIRQ_TIMER, " will be delivered every 1/", config.timer_interrupt_freq_hz,
    " sec = every ", timer_interrupt_period_in_cycles, " cycles", endl;
}

//
// Update time info in shinfo page for each VCPU.
// This should be called before virq 
//
void update_time() {
  if (logable(4)) {
    logfile << "Update virtual real time at cycle ", sim_cycle, " (", total_user_insns_committed, " commits):", endl;
    logfile << "  Global simulation TSC:              ", intstring(sim_cycle, 20), endl;
  }

  foreach (i, bootinfo.vcpu_count) {
    Context& ctx = contextof(i);
    vcpu_time_info_t& timeinfo = sshinfo.vcpu_info[ctx.vcpuid].time;
    timeinfo.tsc_timestamp = ctx.base_tsc + sim_cycle;
    timeinfo.system_time = (W64)(timeinfo.tsc_timestamp * ctx.sys_time_cycles_to_nsec_coeff);
    timeinfo.version &= ~1ULL; // bit 0 == 0 means update all done
    if (logable(4)) logfile << "  VCPU ", i, " base TSC:                    ", intstring(ctx.base_tsc, 20), endl;
  }

  W64 initial_nsecs_since_epoch = (initial_realtime_info.wc_sec * 1000000000ULL) +
    initial_realtime_info.wc_nsec;
  W64 nsecs_since_boot = sshinfo.vcpu_info[0].time.system_time;
  W64 nsecs_since_epoch = initial_nsecs_since_epoch + nsecs_since_boot;

  sshinfo.wc_sec = nsecs_since_epoch / 1000000000ULL;
  sshinfo.wc_nsec = nsecs_since_epoch % 1000000000ULL;

  if (logable(4)) {
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

int inject_events() {
  //
  // Timer interrupts
  //

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

void backup_and_reopen_logfile() {
  if (config.log_filename) {
    // cerr << "Logging to ", config.log_filename, "...", endl, flush;
    if (logfile) logfile.close();
    stringbuf oldname;
    oldname << config.log_filename, ".backup"; // assert fails here
    sys_unlink(oldname);
    sys_rename(config.log_filename, oldname);
    logfile.open(config.log_filename);
  }
}

void ptlsim_init() {
  stringbuf sb;
  int rc;

  byte startup_log_buffer[65536];
  memset(startup_log_buffer, 0, sizeof(startup_log_buffer));
  bootinfo.startup_log_buffer = startup_log_buffer;
  bootinfo.startup_log_buffer_tail = 0;
  bootinfo.startup_log_buffer_size = lengthof(startup_log_buffer);

  early_printk("PTLsim/Xen initializing...\n");

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

  if (rc < 0) {
    stringbuf sb; sb << "ptlxen: Cannot connect to dom0 hostcall port ", bootinfo.monitor_hostcall_port, "; aborting", endl;
    early_printk(sb);
    return;
  }

  bootinfo.hostcall_port = bindreq.local_port;

  bindreq.remote_dom = 0; // dom0
  bindreq.remote_port = bootinfo.monitor_upcall_port;
  rc = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain, &bindreq);

  if (rc < 0) {
    stringbuf sb; sb << "ptlxen: Cannot connect to dom0 upcall port ", bootinfo.monitor_upcall_port, "; aborting", endl;
    early_printk(sb);
    return;
  }

  bootinfo.upcall_port = bindreq.local_port;

  sb.reset(); sb << "ptlxen: Connected hostcall_port ", bootinfo.hostcall_port, ", upcall_port ", bootinfo.upcall_port, endl;
  early_printk(sb);

  rc = HYPERVISOR_set_callbacks((Waddr)xen_event_callback_entry, 0, 0);

  clear_evtchn(bootinfo.hostcall_port);
  clear_evtchn(bootinfo.upcall_port);

  // Enable upcalls:
  sti();
  barrier();

  // Unmask the control port
  unmask_evtchn(bootinfo.hostcall_port);
  unmask_evtchn(bootinfo.upcall_port);

  prep_address_space();

  assert(HYPERVISOR_set_trap_table(trap_table) == 0);

	HYPERVISOR_vm_assist(VMASST_CMD_enable, VMASST_TYPE_writable_pagetables);

  // Disable boot logging
  bootinfo.startup_log_buffer_size = 0;

  //
  // At this point we can start making host requests
  //
  call_global_constuctors();

  bootinfo.ptlsim_state = PTLSIM_STATE_RUNNING;
}

stringbuf current_log_filename;

void print_sysinfo(ostream& os) {
  xen_capabilities_info_t xen_caps = "";
  xen_platform_parameters_t xen_params;

  HYPERVISOR_xen_version(XENVER_platform_parameters, &xen_params);
  HYPERVISOR_xen_version(XENVER_capabilities, &xen_caps);

  Waddr total_machine_pages = HYPERVISOR_memory_op(XENMEM_maximum_ram_page, NULL);
  assert(total_machine_pages > 0);

  Waddr xen_hypervisor_start_va = xen_params.virt_start;

  os << "System Information:", endl;
  os << "  Running on hypervisor version ", xen_caps, endl;
  os << "  Total machine physical pages ", total_machine_pages, " (", ((total_machine_pages * PAGE_SIZE) / 1024), " KB host physical memory)", endl;
  os << "  Xen is mapped at virtual address ", (void*)(Waddr)xen_hypervisor_start_va, endl;
  os << "  PTLsim is running across ", bootinfo.vcpu_count, " VCPUs:", endl;

  foreach (i, bootinfo.vcpu_count) {
    const vcpu_time_info_t& timeinfo = shinfo.vcpu_info[i].time;
    os << "    VCPU ", i, ": ", (get_core_freq_hz(timeinfo) / 1000000), " MHz", endl;
  }
  os << endl;
}

W64 handle_upcall(PTLsimConfig& config, bool blocking = true) {
  // This needs to be static because string parameters point into here:
  static char reqstr[4096];
  static bool first_time = true;

  // Clear it: we will check ourselves

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

  sequential_core_toplevel_loop();

#if 0
  //
  // Debugging support code, to crash domain at specific point
  //

  Waddr patch_entry = 0xffffffff8010b94c;
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

extern "C" void ptlsim_main(PTLsimMonitorInfo* dummy) {
  ptlsim_init();
  config.reset();
  configparser.setup();

  init_uops();
  init_translate();

  bool first_time = true;

  foreach (i, bootinfo.vcpu_count) {
    Context& ctx = contextof(i);
    ctx.vcpuid = i;
    ctx.init();
  }

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

      //++MTY TODO: also use VCPUOP_get_registered_runstate_memory_area
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
        shutdown(bootinfo.ctx, pause);
      else switch_to_native(bootinfo.ctx, pause);

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
}
