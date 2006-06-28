//
// PTLsim: Cycle Accurate x86-64 Simulator
// Xen interface inside the user domain
//
// Copyright 2005-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>
#include <ptlxen.h>
#include <mm.h>

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

int HYPERVISOR_event_channel_op(void *op) {
  return _hypercall1(int, event_channel_op, op);
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

W64 got_upcall = 0;

// This is a barrier for the compiler only, NOT the processor!
#define barrier() asm volatile("": : :"memory")

template <typename T>
static inline T xchg(T& v, T newv) {
	switch (sizeof(T)) {
  case 1: asm volatile("xchgb %[newv],%[v]" : [v] "+m" (v), [newv] "+r" (newv) : : "memory"); break;
  case 2: asm volatile("xchgw %[newv],%[v]" : [v] "+m" (v), [newv] "+r" (newv) : : "memory"); break;
  case 4: asm volatile("xchgl %[newv],%[v]" : [v] "+m" (v), [newv] "+r" (newv) : : "memory"); break;
  case 8: asm volatile("xchgq %[newv],%[v]" : [v] "+m" (v), [newv] "+r" (newv) : : "memory"); break;
	}
	return newv;
}

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
  if (shinfo_evtchn_pending[port] && (!x86_locked_bts<unsigned long>(vcpu_info.evtchn_pending_sel, port >> 5))) {
    early_printk("unmask_evtchn: forcing evtchn callback\n");
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

W64 trigger_terminate = 0;
W64 trigger_switch_to_native = 0;

void handle_ptlsim_upcall(const PTLsimUpcall& upcall) {
  trigger_switch_to_native = 1;
}

inline W32 get_eflags() {
  W64 eflags;
  asm volatile("pushfq; popq %[eflags]" : [eflags] "=r" (eflags) : : "memory");
  return eflags;
}

void handle_event(int port, struct pt_regs* regs) {
  stringbuf sb; sb << "handle_event(port ", port, ")", endl; early_printk(sb);

  // Can't use anything that makes host calls in here!
  if (port == bootinfo.upcall_port) {
    // Upcall 
    handle_ptlsim_upcall(bootinfo.upcall);
    bootinfo.upcall.op = PTLSIM_UPCALL_NOP;
  } else if (port == bootinfo.hostcall_port) {
    // No action: will automatically unblock and return to hostcall caller
  } else {
    // some user port: copy to virtualized shared info page and notify simulation loop
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

  evtchn_op_t sendop;
  sendop.cmd = EVTCHNOP_send;
  sendop.u.send.port = bootinfo.hostcall_port;
  rc = HYPERVISOR_event_channel_op(&sendop);

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
int switch_to_native(Context* ctx) {
  Context ptlctx[32];
  int rc;

  PTLsimHostCall call;
  call.op = PTLSIM_HOST_SWITCH_TO_NATIVE;
  call.ready = 0;
  call.switch_to_native.guestctx = ctx;
  call.switch_to_native.ptlctx = ptlctx;

  rc = synchronous_host_call(call);
  return rc;
}

int shutdown(Context* ctx) {
  Context ptlctx[32];
  int rc;

  PTLsimHostCall call;
  call.op = PTLSIM_HOST_TERMINATE;
  call.ready = 0;
  call.terminate.guestctx = ctx;
  call.terminate.ptlctx = ptlctx;
  call.terminate.exitcode = 0;

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

ssize_t sys_read(int fd, void* buf, size_t count) {
  return (ssize_t)synchronous_host_call(PTLsimHostCall(__NR_read, fd, (Waddr)buf, count));
}

ssize_t sys_write(int fd, const void* buf, size_t count) {
  return (ssize_t)synchronous_host_call(PTLsimHostCall(__NR_write, fd, (Waddr)buf, count));
}

int sys_open(const char* pathname, int flags, int mode) {
  return (int)synchronous_host_call(PTLsimHostCall(__NR_open, (Waddr)pathname, flags, mode));
}

int sys_close(int fd) {
  return (int)synchronous_host_call(PTLsimHostCall(__NR_close, fd));
}

W64 sys_seek(int fd, W64 offset, unsigned int origin) {
  return (W64)synchronous_host_call(PTLsimHostCall(__NR_lseek, fd, offset, origin));
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
char* dumpcode_filename = null;

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
  abort();
}

void early_printk(const char* p) {
  int count = min((int)strlen(p), bootinfo.startup_log_buffer_size);

  foreach (i, count) {
    bootinfo.startup_log_buffer[bootinfo.startup_log_buffer_tail] = p[i];
    bootinfo.startup_log_buffer_tail = (bootinfo.startup_log_buffer_tail + 1) & (bootinfo.startup_log_buffer_size - 1);
  }
}

extern "C" void xen_event_callback_entry();

//Hashtable<W64, PageFrameType, 512> pinned_pages;

// Just big enough to have more than one word; rely on having no bounds checks:
typedef bitvec<65> infinite_bitvec_t;

infinite_bitvec_t* ptlsim_mfn_bitmap = null;

void* ptl_virt_to_phys(void* p) {
  Waddr virt = (Waddr)p;

  assert(inrange(virt, (Waddr)PTLSIM_VIRT_BASE, (Waddr)(PTLSIM_VIRT_BASE + ((PAGE_SIZE*bootinfo.mfn_count)-1))));
  return (void*)((bootinfo.ptl_pagedir[(virt - PTLSIM_VIRT_BASE) >> 12].phys << 12) + lowbits(virt, 12));
}

// Update a PTE entry within PTLsim:
template <typename T>
int update_ptl_pte(T& dest, const T& src) {
	mmu_update_t u;
	u.ptr = (W64)ptl_virt_to_phys(&dest);
	u.val = (W64)src;
  return HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF);
}

LongModeLevel1PTE page_table_walk_longmode(W64 rawvirt, W64 toplevel_mfn) {
  VirtAddr virt(rawvirt);

  LongModeLevel4PTE& level4 = ((LongModeLevel4PTE*)(PHYS_VIRT_BASE + (toplevel_mfn << 12)))[virt.lm.level4];
  LongModeLevel1PTE final = (W64)level4;
  if (!level4.p) return final;
  if (!level4.a) level4.a = 1;

  LongModeLevel3PTE& level3 = ((LongModeLevel3PTE*)(PHYS_VIRT_BASE + (level4.next << 12)))[virt.lm.level3];
  final.accum(level3);
  if (!level3.p) return final;
  if (!level3.a) level3.a = 1;

  LongModeLevel2PTE& level2 = ((LongModeLevel2PTE*)(PHYS_VIRT_BASE + (level3.next << 12)))[virt.lm.level2];
  final.accum(level2);
  if (!level2.p) return final;
  if (!level2.a) level2.a = 1;

  if (level2.psz) {
    final.phys = level2.next;
    final.pwt = level2.pwt;
    final.pcd = level2.pcd;
    final.a = level2.a;
    final.d = level2.d;
    return final;
  }

  LongModeLevel1PTE& level1 = ((LongModeLevel1PTE*)(PHYS_VIRT_BASE + (level2.next << 12)))[virt.lm.level1];
  final.accum(level1);
  if (!level1.p) return final;
  if (!level1.a) level1.a = 1;

  final.phys = level1.phys;
  final.g = level1.g;
  final.pat = level1.pat;
  final.pwt = level1.pwt;
  final.pcd = level1.pcd;
  final.a = level1.a;
  final.d = level1.d;
  return final;
}

void prep_address_space() {
  int bytes_required = ceil(bootinfo.total_machine_pages, 8) / 8;

  ptlsim_mfn_bitmap = (infinite_bitvec_t*)ptl_alloc_private_pages(bytes_required);
  memset(ptlsim_mfn_bitmap, 0, bytes_required);

  foreach (i, bootinfo.mfn_count) {
    mfn_t mfn = bootinfo.ptl_pagedir[i].phys;
    assert(mfn < bootinfo.total_machine_pages);
    (*ptlsim_mfn_bitmap)[mfn] = 1;
  }
}

const SegmentDescriptor& Context::get_gdt_entry(W16 idx) {
  if (idx >= gdtsize) return *((const SegmentDescriptor*)null);
  mfn_t mfn = gdtpages[idx / 512];
  return *(const SegmentDescriptor*)phys_to_ptl_virt((mfn << 12) + (lowbits(idx, 9) * 8));
}

void Context::update_shadow_segment_descriptors() {
  seg[SEGID_CS] = get_gdt_entry(seg[SEGID_CS].selector);
  use32 = seg[SEGID_CS].use32;
  use64 = seg[SEGID_CS].use64;
  virt_addr_mask = (use64 ? 0xffffffffffffffffULL : 0x00000000ffffffffULL);

  seg[SEGID_DS] = get_gdt_entry(seg[SEGID_DS].selector);
  seg[SEGID_SS] = get_gdt_entry(seg[SEGID_SS].selector);
  seg[SEGID_ES] = get_gdt_entry(seg[SEGID_ES].selector);
  
  //
  // FS and GS are special on x86-64: they have bases, but the full 64-bit base
  // is specified by the FSBASE (0xc0000100) and GSBASE (0xc0000101) MSRs.
  //
  SegmentDescriptorCache& fs = seg[SEGID_FS];
  if (fs.selector) {
    fs = get_gdt_entry(fs.selector);
  } else {
    // If fs.selector is zero, base is forced to fs_base
    fs.present = 1;
    fs.base = fs_base;
    fs.limit = 0xffffffffffffffffULL;
    fs.dpl = 3;
  }

  SegmentDescriptorCache& gs = seg[SEGID_GS];
  if (gs.selector) {
    gs = get_gdt_entry(gs.selector);
  } else {
    // If fs.selector is zero, base is forced to fs_base
    gs.present = 1;
    gs.base = (kernel_mode) ? gs_base_kernel : gs_base_user;
    gs.limit = 0xffffffffffffffffULL;
    gs.dpl = 3;
  }
}

//
// Map all machine pages belonging to the domain into our address space,
// starting at PHYS_VIRT_BASE. The permissions are set according to the
// Xen pinned status (normal pages are writable, PT pages are read-only).
//
// ++MTY TODO Need to handle grant pages here too - we need a new hypercall
// to return the MFNs passed to GNTTABOP_setup_table since Xen does not
// provide a way of reading this back.
//

void update_address_space() {
  PageFrameType* pftlist = (PageFrameType*)ptl_alloc_private_pages((bootinfo.max_pages + 1) * sizeof(PageFrameType));
  assert(pftlist);

  cerr << "Getting ", bootinfo.max_pages, " pages and types to pftlist ", pftlist, " (", bootinfo.max_pages, " max pages)", endl, flush;

  int real_page_count = query_pages(pftlist, bootinfo.max_pages);

  cerr << "Queried ", real_page_count, " out of ", bootinfo.max_pages, " pages and types:", endl, flush;

  // Add the shared info page
  PageFrameType& shinfo_pft = pftlist[real_page_count];
  shinfo_pft.pin = 0;
  shinfo_pft.type = 0;
  shinfo_pft.mfn = bootinfo.shared_info_mfn;
  real_page_count++;

  int map_bytes_required = ceil(bootinfo.total_machine_pages, 8) / 8;

  infinite_bitvec_t& pinned_mfn_bitmap = *(infinite_bitvec_t*)ptl_alloc_private_pages(map_bytes_required);
  memset(&pinned_mfn_bitmap, 0, map_bytes_required);

  foreach (i, real_page_count) {
    const PageFrameType& pft = pftlist[i];
    assert(pft.mfn < bootinfo.total_machine_pages);
    pinned_mfn_bitmap[pft.mfn] = (pft.type != PageFrameType::NORMAL);
  }

  // GDT pages must also be mapped read-only:
  foreach (c, bootinfo.vcpu_count) {
    int gdt_page_count = ceil(bootinfo.ctx[c].gdtsize, 512) / 512;
    cerr << "GDT size: ", bootinfo.ctx[c].gdtsize, " -> ", gdt_page_count, " pages", endl;
    foreach (i, gdt_page_count) {
      mfn_t mfn = bootinfo.ctx[c].gdtpages[i];
      assert(mfn < bootinfo.total_machine_pages);
      cerr << "  Pin GDT mfn ", mfn, endl;
      pinned_mfn_bitmap[mfn] = 1;
    }
  }

  foreach (i, real_page_count) {
    const PageFrameType& pft = pftlist[i];

    if ((*ptlsim_mfn_bitmap)[pft.mfn]) continue;

    LongModeLevel1PTE pte = 0;
    pte.p = 1;
    pte.rw = (!pinned_mfn_bitmap[pft.mfn]);
    pte.us = 1;
    pte.phys = pft.mfn;
    
    int rc;
    rc = update_ptl_pte(bootinfo.phys_pagedir[pft.mfn], pte);

    if (rc < 0) {
      cerr << intstring(i, 8), ": mfn ", intstring(pft.mfn, 8), ", pin? ", pft.pin, ", type ", pft.type, ": ", PageFrameType::names[pft.type], (((*ptlsim_mfn_bitmap)[pft.mfn]) ? " [PTLsim]" : ""),  endl;
      cerr << "  Cannot map mfn ", pft.mfn, " with pte ", pte, ": rc ", rc, endl;
    }
  }

  ptl_free_private_pages(&pinned_mfn_bitmap, map_bytes_required);
  ptl_free_private_pages(pftlist, bootinfo.max_pages * sizeof(PageFrameType));
}

//
// This is required before switching back to native mode, since we may have
// read/write maps of pages that the guest kernel thinks are read-only
// everywhere; this will cause later pin operations to fail.
//
// We also need to hook into the MMUEXT_pin_xxx hypercalls while simulating
// so we unmap our read-write map to the page when these occur.
//
void unmap_address_space() {
  PageFrameType* pftlist = (PageFrameType*)ptl_alloc_private_pages(bootinfo.max_pages * sizeof(PageFrameType));
  assert(pftlist);

  int real_page_count = query_pages(pftlist, bootinfo.max_pages);

  int n = 0;
  foreach (i, real_page_count) {
    const PageFrameType& pft = pftlist[i];
    assert(pft.mfn < bootinfo.total_machine_pages);

    LongModeLevel1PTE pte = 0;
    int rc = update_ptl_pte(bootinfo.phys_pagedir[pft.mfn], pte);
    if (rc < 0) cerr << "  Cannot unmap mfn ", pft.mfn, " with pte ", pte, ": rc ", rc, endl;
  }

  ptl_free_private_pages(pftlist, bootinfo.max_pages * sizeof(PageFrameType));
}

extern "C" void ptlsim_preinit(PTLsimMonitorInfo* dummy) {
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
  evtchn_op_t bindreq;
  bindreq.cmd = EVTCHNOP_bind_interdomain;
  bindreq.u.bind_interdomain.remote_dom = 0; // dom0
  bindreq.u.bind_interdomain.remote_port = bootinfo.monitor_hostcall_port;
  rc = HYPERVISOR_event_channel_op(&bindreq);

  if (rc < 0) {
    stringbuf sb; sb << "ptlxen: Cannot connect to dom0 hostcall port ", bootinfo.monitor_hostcall_port, "; aborting", endl;
    early_printk(sb);
    return;
  }

  bootinfo.hostcall_port = bindreq.u.bind_interdomain.local_port;

  bindreq.cmd = EVTCHNOP_bind_interdomain;
  bindreq.u.bind_interdomain.remote_dom = 0; // dom0
  bindreq.u.bind_interdomain.remote_port = bootinfo.monitor_upcall_port;
  rc = HYPERVISOR_event_channel_op(&bindreq);

  if (rc < 0) {
    stringbuf sb; sb << "ptlxen: Cannot connect to dom0 upcall port ", bootinfo.monitor_upcall_port, "; aborting", endl;
    early_printk(sb);
    return;
  }

  bootinfo.upcall_port = bindreq.u.bind_interdomain.local_port;

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

  //
  // At this point we can start making host requests
  //
  call_global_constuctors();
  logfile.open(1);

  bootinfo.ptlsim_state = PTLSIM_STATE_RUNNING;
  
  cerr << "//", endl;
  cerr << "// PTLsim/Xen initialized", endl;
  cerr << "//", endl;
  cerr.flush();

  prep_address_space();
  update_address_space();

  Context& ctx = contextof(0);
  ctx.update_shadow_segment_descriptors();

  cerr << "vcpu0 user context:", endl, ctx, flush;

  void* ripvirt = (void*)(Waddr)ctx.commitarf[REG_rip];

  cerr << "rip: ", ripvirt, endl;
  cerr << "Toplevel page table in cr3: ", (ctx.cr3 >> 12), endl;

  LongModeLevel1PTE entrypte = ctx.virt_to_pte((Waddr)ripvirt);
  cerr << entrypte, endl;

  byte* entryptr = (byte*)pte_to_ptl_virt((Waddr)ripvirt, entrypte);

  cerr << "Entry ptr = ", entryptr, endl, flush;

  byte insnbuf[16];
  PageFaultErrorCode pfec;
  Waddr faultaddr;
  int n = ctx.copy_from_user(insnbuf, ctx.commitarf[REG_rip], sizeof(insnbuf), pfec, faultaddr, true);

  cerr << "Got ", n, " bytes of insn data: ", bytemaskstring(entryptr, 0xffffffffffffffffULL, n), endl, flush;

  cerr << "Now ready to run...", endl, flush;
  
  //cerr << "Dumping grant table...", endl, flush;
  //gnttab_dump_table grantop;
  //grantop.dom = DOMID_SELF;
  //rc = HYPERVISOR_grant_table_op(GNTTABOP_dump_table, &grantop, 1);
  //cerr << "Dump rc ", rc, ", status ", grantop.status, endl, flush;

  unmap_address_space();

  cerr << "Unmapped address space", endl, flush;

  int i = 0;
  int iter = 0;
#if 0
  for (;;) {
    if (trigger_switch_to_native || (iter == 1)) {
      early_printk("Request from ptlmon: switch to native\n");
      cerr << "Request from ptlmon: switch to native", endl, flush;
      trigger_switch_to_native = 0;

      early_printk("Request from ptlmon: doing switch to native\n");
      switch_to_native(bootinfo.ctx);

      early_printk("Request from ptlmon: back from switch to native\n");      
      cerr << "Returned from switch to native: now back in sim", endl, flush;
    }
    barrier();
    i++;
    if (lowbits(i, 28) == 0) {
      stringbuf sb; sb << "In main loop iter ", iter, endl;
      early_printk(sb);
      cerr << sb, endl, flush;
      iter++;
    }
  }
#endif
  shutdown(bootinfo.ctx);

  // We should never get here!
  abort();
}
/*
  sb.reset(); sb << "  Before:", endl; early_printk(sb);
  sb.reset(); sb << "    mask    ", bitstring(shinfo_evtchn_mask.integer(), 32, true), endl; early_printk(sb);
  sb.reset(); sb << "    pending ", bitstring(shinfo_evtchn_pending.integer(), 32, true), endl; early_printk(sb);
  sb.reset(); sb << "    up mask ", shinfo.vcpu_info[0].evtchn_upcall_mask, endl; early_printk(sb);
  sb.reset(); sb << "    up pend ", shinfo.vcpu_info[0].evtchn_upcall_pending, endl; early_printk(sb);
*/
