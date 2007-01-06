// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Interface between PTLcore and PTLmon dom0 control process
//
// Copyright 2005-2006 Matt T. Yourst <yourst@yourst.com>
//

#ifndef _PTLXEN_H_
#define _PTLXEN_H_

#include <globals.h>
#include <superstl.h>

#define __XEN_TOOLS__
asmlinkage {  
#include <xen-types.h>
#include <xen/xen.h>
#include <xen/domctl.h>
#include <xen/sched.h>
#include <xen/event_channel.h>
#include <xen/grant_table.h>
#include <xen/vcpu.h>
#include <xen/memory.h>
#include <xen/version.h>
#include <xen/xenoprof.h>
#include <xen/callback.h>
#include <xen/physdev.h>
#include <xen/features.h>
}

typedef unsigned long pfn_t;
typedef unsigned long mfn_t;
typedef unsigned long pte_t;

#define PML4_SHIFT (12+9+9+9)
//#define PTLSIM_VIRT_BASE 0xffffff0000000000ULL // PML4 entry 510
//#define PHYS_VIRT_BASE   0xfffffe0000000000ULL // PML4 entry 508 (enough for 2^39 bytes physical RAM)
#define PTLSIM_VIRT_BASE 0x0000000000000000ULL // PML4 entry 0
#define PHYS_VIRT_BASE   0x0000010000000000ULL // PML4 entry 2 (enough for 2^39 bytes physical RAM)

#define PTLSIM_RESERVED_VIRT_BASE 0xfffffe0000000000ULL // Start of guest-inaccessible PTLsim region
#define PTLSIM_RESERVED_VIRT_END  0xffffff7fffffffffULL // End of guest-inaccessible PTLsim region
// PML4 entry 511 is usually occupied by Linux itself

#define virt_is_inside_ptlsim(x) ((((W64)(x)) >> PML4_SHIFT) == (PTLSIM_VIRT_BASE >> PML4_SHIFT))
#define virt_is_inside_physmap(x) ((((W64)(x)) >> PML4_SHIFT) == (PHYS_VIRT_BASE >> PML4_SHIFT))

#define PTLSIM_BOOT_PAGE_PFN 0
#define PTLSIM_BOOT_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_BOOT_PAGE_PFN * 4096))
#define PTLSIM_BOOT_PAGE_PADDING 2048 // bytes of pre-padding (where ELF header goes)

#define PTLSIM_HYPERCALL_PAGE_PFN 1
#define PTLSIM_HYPERCALL_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_HYPERCALL_PAGE_PFN * 4096))

#define PTLSIM_SHINFO_PAGE_PFN 2
#define PTLSIM_SHINFO_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_SHINFO_PAGE_PFN * 4096))

#define PTLSIM_SHADOW_SHINFO_PAGE_PFN 3
#define PTLSIM_SHADOW_SHINFO_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_SHADOW_SHINFO_PAGE_PFN * 4096))

//
// The transfer page is used to copy data *into* the domain, since all
// other pages are mapped as read only. Thunked system calls and other
// utility functions use this facility. PTLsim may need to copy data
// from this buffer to its final destination inside the domain.
//
#define PTLSIM_XFER_PAGE_PFN 4
#define PTLSIM_XFER_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_XFER_PAGE_PFN * 4096))

// Maximum VCPUs per domain allowed by Xen:
#define MAX_CONTEXTS 32 // up to 32 VCPUs per domain

#define PTLSIM_CTX_PAGE_PFN 5
#define PTLSIM_CTX_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_CTX_PAGE_PFN * 4096))
#define PTLSIM_CTX_PAGE_COUNT MAX_CONTEXTS

#define PTLSIM_FIRST_READ_ONLY_PAGE (PTLSIM_CTX_PAGE_PFN + PTLSIM_CTX_PAGE_COUNT)

#define INVALID_MFN 0xffffffffffffffffULL

#define PTES_PER_PAGE (PAGE_SIZE / sizeof(pte_t))

#define PTLSIM_STUB_MAGIC 0x4b4f6d69734c5450ULL // "PTLsimOK"
#define PTLSIM_BOOT_PAGE_MAGIC 0x50426d69734c5450ULL // "PTLsimBP"
#define MAX_RESERVED_PAGES 131072 // on 64-bit platforms, this is 512 MB

#include <ptlhwdef.h>
#include <config.h>

union CPUVendorID {
  char text[13];
  W32 data[3];
};

enum {
  CPU_TYPE_UNKNOWN = 0,
  CPU_TYPE_AMD_K8 = 1,
  CPU_TYPE_INTEL_CORE2 = 2,
  CPU_TYPE_INTEL_PENTIUM4 = 3,
  CPU_TYPE_COUNT = 4
};

extern int cpu_type;
int get_cpu_type();
const char* get_cpu_type_name(int cputype);

struct PerfEvtSelMSR {
  W32 event:8, unitmask:8, user:1, kernel:1, edge:1, pinctl:1, interrupt:1, dummy0:1, enabled:1, threshold_lt_or_eq:1, events_per_cycle_threshold:8;
  RawDataAccessors(PerfEvtSelMSR, W32);
};

static inline W64 rdpmc(W32 op) {
  W32 eax;
  W32 edx;
	asm volatile("rdpmc" : "=a" (eax), "=d" (edx) : "c" (op));
  return (W64(edx) << 32) + W64(eax);
}

static inline W64 pages_to_kb(W64 pages) { return (pages * 4096) / 1024; }

enum {
  PTLSIM_HOST_NOP,
  //
  // Inform PTLmon of our startup status
  //
  PTLSIM_HOST_INITIALIZE,

  //
  // Perform a Linux system call in the context of PTLmon
  // in dom0 on behalf of PTLsim running inside the VM.
  // System calls can directly access PTLsim memory but
  // not the guest's memory. Things like mmap() et al are
  // obviously not allowed.
  //
  // NOTE: This can be a potential security problem
  // if PTLmon is running with root privileges, as
  // it usually does.
  //
  PTLSIM_HOST_SYSCALL,

  //
  // Get a pending request from PTLmon, typically in response
  // to an upcall event notification. This call will block
  // until a request is available.
  //
  // Requests are provided in text format as a command line.
  //
  PTLSIM_HOST_ACCEPT_UPCALL,

  //
  // Notify external waiters that the current simulation
  // phase is complete, i.e. PTLsim has returned to
  // waiting for a request, so parameters may be updated
  // or a new run can be started.
  //
  PTLSIM_HOST_COMPLETE_UPCALL,

  //
  // Inject an upcall into the queue for later retrieval.
  // This is done by ptlmon so it can synchronize with
  // asynchronous upcalls.
  //
  PTLSIM_HOST_INJECT_UPCALL,

  //
  // Inject an upcall into the queue for later retrieval.
  // This is done by ptlmon so it can synchronize with
  // asynchronous upcalls.
  //
  PTLSIM_HOST_FLUSH_UPCALL_QUEUE,

  //
  // Switch to native mode, suspending PTLsim and
  // freezing its state until we switch back.
  //
  PTLSIM_HOST_SWITCH_TO_NATIVE,

  //
  // Switch back to simulation mode. This is normally
  // done by a special x86 opcode that causes an
  // exception to be passed down to Xen, which in
  // turn passes it back up to PTLmon, which interprets
  // it as a synthetic PTLSIM_HOST_SWITCH_TO_SIM request.
  //
  PTLSIM_HOST_SWITCH_TO_SIM,

  //
  // Configure CPU performance counters in a model-specific
  // manner (both Intel and AMD CPUs use the same PerfEvtSel
  // register formats, but the events are obviously different.
  //
  PTLSIM_HOST_SETUP_PERFCTRS,

  //
  // Clear or overwrite the performance counter values.
  //
  PTLSIM_HOST_WRITE_PERFCTRS,

  //
  // Flush all processor caches (for accurate timing measurements)
  //
  PTLSIM_HOST_FLUSH_CACHE,

  //
  // Terminate PTLsim and PTLmon, removing it
  // from the address space, and kill the domain.
  //
  PTLSIM_HOST_SHUTDOWN,
};

// Calls from guest domain -> ptlmon in dom0:
struct PTLsimHostCall {
  W32 op;
  W32 ready;
  W64 rc;
  union {
    struct {
      int dummy;
    } initialize;
    struct {
      W64 syscallid;
      W64 arg1;
      W64 arg2;
      W64 arg3;
      W64 arg4;
      W64 arg5;
      W64 arg6;
    } syscall;
    struct {
      char* buf;
      size_t length;
      bool blocking;
    } accept_upcall;
    struct {
      W64 uuid;
    } complete_upcall;
    struct {
      const char* buf;
      size_t length;
      bool flush;
    } inject_upcall;
    struct {
      W64 uuid_limit;
    } flush_upcall_queue;
    struct {
      W64 value;
      W32 index;
      W32 cpu;
    } perfctr;
    struct {
      bool pause;
    } switch_to_native;
    struct {
      int reason;
    } shutdown;
  };

  PTLsimHostCall() { }

  PTLsimHostCall(int op) {
    this->op = op;
    this->rc = 0;
    this->ready = 0;
  }

  PTLsimHostCall(W64 syscallid, W64 arg1 = 0, W64 arg2 = 0, W64 arg3 = 0, W64 arg4 = 0, W64 arg5 = 0, W64 arg6 = 0) {
    this->op = PTLSIM_HOST_SYSCALL;
    this->rc = 0;
    this->ready = 0;
    this->syscall.syscallid = syscallid;
    this->syscall.arg1 = arg1;
    this->syscall.arg2 = arg2;
    this->syscall.arg3 = arg3;
    this->syscall.arg4 = arg4;
    this->syscall.arg5 = arg5;
    this->syscall.arg6 = arg6;
  }
};

// PTLsim states
enum {
  PTLSIM_STATE_NONE,
  PTLSIM_STATE_INITIALIZING,
  PTLSIM_STATE_RUNNING,
  PTLSIM_STATE_NATIVE,
};

struct PTLsimMonitorInfo {
  byte padding[PTLSIM_BOOT_PAGE_PADDING];

  W64 mfn_count;
  W64 avail_mfn_count;
  W64 total_machine_pages;
  Level1PTE* ptl_pagedir;
  Level2PTE* ptl_pagedir_map;
  Level3PTE* ptl_level3_map;
  Level4PTE* toplevel_page_table;
  shared_info_t* shared_info;
  W64 ptl_pagedir_mfn_count;
  mfn_t ptl_pagedir_map_mfn;
  mfn_t ptl_level3_mfn;
  mfn_t toplevel_page_table_mfn;
  mfn_t shared_info_mfn;
  PTLsimHostCall hostreq;
  W16 hostcall_port;
  W16 monitor_hostcall_port;
  W16 upcall_port;
  W16 monitor_upcall_port;
  W16 breakout_port;
  W16 monitor_breakout_port;
  W32 stack_size;
  byte* stack_top;
  byte* heap_start;
  byte* heap_end;
  byte* per_vcpu_stack_base;
  W64 max_pages;
  W32s queued_upcall_count;
  byte vcpu_count;
  byte ptlsim_state; // (PTLSIM_STATE_xxx)
  byte context_spinlock;
  byte abort_request;
  W64  vcpu_ctx_initialized;
  W64  phys_cpu_affinity;
};

W64 inject_upcall(const char* buf, size_t count, bool flush = false);

ostream& operator <<(ostream& os, const shared_info& si);

ostream& print_page_table(ostream& os, Level1PTE* ptes, W64 baseaddr);

#ifndef PTLSIM_IN_PTLMON

static inline void* getbootinfo() { return (void*)(Waddr)PTLSIM_BOOT_PAGE_VIRT_BASE; }
#define bootinfo (*((PTLsimMonitorInfo*)getbootinfo()))
#define shinfo (*((shared_info_t*)(Waddr)PTLSIM_SHINFO_PAGE_VIRT_BASE))

#define xferpage ((char*)(PTLSIM_XFER_PAGE_VIRT_BASE))

#define shinfo_evtchn_pending (*((bitvec<4096>*)&shinfo.evtchn_pending))
#define shinfo_evtchn_mask (*((bitvec<4096>*)&shinfo.evtchn_mask))
#define shinfo_evtchn_pending_sel(vcpuid) (*((bitvec<64>*)&shinfo.vcpu_info[vcpuid].evtchn_pending_sel))

#define sshinfo (*((shared_info_t*)PTLSIM_SHADOW_SHINFO_PAGE_VIRT_BASE))
#define sshinfo_evtchn_pending (*((bitvec<4096>*)&sshinfo.evtchn_pending))
#define sshinfo_evtchn_mask (*((bitvec<4096>*)&sshinfo.evtchn_mask))
#define sshinfo_evtchn_pending_sel(vcpuid) (*((bitvec<64>*)&sshinfo.vcpu_info[vcpuid].evtchn_pending_sel))

static inline W32 get_eflags() {
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

struct PageFrameType {
  Waddr mfn:28, type:3, pin:1;
  
  enum {
    NORMAL = 0,
    L1 = 1,
    L2 = 2,
    L3 = 3,
    L4 = 4,
    INVALID = 7,
    COUNT = 8,
  };

  static const char* names[COUNT];

  PageFrameType() { }
  operator Waddr() const { return *((const Waddr*)this); }
};

//
// Hypercalls
//
int HYPERVISOR_set_trap_table(trap_info_t *table);
int HYPERVISOR_mmu_update(mmu_update_t *req, int count, int *success_count, domid_t domid);
int HYPERVISOR_set_gdt(unsigned long *frame_list, int entries);
int HYPERVISOR_stack_switch(unsigned long ss, unsigned long esp);
int HYPERVISOR_set_callbacks(unsigned long event_address, unsigned long failsafe_address, unsigned long syscall_address);
int HYPERVISOR_fpu_taskswitch(int set);
int HYPERVISOR_sched_op_compat(int cmd, unsigned long arg);
int HYPERVISOR_domctl_op(xen_domctl_t *domctl_op);
int HYPERVISOR_set_debugreg(int reg, unsigned long value);
unsigned long HYPERVISOR_get_debugreg(int reg);
int HYPERVISOR_update_descriptor(unsigned long ma, unsigned long word);
int HYPERVISOR_memory_op(unsigned int cmd, void *arg);
int HYPERVISOR_multicall(void *call_list, int nr_calls);
int HYPERVISOR_update_va_mapping(unsigned long va, pte_t new_val, unsigned long flags);
long HYPERVISOR_set_timer_op(W64 timeout);
// HYPERVISOR_event_channel_op_compat
int HYPERVISOR_xen_version(int cmd, void *arg);
int HYPERVISOR_console_io(int cmd, int count, char *str);
// HYPERVISOR_physdev_op_compat
int HYPERVISOR_grant_table_op(unsigned int cmd, void *uop, unsigned int count);
int HYPERVISOR_vm_assist(unsigned int cmd, unsigned int type);
int HYPERVISOR_update_va_mapping_otherdomain(unsigned long va, pte_t new_val, unsigned long flags, domid_t domid);
// iret
int HYPERVISOR_vcpu_op(int cmd, int vcpuid, void *extra_args);
int HYPERVISOR_set_segment_base(int reg, unsigned long value);
int HYPERVISOR_mmuext_op(struct mmuext_op *op, int count, int *success_count, domid_t domid);
// acm_op
int HYPERVISOR_nmi_op(unsigned long op, void *arg);
int HYPERVISOR_sched_op(int cmd, void *arg);
int HYPERVISOR_callback_op(int cmd, void *arg);
int HYPERVISOR_xenoprof_op(int cmd, unsigned long arg1, unsigned long arg2);
int HYPERVISOR_event_channel_op(int cmd, void *op);
int HYPERVISOR_physdev_op(void *physdev_op);

#define contextbase ((Context*)PTLSIM_CTX_PAGE_VIRT_BASE)

static inline Context& contextof(int vcpu) {
  return contextbase[vcpu];
}

#define contextcount bootinfo.vcpu_count

//
// Utility functions
//
W64s synchronous_host_call(const PTLsimHostCall& call, bool spin = false, bool ignorerc = false);
void print_regs(ostream& os, const W64* regs);
void print_stack(ostream& os, Waddr sp);
int shutdown(int reason);

//
// PTLsim internal page table management
//

extern mmu_update_t mmuqueue[1024];
extern int mmuqueue_count;

int do_commit_page_table_updates();

static inline int commit_page_table_updates() {
  int rc = 0;
  if likely (mmuqueue_count) rc = do_commit_page_table_updates();
  return rc;
}

template <typename T>
T add_page_table_update(T& target, const T& source) {
  if unlikely (mmuqueue_count >= lengthof(mmuqueue)) {
    commit_page_table_updates();
  }

  // Don't process redundant updates
  if unlikely (target == source) return source;

  mmu_update_t& mmu = mmuqueue[mmuqueue_count++];
  mmu.ptr = (W64)&target;
  mmu.val = source;
  return source;
}

static inline Level1PTE operator <=(Level1PTE& target, Level1PTE source) {
  return add_page_table_update(target, source);
}

static inline Level2PTE operator <=(Level2PTE& target, Level2PTE source) {
  return add_page_table_update(target, source);
}

static inline Level3PTE operator <=(Level3PTE& target, Level3PTE source) {
  return add_page_table_update(target, source);
}

static inline Level4PTE operator <=(Level4PTE& target, Level4PTE source) {
  return add_page_table_update(target, source);
}

static inline void* phys_to_mapped_virt(W64 rawphys) {
  return (void*)signext64(PHYS_VIRT_BASE + rawphys, 48);
}

static inline W64 ptl_virt_to_phys(void* p) {
  Waddr virt = (Waddr)p;

  assert(inrange(virt, (Waddr)PTLSIM_VIRT_BASE, (Waddr)(PTLSIM_VIRT_BASE + ((PAGE_SIZE*bootinfo.mfn_count)-1))));
  return ((bootinfo.ptl_pagedir[(virt - PTLSIM_VIRT_BASE) >> 12].mfn << 12) + lowbits(virt, 12));
}

//
// Notice that we have carefully arranged PTLSIM_VIRT_BASE
// to be PHYS_VIRT_BASE + (1<<40). This means that a mapped
// physical address inside PTLsim will be in the format:
// 0x100xxxxxxxx, i.e. if bit 40 is set, the physical address
// is not in the guest-visible DRAM but in PTLsim space.
//
static inline W64 mapped_virt_to_phys(void* rawvirt) {
  return (Waddr)rawvirt - PHYS_VIRT_BASE;
}

static inline void* pte_to_mapped_virt(W64 rawvirt, const Level1PTE& pte) {
  if unlikely (!pte.p) return null;
  return phys_to_mapped_virt((pte.mfn << 12) + lowbits(rawvirt, 12));
}

static inline pfn_t ptl_virt_to_pfn(void* p) {
  Waddr vpn = ((Waddr)p) >> 12;
  if (!inrange(vpn, (Waddr)(PTLSIM_VIRT_BASE >> 12), (Waddr)(PTLSIM_VIRT_BASE >> 12) + bootinfo.mfn_count - 1)) return (pfn_t)INVALID_MFN;
  return vpn - (PTLSIM_VIRT_BASE >> 12);
}

static inline mfn_t ptl_virt_to_mfn(void* p) {
  pfn_t pfn = ptl_virt_to_pfn(p);
  if unlikely (pfn == INVALID_MFN) return (mfn_t)INVALID_MFN;

  return bootinfo.ptl_pagedir[pfn].mfn;
}

template <typename T>
int update_phys_pte(Waddr dest, const T& src);

template <typename T>
static inline int update_phys_pte_mfn_and_slot(mfn_t mfn, int slot, const T& src) {
  return update_phys_pte((mfn << 12) + (slot * sizeof(Level4PTE)), src);
}

template <typename T>
static inline int update_ptl_pte(T& dest, const T& src) {
  return update_phys_pte((Waddr)ptl_virt_to_phys(&dest), src);
}

int pin_page_table_page(void* virt, int level);
int make_ptl_page_writable(void* virt, bool writable);

int query_pages(page_type_t* pt, int count);
page_type_t query_page(mfn_t mfn);

//
// Physical memory map (physmap)
//
void build_physmap_page_tables();
int map_phys_page(mfn_t mfn, Waddr rip = 0);
void unmap_phys_page(mfn_t mfn);
void unmap_phys_page_tree(mfn_t root);
void unmap_address_space();

asmlinkage void do_page_fault(W64* regs);
void find_all_mappings_of_mfn(mfn_t mfn);

//
// Page table control
//
static inline mfn_t get_cr3_mfn() {
  Waddr cr3;
  asm volatile("mov %%cr3,%[out]" : [out] "=r" (cr3));
  return (cr3 >> 12);
}

void inject_ptlsim_into_toplevel(mfn_t mfn);
void switch_page_table(mfn_t mfn);
ostream& print_page_table_with_types(ostream& os, Level1PTE* ptes);

//
// Page Table Walks
//

Waddr virt_to_pte_phys_addr(W64 rawvirt, W64 toplevel_mfn, int level = 0);
Level1PTE page_table_walk_debug(W64 rawvirt, W64 toplevel_mfn, bool DEBUG);
Level1PTE page_table_walk(W64 rawvirt, W64 toplevel_mfn);
void page_table_acc_dirty_update(W64 rawvirt, W64 toplevel_mfn, const PTEUpdate& update);

//
// Loads and Stores
//
W64 storemask(Waddr physaddr, W64 data, byte bytemask);

//
// Self modifying code support
//
extern struct Level1PTE* phys_pagedir;

static inline bool smc_isdirty(Waddr mfn) {
  // MFN (2^28)-1 is INVALID_MFN as stored in RIPVirtPhys:
  if unlikely (mfn >= bootinfo.total_machine_pages) return false;
  return phys_pagedir[mfn].d;
}

void smc_setdirty_internal(Level1PTE& pte, bool dirty);

static inline void smc_setdirty_value(Waddr mfn, bool dirty) {
  if unlikely (mfn >= bootinfo.total_machine_pages) return;
  Level1PTE& pte = phys_pagedir[mfn];
  if likely (pte.d == dirty) return;
  smc_setdirty_internal(pte, dirty);
}

static inline void smc_setdirty(Waddr mfn) {
  smc_setdirty_value(mfn, 1);
}

static inline void smc_cleardirty(Waddr mfn) {
  smc_setdirty_value(mfn, 0);
}

//
// Memory hypercalls
//
W64 handle_mmu_update_hypercall(Context& ctx, mmu_update_t* reqp, W64 count, int* total_updates_ptr, domid_t domain, bool debug);
W64 handle_update_va_mapping_hypercall(Context& ctx, W64 va, Level1PTE newpte, W64 flags, bool debug);
W64 handle_memory_op_hypercall(Context& ctx, W64 op, void* arg, bool debug);
W64 handle_mmuext_op_hypercall(Context& ctx, mmuext_op_t* reqp, W64 count, int* total_updates_ptr, domid_t domain, bool debug);
W64 handle_grant_table_op_hypercall(Context& ctx, W64 cmd, byte* arg, W64 count, bool debug);

//
// PTLsim event and timer control
//
void mask_evtchn(int port);
void force_evtchn_callback();
void unmask_evtchn(int port);
void clear_evtchn(int port);
void cli();
void sti();
asmlinkage void xen_event_callback(W64* regs);

//
// Shadow Event Channels
//
bool shadow_evtchn_set_pending(unsigned int port);
int shadow_evtchn_unmask(unsigned int port);

//
// Check the specified VCPU for pending events.
//
inline bool Context::check_events() const {
  const vcpu_info_t& vcpuinfo = sshinfo.vcpu_info[vcpuid];

  return ((!vcpuinfo.evtchn_upcall_mask) && vcpuinfo.evtchn_upcall_pending);
}

//
// Timers
//
W64 get_core_freq_hz(const vcpu_time_info_t& timeinfo);
W64 get_core_freq_hz();
void capture_initial_timestamps();
void reconstruct_virq_to_port_mappings();
void virtualize_time_for_native_mode();
void time_and_virq_resume();
void update_time();
int inject_events();
void reset_mode_switch_delta_cycles_and_insns(W64& delta_cycles, W64& delta_insns);

//
// Event channel and timer related hypercalls
//
W64 handle_event_channel_op_hypercall(Context& ctx, int op, void* arg, bool debug);
W64 handle_set_timer_op_hypercall(Context& ctx, W64 arg1, bool debug);
W64 handle_vcpu_op_hypercall(Context& ctx, W64 arg1, W64 arg2, W64 arg3, bool debug);
W64 handle_sched_op_hypercall(Context& ctx, W64 op, void* arg, bool debug);

//
// Performance counters
//
bool perfctrs_init();
void perfctrs_start();
void perfctrs_stop();
void perfctrs_dump(ostream& os);

//
// Subset of system calls available under PTLsim/Xen:
//
extern "C" {
  // These require pointer thunking, but all pointers are read-only:
  int sys_open(const char* pathname, int flags, int mode);
  ssize_t sys_write(int fd, const void* buf, size_t count);
  int sys_unlink(const char* pathname);
  int sys_rename(const char* oldpath, const char* newpath);
  // These require pointer thunking, but some pointers are writable.
  // Thereis generally only one writable pointer per call.
  ssize_t sys_read(int fd, void* buf, size_t count);
  int sys_readlink(const char *path, char *buf, size_t bufsiz);
  struct utsname;
  int sys_uname(struct utsname* buf);
  // These are artificially implemented with Xen hypercalls or references:
  int sys_gettimeofday(struct timeval* tv, struct timezone* tz);
  time_t sys_time(time_t* t);
  W64 sys_nanosleep(W64 nsec);
  // These access no pointers:
  int sys_close(int fd);
  ssize_t sys_fdatasync(int fd);
  W64 sys_seek(int fd, W64 offset, unsigned int origin);

  void* malloc(size_t size) __attribute__((__malloc__));
  void free(void* ptr);
  char* getenv(const char* name);
};

//
// Mode switch requests initiated within the simulation
// via assists, shutdowns, etc.
//

extern int assist_requested_break;
extern stringbuf assist_requested_break_command;

extern W64 ptlsim_hypercall_histogram[64];

#endif // PTLSIM_IN_PTLMON

#endif // _PTLXEN_H_
