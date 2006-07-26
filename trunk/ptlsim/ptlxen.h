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

extern "C" {  
#include <xen-types.h>
#include <xen/xen.h>
#include <xen/dom0_ops.h>
#include <xen/sched.h>
#include <xen/event_channel.h>
#include <xen/grant_table.h>
#include <xen/vcpu.h>
#include <xen/memory.h>
#include <xen/version.h>
#include <xen/sched_ctl.h>
#include <xen/xenoprof.h>
#include <xen/callback.h>
#include <xen/features.h>
#include "xc_ptlsim.h"
}

#include <ptlhwdef.h>
#include <config.h>

//
// The boot page is page 0 in PTL space, but gcc does not like null
// pointers and will complain without the following contortions:
//
//#define bootinfo (*((PTLsimMonitorInfo*)(Waddr)PTLSIM_BOOT_PAGE_VIRT_BASE))

#ifndef EXCLUDE_BOOTINFO_SHINFO
static inline void* getbootinfo() { return (void*)(Waddr)PTLSIM_BOOT_PAGE_VIRT_BASE; }
#define bootinfo (*((PTLsimMonitorInfo*)getbootinfo()))
#define shinfo (*((shared_info_t*)(Waddr)PTLSIM_SHINFO_PAGE_VIRT_BASE))

#define shinfo_evtchn_pending (*((bitvec<4096>*)&shinfo.evtchn_pending))
#define shinfo_evtchn_mask (*((bitvec<4096>*)&shinfo.evtchn_mask))
#define shinfo_evtchn_pending_sel(vcpuid) (*((bitvec<64>*)&shinfo.vcpu_info[vcpuid].evtchn_pending_sel))

#define sshinfo (*(bootinfo.shadow_shinfo))
#define sshinfo_evtchn_pending (*((bitvec<4096>*)&sshinfo.evtchn_pending))
#define sshinfo_evtchn_mask (*((bitvec<4096>*)&sshinfo.evtchn_mask))
#define sshinfo_evtchn_pending_sel(vcpuid) (*((bitvec<64>*)&sshinfo.vcpu_info[vcpuid].evtchn_pending_sel))

#endif

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
int HYPERVISOR_dom0_op(dom0_op_t *dom0_op);
int HYPERVISOR_set_debugreg(int reg, unsigned long value);
unsigned long HYPERVISOR_get_debugreg(int reg);
int HYPERVISOR_update_descriptor(unsigned long ma, unsigned long word);
int HYPERVISOR_memory_op(unsigned int cmd, void *arg);
int HYPERVISOR_multicall(void *call_list, int nr_calls);
int HYPERVISOR_update_va_mapping(unsigned long va, pte_t new_val, unsigned long flags);
long HYPERVISOR_set_timer_op(u64 timeout);
// HYPERVISOR_event_channel_op_compat
int HYPERVISOR_xen_version(int cmd, void *arg);
int HYPERVISOR_console_io(int cmd, int count, char *str);
// HYPERVISOR_physdev_op_compat()
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
int HYPERVISOR_xenoprof_op(int op, unsigned long arg1, unsigned long arg2);
int HYPERVISOR_event_channel_op(void *op);
int HYPERVISOR_physdev_op(void *physdev_op);

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
  // Terminate PTLsim and PTLmon, removing it
  // from the address space.
  //
  PTLSIM_HOST_TERMINATE,

  //
  // Query the pages belonging to the domain
  // and their respective types
  //
  PTLSIM_HOST_QUERY_PAGES,

  //
  // Notify external waiters that the current simulation
  // phase is complete, i.e. PTLsim has returned to
  // waiting for a request, so parameters may be updated
  // or a new run can be started.
  //
  PTLSIM_HOST_COMPLETE_UPCALL,
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
      size_t count;
      bool blocking;
    } accept_upcall;
    struct {
      Context* guestctx;
      Context* ptlctx;
      bool pause;
    } switch_to_native;
    struct {
      Context* guestctx;
      Context* ptlctx;
      bool pause;
    } terminate;
    struct {
      PageFrameType* pft;
      int count;
    } querypages;
    struct {
      W64 uuid;
    } complete_upcall;
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

struct PTLsimMonitorInfo: public PTLsimBootPageInfo {
  PTLsimHostCall hostreq;
  int queued_upcall_count;
  int hostcall_port;
  int monitor_hostcall_port;
  int upcall_port;
  int monitor_upcall_port;
  int argc;
  char** argv;
  byte* stack_top;
  int stack_size;
  byte* heap_start;
  byte* heap_end;
  int vcpu_count;
  int max_pages;
  int total_machine_pages;
  Context* ctx;
  shared_info_t* shadow_shinfo;
  byte* startup_log_buffer;
  int startup_log_buffer_tail;
  int startup_log_buffer_size;
  int ptlsim_state; // (PTLSIM_STATE_xxx)
};

ostream& print_page_table(ostream& os, Level1PTE* ptes, W64 baseaddr);

#ifndef EXCLUDE_BOOTINFO_SHINFO

Level1PTE page_table_walk(W64 rawvirt, W64 toplevel_mfn);
void page_table_acc_dirty_update(W64 rawvirt, W64 toplevel_mfn, const PTEUpdate& update);

static inline Context& contextof(int vcpu) { return bootinfo.ctx[vcpu]; }

static inline void* phys_to_mapped_virt(W64 rawphys) {
  return (void*)signext64(PHYS_VIRT_BASE + rawphys, 48);
}

static inline void* ptl_virt_to_phys(void* p) {
  Waddr virt = (Waddr)p;

  assert(inrange(virt, (Waddr)PTLSIM_VIRT_BASE, (Waddr)(PTLSIM_VIRT_BASE + ((PAGE_SIZE*bootinfo.mfn_count)-1))));
  return (void*)((bootinfo.ptl_pagedir[(virt - PTLSIM_VIRT_BASE) >> 12].phys << 12) + lowbits(virt, 12));
}

static inline W64 mapped_virt_to_phys(void* rawvirt) {
  return ((Waddr)lowbits((Waddr)rawvirt, 48)) - PHYS_VIRT_BASE;
}

static inline void* pte_to_mapped_virt(W64 rawvirt, const Level1PTE& pte) {
  if unlikely (!pte.p) return null;
  return phys_to_mapped_virt((pte.phys << 12) + lowbits(rawvirt, 12));
}

static inline pfn_t ptl_virt_to_pfn(void* p) {
  Waddr vpn = ((Waddr)p) >> 12;
  if (!inrange(vpn, (Waddr)(PTLSIM_VIRT_BASE >> 12), (Waddr)(PTLSIM_VIRT_BASE >> 12) + bootinfo.mfn_count - 1)) return (pfn_t)INVALID_MFN;
  return vpn - (PTLSIM_VIRT_BASE >> 12);
}

static inline mfn_t ptl_virt_to_mfn(void* p) {
  pfn_t pfn = ptl_virt_to_pfn(p);
  if unlikely (pfn == INVALID_MFN) return (mfn_t)INVALID_MFN;

  return bootinfo.ptl_pagedir[pfn].phys;
}

W64 storemask(Waddr physaddr, W64 data, byte bytemask);

static inline bool smc_isdirty(Waddr mfn) {
  // MFN (2^28)-1 is INVALID_MFN as stored in RIPVirtPhys:
  if unlikely (mfn >= bootinfo.total_machine_pages) return false;
  return bootinfo.phys_pagedir[mfn].d;
}

void smc_setdirty_internal(Level1PTE& pte, bool dirty);

static inline void smc_setdirty_value(Waddr mfn, bool dirty) {
  if unlikely (mfn >= bootinfo.total_machine_pages) return;
  Level1PTE& pte = bootinfo.phys_pagedir[mfn];
  if likely (pte.d == dirty) return;
  smc_setdirty_internal(pte, dirty);
}

static inline void smc_setdirty(Waddr mfn) {
  smc_setdirty_value(mfn, 1);
}

static inline void smc_cleardirty(Waddr mfn) {
  smc_setdirty_value(mfn, 0);
}

int inject_events();
bool check_for_async_sim_break();

#endif

//
// Subset of system calls available under PTLsim/Xen:
//
extern "C" {
  int sys_open(const char* pathname, int flags, int mode);
  int sys_close(int fd);
  ssize_t sys_read(int fd, void* buf, size_t count);
  ssize_t sys_write(int fd, const void* buf, size_t count);
  ssize_t sys_fdatasync(int fd);
  W64 sys_seek(int fd, W64 offset, unsigned int origin);
  int sys_unlink(const char* pathname);
  int sys_rename(const char* oldpath, const char* newpath);
  int sys_readlink(const char *path, char *buf, size_t bufsiz);
  W64 sys_nanosleep(W64 nsec);

  struct utsname;
  int sys_uname(struct utsname* buf);
  
  void* malloc(size_t size) __attribute__((__malloc__));
  void free(void* ptr);
  char* getenv(const char* name);

  int sys_gettimeofday(struct timeval* tv, struct timezone* tz);
  time_t sys_time(time_t* t);
};

// 
// Configuration Options:
//
struct PTLsimConfig {
  W64 domain;
  bool run;
  bool native;
  bool pause;
  bool kill;
  stringbuf core_name;

  W64 clock_adj_factor;

  // Logging
  bool quiet;
  stringbuf log_filename;
  W64 loglevel;
  W64 start_log_at_iteration;
  bool log_ptlsim_boot;
  bool log_on_console;

  // Statistics Database
  stringbuf stats_filename;
  W64 snapshot_cycles;
  bool snapshot_now;

  // Stopping Point
  W64 stop_at_user_insns;
  W64 stop_at_iteration;
  W64 stop_at_rip;
  W64 insns_in_last_basic_block;
  W64 flush_interval;

  // Event tracing
  stringbuf event_trace_record_filename;
  bool event_trace_record_stop;
  stringbuf event_trace_replay_filename;

  // Core features
  W64 core_freq_hz;
  W64 timer_interrupt_freq_hz;
  bool pseudo_real_time_clock;

  // Other info
  stringbuf dumpcode_filename;

  W64 console_mfn;

  void reset();
};

extern PTLsimConfig config;

extern ConfigurationParser<PTLsimConfig> configparser;

ostream& operator <<(ostream& os, const PTLsimConfig& config);

ostream& operator <<(ostream& os, const shared_info& si);

void print_banner(ostream& os);

#endif // _PTLXEN_H_
