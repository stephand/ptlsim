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
#include "xc_ptlsim.h"
}

#include <ptlhwdef.h>

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
#endif

LongModeLevel1PTE page_table_walk_longmode(W64 rawvirt, W64 toplevel_mfn);
ostream& print_page_table(ostream& os, LongModeLevel1PTE* ptes, W64 baseaddr);

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
      Context* guestctx;
      Context* ptlctx;
    } switch_to_native;
    struct {
      int dummy;
    } switch_to_sim;
    struct {
      Context* guestctx;
      Context* ptlctx;
      int exitcode;
    } terminate;
    struct {
      PageFrameType* pft;
      int count;
    } querypages;
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

//
// Notifications (upcalls) from ptlmon in dom0 -> guest domain
//
// These are asynchronous notifications, i.e. ptlmon does not
// expect a reply. If a reply is required, the guest must do
// a normal host call to send it.
//
// Inside PTLsim, the upcall handler is like an irq handler:
// it cannot do anything that may block, and that includes
// making any normal host calls. Instead, it should just
// set some flags for later processing.
//
enum {
  PTLSIM_UPCALL_NOP,
  PTLSIM_UPCALL_TERMINATE,
  PTLSIM_UPCALL_SWITCH_TO_NATIVE,
  PTLSIM_UPCALL_SET_LOGLEVEL,
  PTLSIM_UPCALL_SNAPSHOT_NOW,

  // Pseudo-upcalls (interpreted only by ptlmon):
  PTLSIM_UPCALL_SWITCH_TO_SIM,
  PTLSIM_UPCALL_WAIT_FOR_COMPLETION,
};

struct PTLsimUpcall {
  W32 op; // PTLSIM_UPCALL_...
  union {
    struct {
      int exitcode;
    } terminate;
    struct {
    } switch_to_sim;
    struct {
    } wait_for_completion;
    struct {
      int snapshot_before_switch;
    } switch_to_native;
    struct {
      int loglevel;
    } set_loglevel;
    struct {
      int create_named_snapshot;
      char snapshot_name[64];
    } snapshot_now;
  } call;
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
  PTLsimUpcall upcall;
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
  byte* startup_log_buffer;
  int startup_log_buffer_tail;
  int startup_log_buffer_size;
  int ptlsim_state; // (PTLSIM_STATE_xxx)
};

#ifndef EXCLUDE_BOOTINFO_SHINFO

static inline Context& contextof(int vcpu) { return bootinfo.ctx[vcpu]; }

static inline void* phys_to_ptl_virt(W64 rawphys) {
  return (void*)(PHYS_VIRT_BASE + rawphys);
}

static inline void* pte_to_ptl_virt(W64 rawvirt, const LongModeLevel1PTE& pte) {
  if (!pte.p) return null;
  return phys_to_ptl_virt((pte.phys << 12) + lowbits(rawvirt, 12));
}

inline int Context::copy_from_user(void* target, Waddr source, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr, bool forexec) {
  LongModeLevel1PTE pte;

  int n = 0;

  pfec = 0;
  pte = virt_to_pte(source);
  if ((!pte.p) | (forexec & pte.nx) | ((!kernel_mode) & (!pte.us))) {
    faultaddr = source;
    pfec.p = !pte.p;
    pfec.nx = pte.nx;
    pfec.us = ((!kernel_mode) & (!pte.us));
    return 0;
  }

  n = min(4096 - lowbits(source, 12), (Waddr)15);
  memcpy(target, pte_to_ptl_virt(source, pte), n);

  // All the bytes were on the first page
  if (n == bytes) return n;

  // Go on to second page, if present
  pte = virt_to_pte(source + n);
  if ((!pte.p) | (forexec & pte.nx) | ((!kernel_mode) & (!pte.us))) {
    faultaddr = source + n;
    pfec.p = !pte.p;
    pfec.nx = pte.nx;
    pfec.us = ((!kernel_mode) & (!pte.us));
    return n;
  }

  memcpy((byte*)target + n, pte_to_ptl_virt(source + n, pte), bytes - n);
  n = bytes;
  return n;
}

inline int Context::copy_to_user(Waddr target, void* source, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr) {
  LongModeLevel1PTE pte;

  pfec = 0;
  pte = virt_to_pte(target);
  if ((!pte.p) | (!pte.rw) | ((!kernel_mode) & (!pte.us))) {
    faultaddr = target;
    pfec.p = !pte.p;
    pfec.us = ((!kernel_mode) & (!pte.us));
    return 0;
  }

  byte* targetlo = (byte*)pte_to_ptl_virt(target, pte);
  int nlo = min(4096 - lowbits(target, 12), (Waddr)15);

  // All the bytes were on the first page
  if (nlo == bytes) {
    memcpy(targetlo, source, nlo);
    return bytes;
  }

  // Go on to second page, if present
  pte = virt_to_pte(target + nlo);
  if ((!pte.p) | (!pte.rw) | ((!kernel_mode) & (!pte.us))) {
    faultaddr = target + nlo;
    pfec.p = !pte.p;
    pfec.us = ((!kernel_mode) & (!pte.us));
    return nlo;
  }

  memcpy(pte_to_ptl_virt(target + nlo, pte), (byte*)source + nlo, bytes - nlo);
  memcpy(targetlo, source, nlo);

  return bytes;
}

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

#endif // _PTLXEN_H_
