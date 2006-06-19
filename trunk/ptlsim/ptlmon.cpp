//
// PTLsim: Cycle Accurate x86-64 Simulator
// PTLxen monitor and control program running in dom0
//
// Copyright 2005-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>
#include <config.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <mqueue.h>

typedef W16 domid_t;

#include <xen-types.h>
#include <xen/linux/privcmd.h>
#include <xen/linux/evtchn.h>
#include <ptlxen.h>

extern "C" {
#include <xenctrl.h>
};

#undef DEBUG

static inline W64 do_syscall_64bit(W64 syscallid, W64 arg1, W64 arg2, W64 arg3, W64 arg4, W64 arg5, W64 arg6) {
  W64 rc;
  asm volatile ("movq %5,%%r10\n"
                "movq %6,%%r8\n"
                "movq %7,%%r9\n"
                "syscall\n"
                : "=a" (rc)
                : "0" (syscallid),"D" ((W64)(arg1)),"S" ((W64)(arg2)),
                "d" ((W64)(arg3)), "g" ((W64)(arg4)), "g" ((W64)(arg5)),
                "g" ((W64)(arg6)) 
                : "r11","rcx","memory" ,"r8", "r10", "r9" );
	return rc;
}

static inline W32 do_syscall_32bit(W32 sysid, W32 arg1, W32 arg2, W32 arg3, W32 arg4, W32 arg5, W32 arg6) {
  W32 rc;
  asm volatile ("push %%rbp ; movl %[arg6],%%ebp ; int $0x80 ; pop %%rbp" : "=a" (rc) :
                "a" (sysid), "b" (arg1), "c" (arg2), "d" (arg3),
                "S" (arg4), "D" (arg5), [arg6] "r" (arg6));
  return rc;
}

static int do_privcmd(int xc_handle, unsigned int cmd, unsigned long data) {
  return ioctl(xc_handle, cmd, data);
}

int do_xen_hypercall(int xc_handle, privcmd_hypercall_t *hypercall) {
  return do_privcmd(xc_handle, IOCTL_PRIVCMD_HYPERCALL, (unsigned long)hypercall);
}

static int do_evtchn_op(int xc_handle, int cmd, void *arg, size_t arg_size) {
  int ret = -1;
  privcmd_hypercall_t hypercall;
  
  hypercall.op     = __HYPERVISOR_event_channel_op;
  hypercall.arg[0] = cmd;
  hypercall.arg[1] = (unsigned long)arg;
  
  if ( mlock(arg, arg_size) != 0 ) {
    goto out;
  }

  if ((ret = do_xen_hypercall(xc_handle, &hypercall)) < 0) {
    // cerr << "do_evtchn_op: HYPERVISOR_event_channel_op failed: ", ret, ", errno ", errno, " (", strerror(errno), ")", endl;
  }

  munlock(arg, arg_size);
  out:
  return ret;
}

static int xc_alloc_unbound(int xc, int domfrom, int domto) {
  evtchn_alloc_unbound_t req;
  req.dom = domto;
  req.remote_dom = domfrom;
  int rc = do_evtchn_op(xc, EVTCHNOP_alloc_unbound, &req, sizeof(req));
  cout << "Result: ", rc, " vs port ", req.port, endl;
  return (rc < 0) ? rc : req.port;
}

static int xc_bind_interdomain(int xc, int remotedom, int remoteport) {
  evtchn_bind_interdomain_t req;
  req.remote_dom = remotedom;
  req.remote_port = remoteport;
  int rc = do_evtchn_op(xc, EVTCHNOP_bind_interdomain, &req, sizeof(req));
  return (rc < 0) ? rc : req.local_port;
}

static int xc_send(int xc, int localport) {
  evtchn_send_t req;
  req.port = localport;
  int rc = do_evtchn_op(xc, EVTCHNOP_send, &req, sizeof(req));
  return rc;
}

static int xc_evtchn_unmask(int xc, int localport) {
  evtchn_unmask_t req;
  req.port = localport;
  int rc = do_evtchn_op(xc, EVTCHNOP_unmask, &req, sizeof(req));
  return rc;
}

#define barrier() asm volatile("": : :"memory")

#if defined(__i386__)

#define L1_PAGETABLE_SHIFT_PAE	12
#define L2_PAGETABLE_SHIFT_PAE	21
#define L3_PAGETABLE_SHIFT_PAE	30

#define L1_PAGETABLE_SHIFT		12
#define L2_PAGETABLE_SHIFT		22

#define L0_PAGETABLE_MASK_PAE	0x0000000ffffff000ULL
#define L1_PAGETABLE_MASK_PAE	0x1ffULL
#define L2_PAGETABLE_MASK_PAE	0x1ffULL
#define L3_PAGETABLE_MASK_PAE	0x3ULL

#define L0_PAGETABLE_MASK		0xfffff000ULL
#define L1_PAGETABLE_MASK		0x3ffULL
#define L2_PAGETABLE_MASK		0x3ffULL

#elif defined(__x86_64__)

#define L1_PAGETABLE_SHIFT_PAE	12
#define L2_PAGETABLE_SHIFT_PAE	21
#define L3_PAGETABLE_SHIFT_PAE	30
#define L4_PAGETABLE_SHIFT_PAE	39

#define L1_PAGETABLE_SHIFT		L1_PAGETABLE_SHIFT_PAE
#define L2_PAGETABLE_SHIFT		L2_PAGETABLE_SHIFT_PAE

#define L0_PAGETABLE_MASK_PAE	0x000000fffffff000ULL
#define L1_PAGETABLE_MASK_PAE	0x1ffULL
#define L2_PAGETABLE_MASK_PAE	0x1ffULL
#define L3_PAGETABLE_MASK_PAE	0x1ffULL
#define L4_PAGETABLE_MASK_PAE	0x1ffULL

#define L0_PAGETABLE_MASK		L0_PAGETABLE_MASK_PAE
#define L1_PAGETABLE_MASK		L1_PAGETABLE_MASK_PAE
#define L2_PAGETABLE_MASK		L2_PAGETABLE_MASK_PAE

#endif

#define mmap_invalid(addr) (((W64)(addr) & 0xfffffffffffff000) == 0xfffffffffffff000)
#define mmap_valid(addr) (!mmap_invalid(addr))

#define PTL_PAGE_POOL_BASE 0x70000000LL

void* sys_mmap(void* start, W64 length, int prot, int flags, int fd, off_t offset) {
  return mmap(start, length, prot, flags, fd, offset);
}

int sys_munmap(void* start, W64 length) {
  return munmap((void*)start, length);
}

int sys_mprotect(void* start, W64 length, int prot) {
  return mprotect(start, length, prot);
}

int sys_madvise(void* start, W64 length, int action) {
  return madvise(start, length, action);
}

void* ptl_alloc_private_pages(Waddr bytecount, int prot, Waddr base = 0, int extraflags = 0) {
  int flags = MAP_ANONYMOUS|MAP_NORESERVE | (base ? MAP_FIXED : 0);
  //flags |= (inside_ptlsim) ? MAP_SHARED : MAP_PRIVATE;
  flags |= MAP_PRIVATE;
  flags |= extraflags;
  if (base == 0) base = PTL_PAGE_POOL_BASE;
  void* addr = sys_mmap((void*)base, ceil(bytecount, PAGE_SIZE), prot, flags, 0, 0);

  return addr;
}

void* ptl_alloc_private_32bit_pages(Waddr bytecount, int prot, Waddr base) {
#ifdef __x86_64__
  int flags = MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE | (base ? MAP_FIXED : MAP_32BIT);
#else
  int flags = MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE | (base ? MAP_FIXED : 0);
#endif
  return sys_mmap((void*)base, ceil(bytecount, PAGE_SIZE), prot, flags, 0, 0);  
}

bool ptl_lock_private_pages(void* addr, Waddr bytecount) {
  return (mlock(addr, bytecount) == 0);
}

bool ptl_unlock_private_pages(void* addr, Waddr bytecount) {
  return (munlock(addr, bytecount) == 0);
}

void ptl_free_private_pages(void* addr, Waddr bytecount) {
  sys_munmap(addr, bytecount);
}

void ptl_zero_private_pages(void* addr, Waddr bytecount) {
  sys_madvise((void*)floor((Waddr)addr, PAGE_SIZE), bytecount, MADV_DONTNEED);
}

#define PSL_T 0x00000100 // single step bit in eflags

union DebugReg {
  struct {
    W64 l0:1, g0:1, l1:1, g1:1, l2:1, g2:1, l3:1, g3:1, le:1, ge:1, res1:3, gd:1, res2:2,
    t0:2, s0:2, t1:2, s1:2, t2:2, s2:2, t3:2, s3:2;
  } fields;
  W64 data;

  DebugReg() { }

  DebugReg(W64 data) { this->data = data; }

  operator W64() const { return data; }
};

#define DEBUGREG_TYPE_EXEC  0
#define DEBUGREG_TYPE_WRITE 1
#define DEBUGREG_TYPE_IO    2
#define DEBUGREG_TYPE_RW    3

#define DEBUGREG_SIZE_1     0
#define DEBUGREG_SIZE_2     1
#define DEBUGREG_SIZE_8     2
#define DEBUGREG_SIZE_4     3

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

// 
// These options are directly handled by PTLmon rather than PTLcore:
//
W64 domain = (W64)-1;
W64 action_inject = 0;
W64 action_switch_to_sim = 0;
W64 action_switch_to_native = 0;
W64 action_wait_for_completion = 0;

//
// The following options support live updates (adjustable at runtime);
// adjusting these causes an upcall into the domain running PTLsim
//
W64 clock_adj_factor = 1000; // Default slowdown of 1000x

char* log_filename = null;
W64 loglevel = 0;

char* stats_filename = null;
W64 snapshot_cycles = infinity;
W64 snapshot_now = 0;

//++MTY TODO: dump every snapshot to disk as it's taken - users are reporting problems with huge stats trees

W64 trigger_enabled = 0;
char* trigger_template_filename = null;
W64 trigger_template_rip = 0;

char* event_trace_record_filename = null;
W64 event_trace_stop = 0;
char* event_trace_replay_filename = 0;

static ConfigurationOption optionlist[] = {
  {null,                                 OPTION_TYPE_SECTION, 0, "PTLmon Control", null},
  {"domain",                             OPTION_TYPE_W64,     0, "Domain to access", &domain},
  {"inject",                             OPTION_TYPE_BOOL,    0, "Inject PTLsim into domain, or reboot existing PTLsim instance in domain", &action_inject},
  {"sim",                                OPTION_TYPE_BOOL,    0, "Switch to simulation mode using default core", &action_switch_to_sim},
  {"native",                             OPTION_TYPE_BOOL,    0, "Switch to native mode", &action_switch_to_native},
  {"wait",                               OPTION_TYPE_BOOL,    0, "Wait for PTLsim inside domain to complete fixed length run", &action_wait_for_completion},
  {"clockadj",                           OPTION_TYPE_W64,     0, "Clock adjustment factor (slowdown) for interrupts, DMAs and timers", &clock_adj_factor},

  {null,                                 OPTION_TYPE_SECTION, 0, "Logging", null},
  {"logfile",                            OPTION_TYPE_STRING,  0, "Log filename (use /dev/fd/1 for stdout, /dev/fd/2 for stderr)", &log_filename},
  {"loglevel",                           OPTION_TYPE_W64,     0, "Log level", &loglevel},

  {null,                                 OPTION_TYPE_SECTION, 0, "Statistics Database", null},
  {"stats",                              OPTION_TYPE_STRING,  0, "Statistics data store hierarchy root", &stats_filename},
  {"snapshot",                           OPTION_TYPE_W64,     0, "Take statistical snapshot and reset every <snapshot> cycles", &snapshot_cycles},
  {"snapshot-now",                       OPTION_TYPE_W64,     0, "Take statistical snapshot immediately", &snapshot_now},

  // NOTE: instead of templates, maybe we should just go with ptlsim utility (ptltrigger) running inside of VM to execute a special MSR write or something

  {null,                                 OPTION_TYPE_SECTION, 0, "Triggers", null},
  {"trigger",                            OPTION_TYPE_BOOL,    0, "Trigger mode: wait for trigger before switching to simulation mode", &trigger_enabled},
  {"trigger-file",                       OPTION_TYPE_STRING,  0, "Template ELF executable from which to take template basic block", &trigger_template_filename},
  {"trigger-rip",                        OPTION_TYPE_W64,     0, "RIP in template file of basic block to match (trigger when translated)", &trigger_template_rip},

  {null,                                 OPTION_TYPE_SECTION, 0, "Event Trace Recording", null},
  {"-event-record",                      OPTION_TYPE_STRING,  0, "Save replay events (interrupts, DMAs, etc) to this file", &event_trace_record_filename},
  {"-event-record-stop",                 OPTION_TYPE_BOOL,    0, "Stop recording events", &event_trace_stop},
  {"-event-replay",                      OPTION_TYPE_STRING,  0, "Replay events (interrupts, DMAs, etc) to this file, starting at Xen checkpoint", &event_trace_replay_filename},
};

union VirtAddr {
  struct { W64 offset:12, level1:9, level2:9, level3:9, level4:9, signext:16; } lm;
  struct { W64 offset:12, level1:9, level2:9, level3:9, level4:9, signext:16; } pae;
  struct { W32 offset:12, level1:10, level2:10; } x86;
  W64 raw;

  VirtAddr() { }
  VirtAddr(W64 data) { this->raw = data; }

  operator W64() const { return raw; }
};

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

// This is from ptlxen.bin.o:
extern byte _binary_ptlxen_bin_start;
extern byte _binary_ptlxen_bin_end;

struct XenController {
  int xc;
  int domain;
  mfn_t* pagelist;
  W64 pagecount;
  W64 maxpages;
  cpumap_t cpus;
  xc_domaininfo_t info;

  shared_info_t* shinfo;

  LongModeLevel4PTE* toplevel_page_table;

  LongModeLevel1PTE* ptes;
  int ptes_page_count;

  LongModeLevel1PTE* phys_ptes;
  int phys_ptes_page_count;

  byte* image;
  int ptl_page_count;
  int ptl_remaining_pages;

  mfn_t* pagedir_mfns;

  PTLsimMonitorInfo* bootinfo;

  int vcpu_count;
  int vcpu_online_count;

  int evtchnfd;
  int ptlsim_hostcall_port;
  int ptlsim_upcall_port;

  W64 total_machine_pages;
  W64 xen_hypervisor_start_va;
  int page_table_levels;

  vcpu_guest_context_t* frozen_ptlctx;
  vcpu_guest_context_t* frozen_guestctx;

  XenController() { reset(); }

  void reset() {
    xc = -1; domain = -1; pagelist = 0; pagecount = 0; shinfo = null; ptlsim_hostcall_port = -1;
    frozen_ptlctx = null;
    frozen_guestctx = null;
  }

  void* map_pages(mfn_t* mfns, size_t count, int prot = PROT_READ, void* base = null, int flags = 0) {
    if (base) flags |= MAP_FIXED;
    void* addr = mmap(base, count * PAGE_SIZE, prot, flags | MAP_SHARED, xc, 0);

    if (mmap_invalid(addr)) return null;

    privcmd_mmapbatch_t ioctlx; 
    ioctlx.num = count;
    ioctlx.dom = domain;
    ioctlx.addr = (unsigned long)addr;
    ioctlx.arr = mfns;
    int rc = ioctl(xc, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx);

    if (rc < 0) {
      cout << "ERROR: XenController::map_pages() failed: errno = ", strerror(errno), endl, flush;
      munmap(addr, count * PAGE_SIZE);
      return null;
    }
    return addr;
  }

  byte* map_page(mfn_t mfn, int prot = PROT_READ, void* addr = null) {
    mfn_t mfns[1];
    mfns[0] = mfn;

    return (byte*)map_pages(mfns, 1, prot, addr);
  }

  void unmap_pages(void* virt, int count) {
    int rc = munmap(virt, count * PAGE_SIZE);
    if (rc < 0) {
      cout << "unmap_pages(", virt, ", ", count, "): rc = ", rc, ", errno ", strerror(errno), endl, flush;
      assert(false);
    }
  }

  void unmap_page(void* virt) {
    unmap_pages(virt, 1);
  }

  mfn_t ptl_virt_to_mfn(void* virt) {
    W64 pfn = ((Waddr)virt) >> log2(PAGE_SIZE);
    W64 pfn_lo = ((Waddr)image) >> log2(PAGE_SIZE);
    W64 pfn_hi = pfn_lo + ptl_page_count - 1;
    // cout << "ptl_virt_to_mfn(", virt, "): pfn ", pfn, " vs [", pfn_lo, " to ", pfn_hi, "], rel ", (pfn - pfn_lo), endl, flush;
    if (!inrange(pfn, pfn_lo, pfn_hi)) {
      assert(false);
      return INVALID_MFN;
    }
    return pagedir_mfns[pfn - pfn_lo];
  }

  bool map_ptlsim_pages(shared_info_t* shinfo) {    
    static const bool DEBUG = 0;

    PTLsimStub* stub = (PTLsimStub*)(((byte*)shinfo) + PAGE_SIZE - sizeof(PTLsimStub));
    if (stub->magic != PTLSIM_STUB_MAGIC) {
      cerr << endl;
      cerr << "PTLsim error: domain ", domain, " does not have any physical memory reserved for PTLsim.", endl,
        endl,
        "Please use the reservedmem=xxx option in the domain config file, or use", endl,
        "the 'xm restore <filename> --reserve xxx' option to reserve the specified", endl,
        "number of megabytes and hide it from the guest OS. At least 32 MB is required.", endl,
        endl;

      return false;
    }

    bootinfo = (PTLsimMonitorInfo*)map_page(stub->boot_page_mfn);
    assert(bootinfo);

    assert(bootinfo->magic == PTLSIM_BOOT_PAGE_MAGIC);

    ptl_page_count = bootinfo->mfn_count;
    ptl_remaining_pages = bootinfo->avail_mfn_count;

    if (DEBUG) cout << "Map pagedir map mfn ", bootinfo->ptl_pagedir_map_mfn, endl, flush;
    LongModeLevel2PTE* pagedir_map_ptes = (LongModeLevel2PTE*)map_page(bootinfo->ptl_pagedir_map_mfn);
    assert(pagedir_map_ptes);

    mfn_t* pagedir_map_mfns = new mfn_t[bootinfo->ptl_pagedir_mfn_count];
    foreach (i, bootinfo->ptl_pagedir_mfn_count) { pagedir_map_mfns[i] = pagedir_map_ptes[i].next; }

    unmap_page(pagedir_map_ptes);

    if (DEBUG) {
      foreach (i, bootinfo->ptl_pagedir_mfn_count)
        cout << "  pagedir page ", intstring(i, 8), " -> mfn ", intstring(pagedir_map_mfns[i], 8), endl;
    }

    ptes = (LongModeLevel1PTE*)map_pages(pagedir_map_mfns, bootinfo->ptl_pagedir_mfn_count, PROT_READ);
    assert(ptes);

    delete[] pagedir_map_mfns;

    pagedir_mfns = new mfn_t[ptl_page_count];

    foreach (i, ptl_page_count) pagedir_mfns[i] = ptes[i].phys;

    PTLsimBootPageInfo* newbootinfo = bootinfo->boot_page;

    unmap_pages(ptes, bootinfo->ptl_pagedir_mfn_count);
    unmap_page(bootinfo);

    if (DEBUG) cout << "Remap first ", ptl_remaining_pages, " pages at ", (void*)PTLSIM_VIRT_BASE, endl, flush;
    image = (byte*)map_pages(pagedir_mfns, ptl_remaining_pages, PROT_READ|PROT_WRITE|PROT_EXEC, (void*)PTLSIM_VIRT_BASE, MAP_FIXED);

    void* page_table_virt_base = (void*)(PTLSIM_VIRT_BASE + (ptl_remaining_pages * PAGE_SIZE));
    W64 page_table_pages = (ptl_page_count - ptl_remaining_pages);
    if (DEBUG) cout << "Remap last ", page_table_pages, " pages at ", page_table_virt_base, endl, flush;
    assert(map_pages(pagedir_mfns + ptl_remaining_pages, page_table_pages, PROT_READ, page_table_virt_base, MAP_FIXED) == page_table_virt_base);

    bootinfo = (PTLsimMonitorInfo*)newbootinfo;

    ptes = bootinfo->ptl_pagedir;
    phys_ptes = bootinfo->phys_pagedir;
    phys_ptes_page_count = bootinfo->phys_pagedir_mfn_count;

    toplevel_page_table = bootinfo->toplevel_page_table;
    if (DEBUG) cout << "toplevel_page_table = ", toplevel_page_table, " (mfn ", ptl_virt_to_mfn(toplevel_page_table), ")", endl;
    if (DEBUG) cout << "toplevel_page_table_mfn = ", bootinfo->toplevel_page_table_mfn, endl, flush;
    assert(bootinfo->toplevel_page_table_mfn == ptl_virt_to_mfn(toplevel_page_table));
    assert(bootinfo->magic == PTLSIM_BOOT_PAGE_MAGIC);

    assert(bootinfo->ptl_pagedir != 0);

    if (DEBUG) {
      cout << "PTLsim mapped at ", image, ":", endl;
      cout << "Page counts:", endl;
      cout << "  Total pages:      ", intstring(ptl_page_count, 8), endl;
      cout << "  Remaining pages:  ", intstring(ptl_remaining_pages, 8), endl;
      cout << "Addresses:", endl;
      cout << "  Base:             ", (void*)image, endl;
      cout << "  PTL PTEs:         ", (void*)ptes, endl;
      cout << "  Physical PTEs:    ", (void*)phys_ptes, endl;
      cout << flush;
    }

    return true;
  }

  byte* alloc_page_from_end(mfn_t& mfn) {
    assert(ptl_remaining_pages > 0);
    ptl_remaining_pages--;
    byte* addr = image + (ptl_remaining_pages * PAGE_SIZE);
    cout << "alloc_page_from_end(): alloc page ", ptl_remaining_pages, ", virt ", addr, endl, flush;
    mfn = ptl_virt_to_mfn(addr);
    cout << "alloc_page_from_end(): alloc page ", ptl_remaining_pages, ", virt ", addr, ", mfn ", mfn, endl, flush; 
    memset(addr, 0, PAGE_SIZE);
    return addr;
  }

  void pin_page_table_page(void* virt, W64 prefix, int level) {
    assert(false);
    return;

    LongModeLevel1PTE* ptes = (LongModeLevel1PTE*)virt;
    assert(inrange(level, 1, 4));
    mfn_t mfn = ptl_virt_to_mfn(ptes);
    assert(mfn != INVALID_MFN);

    cout << "pin_page_table_page(", ptes, ", level ", level, ") => mfn ", mfn, endl, flush;

    int level_to_function[4] = {MMUEXT_PIN_L1_TABLE, MMUEXT_PIN_L2_TABLE, MMUEXT_PIN_L3_TABLE, MMUEXT_PIN_L4_TABLE};
    int func = level_to_function[level - 1];

    int rc = 0;
    mmuext_op op;

    // First unpin the table (this is absolutely required):
    op.cmd = MMUEXT_UNPIN_TABLE;
    op.arg1.mfn = mfn;
    rc = xc_mmuext_op(xc, &op, 1, domain);
    if (rc < 0) {
      cout << "Warning: while unpinning mfn ", mfn, ": MMUEXT_UNPIN_TABLE failed (probably not pinned)", endl;
    }

    op.cmd = func;
    op.arg1.mfn = mfn;

    // Pages can only be pinned once!
    rc = xc_mmuext_op(xc, &op, 1, domain);

    if (rc < 0) {
      cout << "ERROR: pin_page_table_page(", ptes, ", level ", level, ") (mfn ", mfn, "): rc = ", rc, endl, flush;
      if (level == 1) {
        print_page_table(cout, (LongModeLevel1PTE*)ptes, prefix);
      }
      cout.flush();

      assert(false);
    }
  }

  bool attach(int domain) {
    static const bool DEBUG = 1;

    int rc;

    reset();

    this->domain = domain;
    xc = xc_interface_open();
    if (xc < 0) {
      cerr << endl;
      cerr << "PTLsim error: cannot connect to Xen hypervisor (xc_interface_open failed: rc ", xc, ")", endl,
        endl,
        "Please make sure you are running as root, the machine is running under Xen,", endl,
        "and the appropriate Xen libraries are installed.", endl, endl;

      return false;
    }

    xen_capabilities_info_t xen_caps = "";
    xen_platform_parameters_t xen_params;

    assert(xc_version(xc, XENVER_platform_parameters, &xen_params) == 0);
    assert(xc_version(xc, XENVER_capabilities, &xen_caps) == 0);

    total_machine_pages = xc_memory_op(xc, XENMEM_maximum_ram_page, NULL);
    assert(total_machine_pages > 0);

    xen_hypervisor_start_va = xen_params.virt_start;

    if (strstr(xen_caps, "xen-3.0-x86_64"))
      page_table_levels = 4;
    else if (strstr(xen_caps, "xen-3.0-x86_32p"))
      page_table_levels = 3; 
    else if (strstr(xen_caps, "xen-3.0-x86_32"))
      page_table_levels = 2; 
    else {
      cerr << "XenController: hypervisor version or capabilities '", xen_caps, "' not supported", endl; 
      return false;
    }

    if (!strstr(xen_caps, "ptlsim")) {
      cerr << endl;
      cerr << "PTLsim error: the Xen hypervisor on this machine does not support", endl,
        "the required PTLsim extensions. Please apply the PTLsim patch to", endl,
        "enable these features. The installed Xen version is ", xen_caps, endl, endl;
      return false;
    }

    if (DEBUG) {
      cerr << "Xen Information:", endl;
      cerr << "  Running on Xen version ", xen_caps, endl;
      cerr << "  Total machine physical pages: ", total_machine_pages, " (", ((total_machine_pages * PAGE_SIZE) / 1024), " KB host physical memory)", endl;
      cerr << "  Xen is mapped at virtual address ", (void*)(Waddr)xen_hypervisor_start_va, endl;
      cerr << "  Page table has ", page_table_levels, " levels", endl;
    }

    //
    // Attach to target domain
    //
    dom0_op_t op;

    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = domain;
    rc = xc_dom0_op(xc, &op);

    memcpy(&info, &op.u.getdomaininfo, sizeof(info));
    vcpu_count = info.max_vcpu_id + 1;
    vcpu_online_count = info.nr_online_vcpus;

    if (rc | (info.domain != domain)) {
      cerr << endl;
      cerr << "PTLsim error: cannot access domain ", domain, " (error ", rc, ")", endl,
        "Please make sure the specified domain is running.", endl, endl;
      return false;
    }

    if (DEBUG) cerr << "PTLsim has connected to domain ", domain, ":", endl;

    if (info.flags & DOMFLAGS_PAUSED) {
      cerr << "  Domain was already paused", endl;
    } else if ((rc = xc_domain_pause(xc, domain))) {
      cerr << "XenController: PAUSE failed (", rc, ")", endl;
      return false;
    }

    maxpages = info.tot_pages;

    shinfo = (shared_info_t*)map_page(info.shared_info_frame, PROT_READ|PROT_WRITE);

    if(!shinfo) {
      cerr << "XenController: xc_map_foreign_range(info.shared_info_frame ", info.shared_info_frame, ") failed", endl;
      return false;
    }

    int max_pfn = shinfo->arch.max_pfn;

    if (DEBUG) {
      cerr << "  ", vcpu_online_count, " out of ", vcpu_count, " VCPUs online", endl;
      cerr << "  ", info.tot_pages, " total pages (", ((info.tot_pages * 4096) / (1024 * 1024)), " MB), limit ", ((info.tot_pages * 4096) / (1024 * 1024)), " MB", endl;
    }

    return map_ptlsim_pages(shinfo);
  }

  //
  //
  //
  W64 virt_to_mfn(W64 toplevel_mfn, W64 rawvirt) {
    VirtAddr virt(rawvirt);
    LongModeLevel4PTE* level4_base = null;
    LongModeLevel3PTE* level3_base = null;
    LongModeLevel2PTE* level2_base = null;
    LongModeLevel1PTE* level1_base = null;

    LongModeLevel4PTE level4;
    LongModeLevel3PTE level3;
    LongModeLevel2PTE level2;
    LongModeLevel1PTE level1;

    // cout << "Translating virt ", (void*)rawvirt, " (vpn ", (rawvirt >> 12), ") using toplevel mfn ", toplevel_mfn, ":", endl;

    level4_base = (LongModeLevel4PTE*)map_page(toplevel_mfn);
    level4 = level4_base[virt.lm.level4];
    // cout << "  Level 4: mfn ", intstring(toplevel_mfn, 12), ", pte ", intstring(virt.lm.level4, 4), " -> ", level4, endl;
    if (!level4.p) goto out_level4;

    level3_base = (LongModeLevel3PTE*)map_page(level4.next);
    level3 = level3_base[virt.lm.level3];
    // cout << "  Level 3: mfn ", intstring(level4.next, 12), ", pte ", intstring(virt.lm.level3, 4), " -> ", level3, endl;

    if (!level3.p) goto out_level3;

    level2_base = (LongModeLevel2PTE*)map_page(level3.next);
    level2 = level2_base[virt.lm.level2];
    // cout << "  Level 2: mfn ", intstring(level3.next, 12), ", pte ", intstring(virt.lm.level2, 4), " -> ", level2, endl;

    if (!level2.p) goto out_level2;
    if (level2.psz) {
      W64 mfn = level2.next;
      unmap_page(level4_base);
      unmap_page(level3_base);
      unmap_page(level2_base);
      return mfn; // 2MB/4MB huge pages
    }

    level1_base = (LongModeLevel1PTE*)map_page(level2.next);
    level1 = level1_base[virt.lm.level1];
    // cout << "  Level 1: mfn ", intstring(level2.next, 12), ", pte ", intstring(virt.lm.level1, 4), " -> ", level1, endl;

    if (!level4.p) goto out_level1;

    // cout << "  Final: mfn ", intstring(level1.phys, 12), endl;

    return level1.phys;

  out_level1:
    unmap_page(level1_base);
  out_level2:
    unmap_page(level2_base);
  out_level3:
    unmap_page(level3_base);
  out_level4:
    unmap_page(level4_base);
    return INVALID_MFN;
  }

  //
  // Prepare the initial PTLsim entry context
  //
  void prep_initial_context(vcpu_guest_context_t* ctx, int vcpu_count) {
    //
    //++MTY TODO: Put all other VCPUs into spin state (i.e. blocked)
    //

    foreach (i, vcpu_count) {
      vcpu_guest_context_t& ptlctx = ctx[i];
      // These are filled in later on a per-VCPU basis.
      // ptlctx.user_regs.rip = ehdr.e_entry;
      // ptlctx.user_regs.rsp = (Waddr)sp;
      // ptlctx.user_regs.rdi = (Waddr)si; // start info in %rdi (arg[0])
      //memset(ptlctx, 0, sizeof(ptlctx));

      // Use as a template:
      getcontext(i, ptlctx);

      ptlctx.ctrlreg[3] = (ptl_virt_to_mfn(toplevel_page_table) << log2(PAGE_SIZE));

      ptlctx.user_regs.cs = FLAT_KERNEL_CS;
      ptlctx.user_regs.ds = FLAT_KERNEL_DS;
      ptlctx.user_regs.ss = FLAT_KERNEL_SS;
      ptlctx.user_regs.es = FLAT_KERNEL_DS;
      ptlctx.user_regs.fs = 0;
      ptlctx.user_regs.gs = 0;
      ptlctx.user_regs.eflags = 0; // 1<<9 (set interrupt flag)
      ptlctx.user_regs.saved_upcall_mask = 1;

      memset(ptlctx.trap_ctxt, 0, sizeof(ptlctx.trap_ctxt));

#if defined(__i386__)
      ptlctx.event_callback_cs     = FLAT_KERNEL_CS;
      ptlctx.event_callback_eip    = 0;
      ptlctx.failsafe_callback_cs  = FLAT_KERNEL_CS;
      ptlctx.failsafe_callback_eip = 0;
#elif defined(__x86_64__)
      ptlctx.event_callback_eip    = 0;
      ptlctx.failsafe_callback_eip = 0;
      ptlctx.syscall_callback_eip  = 0;
#endif
    }
  }

  bool inject_ptlsim_image(int argc, char** argv, int stacksize) {
    static const bool DEBUG = 1;

    int rc;

    size_t bytes = &_binary_ptlxen_bin_end - &_binary_ptlxen_bin_start;
    const byte* data = &_binary_ptlxen_bin_start;

    if (DEBUG) cerr << "Injecting PTLsim into domain ", domain, ":", endl;
    if (DEBUG) cerr << "  PTLcore is ", bytes, " bytes @ virt addr ", image, endl, flush;

    // Copy ELF header
    memcpy(image, data, PTLSIM_BOOT_PAGE_PADDING);
    // Skip boot info page, hypercall page and shinfo
    int bytes_remaining = bytes - PTLSIM_ELF_SKIP_END;
    memcpy(image + PTLSIM_ELF_SKIP_END, data + PTLSIM_ELF_SKIP_END, bytes_remaining);

    Elf64_Ehdr& ehdr = *(Elf64_Ehdr*)image;
    Elf64_Phdr* phdr = (Elf64_Phdr*)(((byte*)&ehdr) + ehdr.e_phoff);

    byte* stacktop = image + (ptl_remaining_pages * PAGE_SIZE);
    byte* sp = stacktop;

    if (DEBUG) cerr << "  Setting up ", stacksize, "-byte stack starting at ", sp, endl, flush;

    sp -= (vcpu_count * sizeof(vcpu_guest_context_t));
    vcpu_guest_context_t* ctx = (vcpu_guest_context_t*)sp;

    bootinfo->vcpu_count = vcpu_count;
    bootinfo->stack_top = stacktop;
    bootinfo->stack_size = stacksize;

    // These will be filled in by PTLsim once it starts up:
    bootinfo->startup_log_buffer = null;
    bootinfo->startup_log_buffer_tail = 0;
    bootinfo->startup_log_buffer_size = 0;

    //
    // Build ptlcore command line arguments
    //
    sp -= (argc+1) * sizeof(char*);
    char** newargv = (char**)sp;

    bootinfo->argv = newargv;
    bootinfo->argc = argc;

    foreach (i, argc+1) {
      int n = strlen(argv[i])+1;
      sp -= n;
      memcpy(sp, argv[i], n);
      newargv[i] = (char*)sp;
    }

    // Align sp to 16-byte boundary according to what gcc expects:
    sp = floorptr(sp, 16);

    //
    // Prepare the heap
    //
    byte* end_of_image = image + ceil(phdr[0].p_memsz, PAGE_SIZE);
    Waddr bss_size = phdr[0].p_memsz - phdr[0].p_filesz;
    if (DEBUG) cerr << "  PTLcore file size ", phdr[0].p_filesz, ", virtual size ", phdr[0].p_memsz, ", end_of_image ", end_of_image, endl;
    bootinfo->heap_start = end_of_image;
    bootinfo->heap_end = stacktop - stacksize;
    if (DEBUG) cerr << "  Heap start ", bootinfo->heap_start, " to heap end ", bootinfo->heap_end, " (", ((bootinfo->heap_end - bootinfo->heap_start) / 1024), " kbytes)", endl;
    if (DEBUG) cerr << "  Zero ", bss_size, " bss bytes starting at ", (image + phdr[0].p_filesz), endl, flush;
    if (DEBUG) cerr << "  PTLsim has ", ptl_remaining_pages, " pages left out of ", ptl_page_count, " pages allocated", endl;

    memset(image + phdr[0].p_filesz, 0, bss_size);

    bootinfo->ctx = ctx;
    bootinfo->monitor_hostcall_port = ptlsim_hostcall_port;
    bootinfo->hostcall_port = -1; // will be filled in by PTLsim on connect
    bootinfo->monitor_upcall_port = ptlsim_upcall_port;
    bootinfo->upcall_port = -1; // will be filled in by PTLsim on connect
    bootinfo->hostreq.ready = 0;
    bootinfo->hostreq.op = PTLSIM_HOST_NOP;
    bootinfo->ptlsim_state = PTLSIM_STATE_INITIALIZING;

    vcpu_guest_context_t* ptlctx = new vcpu_guest_context_t[vcpu_count];
    prep_initial_context(ptlctx, vcpu_count);

    ptlctx[0].user_regs.rip = ehdr.e_entry;
    ptlctx[0].user_regs.rsp = (Waddr)sp;
    ptlctx[0].user_regs.rdi = (Waddr)bootinfo; // start info in %rdi (arg[0])

    frozen_guestctx = ctx;
    frozen_ptlctx = ptlctx;

    W64 target_cr3 = (ptl_virt_to_mfn(toplevel_page_table) << log2(PAGE_SIZE));
    if (DEBUG) cerr << "  PTLsim toplevel cr3 = ", (void*)ptlctx[0].ctrlreg[3], " (mfn ", (ptlctx[0].ctrlreg[3] >> log2(PAGE_SIZE)), ")", endl;
    if (DEBUG) cerr << "  Guest was interrupted at rip ", (void*)(Waddr)ctx[0].user_regs.rip, endl, flush;
    if (DEBUG) cerr << "  PTLsim entrypoint at ", (void*)ehdr.e_entry, endl;
    if (DEBUG) cerr << "  Ready, set, go!", endl, flush;

    switch_to_ptlsim(true);

    if (DEBUG) cerr << "  PTLsim is now in control inside domain ", domain, endl, flush;

    return true;
  }

  ostream& print_evtchn_mask(ostream& os, const char* title, const unsigned long* data) {
    os << title, ":", endl;
    foreach (i, 8) { // foreach (i, 64) {  // really 4096 possible events
      if (data[i]) {
        os << "  word ", intstring(i, -2), " = ", hexstring(data[i], 64), endl;
      }
    }
    return os;
  }

  void alloc_control_port() {
    evtchnfd = open("/dev/xen/evtchn", O_RDWR);
    assert(evtchnfd >= 0);

    ioctl_evtchn_bind_unbound_port alloc;
    alloc.remote_domain = domain;
    ptlsim_hostcall_port = ioctl(evtchnfd, IOCTL_EVTCHN_BIND_UNBOUND_PORT, &alloc);

    alloc.remote_domain = domain;
    ptlsim_upcall_port = ioctl(evtchnfd, IOCTL_EVTCHN_BIND_UNBOUND_PORT, &alloc);
  }

  void swap_context(vcpu_guest_context_t* saved, vcpu_guest_context_t* restored, int vcpu_count) {
    int rc;
    pause();

    foreach (i, vcpu_count) {
      rc = getcontext(i, saved[i]);
      rc = setcontext(i, restored[i]);
      shinfo->vcpu_info[i].evtchn_upcall_mask = restored[i].user_regs.saved_upcall_mask;
    }
  }

  //
  // Switch back to a frozen instance of PTLsim
  //
  void switch_to_ptlsim(bool first_time = false) {
    assert(frozen_guestctx);
    assert(frozen_ptlctx);
    if (frozen_ptlctx[0].event_callback_eip == 0) {
      // Block upcalls until PTLsim installs its handlers for the first time
      shinfo->vcpu_info[0].evtchn_upcall_mask = 1;
    } else {
      // Unblock everything
      shinfo->evtchn_mask[0] = 0;
      shinfo->evtchn_pending[0] = 0;
      shinfo->vcpu_info[0].evtchn_pending_sel = 0;
      shinfo->vcpu_info[0].evtchn_upcall_pending = 0;
      shinfo->vcpu_info[0].evtchn_upcall_mask = 0;
    }
    swap_context(frozen_guestctx, frozen_ptlctx, vcpu_count);

    //
    // Send event to kick-start it
    //
    if (!first_time) {
      bootinfo->hostreq.ready = 1;
      bootinfo->hostreq.rc = 0;
      ioctl_evtchn_notify notify;
      notify.port = ptlsim_hostcall_port;
      ioctl(evtchnfd, IOCTL_EVTCHN_NOTIFY, &notify);
    }

    bootinfo->ptlsim_state = PTLSIM_STATE_RUNNING;

    unpause();
  }

  int process_event() {
    int rc;

    W32 readyport = 0;
    rc = read(evtchnfd, &readyport, sizeof(readyport));
    // Re-enable it:
    rc = write(evtchnfd, &readyport, sizeof(readyport));

    bootinfo->hostreq.ready = 0;

    switch (bootinfo->hostreq.op) {
    case PTLSIM_HOST_SYSCALL: {
#if 0
      cout << "  syscall request ", bootinfo->hostreq.syscall.syscallid, " (",
        bootinfo->hostreq.syscall.arg1, ", ",
        bootinfo->hostreq.syscall.arg2, ", ",
        bootinfo->hostreq.syscall.arg3, ", ",
        bootinfo->hostreq.syscall.arg4, ", ",
        bootinfo->hostreq.syscall.arg5, ", ",
        bootinfo->hostreq.syscall.arg6, ")", endl, flush;
#endif
      bootinfo->hostreq.rc = do_syscall_64bit(bootinfo->hostreq.syscall.syscallid,
                                              bootinfo->hostreq.syscall.arg1,
                                              bootinfo->hostreq.syscall.arg2,
                                              bootinfo->hostreq.syscall.arg3,
                                              bootinfo->hostreq.syscall.arg4,
                                              bootinfo->hostreq.syscall.arg5,
                                              bootinfo->hostreq.syscall.arg6);
#if 0
      cout << "  syscall result = ", bootinfo->hostreq.rc, endl, flush;
#endif
      break;
    };
    case PTLSIM_HOST_SWITCH_TO_NATIVE:
    case PTLSIM_HOST_TERMINATE: {
      pause();
      assert(bootinfo->ptlsim_state == PTLSIM_STATE_RUNNING);
      frozen_ptlctx = bootinfo->hostreq.switch_to_native.ptlctx;
      frozen_guestctx = bootinfo->hostreq.switch_to_native.guestctx;
      swap_context(frozen_ptlctx, frozen_guestctx, vcpu_count);
      //
      // Unmask and clear all events, so the guest kernel gets them when it wakes up.
      // It may have missed some periodic events (timer, console) but those can be
      // discarded without ill effects (other than unavoidable jumpyness).
      //
      shinfo->evtchn_mask[0] = 0;
      shinfo->evtchn_pending[0] = 0;
      shinfo->vcpu_info[0].evtchn_pending_sel = 0;
      shinfo->vcpu_info[0].evtchn_upcall_pending = 0;
      shinfo->vcpu_info[0].evtchn_upcall_mask = 0;

      bootinfo->ptlsim_state = ((bootinfo->hostreq.op == PTLSIM_HOST_SWITCH_TO_NATIVE) ? PTLSIM_STATE_NATIVE : PTLSIM_STATE_NONE);
      cout << "ptlmon: Switched domain ", domain, " to native mode", endl, flush;
      bootinfo->hostreq.rc = 0;
      unpause();

      return (bootinfo->hostreq.op == PTLSIM_HOST_TERMINATE);
    };

    default:
      bootinfo->hostreq.rc = (W64)-ENOSYS;
    };
    bootinfo->hostreq.ready = 1;
    ioctl_evtchn_notify notify;
    notify.port = ptlsim_hostcall_port;
    rc = ioctl(evtchnfd, IOCTL_EVTCHN_NOTIFY, &notify);
    return 0;
  }

  //
  // Send an asynchronous upcall to PTLsim inside the domain
  //
  int send_upcall(const PTLsimUpcall& upcall) {
    memcpy(&bootinfo->upcall, &upcall, sizeof(upcall));
    ioctl_evtchn_notify notify;
    notify.port = ptlsim_upcall_port;
    int rc = ioctl(evtchnfd, IOCTL_EVTCHN_NOTIFY, &notify);
    return rc;
  }

  XenController(int domain) {
    attach(domain);
  }

  int detach() {
    static const bool DEBUG = 0;

    int rc;

    if ((xc < 0) | (domain < 0)) return 0;

    xc_domain_unpause(xc, domain);

    if (ptlsim_hostcall_port >= 0) {
      evtchn_close arg;
      arg.port = ptlsim_hostcall_port;
      int rc = do_evtchn_op(xc, EVTCHNOP_close, &arg, sizeof(arg));
    }

    if (ptlsim_upcall_port >= 0) {
      evtchn_close arg;
      arg.port = ptlsim_upcall_port;
      int rc = do_evtchn_op(xc, EVTCHNOP_close, &arg, sizeof(arg));
    }

    domain = -1;

    if (xc >= 0) assert(xc_interface_close(xc) == 0);

    xc = -1;

    return 0;
  }

  int getcontext(int vcpu, vcpu_guest_context_t& ctx) {
    vcpu_guest_context_t tempctx;
    assert(domain != 0);
    int rc = xc_vcpu_getcontext(xc, domain, vcpu, &tempctx);
    ctx = tempctx;
    return rc;
  }

  int setcontext(int vcpu, vcpu_guest_context_t& ctx) {
    vcpu_guest_context_t tempctx;
    tempctx = ctx;
    assert(domain != 0);
    int rc = xc_vcpu_setcontext(xc, domain, vcpu, &tempctx);
    return rc;
  }

  int pause() {
    int rc;
    if ((rc = xc_domain_pause(xc, domain))) {
      cout << "XenController: PAUSE failed (", rc, ")", endl;
      return rc;
    }
    return rc;
  }

  int unpause() {
    int rc;
    if ((rc = xc_domain_unpause(xc, domain))) {
      cout << "XenController: UNPAUSE failed (", rc, ")", endl;
      return rc;
    }
    return rc;
  }

  int enable_dirty_logging() {
    int rc = xc_shadow_control(xc, domain, DOM0_SHADOW_CONTROL_OP_ENABLE_LOGDIRTY, NULL, 0, NULL);

    if (rc < 0) {
      cout << "XenController::enable_dirty_logging(): couldn't enable: rc ", rc, endl;
    }

    return rc;
  }

  int disable_dirty_logging() {
    int rc = xc_shadow_control(xc, domain, DOM0_SHADOW_CONTROL_OP_OFF, NULL, 0, NULL);

    if (rc < 0) {
      cout << "XenController::disble_dirty_logging(): couldn't enable: rc ", rc, endl;
    }

    return rc;
  }

  int query_dirty_pages() {
    pause();

    cout << "Updating page map for ", info.max_pages, " total pages", endl;

    //
    // Get frame MFNs
    //
    mfn_t* pagelist = (mfn_t*)ptl_alloc_private_pages(info.max_pages * sizeof(mfn_t), PROT_READ | PROT_WRITE);
    assert(mmap_valid(pagelist));

    //
    // NOTE: All this does inside Xen is goes through the linked list of pages
    // belonging to the domain, and puts them in an array in arbitrary order.
    // The order is always the same when the domain is paused, however.
    //
    int pagecount = xc_get_pfn_list(xc, domain, pagelist, info.max_pages);
    cout << "Got ", pagecount, " out of max ", info.max_pages, " pages", endl;
    assert(pagecount > 0);

    //
    // Get frame types
    //
    unsigned long* typelist = (unsigned long*)ptl_alloc_private_pages(info.max_pages * sizeof(unsigned long), PROT_READ | PROT_WRITE);
    assert(mmap_valid(typelist));

    int pagetypecount = xc_get_pfn_type_batch(xc, domain, info.max_pages, typelist);
    cout << "Got ", pagecount, " out of max ", info.max_pages, " page types", endl;
    assert(pagetypecount > 0);
    assert(pagetypecount == pagecount);

    // Use DOM0_GETPAGEFRAMEINFO to find out which frames are data/shared/L1/L2/L3/L4-pagetable-pinned so we don't try to map them read-write

    //
    // Print the list (including pages belonging to PTLsim):
    //

    cout << "Page list of ", pagecount, " pages (", ((pagecount * PAGE_SIZE) / 1024), " kbytes):", endl;
    foreach (i, pagecount) {
      unsigned long type = typelist[i];
      cout << intstring(i, 8), ": mfn ", intstring(pagelist[i], 8), ", type ", hexstring(type, 32);
      if (type & L1TAB) cout << " L1";
      if (type & L2TAB) cout << " L2";
      if (type & L3TAB) cout << " L3";
      if (type & L4TAB) cout << " L4";
      if (type & LPINTAB) cout << " pintab";
      if (type & XTAB) cout << " invalid";
      cout << endl;
    }

    //
    // Assume the shared info frame and other system pages not in the list
    // are always dirty.
    //

    int mapbytes = ceil(((info.max_pages, 8) / 8), PAGE_SIZE);

    cout <<"XenController::query_dirty_pages(): ", mapbytes, " map bytes for ", info.max_pages, " pages", endl, flush;

    byte* dirty_page_bitmap = (byte*)ptl_alloc_private_pages(mapbytes, PROT_READ|PROT_WRITE);

    assert(mmap_valid(dirty_page_bitmap));
    assert(ptl_lock_private_pages(dirty_page_bitmap, mapbytes));

    dom0_shadow_control_stats_t stats;
    memset(&stats, 0, sizeof(stats));

    int dirtybitcount = xc_shadow_control(xc, domain, DOM0_SHADOW_CONTROL_OP_PEEK, (long unsigned int*)dirty_page_bitmap, maxpages, &stats);

    assert(ptl_unlock_private_pages(dirty_page_bitmap, mapbytes));

    cout << "Got ", dirtybitcount, " out of max ", info.max_pages, " dirty bits", endl;

    cout << "Shadow control stats:", endl;
    cout << "  ", intstring(stats.fault_count, 8), " page faults", endl;
    cout << "  ", intstring(stats.dirty_count, 8), " dirty pages", endl;
    cout << "  ", intstring(stats.dirty_net_count, 8), " dirty pages from network virtual DMA", endl;
    cout << "  ", intstring(stats.dirty_block_count, 8), " dirty pages from block virtual DMA", endl;

    int dirty_page_count = 0;

    cout << "Dirty pages:", endl;

    foreach (i, maxpages) {
      bool dirty = bit(dirty_page_bitmap[i >> 3], lowbits(i, 3));
      mfn_t mfn = pagelist[i];

      if (dirty) {
        unsigned long type = typelist[i];
        cout << intstring(i, 8), ": mfn ", intstring(pagelist[i], 8), ", type ", hexstring(type, 32);
        if (type & L1TAB) cout << " L1";
        if (type & L2TAB) cout << " L2";
        if (type & L3TAB) cout << " L3";
        if (type & L4TAB) cout << " L4";
        if (type & LPINTAB) cout << " pintab";
        if (type & XTAB) cout << " invalid";
        cout << endl;
      }
    }

    ptl_free_private_pages(dirty_page_bitmap, mapbytes);
    ptl_free_private_pages(typelist, info.max_pages * sizeof(unsigned long));
    ptl_free_private_pages(pagelist, info.max_pages * sizeof(mfn_t));

    return 0;
  }

  ostream& print_log_buffer(ostream& os) const {
    os << "========================================================", endl;
    os << "Log buffer @ ", bootinfo->startup_log_buffer, " (tail ", bootinfo->startup_log_buffer_tail, ", size ", bootinfo->startup_log_buffer_size, ")", endl;
    if (!bootinfo->startup_log_buffer) {
      os << "  (log buffer not initialized)", endl;
      return os;
    }

    // Must be a power of two:
    W32 log_buffer_mask = bootinfo->startup_log_buffer_size - 1;

    int t = bootinfo->startup_log_buffer_tail;

    foreach (i, bootinfo->startup_log_buffer_size) {
      void* p = (void*)&bootinfo->startup_log_buffer[t];
      char c = bootinfo->startup_log_buffer[t];
      if (c) os << (char)c;
      t = (t + 1) & (bootinfo->startup_log_buffer_size - 1);
    }

    os << "(end of log buffer)", endl;
    return os;
  }

  ~XenController() {
    detach();
  }
};

utsname hostinfo;

void print_banner(ostream& os, int argc, char** argv) {
  sys_uname(&hostinfo);

  os << "//  ", endl;
#ifdef __x86_64__
  os << "//  PTLsim: Cycle Accurate Full System SMP/SMT x86-64 Simulator", endl;
#else
  os << "//  PTLsim: Cycle Accurate Full System SMP/SMT x86 Simulator (32-bit version)", endl;
#endif
  os << "//  Copyright 1999-2006 Matt T. Yourst <yourst@yourst.com>", endl;
  os << "// ", endl;
  os << "//  Revision ", stringify(SVNREV), " (", stringify(SVNDATE), ")", endl;
  os << "//  Built ", __DATE__, " ", __TIME__, " on ", stringify(BUILDHOST), " using gcc-", 
    stringify(__GNUC__), ".", stringify(__GNUC_MINOR__), endl;
  os << "//  Running on ", hostinfo.nodename, ".", hostinfo.domainname, " (", (int)math::floor(CycleTimer::gethz() / 1000000.), " MHz)", endl;
  os << "//  ", endl;
  os << "//  Arguments: ";
  foreach (i, argc) {
    os << argv[i];
    if (i != (argc-1)) os << ' ';
  }
  os << endl;
  os << "//  ", endl, endl;
  os << flush;
}

void print_banner(int argc, char** argv) {
  print_banner(cerr, argc, argv);
}

extern "C" void sigterm_handler(int sig, siginfo_t* si, void* contextp) {
  sys_exit(0);
}

int send_request_to_ptlmon(int domain, const PTLsimUpcall& upcall) {
  int rc;
  int sd = socket(PF_LOCAL, SOCK_STREAM, 0);
  assert(sd >= 0);

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));

  stringbuf sockname;
  sockname << "/tmp/ptlmon-domain-", domain;

  addr.sun_family = AF_LOCAL;
  strncpy(addr.sun_path, (char*)sockname, sizeof(addr.sun_path)-1);

  if (connect(sd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) < 0) {
    cout << "ERROR: Cannot connect to PTLmon control socket '", sockname, "': error ", strerror(errno), endl;
    return -1;
  }

  rc = sys_write(sd, &upcall, sizeof(upcall));
  cout << "Sent message (rc = ", rc, " vs size ", sizeof(upcall), "); wait for reply...", endl, flush;

  int upcallrc = 0;
  rc = sys_read(sd, &upcallrc, sizeof(upcallrc)); 
  cout << "Received upcall reply: bytes = ", rc, ", upcallrc ", upcallrc, endl, flush;

  sys_close(sd);

  return 0;
}

int ptlmon_thread(int domain) {
  return 0;
}

int main(int argc, char** argv) {
  int rc;

  print_banner(argc, argv);

  ConfigurationParser options(optionlist, lengthof(optionlist));

  argc--; argv++;

  if (!argc) {
    options.printusage(cout);
    return -1;
  }

  int n = options.parse(argc, argv);

  if ((W64s)domain < 0) {
    cout << "Please use the -domain XXX option to specify a Xen domain to access.", endl, endl;
    return -2;
  }

  if (action_switch_to_sim) {
    PTLsimUpcall upcall;
    upcall.op = PTLSIM_UPCALL_SWITCH_TO_SIM;
    send_request_to_ptlmon(domain, upcall);
  } else if (action_switch_to_native) {
    PTLsimUpcall upcall;
    upcall.op = PTLSIM_UPCALL_SWITCH_TO_NATIVE;
    send_request_to_ptlmon(domain, upcall);
  } else if (action_wait_for_completion) {
    PTLsimUpcall upcall;
    upcall.op = PTLSIM_UPCALL_WAIT_FOR_COMPLETION;
    send_request_to_ptlmon(domain, upcall);
  } else {
    // Inject into guest for first time, or reboot PTLsim within guest
    XenController xc;
    if (!xc.attach(domain)) return -1;
    xc.alloc_control_port();
    xc.inject_ptlsim_image(argc, argv, 1048576);

    int rc = 0;
    int sd = socket(PF_LOCAL, SOCK_STREAM, 0);
    assert(sd >= 0);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));

    stringbuf sockname;
    sockname << "/tmp/ptlmon-domain-", domain;
    unlink(sockname);

    addr.sun_family = AF_LOCAL;
    strncpy(addr.sun_path, (char*)sockname, sizeof(addr.sun_path)-1);

    if (bind(sd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) < 0) {
      cout << "ERROR: Cannot bind control socket '", sockname, "': error ", strerror(errno), endl;
      return 0;
    }

    // Start listening in pre-fork to avoid race:
    if ((rc = listen(sd, 0)) < 0) {
      cout << "ERROR: Cannot bind control socket '", sockname, "': error ", strerror(errno), endl;
      return 0;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sigterm_handler;
    sa.sa_flags = SA_SIGINFO;
    assert(sys_rt_sigaction(SIGXCPU, &sa, NULL, sizeof(W64)) == 0);

    //
    // Child process: act as server
    //

    int waitfd = epoll_create(1);
    assert(waitfd >= 0);
    epoll_event eventctl;

    memset(&eventctl, 0, sizeof(eventctl));
    eventctl.events = EPOLLIN|EPOLLPRI|EPOLLERR|EPOLLHUP;
    eventctl.data.fd = sd;
    assert(epoll_ctl(waitfd, EPOLL_CTL_ADD, sd, &eventctl) == 0);

    memset(&eventctl, 0, sizeof(eventctl));
    eventctl.events = EPOLLIN|EPOLLPRI|EPOLLERR|EPOLLHUP;
    eventctl.data.fd = xc.evtchnfd;
    assert(epoll_ctl(waitfd, EPOLL_CTL_ADD, xc.evtchnfd, &eventctl) == 0);

    for (;;) {
      epoll_event event;
      memset(&event, 0, sizeof(event));
      int rc = epoll_wait(waitfd, &event, 1, -1);
      if (rc < 0) break;

      if (event.data.fd == sd) {
        sockaddr_un acceptaddr;
        socklen_t acceptlen = sizeof(acceptaddr);
        int acceptsd = accept(sd, (sockaddr*)&acceptaddr, &acceptlen);
        // NOTE: potential denial of service here, if data hasn't arrived yet (can hold up servicing hostcalls from ptlcore): use a timeout

        int upcallrc = 0;
        PTLsimUpcall upcall;
        rc = sys_read(acceptsd, &upcall, sizeof(upcall));
        upcallrc = -EINVAL;

        if (rc == sizeof(upcall)) {
          // Check for upcalls handled directly by ptlmon:
          switch (upcall.op) {
          case PTLSIM_UPCALL_SWITCH_TO_SIM:
            if (xc.bootinfo->ptlsim_state == PTLSIM_STATE_NATIVE) {
              cout << "Switching domain from native mode back to PTLsim mode...", endl, flush;
              xc.switch_to_ptlsim();
              cout << "Domain ", domain, " switched back to PTLsim mode...", endl, flush;
              upcallrc = 0;
            } else {
              cout << "ptlmon: Warning: cannot switch to simulation mode: domain ", domain, " was already in state ", xc.bootinfo->ptlsim_state, endl, flush;
            }
            break;
            // case PTLSIM_UPCALL_WAIT_FOR_COMPLETION: { }
          default:
            cout << "Sending upcall...", endl, flush;
            xc.send_upcall(upcall);
            cout << "Sent upcall!", endl, flush;

            upcallrc = 0;
            break;
          }
        }

        sys_write(acceptsd, &upcallrc, sizeof(upcallrc));
        sys_close(acceptsd);
      } else if (event.data.fd == xc.evtchnfd) {
        int done = xc.process_event();

        if (done) {
          cout << "PTLsim exited", endl, flush;
          xc.print_log_buffer(cout);
          cout << flush;
          break;
        }
      }
    }

    cout << "Process ", sys_gettid(), " exiting loop...", endl, flush;

    xc.unpause();
    xc.detach();

    cout << "All done!", endl, flush;
    cerr << flush;

    sys_exit(0);
  }

  return 0;
}

/*
  cout << "After notify:", endl, flush;
  cout << "  evtchn_mask = ", *(bitvec<64>*)(&shinfo->evtchn_mask[0]), endl;
  cout << "  evtchn_pend = ", *(bitvec<64>*)(&shinfo->evtchn_pending[0]), endl;
  cout << "  evtchn_upcall_mask = ", shinfo->vcpu_info[0].evtchn_upcall_mask, endl, flush;
  cout << "  evtchn_upcall_pend = ", shinfo->vcpu_info[0].evtchn_upcall_pending, endl, flush;
  
  print_log_buffer(cout);
  cout << flush;
*/
