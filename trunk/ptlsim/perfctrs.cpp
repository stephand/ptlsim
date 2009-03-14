//
// PTLsim: Cycle Accurate x86-64 Simulator
// Performance counters
//
// Copyright 1999-2008 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>
#include <ptlxen.h>
#include <stats.h>

static const int MAX_PERFCTRS = 2;

//
// Generic events
//

struct CounterConfig {
  W32 event;
  W32 unitmask;
};

struct CounterPairConfig {
  CounterConfig config[MAX_PERFCTRS];
};

enum {
  GENERIC_PERFCTR_UOPS_PER_X86_INSN      = 0,
  GENERIC_PERFCTR_L1D_MISS_RATE          = 1,
  GENERIC_PERFCTR_L1I_MISS_RATE          = 2,
  GENERIC_PERFCTR_DTLB_MISS_RATE         = 3,
  GENERIC_PERFCTR_L2_MISS_RATE           = 4,
  GENERIC_PERFCTR_BRANCH_MISPREDICT_RATE = 5,
  GENERIC_PERFCTR_COUNT                  = 6
};

static const char* generic_perfctr_names[GENERIC_PERFCTR_COUNT] = {
  "uops-per-x86-insn",
  "L1D-miss-rate",
  "L1I-miss-rate",
  "DTLB-miss-rate",
  "L2-miss-rate",
  "branch-mispredict-rate"
};

//
// Intel events
//

enum {
  INTEL_MSR_PERFCTR_BASE                      = 0xc1,
  INTEL_MSR_PERFEVTSEL_BASE                   = 0x186,
};

enum {
  INTEL_UNHALTED_CYCLES                       = 0x3c,
  INTEL_L2_REQUESTS                           = 0x2e,
  INTEL_L1D_REPL                              = 0x45,
  INTEL_INST_RETIRED                          = 0xc0,
  INTEL_UOPS_RETIRED                          = 0xc2,
  INTEL_BR_INST_RETIRED                       = 0xc4,
  INTEL_BR_INST_MISPRED                       = 0xc5,
  INTEL_MEM_LOAD_RETIRED                      = 0xcb,
  INTEL_L1I_READS                             = 0x80,
  INTEL_L1I_MISSES                            = 0x81,
  INTEL_ITLB_MISSES                           = 0x82,
};

enum {
  INTEL_UNHALTED_CYCLES_CORE                  = 0x01,
  INTEL_UNHALTED_CYCLES_BUS                   = 0x02,
  INTEL_UNHALTED_CYCLES_BUS_OTHER_CORE        = 0x04,
};

enum {
  INTEL_INST_RETIRED_ANY                      = 0x00,
  INTEL_INST_RETIRED_LOADS                    = 0x01,
  INTEL_INST_RETIRED_STORES                   = 0x02,
  INTEL_INST_RETIRED_OTHER                    = 0x04,
};

enum {
  INTEL_MEM_LOAD_RETIRED_L1D_MISS             = 0x01,
  INTEL_MEM_LOAD_RETIRED_L1D_LINE_MISS        = 0x02,
  INTEL_MEM_LOAD_RETIRED_L2_MISS              = 0x04,
  INTEL_MEM_LOAD_RETIRED_L2_LINE_MISS         = 0x08,
  INTEL_MEM_LOAD_RETIRED_DTLB_MISS            = 0x10,
};

enum {
  INTEL_UOPS_RETIRED_LD_ALU                   = 0x01,
  INTEL_UOPS_RETIRED_STD_STA                  = 0x02,
  INTEL_UOPS_RETIRED_CMP_BR                   = 0x04,
  INTEL_UOPS_RETIRED_NON_FUSED                = 0x08,
  INTEL_UOPS_RETIRED_ANY                      = 0x0f,
};

enum {
  INTEL_L2_REQUESTS_MISSES                    = 0x41,
  INTEL_L2_REQUESTS_ALL                       = 0x4f,
};

CounterPairConfig intel_core2_counter_config[GENERIC_PERFCTR_COUNT] = {
  {{ // GENERIC_PERFCTR_UOPS_PER_X86_INSN
    {INTEL_UOPS_RETIRED, INTEL_UOPS_RETIRED_ANY},
    {INTEL_INST_RETIRED, INTEL_INST_RETIRED_ANY},
  }},
  /*
  {{ // GENERIC_PERFCTR_UOPS_PER_X86_INSN
    {INTEL_UNHALTED_CYCLES, INTEL_UNHALTED_CYCLES_CORE},
    {INTEL_UNHALTED_CYCLES, INTEL_UNHALTED_CYCLES_CORE},
  }},
  */
  {{ // GENERIC_PERFCTR_L1D_MISS_RATE
    {INTEL_MEM_LOAD_RETIRED, INTEL_MEM_LOAD_RETIRED_L1D_MISS}, // Count ALL L1 misses, not just those that first initiate a line fetch
    {INTEL_INST_RETIRED, INTEL_INST_RETIRED_LOADS} // total retired x86 insns containing loads
  }},
  {{ // GENERIC_PERFCTR_L1I_MISS_RATE
    {INTEL_L1I_MISSES, 0},
    {INTEL_L1I_READS, 0},
  }},
  {{ // GENERIC_PERFCTR_DTLB_MISS_RATE
    {INTEL_MEM_LOAD_RETIRED, INTEL_MEM_LOAD_RETIRED_DTLB_MISS},
    {INTEL_INST_RETIRED, INTEL_INST_RETIRED_LOADS},
  }},
  {{ // GENERIC_PERFCTR_L2_MISS_RATE
    {INTEL_L2_REQUESTS, INTEL_L2_REQUESTS_MISSES},
    {INTEL_L2_REQUESTS, INTEL_L2_REQUESTS_ALL},
  }},
  {{ // GENERIC_PERFCTR_BRANCH_MISPREDICT_RATE
    {INTEL_BR_INST_MISPRED, 0},
    {INTEL_BR_INST_RETIRED, 0},
  }},
};

//
// AMD events
//
// Unlike Intel, AMD's events are actually well organized;
// in most cases the unit mask is 0 unless otherwise specified.
//

enum {
  AMD_MSR_PERFEVTSEL_BASE                     = 0xc0010000,
  AMD_MSR_PERFCTR_BASE                        = 0xc0010004,
};

enum {
  AMD_UNHALTED_CYCLES                         = 0x76,
  AMD_INST_RETIRED                            = 0xc0,
  AMD_UOPS_RETIRED                            = 0xc1,
  AMD_L1D_ACCESSES                            = 0x40,
  AMD_L1D_MISSES                              = 0x41, // only counts first miss on an outstanding line
  AMD_L1I_ACCESSES                            = 0x80,
  AMD_L1I_MISSES                              = 0x81,
  AMD_BR_INST_RETIRED                         = 0xc2,
  AMD_BR_INST_MISPRED                         = 0xc3,
  AMD_L1_DTLB_MISS_AND_L2_DTLB_HIT            = 0x45, // relative to L1D_ACCESSES
  AMD_L1_DTLB_AND_L2_DTLB_MISS                = 0x46, // relative to L1D_ACCESSES
  AMD_L2_CACHE_MISS                           = 0x7e,  // all misses through L2 (including page walk traffic)
  AMD_FETCH_STALL_TOTAL                       = 0x87, // may be overlapped of the stalls below
  AMD_RET_STACK_HITS                          = 0x88, // speculative, _DO NOT_ compare with retired branch ops!
  AMD_DECODER_EMPTY                           = 0xD0,
  AMD_DISPATCH_STALL_TOTAL                    = 0xD1,
  AMD_DISPATCH_STALL_BR_MISPRED               = 0xD2,
  AMD_DISPATCH_STALL_ROB_FULL                 = 0xD5,
  AMD_DISPATCH_STALL_ISSUEQ_FULL              = 0xD5,
  AMD_DISPATCH_STALL_LS_FULL                  = 0xD8
};

CounterPairConfig amd_k8_counter_config[GENERIC_PERFCTR_COUNT] = {
  {{ // GENERIC_PERFCTR_UOPS_PER_X86_INSN
    {AMD_UOPS_RETIRED, 0},
    {AMD_INST_RETIRED, 0},
  }},
  {{ // GENERIC_PERFCTR_L1D_MISS_RATE
    {AMD_L1D_MISSES, 0}, // total L1D misses (including speculative)
    {AMD_L1D_ACCESSES, 0} // total accesses (including speculative)
  }},
  {{ // GENERIC_PERFCTR_L1I_MISS_RATE
    {AMD_L1I_MISSES, 0}, // total L1D misses (including speculative)
    {AMD_L1I_ACCESSES, 0} // total accesses (including speculative)
  }},
  {{ // GENERIC_PERFCTR_DTLB_MISS_RATE
    {AMD_L1_DTLB_AND_L2_DTLB_MISS, 0}, // or AMD_L1_DTLB_MISS_AND_L2_DTLB_HIT
    {AMD_L1D_ACCESSES, 0},
  }},
  {{ // GENERIC_PERFCTR_L2_MISS_RATE
    {AMD_L2_CACHE_MISS, 0},
    {AMD_L1D_ACCESSES, 0},
  }},
  {{ // GENERIC_PERFCTR_BRANCH_MISPREDICT_RATE
    {AMD_BR_INST_MISPRED, 0},
    {AMD_BR_INST_RETIRED, 0},
  }},
};

//
// Common code
//
int perfctrs_setup_perfctr(int cpu, int index, W64 value) {
  PTLsimHostCall call;
  call.op = PTLSIM_HOST_SETUP_PERFCTRS;
  call.ready = 0;
  call.perfctr.cpu = cpu;
  call.perfctr.index = index;
  call.perfctr.value = value;
  return synchronous_host_call(call);
}

int perfctrs_write_perfctr(int cpu, int index, W64 value) {
  PTLsimHostCall call;
  call.op = PTLSIM_HOST_WRITE_PERFCTRS;
  call.ready = 0;
  call.perfctr.cpu = cpu;
  call.perfctr.index = index;
  call.perfctr.value = value;
  return synchronous_host_call(call);
}

PerfEvtSelMSR setup_perfevtsel(int event, int unitmask) {
  PerfEvtSelMSR sel = 0;
  sel.event = event;
  sel.unitmask = unitmask;
  sel.user = 1;
  sel.kernel = 0; // Do not monitor the hypervisor (but still catch guest pseudo kernel mode)
  sel.edge = 0;
  sel.pinctl = 0;
  sel.interrupt = 0;
  sel.enabled = 1;
  sel.threshold_lt_or_eq = 0;
  sel.events_per_cycle_threshold = 0;

  return sel;
}

bool perfctrs_init() {
  if likely (!config.perfctr_name.set()) return false;

  int generic_perfctr_id = -1;

  foreach (i, GENERIC_PERFCTR_COUNT) {
    if unlikely (strequal(config.perfctr_name, generic_perfctr_names[i])) {
      generic_perfctr_id = i;
      break;
    }
  }

  if unlikely (generic_perfctr_id < 0) {
    cerr << "Warning: -perfctr name '", config.perfctr_name, "' is not supported.", endl, flush;
    logfile << "Warning: -perfctr name '", config.perfctr_name, "' is not supported.", endl, flush;
    return false;
  }

  logfile << "Performance counters activated:", endl;
  logfile << "  CPU type: ", get_cpu_type_name(cpu_type), endl;
  logfile << "  Selected performance counter set #", generic_perfctr_id, " (", generic_perfctr_names[generic_perfctr_id], ")", endl;

  CounterPairConfig* cp = null;

  switch (cpu_type) {
  case CPU_TYPE_AMD_K8:
    cp = &amd_k8_counter_config[generic_perfctr_id];
    break;
  case CPU_TYPE_INTEL_CORE2:
    cp = &intel_core2_counter_config[generic_perfctr_id];
    break;
  case CPU_TYPE_INTEL_PENTIUM4:
    cp = null;
    logfile << "  This processor is not supported.", endl;
    break;
  default:
    cp = null;
    logfile << "  This processor is not supported.", endl;
    break;
  }

  if unlikely (!cp) return false;

  foreach (i, MAX_PERFCTRS) {
    PerfEvtSelMSR msr = setup_perfevtsel(cp->config[i].event, cp->config[i].unitmask);

    logfile << "  Set up counter ", i, " = ", (void*)W32(msr), endl;

    foreach (pcpu, 64) {
      if likely (!bit(bootinfo.phys_cpu_affinity, pcpu)) continue;
      // Assume all processor models have at least 2 perfctrs:
      logfile << "    Configuring Physical CPU ", pcpu, endl, flush;

      // Disable event counting
      perfctrs_setup_perfctr(pcpu, i, 0);

      // Clear counter
      perfctrs_write_perfctr(pcpu, i, 0);

      // Setup and enable event counting
      perfctrs_setup_perfctr(pcpu, i, msr);
    }
  }

  if (cpu_type == CPU_TYPE_AMD_K8) {
    // Take advantage of the other two counters: AMD gives us 4 instead of 2
    PerfEvtSelMSR msr2 = setup_perfevtsel(AMD_UNHALTED_CYCLES, 0);
    PerfEvtSelMSR msr3 = setup_perfevtsel(AMD_INST_RETIRED, 0);
    logfile << "  Set up counter 2 = ", (void*)W32(msr2), endl, flush;
    logfile << "  Set up counter 3 = ", (void*)W32(msr3), endl, flush;

    foreach (pcpu, 64) {
      if likely (!bit(bootinfo.phys_cpu_affinity, pcpu)) continue;
      // Assume all processor models have at least 2 perfctrs:
      logfile << "    Configuring Physical CPU ", pcpu, endl, flush;

      perfctrs_setup_perfctr(pcpu, 2, msr2);
      perfctrs_setup_perfctr(pcpu, 3, msr3);
    }
  }

  logfile << "  Configuration done and counters started", endl, flush;

  int limit = (cpu_type == CPU_TYPE_AMD_K8) ? 4 : 2;
  foreach (i, limit) {
    logfile << "  Initial pmc", i, ": ", intstring(rdpmc(i), 20), endl;
  }

#if 0
  //
  // Testing and calibration:
  //
  static const int SIZE = 8*1024*1024;
  byte* p = (byte*)ptl_alloc_private_pages(SIZE);

  memset(p, 0, SIZE);
  cerr << (SIZE/64)-1, " cache lines at ", p, endl, flush;

  int yyy = 0;

  barrier();
  perfctrs_start();

  foreach (i, (SIZE/64)-1) {
    barrier();
    byte* pp = p + (i * 64);
    yyy += pp[0] + pp[1];
    barrier();
  }

  perfctrs_stop();
  perfctrs_dump(logfile);
  cerr << "yyy = ", yyy, endl;

  ptl_free_private_pages(p, SIZE);
#endif

  return 0;
}

W64 tsc_start;
W64 tsc_stop;
W64 perfctr_start[4];
W64 perfctr_stop[4];

void perfctrs_start() {
  if unlikely (!config.perfctr_name.set()) return;
  int limit = (cpu_type == CPU_TYPE_AMD_K8) ? 4 : 2;

  flush_cache();
  barrier();
  tsc_start = rdtsc();

  foreach (i, limit) {
    perfctr_start[i] = rdpmc(i);
  }
}

void perfctrs_stop() {
  if unlikely (!config.perfctr_name.set()) return;
  barrier();

  int limit = (cpu_type == CPU_TYPE_AMD_K8) ? 4 : 2;

  tsc_stop = rdtsc();
  foreach (i, limit) {
    perfctr_stop[i] = rdpmc(i);
  }
}

void perfctrs_dump(ostream& os) {
  if unlikely (!config.perfctr_name.set()) return;

  int limit = (cpu_type == CPU_TYPE_AMD_K8) ? 4 : 2;

  os << "Performance counters (start, stop, delta):", endl;

  W64 tsc_delta = tsc_stop - tsc_start;

  os << "  Ctr ...........Start  ...........Stop ...........Delta", endl;

  os << "  TSC ", intstring(tsc_start, 16), " ", intstring(tsc_stop, 16), " ", intstring(tsc_delta, 16), endl;

  foreach (i, limit) {
    W64 delta = perfctr_stop[i] - perfctr_start[i];
    os << "  #", i, ": ", intstring(perfctr_start[i], 16), " ", intstring(perfctr_stop[i], 16), " ", intstring(delta, 16), endl;
  }
}
