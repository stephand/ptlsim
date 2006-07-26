//
// PTLsim: Cycle Accurate x86-64 Simulator
// Simulator Control
//
// Copyright 2000-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <elf.h>

#include <ptlsim.h>
#include <datastore.h>


CycleTimer total_time;

ostream logfile;
W64 sim_cycle = 0;
W64 user_insn_commits = 0;
W64 iterations = 0;
W64 total_uops_executed = 0;
W64 total_uops_committed = 0;
W64 total_user_insns_committed = 0;
W64 total_basic_blocks_committed = 0;

void PTLsimConfig::reset() {
  // Logging
  quiet = 0;
  log_filename = "ptlsim.log";
  loglevel = 0;
  start_log_at_iteration = infinity;

  // Statistics Database
  stats_filename.reset();
  snapshot_cycles = infinity;

  // Starting Point
  start_at_rip = 0;
  include_dyn_linker = 1;
  trigger_mode = 0;

  // Stopping Point
  stop_at_user_insns = infinity;
  stop_at_iteration = infinity;
  stop_at_rip = 0xffffffffffffffffULL;
  insns_in_last_basic_block = 65536;
  flush_interval = infinity;

  // Simulation Mode
  use_out_of_order_core = 1;
  sequential_mode_insns = 0;
  exit_after_fullsim = 0;

  // Code Dumps
  dumpcode_filename.reset();
  dump_at_end = 0;
  overshoot_and_dump = 0;
  pause_at_startup = 0;
  perfect_cache = 0;
}

PTLsimConfig config;
ConfigurationParser<PTLsimConfig> configparser;

template <>
void ConfigurationParser<PTLsimConfig>::setup() {
  section("Logging Control");
  add(quiet,                        "quiet",                "Do not print PTLsim system information banner");
  add(log_filename,                 "logfile",              "Log filename (use /dev/fd/1 for stdout, /dev/fd/2 for stderr)");
  add(loglevel,                     "loglevel",             "Log level (0 to 99)");
  add(start_log_at_iteration,       "startlog",             "Start logging after iteration <starlog>");

  section("Statistics Database");
  add(stats_filename,               "stats",                "Statistics data store hierarchy root");
  add(snapshot_cycles,              "snapshot",             "Take statistical snapshot and reset every <snapshot> cycles");

  section("Start Point");
  add(start_at_rip,                 "startrip",             "Start at rip <startrip>");
  add(include_dyn_linker,           "excludeld",            "Exclude dynamic linker execution");
  add(trigger_mode,                 "trigger",              "Trigger mode: wait for user process to do simcall before entering PTL mode");

  section("Stop Point");
  add(stop_at_user_insns,           "stopinsns",            "Stop after executing <stopinsns> user instructions");
  add(stop_at_iteration,            "stop",                 "Stop after <stop> cycles");
  add(stop_at_rip,                  "stoprip",              "Stop before rip <stoprip> is translated for the first time");
  add(insns_in_last_basic_block,    "bbinsns",              "In final basic block, only translate <bbinsns> user instructions");
  add(flush_interval,               "flushevery",           "Flush the pipeline every N committed instructions");

  section("Simulation Mode");
  add(sequential_mode_insns,        "seq",                  "Run in sequential mode for <seq> instructions before switching to out of order");
  add(exit_after_fullsim,           "exitend",              "Kill the thread after full simulation completes rather than going native");

  section("Code Dumps");
  add(dumpcode_filename,            "dumpcode",             "Save page of user code at final rip to file <dumpcode>");
  add(dump_at_end,                  "dump-at-end",          "Set breakpoint and dump core before first instruction executed on return to native mode");
  add(overshoot_and_dump,           "overshoot-and-dump",   "Set breakpoint and dump core after first instruction executed on return to native mode");
  add(pause_at_startup,             "pause-at-startup",     "Pause for N seconds after starting up (to allow debugger to attach)");
  add(perfect_cache,                "perfect-cache",        "Perfect cache hit rate");
};

ostream& operator <<(ostream& os, const PTLsimConfig& config) {
  return configparser.print(os, config);
}

DataStoreNode* dsroot = null;
W64 snapshotid;


void print_usage(int argc, const char** argv) {
  cerr << "Syntax: ptlsim <executable> <arguments...>", endl;
  cerr << "All other options come from file /home/<username>/.ptlsim/path/to/executable", endl, endl;

  configparser.printusage(cerr, config);
}

utsname hostinfo;

void print_banner(ostream& os, int argc, const char** argv) {
  sys_uname(&hostinfo);

  os << "//  ", endl;
#ifdef __x86_64__
  os << "//  PTLsim: Cycle Accurate x86-64 Simulator", endl;
#else
  os << "//  PTLsim: Cycle Accurate x86 Simulator (32-bit version)", endl;
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
  os << "//  Thread ", sys_getpid(), " is running in ", (ctx.use64 ? "64-bit x86-64" : "32-bit x86"), " mode", endl;
  os << "//  ", endl;
  os << endl;
  os << flush;
}

void print_banner(int argc, const char** argv) {
  print_banner(cerr, argc, argv);
}

const char* get_full_exec_filename() {
  static char full_exec_filename[1024];
  int rc = sys_readlink("/proc/self/exe", full_exec_filename, sizeof(full_exec_filename)-1);
  assert(inrange(rc, 0, (int)sizeof(full_exec_filename)-1));
  full_exec_filename[rc] = 0;
  return full_exec_filename;
}

time_t ptlsim_build_timestamp;

void backup_and_reopen_logfile() {
  if (config.log_filename) {
    if (logfile) logfile.close();
    stringbuf oldname;
    oldname << config.log_filename, ".backup";
    sys_unlink(oldname);
    sys_rename(config.log_filename, oldname);
    logfile.open(config.log_filename);
  }
}

int init_config(int argc, const char** argv) {
  char confroot[1024] = "";
  stringbuf sb;

  char* homedir = getenv("HOME");

  const char* execname = get_full_exec_filename();

  sb << (homedir ? homedir : "/etc"), "/.ptlsim", execname, ".conf";

  char args[4096];
  istream is(sb);
  if (!is) {
    cerr << "ptlsim: Warning: could not find '", sb, "', using defaults", endl;
  }

  const char* simname = "ptlsim";

  for (;;) {
    is >> readline(args, sizeof(args));
    if (!is) break;
    char* p = args;
    while (*p && (*p != '#')) p++;
    if (*p == '#') *p = 0;
    if (args[0]) break;
  }

  is.close();

  char* ptlargs[1024];

  ptlargs[0] = strdup(simname);
  int ptlargc = 0;
  char* p = args;
  while (*p && (ptlargc < (lengthof(ptlargs)-1))) {
    char* pbase = p;
    while ((*p != 0) && (*p != ' ')) p++;
    ptlargc++;
    ptlargs[ptlargc] = strndup(pbase, p - pbase);
    if (*p == 0) break;
    *p++;
    while ((*p != 0) && (*p == ' ')) p++;
  }

  // skip the leading argv[0]; just parse the options:
  configparser.parse(config, ptlargc, ptlargs+1);

  if (config.log_filename) {
    // Can also use "-logfile /dev/fd/1" to send to stdout (or /dev/fd/2 for stderr):
    backup_and_reopen_logfile();
  }

  if (!config.quiet) print_banner(cerr, argc, argv);
  print_banner(logfile, argc, argv);

  //
  // Fix up parameter defaults:
  //
  if ((config.start_log_at_iteration == infinity) && (config.loglevel > 0))
    config.start_log_at_iteration = 0;

  logfile << config;

  if (!config.stats_filename.empty()) {
    dsroot = new DataStoreNode("root");
    DataStoreNode& info = (*dsroot)("ptlsim");

    char timestring[64];

    stringbuf sb;
    sb.reset();
    info.add("timestamp", sys_time(null));

    info.add("svn-revision", stringify(SVNREV));
    info.add("svn-timestamp", stringify(SVNDATE));

    sb.reset();
    info.add("build-timestamp", ptlsim_build_timestamp);

    sb.reset();
    sb << stringify(BUILDHOST);
    info.add("build-hostname", sb);

    sb.reset();
    sb << "gcc-", stringify(__GNUC__), ".", stringify(__GNUC_MINOR__);
    info.add("build-compiler-version", sb);

    sb.reset();
    sb << hostinfo.nodename, ".", hostinfo.domainname;
    info.add("hostname", sb);

    info.add("kernel", hostinfo.release);
    info.add("kernel-build", hostinfo.version);
    info.add("arch", hostinfo.machine);


    info.addfloat("native-mhz", CycleTimer::gethz() / 1000000);

    info.add("executable", execname);

    sb.reset();
    foreach (i, argc) {
      sb << argv[i];
      if (i != (argc-1)) sb << ' ';
    }
    info.add("args", sb);
  }

  snapshotid = 0;

  return 0;
}

void save_stats() {
  total_time.stop();

  logfile << "(Capturing final stats bundle ", snapshotid, " at cycle ", sim_cycle, ")", endl, flush;

  if ((config.sequential_mode_insns > 0) && dsroot)
    seq_capture_stats((*dsroot)("seq"));

  if (config.use_out_of_order_core)
    ooo_capture_stats();

  if (dsroot) {
    if (config.use_out_of_order_core) 
      ooo_capture_stats((*dsroot)("final")); 
    ptl_mm_capture_stats((*dsroot)("ptlsim")("mm"));
  }

  if (!config.stats_filename.empty()) {
    logfile << "Saving stats to data store ", config.stats_filename, " at cycle ", sim_cycle, "...", endl, flush;

    odstream os(config.stats_filename);
    os << *dsroot;
  }

}

extern void shutdown_uops();

void shutdown_subsystems() {
  //
  // Let the subsystems close any special files or buffers
  // they may have open:
  //
  shutdown_uops();
}

// FP control mxcsr for PTLsim internal code:
W32 ptlsim_mxcsr;

void user_process_terminated(int rc) {
  x86_set_mxcsr(MXCSR_DEFAULT);
  logfile << "user_process_terminated(rc = ", rc, "): initiating shutdown at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits...", endl, flush;
  save_stats();
  logfile << "PTLsim exiting...", endl, flush;
  shutdown_subsystems();
  logfile.close();
  sys_exit(rc);
}

void show_stats_and_switch_to_native() {
  x86_set_mxcsr(MXCSR_DEFAULT);
  save_stats();

  if (config.exit_after_fullsim) {
    logfile << endl, "=== Exiting after full simulation on tid ", sys_gettid(), " at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " (", 
      sim_cycle, " cycles, ", total_user_insns_committed, " user commits, ", iterations, " iterations) ===", endl, endl;
    shutdown_subsystems();
    logfile.flush();
    sys_exit(0);
  }

  if (config.overshoot_and_dump | config.dump_at_end) {
    RIPVirtPhys rip(ctx.commitarf[REG_rip]);
    rip.update(ctx);

    BasicBlock* bb = bbcache(rip);
    if (!bb) {
      bb = bbcache.translate(ctx, rip);
    }

    assert(bb->transops[0].som);
    int bytes = bb->transops[0].bytes;
    Waddr ripafter = rip + (config.overshoot_and_dump ? bytes : 0);

    logfile << endl;
    logfile << "Overshoot and dump enabled:", endl;
    logfile << "- Return to rip ", rip, " in native mode", endl;
    if (config.overshoot_and_dump) logfile << "- Execute one x86 insn of ", bytes, " bytes at rip ", rip, endl;
    logfile << "- Breakpoint and dump core at rip ", (void*)ripafter, endl, endl, flush;

    int rc = sys_mprotect((void*)floor(ripafter, PAGE_SIZE), PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC);
    assert(!rc);

    *((byte*)ripafter) = 0xfb; // x86 invalid opcode
  }

  logfile.flush();
  switch_to_native_restore_context();
}

void switch_to_sim() {
  static const bool DEBUG = 0;


  logfile << "Baseline state:", endl;
  logfile << ctx.commitarf;

  Waddr origrip = (Waddr)ctx.commitarf[REG_rip];

  bool done = false;

  //
  // Swap the FP control registers to the user process version, so FP uopimpls
  // can use the real rounding control bits.
  //
  x86_set_mxcsr(ctx.mxcsr | MXCSR_EXCEPTION_DISABLE_MASK);

  if (config.sequential_mode_insns)
    done = sequential_core_toplevel_loop();

  done |= (config.dump_at_end | config.overshoot_and_dump);

  if (!done) {
    if (config.use_out_of_order_core)
      out_of_order_core_toplevel_loop();
  }

  //++MTY TESTING ONLY
  logfile << "Invalidating origrip ", hexstring(origrip, 64), endl;
  bbcache.invalidate_page(lowbits(origrip >> 12, 28)); // technically this is an MFN, but virt == phys

  // Sanitize flags (AMD and Intel CPUs also use bits 1 and 3 for reserved bits, but not for INV and WAIT like we do).
  ctx.commitarf[REG_flags] &= FLAG_NOT_WAIT_INV;

  if (!config.dumpcode_filename.empty()) {
    if (asp.check((void*)(Waddr)ctx.commitarf[REG_rip], PROT_READ)) {
      logfile << "Dumping code at ", (void*)(Waddr)ctx.commitarf[REG_rip], " to ", config.dumpcode_filename, "...", endl, flush;
      odstream os(config.dumpcode_filename);
      byte buf[256];
      memcpy(buf, (void*)(Waddr)ctx.commitarf[REG_rip], sizeof(buf));
      os.write(buf, 256);
      os.close();
    }
  }

  logfile << "Switching to native: returning to rip ", (void*)(Waddr)ctx.commitarf[REG_rip], endl, flush;

  show_stats_and_switch_to_native();
}

int main(int argc, const char** argv) {
  configparser.setup();
  config.reset();

  if (!inside_ptlsim) {
    int rc = 0;
    if (argc < 2) {
      print_banner(argc, argv);
      configparser.printusage(cout, config);
    } else {
      rc = ptlsim_inject(argc, argv);
    }
    cout.flush();
    cerr.flush();
    sys_exit(rc);
  }

  total_time.start();
  init_config(argc, argv);
  init_perfctrs();
  init_signal_callback();

  if (config.pause_at_startup) {
    logfile << "ptlsim: Paused for ", config.pause_at_startup, " seconds; attach debugger to PID ", sys_getpid(), " now...", endl, flush;
    cerr << "ptlsim: Paused for ", config.pause_at_startup, " seconds; attach debugger to PID ", sys_getpid(), " now...", endl, flush;
    sys_nanosleep((W64)config.pause_at_startup * 1000000000);
    cerr << "ptlsim: Continuing...", endl, flush;
    logfile << "ptlsim: Continuing...", endl, flush;
  }

  init_cache();
  init_uops();
  init_translate();

  void* interp_entry = (void*)(Waddr)ctx.commitarf[REG_rip];
  void* program_entry = (void*)(Waddr)find_auxv_entry(AT_ENTRY)->a_un.a_val;

  logfile << "loader: interp_entry ", interp_entry, ", program_entry ", program_entry, endl, flush;

  if (!config.trigger_mode) {
    if (config.start_at_rip)
      set_switch_to_sim_breakpoint((void*)(Waddr)config.start_at_rip);
    else if (config.include_dyn_linker)
      set_switch_to_sim_breakpoint(interp_entry);
    else set_switch_to_sim_breakpoint(program_entry);
  }

  if (!config.trigger_mode) start_perfctrs();

  // Context switch into virtual machine:
  switch_to_native_restore_context();
}
