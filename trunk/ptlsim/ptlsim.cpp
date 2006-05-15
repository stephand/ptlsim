//
// PTLsim: Cycle Accurate x86-64 Simulator
// Simulator Control
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
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
W64 total_user_insns_committed = 0;

W64 ptlsim_quiet = 0;
W64 loglevel = 0;
char* log_filename = null;
W64 include_dyn_linker = 1;
W64 start_at_rip = 0;
W64 start_at_rip_repeat = 1;
W64 stop_at_iteration = infinity;
W64 insns_in_last_basic_block = 65536;
W64 stop_at_rip = 0;
W64 stop_at_user_insns = infinity;
W64 sequential_mode_insns = 0;
W64 start_log_at_iteration = infinity;
W64 start_short_log_at_iteration = infinity;
W64 user_profile_only = 0;
W64 trigger_mode = 0;
W64 exit_after_fullsim;
char* stats_filename = null;
char* dumpcode_filename = null;
W64 perfect_cache = 0;
W64 snapshot_cycles = infinity;
W64 flush_interval = infinity;
W64 pause_at_startup = 0;
W64 overshoot_and_dump = 0;
W64 dump_at_end = 0;

W64 use_out_of_order_core = 1;
W64 use_out_of_order_core_dummy;

DataStoreNode* dsroot = null;
W64 snapshotid;


static ConfigurationOption optionlist[] = {
  {null,                                 OPTION_TYPE_SECTION, 0, "Logging Control", null},
  {"quiet",                              OPTION_TYPE_BOOL,    0, "Do not print PTLsim system information banner", &ptlsim_quiet},
  {"logfile",                            OPTION_TYPE_STRING,  0, "Log filename (use /dev/fd/1 for stdout, /dev/fd/2 for stderr)", &log_filename},
  {"loglevel",                           OPTION_TYPE_W64,     0, "Log level", &loglevel},
  {"startlog",                           OPTION_TYPE_W64,     0, "Start logging after iteration <startlog>", &start_log_at_iteration},
  {"shortlog",                           OPTION_TYPE_W64,     0, "Start summary logging after iteration <shortlog>", &start_short_log_at_iteration},

  {null,                                 OPTION_TYPE_SECTION, 0, "Statistics Database", null},
  {"stats",                              OPTION_TYPE_STRING,  0, "Statistics data store hierarchy root", &stats_filename},
  {"snapshot",                           OPTION_TYPE_W64,     0, "Take statistical snapshot and reset every <snapshot> cycles", &snapshot_cycles},

  {null,                                 OPTION_TYPE_SECTION, 0, "Trace Start Point", null},
  {"startrip",                           OPTION_TYPE_W64,     0, "Start at rip <startrip>", &start_at_rip},
  {"startrepeat",                        OPTION_TYPE_W64,     0, "Start only after passing <startrip> at least <startrepeat> times", &start_at_rip_repeat},
  {"excludeld",                          OPTION_TYPE_BOOL,    0, "Exclude dynamic linker execution", &include_dyn_linker},
  {"trigger",                            OPTION_TYPE_BOOL,    0, "Trigger mode: wait for user process to do simcall before entering PTL mode", &trigger_mode},

  {null,                                 OPTION_TYPE_SECTION, 0, "Trace Stop Point", null},
  {"stop",                               OPTION_TYPE_W64,     0, "Stop after <stop> iterations", &stop_at_iteration},
  {"stoprip",                            OPTION_TYPE_W64,     0, "Stop before rip <stoprip> is translated for the first time", &stop_at_rip},
  {"bbinsns",                            OPTION_TYPE_W64,     0, "In final basic block, only translate <bbinsns> user instructions", &insns_in_last_basic_block},
  {"stopinsns",                          OPTION_TYPE_W64,     0, "Stop after executing <stopinsns> user instructions", &stop_at_user_insns},
  {"flushevery",                         OPTION_TYPE_W64,     0, "Flush the pipeline every N committed instructions", &flush_interval},

  {null,                                 OPTION_TYPE_SECTION, 0, "Sequential and Native Control", null},
  {"seq",                                OPTION_TYPE_W64,     0, "Run in sequential mode for <seq> instructions before switching to out of order", &sequential_mode_insns},
  {"profonly",                           OPTION_TYPE_BOOL,    0, "Profile user code in native mode only; don't simulate anything", &user_profile_only},
  {"exitend",                            OPTION_TYPE_BOOL,    0, "Kill the thread after full simulation completes rather than going native", &exit_after_fullsim},
  {null,                                 OPTION_TYPE_SECTION, 0, "Debugging", null},
  {"dumpcode",                           OPTION_TYPE_STRING,  0, "Save page of user code at final rip to file <dumpcode>", &dumpcode_filename},
  {"dump-at-end",                        OPTION_TYPE_BOOL,    0, "Set breakpoint and dump core before first instruction executed on return to native mode", &dump_at_end},
  {"overshoot-and-dump",                 OPTION_TYPE_BOOL,    0, "Set breakpoint and dump core after first instruction executed on return to native mode", &overshoot_and_dump},
  {"pause-at-startup",                   OPTION_TYPE_W64,     0, "Pause for N seconds after starting up (to allow debugger to attach)", &pause_at_startup},
  {"perfect-cache",                      OPTION_TYPE_BOOL,    0, "Perfect cache hit rate", &perfect_cache},

  {"ooo",                                OPTION_TYPE_BOOL,    0, "Use out of order core (always)", &use_out_of_order_core_dummy},
};

void print_usage(int argc, const char** argv) {
  cerr << "Syntax: ptlsim <executable> <arguments...>", endl;
  cerr << "All other options come from file /home/<username>/.ptlsim/path/to/executable", endl, endl;

  ConfigurationParser(optionlist, lengthof(optionlist)).printusage(cerr);
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
  if (log_filename) {
    if (logfile) logfile.close();
    stringbuf oldname;
    oldname << log_filename, ".backup";
    sys_unlink(oldname);
    sys_rename(log_filename, oldname);
    logfile.open(log_filename);
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

  ConfigurationParser options(optionlist, lengthof(optionlist));
  // skip the leading argv[0]; just parse the options:
  options.parse(ptlargc, ptlargs+1);

  if (log_filename) {
    // Can also use "-logfile /dev/fd/1" to send to stdout (or /dev/fd/2 for stderr):
    backup_and_reopen_logfile();
  }

  if (!ptlsim_quiet) print_banner(cerr, argc, argv);
  print_banner(logfile, argc, argv);

  //
  // Fix up parameter defaults:
  //
  if ((start_log_at_iteration == infinity) && (loglevel > 0))
    start_log_at_iteration = 0;

  logfile << options;

  if (stats_filename) {
    dsroot = new DataStoreNode("root");
    DataStoreNode& info = (*dsroot)("ptlsim");

    char timestring[64];

    stringbuf sb;
    sb.reset();
    info.add("timestamp", sys_time(null));

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

  if ((sequential_mode_insns > 0) && dsroot)
    seq_capture_stats((*dsroot)("seq"));

  if (use_out_of_order_core)
    ooo_capture_stats();

  if (dsroot) {
    if (use_out_of_order_core) 
      ooo_capture_stats((*dsroot)("final")); 
  }

  if (stats_filename) {
    logfile << "Saving stats to data store ", stats_filename, " at cycle ", sim_cycle, "...", endl, flush;

    odstream os(stats_filename);
    os << *dsroot;
  }

}

// FP control mxcsr for PTLsim internal code:
W32 ptlsim_mxcsr;

void user_process_terminated(int rc) {
  x86_set_mxcsr(MXCSR_DEFAULT);
  logfile << "user_process_terminated(rc = ", rc, "): initiating shutdown at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits...", endl, flush;
  save_stats();
  logfile << "PTLsim exiting...", endl, flush;
  logfile.close();
  sys_exit(rc);
}

void show_stats_and_switch_to_native() {
  x86_set_mxcsr(MXCSR_DEFAULT);
  save_stats();

  if (exit_after_fullsim) {
    logfile << endl, "=== Exiting after full simulation on tid ", sys_gettid(), " at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " (", 
      sim_cycle, " cycles, ", total_user_insns_committed, " user commits, ", iterations, " iterations) ===", endl, endl;
    logfile.flush();
    sys_exit(0);
  }

  if (overshoot_and_dump | dump_at_end) {
    Waddr rip = ctx.commitarf[REG_rip];

    BasicBlock** bbp = bbcache(rip);
    BasicBlock* bb;
    if (bbp) {
      bb = *bbp;
    } else {
      bb = translate_basic_block((byte*)rip);
      bbcache.add(rip, bb);
    }

    assert(bb->transops[0].som);
    int bytes = bb->transops[0].bytes;
    Waddr ripafter = rip + (overshoot_and_dump ? bytes : 0);

    logfile << endl;
    logfile << "Overshoot and dump enabled:", endl;
    logfile << "- Return to rip ", (void*)rip, " in native mode", endl;
    if (overshoot_and_dump) logfile << "- Execute one x86 insn of ", bytes, " bytes at rip ", (void*)rip, endl;
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

  bool done = false;

  //
  // Swap the FP control registers to the user process version, so FP uopimpls
  // can use the real rounding control bits.
  //
  x86_set_mxcsr(ctx.commitarf[REG_mxcsr] | MXCSR_EXCEPTION_DISABLE_MASK);

  if (sequential_mode_insns)
    done = sequential_core_toplevel_loop();

  if (!done) {
    if (use_out_of_order_core)
      out_of_order_core_toplevel_loop();
  }

  // Sanitize flags (AMD and Intel CPUs also use bits 1 and 3 for reserved bits, but not for INV and WAIT like we do).
  ctx.commitarf[REG_flags] &= FLAG_NOT_WAIT_INV;

  if (dumpcode_filename) {
    if (asp.check((void*)(Waddr)ctx.commitarf[REG_rip], PROT_READ)) {
      logfile << "Dumping code at ", (void*)(Waddr)ctx.commitarf[REG_rip], " to ", dumpcode_filename, "...", endl, flush;
      odstream os(dumpcode_filename);
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
  if (!inside_ptlsim) {
    int rc = 0;
    if (argc < 2) {
      print_banner(argc, argv);
      print_usage(argc, argv);
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

  if (pause_at_startup) {
    logfile << "ptlsim: Paused for ", pause_at_startup, " seconds; attach debugger to PID ", sys_getpid(), " now...", endl, flush;
    cerr << "ptlsim: Paused for ", pause_at_startup, " seconds; attach debugger to PID ", sys_getpid(), " now...", endl, flush;
    sys_nanosleep((W64)pause_at_startup * 1000000000);
    cerr << "ptlsim: Continuing...", endl, flush;
    logfile << "ptlsim: Continuing...", endl, flush;
  }

  init_cache();
  init_uops();
  init_translate();

  void* interp_entry = (void*)(Waddr)ctx.commitarf[REG_rip];
  void* program_entry = (void*)(Waddr)find_auxv_entry(AT_ENTRY)->a_un.a_val;

  logfile << "loader: interp_entry ", interp_entry, ", program_entry ", program_entry, endl, flush;

  if (!user_profile_only && !trigger_mode) {
    if (start_at_rip)
      set_switch_to_sim_breakpoint((void*)(Waddr)start_at_rip);
    else if (include_dyn_linker)
      set_switch_to_sim_breakpoint(interp_entry);
    else set_switch_to_sim_breakpoint(program_entry);
  }

  if (!trigger_mode) start_perfctrs();

  // Context switch into virtual machine:
  switch_to_native_restore_context();
}
