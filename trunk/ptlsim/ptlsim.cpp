//
// PTLsim: Cycle Accurate x86-64 Simulator
// Shared Functions and Structures
//
// Copyright 2000-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <ptlsim.h>
#include <datastore.h>
#include <stats.h>

#include <elf.h>

#ifndef CONFIG_ONLY
//
// Global variables
//
PTLsimConfig config;
ConfigurationParser<PTLsimConfig> configparser;
PTLsimStats stats;

ostream logfile;
bool logenable = 0;
W64 sim_cycle = 0;
W64 iterations = 0;
W64 total_uops_executed = 0;
W64 total_uops_committed = 0;
W64 total_user_insns_committed = 0;
W64 total_basic_blocks_committed = 0;
#endif

void PTLsimConfig::reset() {
#ifdef PTLSIM_HYPERVISOR
  domain = (W64)(-1);
  run = 0;
  stop = 0;
  native = 0;
  kill = 0;
#endif

  core_name = "ooo";

  quiet = 0;
  log_filename = "logfile";
  loglevel = 0;
  start_log_at_iteration = infinity;
  start_log_at_rip = INVALIDRIP;
  log_on_console = 0;
  log_ptlsim_boot = 0;
  log_buffer_size = 524288;

  event_log_enabled = 0;
  event_log_ring_buffer_size = 32768;
  flush_event_log_every_cycle = 0;
  log_backwards_from_trigger_rip = INVALIDRIP;

  stats_filename.reset();
  snapshot_cycles = infinity;
  snapshot_now.reset();

#ifndef PTLSIM_HYPERVISOR
  // Starting Point
  start_at_rip = INVALIDRIP;
  include_dyn_linker = 1;
  trigger_mode = 0;
  pause_at_startup = 0;
#endif

  stop_at_user_insns = infinity;
  stop_at_iteration = infinity;
  stop_at_rip = INVALIDRIP;
  stop_at_user_insns_relative = infinity;
  insns_in_last_basic_block = 65536;
  flush_interval = infinity;
#ifdef PTLSIM_HYPERVISOR
  event_trace_record_filename.reset();
  event_trace_record_stop = 0;
  event_trace_replay_filename.reset();

  core_freq_hz = 0;
  timer_interrupt_freq_hz = 1000;
  pseudo_real_time_clock = 0;
  realtime = 0;
  mask_interrupts = 0;
  console_mfn = 0;
  pause = 0;
#endif

  perfect_cache = 0;

  dumpcode_filename = "test.dat";
  dump_at_end = 0;
  overshoot_and_dump = 0;

#ifndef PTLSIM_HYPERVISOR
  sequential_mode_insns = 0;
  exit_after_fullsim = 0;
#endif
}

template <>
void ConfigurationParser<PTLsimConfig>::setup() {
#ifdef PTLSIM_HYPERVISOR
  // Full system only
  section("PTLmon Control");
  add(domain,                       "domain",               "Domain to access");

  section("Action (specify only one)");
  add(run,                          "run",                  "Run under simulation");
  add(stop,                         "stop",                 "Stop current simulation run and wait for command");
  add(native,                       "native",               "Switch to native mode");
  add(kill,                         "kill",                 "Kill PTLsim inside domain (and ptlmon), then shutdown domain");
#endif

  section("Simulation Control");

  add(core_name,                    "core",                 "Run using specified core (-core <corename>)");

  section("General Logging Control");
  add(quiet,                        "quiet",                "Do not print PTLsim system information banner");
  add(log_filename,                 "logfile",              "Log filename (use /dev/fd/1 for stdout, /dev/fd/2 for stderr)");
  add(loglevel,                     "loglevel",             "Log level (0 to 99)");
  add(start_log_at_iteration,       "startlog",             "Start logging after iteration <startlog>");
  add(start_log_at_rip,             "startlogrip",          "Start logging after first translation of basic block starting at rip");
  add(log_on_console,               "consolelog",           "Replicate log file messages to console");
  add(log_ptlsim_boot,              "bootlog",              "Log PTLsim early boot and injection process (for debugging)");
  add(log_buffer_size,              "logbufsize",           "Size of PTLsim logfile buffer (not related to -ringbuf)");

  section("Event Ring Buffer Logging Control");
  add(event_log_enabled,            "ringbuf",              "Log all core events to the ring buffer for backwards-in-time debugging");
  add(event_log_ring_buffer_size,   "ringbuf-size",         "Core event log ring buffer size: only save last <ringbuf> entries");
  add(flush_event_log_every_cycle,  "flush-events",         "Flush event log ring buffer to logfile after every cycle");
  add(log_backwards_from_trigger_rip,"ringbuf-trigger-rip", "Print event ring buffer when first uop in this rip is committed");

  section("Statistics Database");
  add(stats_filename,               "stats",                "Statistics data store hierarchy root");
  add(snapshot_cycles,              "snapshot-cycles",      "Take statistical snapshot and reset every <snapshot> cycles");
  add(snapshot_now,                 "snapshot-now",         "Take statistical snapshot immediately, using specified name");
#ifndef PTLSIM_HYPERVISOR
  // Userspace only
  section("Start Point");
  add(start_at_rip,                 "startrip",             "Start at rip <startrip>");
  add(include_dyn_linker,           "excludeld",            "Exclude dynamic linker execution");
  add(trigger_mode,                 "trigger",              "Trigger mode: wait for user process to do simcall before entering PTL mode");
  add(pause_at_startup,             "pause-at-startup",     "Pause for N seconds after starting up (to allow debugger to attach)");
#endif

  section("Trace Stop Point");
  add(stop_at_user_insns,           "stopinsns",            "Stop after executing <stopinsns> user instructions");
  add(stop_at_iteration,            "stop",                 "Stop after <stop> cycles");
  add(stop_at_rip,                  "stoprip",              "Stop before rip <stoprip> is translated for the first time");
  add(stop_at_user_insns_relative,  "stopinsns-rel",        "Stop after executing <stopinsns-rel> user instructions relative to start of current run");
  add(insns_in_last_basic_block,    "bbinsns",              "In final basic block, only translate <bbinsns> user instructions");
  add(flush_interval,               "flushevery",           "Flush the pipeline every N committed instructions");

#ifdef PTLSIM_HYPERVISOR
  // Full system only
  section("Event Trace Recording");
  add(event_trace_record_filename,  "event-record",         "Save replayable events (interrupts, DMAs, etc) to this file");
  add(event_trace_record_stop,      "event-record-stop",    "Stop recording events");
  add(event_trace_replay_filename,  "event-replay",         "Replay events (interrupts, DMAs, etc) to this file, starting at checkpoint");

  section("Timers and Interrupts");
  add(core_freq_hz,                 "corefreq",             "Core clock frequency in Hz (default uses host system frequency)");
  add(timer_interrupt_freq_hz,      "timerfreq",            "Timer interrupt frequency in Hz");
  add(pseudo_real_time_clock,       "pseudo-rtc",           "Real time clock always starts at time saved in checkpoint");
  add(realtime,                     "realtime",             "Operate in real time: no time dilation (not accurate for I/O intensive workloads!)");
  add(mask_interrupts,              "maskints",             "Mask all interrupts (required for guaranteed deterministic behavior)");
  add(console_mfn,                  "console-mfn",          "Track the specified Xen console MFN");
  add(pause,                        "pause",                "Pause domain after using -native");
#endif

  section("Out of Order Core (ooocore)");
  add(perfect_cache,                "perfect-cache",        "Perfect cache performance: all loads and stores hit in L1");

  section("Miscellaneous");
  add(dumpcode_filename,            "dumpcode",             "Save page of user code at final rip to file <dumpcode>");
  add(dump_at_end,                  "dump-at-end",          "Set breakpoint and dump core before first instruction executed on return to native mode");
  add(overshoot_and_dump,           "overshoot-and-dump",   "Set breakpoint and dump core after first instruction executed on return to native mode");
#ifndef PTLSIM_HYPERVISOR
  // Userspace only
  add(sequential_mode_insns,        "seq",                  "Run in sequential mode for <seq> instructions before switching to out of order");
  add(exit_after_fullsim,           "exitend",              "Kill the thread after full simulation completes rather than going native");
#endif
};

#ifndef CONFIG_ONLY

ostream& operator <<(ostream& os, const PTLsimConfig& config) {
  return configparser.print(os, config);
}

void print_banner(ostream& os, const PTLsimStats& stats, int argc, char** argv) {
  utsname hostinfo;
  sys_uname(&hostinfo);

  os << "//  ", endl;
#ifdef __x86_64__
#ifdef PTLSIM_HYPERVISOR
  os << "//  PTLsim: Cycle Accurate x86-64 Full System SMP/SMT Simulator", endl;
#else
  os << "//  PTLsim: Cycle Accurate x86-64 Simulator", endl;
#endif
#else
  os << "//  PTLsim: Cycle Accurate x86 Simulator (32-bit version)", endl;
#endif
  os << "//  Copyright 1999-2006 Matt T. Yourst <yourst@yourst.com>", endl;
  os << "// ", endl;
  os << "//  Revision ", stringify(SVNREV), " (", stringify(SVNDATE), ")", endl;
  os << "//  Built ", __DATE__, " ", __TIME__, " on ", stringify(BUILDHOST), " using gcc-", 
    stringify(__GNUC__), ".", stringify(__GNUC_MINOR__), endl;
  os << "//  Running on ", stats.simulator.run.hostname, endl;
  os << "//  ", endl;
#ifndef PTLSIM_HYPERVISOR
  os << "//  Arguments: ";
  foreach (i, argc) {
    os << argv[i];
    if (i != (argc-1)) os << ' ';
  }
  os << endl;
  os << "//  Thread ", sys_getpid(), " is running in ", (ctx.use64 ? "64-bit x86-64" : "32-bit x86"), " mode", endl;
  os << "//  ", endl;
#endif
  os << endl;
  os << flush;
}

void collect_common_sysinfo(PTLsimStats& stats) {
  utsname hostinfo;
  sys_uname(&hostinfo);

  stringbuf sb;
#define strput(x, y) (strncpy((x), (y), sizeof(x)))

  sb.reset(); sb << __DATE__, " ", __TIME__;
  strput(stats.simulator.version.build_timestamp, sb);
  stats.simulator.version.svn_revision = SVNREV;
  strput(stats.simulator.version.svn_timestamp, stringify(SVNDATE));
  strput(stats.simulator.version.build_hostname, stringify(BUILDHOST));
  sb.reset(); sb << "gcc-", __GNUC__, ".", __GNUC_MINOR__;
  strput(stats.simulator.version.build_compiler, sb);

  stats.simulator.run.timestamp = sys_time(0);
  sb.reset(); sb << hostinfo.nodename, ".", hostinfo.domainname;
  strput(stats.simulator.run.hostname, sb);
  stats.simulator.run.native_hz = get_core_freq_hz();
  strput(stats.simulator.run.kernel_version, hostinfo.release);
}

void print_usage(int argc, char** argv) {
  cerr << "Syntax: ptlsim <executable> <arguments...>", endl;
  cerr << "All other options come from file /home/<username>/.ptlsim/path/to/executable", endl, endl;

  configparser.printusage(cerr, config);
}

stringbuf current_stats_filename;
stringbuf current_log_filename;

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

extern byte _binary_ptlsim_dst_start;
extern byte _binary_ptlsim_dst_end;
StatsFileWriter statswriter;

void capture_stats_snapshot(const char* name) {
  if unlikely (!statswriter) return;

  if (logable(1)|1) {
    logfile << "Making stats snapshot uuid ", statswriter.next_uuid();
    if (name) logfile << " named ", name;
    logfile << " at cycle ", sim_cycle, endl;
  }

  setzero(stats.snapshot_name);

  if (name) {
    stringbuf sb;
    strncpy(stats.snapshot_name, name, sizeof(stats.snapshot_name));
  }

  stats.snapshot_uuid = statswriter.next_uuid();
  statswriter.write(&stats, name);
}

void flush_stats() {
  statswriter.flush();
}

void print_sysinfo(ostream& os);

bool handle_config_change(PTLsimConfig& config, int argc, char** argv) {
  static bool first_time = true;

  if (config.log_filename.set() && (config.log_filename != current_log_filename)) {
    // Can also use "-logfile /dev/fd/1" to send to stdout (or /dev/fd/2 for stderr):
    backup_and_reopen_logfile();
    current_log_filename = config.log_filename;
  }

  logfile.setchain((config.log_on_console) ? &cout : null);

  if (config.stats_filename.set() && (config.stats_filename != current_stats_filename)) {
    // Can also use "-logfile /dev/fd/1" to send to stdout (or /dev/fd/2 for stderr):
    statswriter.open(config.stats_filename, &_binary_ptlsim_dst_start,
                     &_binary_ptlsim_dst_end - &_binary_ptlsim_dst_start,
                     sizeof(PTLsimStats));
    current_stats_filename = config.stats_filename;
  }

  logfile.setbuf(config.log_buffer_size);

  if ((config.loglevel > 0) & (config.start_log_at_rip == INVALIDRIP) & (config.start_log_at_iteration == infinity)) {
    config.start_log_at_iteration = 0;
  }

  // Force printing every cycle if loglevel >= 6:
  if (config.loglevel >= 6) {
    config.event_log_enabled = 1;
    config.flush_event_log_every_cycle = 1;
  }

  //
  // Fix up parameter defaults:
  //
  if (config.start_log_at_rip != INVALIDRIP) {
    config.start_log_at_iteration = infinity;
    logenable = 0;
  } else if (config.start_log_at_iteration != infinity) {
    config.start_log_at_rip = INVALIDRIP;
    logenable = 0;
  }

  if (first_time) {
    if (!config.quiet) {
      print_banner(cerr, stats, argc, argv);
      print_sysinfo(cerr);
#ifdef PTLSIM_HYPERVISOR
      if (!(config.run | config.native | config.kill))
        cerr << "PTLsim is now waiting for a command.", endl, flush;
#endif
    }
    print_banner(logfile, stats, argc, argv);
    print_sysinfo(logfile);
    cerr << flush;
    logfile << config;
    logfile.flush();
    first_time = false;
  }

#ifdef PTLSIM_HYPERVISOR
  int total = config.run + config.stop + config.native + config.kill;
  if (total > 1) {
    logfile << "Warning: only one action (from -run, -stop, -native, -kill) can be specified at once", endl, flush;
    cerr << "Warning: only one action (from -run, -stop, -native, -kill) can be specified at once", endl, flush;
  }
#endif

  return true;
}

Hashtable<const char*, PTLsimMachine*, 1> machinetable;

// Make sure the vtable gets compiled:
PTLsimMachine dummymachine;

bool PTLsimMachine::init(PTLsimConfig& config) { return false; }
int PTLsimMachine::run(PTLsimConfig& config) { return 0; }
void PTLsimMachine::update_stats(PTLsimStats& stats) { return; }
void PTLsimMachine::dump_state(ostream& os) { return; }

void PTLsimMachine::addmachine(const char* name, PTLsimMachine* machine) {
  machinetable.add(name, machine);
}

PTLsimMachine* PTLsimMachine::getmachine(const char* name) {
  PTLsimMachine** p = machinetable.get(name);
  if (!p) return null;
  return *p;
}

// Currently executing machine model:
PTLsimMachine* current_machine = null;

PTLsimMachine* PTLsimMachine::getcurrent() {
  return current_machine;
}

bool simulate(const char* machinename) {
  PTLsimMachine* machine = PTLsimMachine::getmachine(machinename);

  if (!machine) {
    logfile << "Cannot find core named '", machinename, "'", endl;
    return 0;
  }

  if (!machine->initialized) {
    logfile << "Initializing core '", machinename, "'", endl;
    if (!machine->init(config)) {
      logfile << "Cannot initialize core model; check its configuration!", endl;
      return 0;
    }
    machine->initialized = 1;
  }

  logfile << "Switching to simulation core '", machinename, "'...", endl, flush;
  logfile << "Stopping after ", config.stop_at_user_insns, " commits", endl, flush;
  cerr << "Switching to simulation core '", machinename, "'...", endl, flush;
  cerr << "  Stopping after ", config.stop_at_user_insns, " commits", endl, flush;

  sim_cycle = 0;

  current_machine = machine;
  machine->run(config);
  machine->update_stats(stats);
  current_machine = null;

  if (config.dumpcode_filename.set()) {
    byte insnbuf[256];
    PageFaultErrorCode pfec;
    Waddr faultaddr;
    Waddr rip = contextof(0).commitarf[REG_rip];
    int n = contextof(0).copy_from_user(insnbuf, rip, sizeof(insnbuf), pfec, faultaddr);
    logfile << "Saving ", n, " bytes from rip ", (void*)rip, " to ", config.dumpcode_filename, endl, flush;
    ostream(config.dumpcode_filename).write(insnbuf, n);
  }

  cerr << "  Done", endl, flush;

  return 0;
}

extern void shutdown_uops();

void shutdown_subsystems() {
  //
  // Let the subsystems close any special files or buffers
  // they may have open:
  //
  shutdown_uops();
}

#endif // CONFIG_ONLY
