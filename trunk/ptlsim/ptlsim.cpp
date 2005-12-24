//
// PTLsim: Cycle Accurate x86-64 Simulator
// Simulator Control
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>

#include <stdio.h>
#include <elf.h>
#include <asm/unistd.h>

#include <ptlsim.h>
#include <datastore.h>


CycleTimer total_time;

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

void user_process_terminated(int rc) {
  logfile << "user_process_terminated(rc = ", rc, "): initiating PTL shutdown...", endl, flush;
  save_stats();
  logfile << "PTLsim exiting...", endl, flush;
  logfile.close();
  remove_exit_callback();
  sys_exit(rc);
}

void show_stats_and_switch_to_native() {
  save_stats();

  if (exit_after_fullsim) {
    logfile << endl, "=== Exiting after full simulation on tid ", sys_gettid(), " at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " ===", endl, endl;
    logfile.flush();
    remove_exit_callback();
    sys_exit(0);
  }

  logfile.flush();
  init_exit_callback();
  switch_to_native_restore_context();
}

void switch_to_sim() {
  static const bool DEBUG = 0;


  logfile << "Baseline state:", endl;
  logfile << ctx.commitarf;

  bool done = false;

  if (sequential_mode_insns)
    done = sequential_core_toplevel_loop();

  if (!done) {
    if (use_out_of_order_core)
      out_of_order_core_toplevel_loop();
  }

  // Sanitize flags (AMD and Intel CPUs also use bits 1 and 3 for reserved bits, but not for INV and WAIT like we do).
  ctx.commitarf[REG_flags] &= FLAG_NOT_WAIT_INV;

  logfile << "Final state:", endl;
  logfile << ctx.commitarf;

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

  disable_ptlsim_call_gate();
  show_stats_and_switch_to_native();
}

extern char** initenv;

int main(int argc, char* argv[]) {
  if (!inside_ptlsim) {
    int rc = 0;
    if (argc < 2) {
      print_banner(argc, argv);
      print_usage(argc, argv);
    } else {
      rc = ptlsim_inject(argc, argv);
    }
    sys_exit(rc);
  }

  total_time.start();
  environ = initenv;
  init_config(argc, argv);
  init_perfctrs();
  if (ctx.use64) init_exit_callback();

  if (pause_at_startup) {
    logfile << "ptlsim: Paused for ", pause_at_startup, " seconds; attach debugger to PID ", getpid(), " now...", endl, flush;
    cerr << "ptlsim: Paused for ", pause_at_startup, " seconds; attach debugger to PID ", getpid(), " now...", endl, flush;
    sleep(pause_at_startup);
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
  if (!trigger_mode) disable_ptlsim_call_gate();

  // Context switch into virtual machine:
  switch_to_native_restore_context();
}
