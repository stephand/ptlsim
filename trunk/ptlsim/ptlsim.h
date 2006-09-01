// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Simulator Structures
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#ifndef _PTLSIM_H_
#define _PTLSIM_H_

#include <globals.h>
#include <mm.h>
#ifdef PTLSIM_HYPERVISOR
#include <ptlxen.h>
#else
#include <kernel.h>
#endif
#include <ptlhwdef.h>
#include <dcache.h>
#include <config.h>
#include <datastore.h>

extern W64 sim_cycle;
extern W64 total_uops_committed;
extern W64 total_user_insns_committed;

void user_process_terminated(int rc);

ostream& print_user_context(ostream& os, const UserContext& ctx, int width = 4);

void init_uops();
void init_translate();
BasicBlock* translate_basic_block(Context& ctx, Waddr rip);
BasicBlock* invalidate_basic_block(BasicBlock* bb);
BasicBlock* invalidate_basic_block(const RIPVirtPhys& rvp);

static const int MAX_TRANSOP_BUFFER_SIZE = 4;

struct PTLsimConfig;
struct PTLsimStats;

struct PTLsimCore {
  bool initialized;
  PTLsimCore() { initialized = 0; }
  virtual bool init(PTLsimConfig& config);
  virtual int run(PTLsimConfig& config);  
  virtual void update_stats(PTLsimStats& stats);

  static void addcore(const char* name, PTLsimCore* core);
  static PTLsimCore* getcore(const char* name);
};

struct TransOpBuffer {
  TransOp uops[MAX_TRANSOP_BUFFER_SIZE];
  uopimpl_func_t synthops[MAX_TRANSOP_BUFFER_SIZE];
  int index;
  int count;

  bool get(TransOp& uop, uopimpl_func_t& synthop) {
    if (!count) return false;
    uop = uops[index];
    synthop = synthops[index];
    index++;
    if (index >= count) { count = 0; index = 0; }
    return true;
  }

  void reset() {
    index = 0;
    count = 0;
  }

  int put() {
    return count++;
  }

  bool empty() const {
    return (count == 0);
  }

  TransOpBuffer() { reset(); }
};

void split_unaligned(const TransOp& transop, TransOpBuffer& buf);

void capture_translate_timers(DataStoreNode& root);
void capture_translate_stats(DataStoreNode& root);

int out_of_order_core_toplevel_loop();
int checkpoint_core_toplevel_loop();
int sequential_core_toplevel_loop();
int execute_sequential(BasicBlock* bb);

void backup_and_reopen_logfile();

enum {
  SEQEXEC_OK = 0,
  SEQEXEC_EARLY_EXIT,
  SEQEXEC_SMC,
  SEQEXEC_CHECK,
  SEQEXEC_UNALIGNED,
  SEQEXEC_EXCEPTION,
  SEQEXEC_INVALIDRIP,
  SEQEXEC_SKIPBLOCK,
  SEQEXEC_BARRIER,
  SEQEXEC_INTERRUPT,
};

void ooo_capture_stats(const char* snapshotname = null);
void ooo_capture_stats(DataStoreNode& root);
void cpt_capture_stats(const char* snapshotname = null);
void cpt_capture_stats(DataStoreNode& root);
void seq_capture_stats(DataStoreNode& root);
void save_stats();

extern "C" void switch_to_sim();

//
// uop implementations
//

struct AddrPair {
  byte* start;
  byte* end;
};

uopimpl_func_t get_synthcode_for_uop(int op, int size, bool setflags, int cond, int extshift, int sfra, int cachelevel, bool except, bool internal);
uopimpl_func_t get_synthcode_for_cond_branch(int opcode, int cond, int size, bool except);
void synth_uops_for_bb(BasicBlock& bb);

//
// Assists
//

const char* assist_name(assist_func_t func);
int assist_index(assist_func_t func);
void update_assist_stats(assist_func_t assist);
void reset_assist_stats();
void save_assist_stats(DataStoreNode& root);

const char* get_full_exec_filename();
void print_banner(int argc, char* argv[]);
void print_usage(int argc, char* argv[]);
int init_config(int argc, char** argv);

extern ostream logfile;

extern W64 sim_cycle;
extern W64 user_insn_commits;
extern W64 iterations;
extern W64 total_uops_executed;
extern W64 total_uops_committed;
extern W64 total_user_insns_committed;
extern W64 total_basic_blocks_committed;

#ifndef PTLSIM_HYPERVISOR
// 
// Configuration Options:
//
struct PTLsimConfig {
  // Logging
  bool quiet;
  stringbuf log_filename;
  W64 loglevel;
  W64 start_log_at_iteration;
  W64 start_log_at_rip;

  // Statistics Database
  stringbuf stats_filename;
  W64 snapshot_cycles;

  // Starting Point
  W64 start_at_rip;
  bool include_dyn_linker;
  bool trigger_mode;

  // Stopping Point
  W64 stop_at_user_insns;
  W64 stop_at_iteration;
  W64 stop_at_rip;
  W64 insns_in_last_basic_block;
  W64 flush_interval;

  // Simulation Mode
  bool use_out_of_order_core;
  W64 sequential_mode_insns;
  W64 exit_after_fullsim;

  // Code Dumps
  stringbuf dumpcode_filename;
  bool dump_at_end;
  bool overshoot_and_dump;
  W64 pause_at_startup;
  bool perfect_cache;

  void reset();
};

ostream& operator <<(ostream& os, const PTLsimConfig& config);
#endif

struct DataStoreNode;
extern DataStoreNode* dsroot;
extern W64 snapshotid;

//inline bool analyze_in_detail() { return 0; }
inline bool analyze_in_detail() { return (config.loglevel > 0); }

extern bool logenable;
#define logable(level) (unlikely (logenable && (config.loglevel >= level)))


#endif // _PTLSIM_H_
