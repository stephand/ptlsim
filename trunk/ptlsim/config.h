// -*- c++ -*-
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//
// This program is free software; it is licensed under the
// GNU General Public License, Version 2.
//
#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <globals.h>
#include <stdarg.h>

struct ConfigurationOption {
  char* option;
  int type;
  bool ishex;
  char* description;
  void* variable;
};

enum {
  OPTION_TYPE_NONE    = 0, 
  OPTION_TYPE_W64     = 1,
  OPTION_TYPE_FLOAT   = 2,
  OPTION_TYPE_STRING  = 3,
  OPTION_TYPE_TRAILER = 4,
  OPTION_TYPE_BOOL    = 5,
  OPTION_TYPE_SECTION = -1
};

struct ConfigurationParser {
  const ConfigurationOption* options;
  int optioncount;

  ConfigurationParser(ConfigurationOption* options, int optioncount) {
    this->options = options;
    this->optioncount = optioncount;
  }

  int parse(int argc, char* argv[]);
  ostream& printusage(ostream& os) const;
  ostream& print(ostream& os) const;
};

ostream& operator <<(ostream& os, const ConfigurationParser& clp);

const char* get_full_exec_filename();
void print_banner(int argc, char* argv[]);
void print_usage(int argc, char* argv[]);
int init_config(int argc, char** argv);

static const W64 infinity = limits<W64s>::max;
static const W64 MAX_CYCLE = infinity;

extern ostream logfile;

extern W64 ptlsim_quiet;
extern W64 sim_cycle;
extern W64 user_insn_commits;
extern W64 iterations;
extern W64 total_uops_executed;
extern W64 total_user_insns_committed;

extern W64 loglevel;
extern char* log_filename;
extern W64 start_at_rip;
extern W64 start_at_rip_repeat;
extern W64 include_dyn_linker;
extern W64 stop_at_iteration;
extern W64 insns_in_last_basic_block;
extern W64 stop_at_rip;
extern W64 stop_at_user_insns;
extern W64 sequential_mode_insns;
extern W64 start_log_at_iteration;
extern W64 start_short_log_at_iteration;
extern W64 user_profile_only;
extern W64 trigger_mode;
extern W64 exit_after_fullsim;
extern char* stats_filename;
extern W64 snapshot_cycles;
extern W64 flush_interval;
extern W64 perfect_cache;
extern char* dumpcode_filename;
extern W64 use_out_of_order_core;
extern W64 pause_at_startup;
extern W64 overshoot_and_dump;
extern W64 dump_at_end;


struct DataStoreNode;
extern DataStoreNode* dsroot;
extern W64 snapshotid;

//inline bool analyze_in_detail() { return 0; }
inline bool analyze_in_detail() { return (loglevel > 0); }
inline bool shortlog() { return (iterations >= start_short_log_at_iteration); }

#define logable(level) (loglevel >= level)

#endif // _CONFIG_H_
