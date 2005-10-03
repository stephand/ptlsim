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

extern void print_banner(int argc, char* argv[]);
extern void print_usage(int argc, char* argv[]);
extern int parse_options(int argc, char* argv[]);
extern int parse_options_from_env(int argc, char* argv[]);
extern int init_config(int argc, char** argv);

#define MAX_CYCLE (1LL << 62)

extern ostream logfile;
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
extern W64 force_seq_at_iteration;
extern W64 all_sequential;
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


struct DataStoreNode;
extern DataStoreNode* dsroot;
extern W64 snapshotid;

//inline bool analyze_in_detail() { return 0; }
inline bool analyze_in_detail() { return ((iterations >= start_log_at_iteration) | (iterations == stop_at_iteration)); }
inline bool shortlog() { return (iterations >= start_short_log_at_iteration); }

#define logable(level) (loglevel >= level)

#endif // _CONFIG_H_
