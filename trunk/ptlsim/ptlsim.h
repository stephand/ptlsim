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
#include <ptlhwdef.h>
#include <kernel.h>
#include <mm.h>
#include <dcache.h>
#include <config.h>
#include <datastore.h>

extern W64 sim_cycle;

void user_process_terminated(int rc);

ostream& print_user_context(ostream& os, const UserContext& ctx, int width = 4);

void init_uops();
void init_translate();
BasicBlock* translate_basic_block(void* rip);

static const int MAX_TRANSOP_BUFFER_SIZE = 4;

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
  SEQEXEC_CHECK,
  SEQEXEC_UNALIGNED,
  SEQEXEC_EXCEPTION,
  SEQEXEC_INVALIDRIP,
  SEQEXEC_SKIPBLOCK,
  SEQEXEC_BARRIER,
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

static const int BB_CACHE_SIZE = 16384;

struct BasicBlockCache: public Hashtable<W64, BasicBlock*, BB_CACHE_SIZE> {
  BasicBlockCache(): Hashtable<W64, BasicBlock*, BB_CACHE_SIZE>() { }

  ostream& print(ostream& os) const;
};

extern BasicBlockCache bbcache;

static inline ostream& operator <<(ostream& os, const BasicBlockCache& bbcache) {
  return bbcache.print(os);
}

//
// Assists
//

typedef void (*assist_func_t)();

const char* assist_name(assist_func_t func);
int assist_index(assist_func_t func);
void update_assist_stats(assist_func_t assist);
void reset_assist_stats();
void save_assist_stats(DataStoreNode& root);


#endif // _PTLSIM_H_
