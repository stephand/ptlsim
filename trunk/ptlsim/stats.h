// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Statistics data store tree
//
// Copyright 2006 Matt T. Yourst <yourst@yourst.com>
//

#ifndef _STATS_H_
#define _STATS_H_

#include <globals.h>
#include <superstl.h>
#include <datastore.h>
#include <ptlsim.h>

#define STATS_ONLY
#include <decode.h>
#include <ooocore.h>
#include <dcacheint.h>
#undef STATS_ONLY

//
// This file is run through dstbuild to auto-generate
// the code to instantiate a DataStoreNodeTemplate tree.
// Its format must be parsable by dstbuild.
//
// All character array fields MUST be a multiple of 8 bytes!
// Otherwise the structure parser and gcc will not have
// the same interpretation of things.
//

struct PTLsimStats { // rootnode:
  W64 snapshot_uuid;
  char snapshot_name[64];

  struct summary {
    W64 cycles;
    W64 insns;
    W64 uops;
    W64 basicblocks;
  } summary;

  struct simulator {
    // Compile time information
    struct version {
      char build_timestamp[32];
      W64 svn_revision;
      char svn_timestamp[32];
      char build_hostname[64];
      char build_compiler[16];
    } version;

    // Runtime information
    struct run {
      W64 timestamp;
      char hostname[64];
      char hypervisor_version[32];
      W64 native_cpuid;
      W64 native_hz;
    } run;

    struct config {
      // Configuration string passed for this run
      char config[256];
    } config;

    struct performance {
      struct rate {
        double cycles_per_sec;
        double issues_per_sec;
        double user_commits_per_sec;
      } rate;
    } performance;
  } simulator;

  //
  // Decoder and basic block cache
  //
  struct decoder {
    struct throughput {
      W64 basic_blocks;
      W64 x86_insns;
      W64 uops;
      W64 bytes;
    } throughput;

    W64 x86_decode_type[DECODE_TYPE_COUNT]; // label: decode_type_names

    struct bb_decode_type { // node: summable
      W64 all_insns_fast;
      W64 some_complex_insns;
    } bb_decode_type;

    // Alignment of instructions within pages
    struct page_crossings { // node: summable
      W64 within_page;
      W64 crosses_page;
    } page_crossings;

    // Basic block cache
    struct bbcache {
      W64 count;
      W64 inserts;
      W64 invalidates[INVALIDATE_REASON_COUNT]; // label: invalidate_reason_names
    } bbcache;

    // Page cache
    struct pagecache {
      W64 count;
      W64 inserts;
      W64 invalidates[INVALIDATE_REASON_COUNT]; // label: invalidate_reason_names
    } pagecache;

    W64 reclaim_rounds;
  } decoder;

  //
  // Out of Order Core
  //
  struct ooocore {
    struct fetch {
      struct stop { // node: summable
        W64 stalled;
        W64 icache_miss;
        W64 fetchq_full;
        W64 bogus_rip;
        W64 branch_taken;
        W64 full_width;
      } stop;

      W64 opclass[OPCLASS_COUNT]; // label: opclass_names
      W64 width[FETCH_WIDTH+1]; // histo: 0, FETCH_WIDTH, 1

      W64 blocks;
      W64 uops;
      W64 user_insns;
    } fetch;
    struct frontend {
      struct status { // node: summable
        W64 complete;
        W64 fetchq_empty;
        W64 rob_full;
        W64 physregs_full;
        W64 ldq_full;
        W64 stq_full;
      } status;

      W64 width[FRONTEND_WIDTH+1]; // histo: 0, FRONTEND_WIDTH, 1

      struct renamed {
        W64 none;
        W64 reg;
        W64 flags;
        W64 reg_and_flags;
      } renamed;

      struct alloc {
        W64 reg;
        W64 ldreg;
        W64 sfr;
        W64 br;
      } alloc;

      // NOTE: This is capped at 255 consumers to keep the size reasonable:
      W64 consumer_count[256]; // histo: 0, 255, 1
    } frontend;
    struct dispatch {
      W64 width[DISPATCH_WIDTH+1]; // histo: 0, DISPATCH_WIDTH, 1

      struct source { // node: summable
        W64 integer[MAX_PHYSREG_STATE]; // label: physreg_state_names
        W64 fp[MAX_PHYSREG_STATE]; // label: physreg_state_names
        W64 st[MAX_PHYSREG_STATE]; // label: physreg_state_names
        W64 br[MAX_PHYSREG_STATE]; // label: physreg_state_names
      } source;

      W64 cluster[MAX_CLUSTERS]; // label: cluster_names

      struct redispatch {
        W64 trigger_uops;
        W64 deadlock_flushes;
        W64 deadlock_uops_flushed;
        W64 dependent_uops[ROB_SIZE+1]; // histo: 0, ROB_SIZE, 1
      } redispatch;

    } dispatch;
    struct issue {
      struct result { // node: summable
        W64 no_fu;
        W64 replay;
        W64 misspeculated;
        W64 refetch;
        W64 branch_mispredict;
        W64 exception;
        W64 complete;
      } result;
      struct width {
        W64 int0[MAX_ISSUE_WIDTH+1]; // histo: 0, MAX_ISSUE_WIDTH, 1
        W64 int1[MAX_ISSUE_WIDTH+1]; // histo: 0, MAX_ISSUE_WIDTH, 1
        W64 ld[MAX_ISSUE_WIDTH+1]; // histo: 0, MAX_ISSUE_WIDTH, 1
        W64 fp[MAX_ISSUE_WIDTH+1]; // histo: 0, MAX_ISSUE_WIDTH, 1
      } width;
      W64 opclass[OPCLASS_COUNT]; // label: opclass_names

    } issue;
    struct writeback {
      W64 total_writebacks;
      struct width {
        W64 int0[MAX_ISSUE_WIDTH+1]; // histo: 0, MAX_ISSUE_WIDTH, 1
        W64 int1[MAX_ISSUE_WIDTH+1]; // histo: 0, MAX_ISSUE_WIDTH, 1
        W64 ld[MAX_ISSUE_WIDTH+1]; // histo: 0, MAX_ISSUE_WIDTH, 1
        W64 fp[MAX_ISSUE_WIDTH+1]; // histo: 0, MAX_ISSUE_WIDTH, 1
      } width;
    } writeback;

    struct commit {
      W64 total_uops_committed;
      W64 total_user_insns_committed;
      struct freereg { // node: summable
        W64 pending;
        W64 free;
      } freereg;

      W64 free_regs_recycled;

      struct result { // node: summable
        W64 none;
        W64 ok;
        W64 exception;
        W64 skipblock;
        W64 barrier;
        W64 smc;
        W64 stop;
      } result;

      struct setflags { // node: summable
        W64 yes;
        W64 no;
      } setflags;

      W64 width[COMMIT_WIDTH+1]; // histo: 0, COMMIT_WIDTH, 1
      W64 opclass[OPCLASS_COUNT]; // label: opclass_names
    } commit;

    struct branchpred {
      W64 predictions;
      W64 updates;

      // These counters are [0] = mispred, [1] = correct
      W64 cond[2]; // label: branchpred_outcome_names
      W64 indir[2]; // label: branchpred_outcome_names
      W64 ret[2]; // label: branchpred_outcome_names
      W64 summary[2]; // label: branchpred_outcome_names
      struct ras { // node: summable
        W64 pushes;
        W64 overflows;
        W64 pops;
        W64 underflows;
        W64 annuls;
      } ras;
    } branchpred;

    struct dcache {
      struct load {
        struct issue { // node: summable
          W64 complete;
          W64 miss;
          W64 exception;
          W64 ordering;
          W64 unaligned;
          struct replay { // node: summable
            W64 sfr_addr_and_data_not_ready;
            W64 sfr_addr_not_ready;
            W64 sfr_data_not_ready;
            W64 missbuf_full;
          } replay;
        } issue;

        struct hit { // node: summable
          W64 L1;
          W64 L2;
          W64 L3;
          W64 mem;
        } hit;
        
        struct forward { // node: summable
          W64 cache;
          W64 sfr;
          W64 sfr_and_cache;
        } forward;
        
        struct dependency { // node: summable
          W64 independent;
          W64 predicted_alias_unresolved;
          W64 stq_address_match;
        } dependency;
        
        struct type { // node: summable
          W64 aligned;
          W64 unaligned;
          W64 internal;
        } type;
        
        W64 size[4]; // label: sizeshift_names

        W64 datatype[DATATYPE_COUNT]; // label: datatype_names

        struct transfer { // node: summable
          W64 L2_to_L1_full;
          W64 L2_to_L1_partial;
          W64 L2_L1I_full;
        } transfer;
        
        struct dtlb { // node: summable
          W64 hits;
          W64 misses;
        } dtlb;
      } load;
    
      struct fetch {
        struct hit { // node: summable
          W64 L1;
          W64 L2;
          W64 L3;
          W64 mem;
        } hit;
        
        struct itlb { // node: summable
          W64 hits;
          W64 misses;
        } itlb;
      } fetch;

      struct prefetch { // node: summable
        W64 in_L1;
        W64 in_L2;
        W64 required;
      } prefetch;
    
      struct missbuf {
        W64 inserts;
        struct deliver { // node: summable
          W64 mem_to_L3;
          W64 L3_to_L2;
          W64 L2_to_L1D;
          W64 L2_to_L1I;
        } deliver;
      } missbuf;

      struct lfrq {
        W64 inserts;
        W64 wakeups;
        W64 annuls;
        W64 resets;
        W64 total_latency;
        double average_latency;
        W64 width[MAX_WAKEUPS_PER_CYCLE+1]; // histo: 0, MAX_WAKEUPS_PER_CYCLE+1, 1
      } lfrq;

      struct store {
        struct issue { // node: summable
          W64 complete;
          W64 exception;
          W64 ordering;
          W64 unaligned;
          struct replay { // node: summable
            W64 sfr_addr_and_data_not_ready;
            W64 sfr_addr_not_ready;
            W64 sfr_data_not_ready;
            W64 sfr_addr_and_data_and_data_to_store_not_ready;
            W64 sfr_addr_and_data_to_store_not_ready;
            W64 sfr_data_and_data_to_store_not_ready;
          } replay;
        } issue;

        struct forward { // node: summable
          W64 zero;
          W64 sfr;
        } forward;
        
        struct type { // node: summable
          W64 aligned;
          W64 unaligned;
          W64 internal;
        } type;
        
        W64 size[4]; // label: sizeshift_names

        W64 datatype[DATATYPE_COUNT]; // label: datatype_names

        W64 parallel_aliasing;

        W64 prefetches;
      } store;
    } dcache;
  } ooocore;
  struct external {
    W64 assists[ASSIST_COUNT]; // label: assist_names
    W64 traps[256]; // label: x86_exception_names
  } external;
};

extern struct PTLsimStats stats;

#endif // _STATS_H_
