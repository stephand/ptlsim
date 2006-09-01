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
//#include <dcache.h>
#undef STATS_ONLY

#ifdef DSTBUILD
const char* decode_type_names[DECODE_TYPE_COUNT] = {
  "fast", "complex", "x87", "sse", "assist"
};

const char* invalidate_reason_names[INVALIDATE_REASON_COUNT] = {
  "smc", "dma", "spurious", "reclaim", "dirty", "empty"
};
#endif

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

  //#include "testme.txt"
  //W64 opclass[OPCLASS_COUNT]; // label: opclass_names
  //W64 trace_length[64]; // histo: 0, OPCLASS_COUNT-1, 1



  //
  // Out of Order Core
  //
  struct ooocore {
    struct fetch {
      struct stop { // node: summable
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
    struct branchpred {
      W64 predictions;
    } branchpred;
  } ooocore;
};

extern struct PTLsimStats stats;

#endif // _STATS_H_
