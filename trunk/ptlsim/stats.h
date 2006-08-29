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
#include <decode.h>
//#include <ooohwdef.h>
//#include <dcache.h>

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
};

extern struct PTLsimStats stats;

#endif // _STATS_H_
