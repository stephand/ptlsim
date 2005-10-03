// -*- c++ -*-
//
// Data Cache Control
// Copyright 2003-2004 Matt T. Yourst <yourst@yourst.com>
//

#ifndef _DCACHE_H
#define _DCACHE_H

#include <globals.h>

#define VIRT_ADDR_BITS 48
#define PHYS_ADDR_BITS 40

extern void init_cache();

enum { LDST_ALIGN_NORMAL, LDST_ALIGN_LO, LDST_ALIGN_HI };

struct LoadStoreInfo {
  union {
    W64 data;
    struct {
      W16 tag;
      W16 rd;
      W16 cbslot;
      W16 sequential:1, commit:1, sizeshift:2, aligntype:2, sfraused:1, internal:1, signext:1;
    } info;
  };

  operator W64() const { return data; }
  LoadStoreInfo& operator =(const LoadStoreInfo& lsi) { data = lsi.data; return *this; }
};


extern "C" W64 commitstore_unlocked(const SFR& sfr);

int issueload_slowpath(IssueState& state, W64 addr, W64 origaddr, W64 data, SFR& sfra, LoadStoreInfo lsi);
bool probe_cache_and_sfr(W64 addr, const SFR* sfra, int sizeshift);
bool probe_icache(W64 addr);
bool covered_by_sfr(W64 addr, SFR* sfr, int sizeshift);
void initiate_prefetch(W64 addr, int cachelevel);
int initiate_icache_miss(W64 addr);
void annul_lfrq_slot(int lfrqslot);
int issueload_slowpath(IssueState& state, W64 addr, W64 origaddr, W64 data, SFR& sfra, LoadStoreInfo lsi);

typedef W64 (*notify_wakeup_t)(LoadStoreInfo lsi, W64 addr);
extern notify_wakeup_t wakeup_func;
extern notify_wakeup_t icache_wakeup_func;

void dcache_clock();
void dcache_commit();
void dcache_rollback();
void dcache_complete();
void dcache_print_commit();
void dcache_print_rollback();

// sum of 100%:
extern W64 load_issue_unaligned;
extern W64 load_issue_replay_sfr_addr_and_data_not_ready;
extern W64 load_issue_replay_sfr_addr_not_ready;
extern W64 load_issue_replay_sfr_data_not_ready;
extern W64 load_issue_replay_missbuf_full;
extern W64 load_issue_ordering;
extern W64 load_issue_exception;
extern W64 load_issue_complete;
extern W64 load_issue_miss;

// sum of 100%:
extern W64 load_forward_from_cache;
extern W64 load_forward_from_sfr;
extern W64 load_forward_from_sfr_and_cache;

// sum of 100%:
extern W64 load_dependency_independent;
extern W64 load_dependency_predicted_alias_unresolved;
extern W64 load_dependency_stq_address_match;

// n/a:
extern W64 load_hit_L1;

// n/a:
extern W64 fetch_hit_L1;

// sum of 100%
extern W64 load_type_aligned;
extern W64 load_type_unaligned;
extern W64 load_type_internal;
extern W64 load_size[4];

// sum of 100%:
extern W64 store_issue_complete;
extern W64 store_issue_unaligned;
extern W64 store_issue_ordering;
extern W64 store_issue_exception;

extern W64 store_issue_replay_sfr_addr_and_data_not_ready;
extern W64 store_issue_replay_sfr_addr_not_ready;
extern W64 store_issue_replay_sfr_data_not_ready;
extern W64 store_issue_replay_sfr_addr_and_data_and_data_to_store_not_ready;
extern W64 store_issue_replay_sfr_addr_and_data_to_store_not_ready;
extern W64 store_issue_replay_sfr_data_and_data_to_store_not_ready;

extern W64 store_forward_from_zero;
extern W64 store_forward_from_sfr;

extern W64 store_type_aligned;
extern W64 store_type_unaligned;
extern W64 store_type_internal;
extern W64 store_size[4];

// sum of 100%:
extern W64 dtlb_hits;
extern W64 dtlb_misses;

// sum of 100%:
extern W64 itlb_hits;
extern W64 itlb_misses;

#endif // _DCACHE_H
