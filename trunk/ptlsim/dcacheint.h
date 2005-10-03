// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Data Cache Templates
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <ptlsim.h>
#include <dcache.h>
#include <config.h>

// non-debugging only:
#define __RELEASE__
#ifdef __RELEASE__
#undef assert
#define assert(x) (x)
#endif

//#define CACHE_ALWAYS_HITS
//#define L2_ALWAYS_HITS

// 16 KB L1 at 2 cycles
#define L1_LINE_SIZE 64
#define L1_SET_COUNT 64
#define L1_WAY_COUNT 4

// 32 KB L1I
#define L1I_LINE_SIZE 64
#define L1I_SET_COUNT 128
#define L1I_WAY_COUNT 4

// 256 KB L2 at 6 cycles
#define L2_LINE_SIZE 64
#define L2_SET_COUNT 512 // 256 KB
#define L2_WAY_COUNT 8
#define L2_LATENCY   5 // don't include the extra wakeup cycle (waiting->ready state transition) in the LFRQ

// 2 MB L3 cache (4096 sets, 16 ways) with 64-byte lines, latency 16 cycles
#define L3_SET_COUNT 1024
#define L3_WAY_COUNT 16
#define L3_LINE_SIZE 128
#define L3_LATENCY   12

// Load Fill Request Queue (maximum number of missed loads)
#define LFRQ_SIZE 63

// Allow up to 16 outstanding lines in the L2 awaiting service:
#define MISSBUF_COUNT 16
#define MAIN_MEM_LATENCY 140

// How many load wakeups can be driven into the core each cycle:
#define MAX_WAKEUPS_PER_CYCLE 2

// TLBs
#define USE_TLB
#define ITLB_SIZE 32
#define DTLB_SIZE 64

//#define ISSUE_LOAD_STORE_DEBUG
//#define CHECK_LOADS_AND_STORES

extern void validate_caches();

namespace DataCache {
  //
  // Cache Line Types
  //
  template <int linesize>
  struct CacheLine {
    byte dummy;
    void reset() { }
    void invalidate() { reset(); }
    void fill(W64 tag, const bitvec<linesize>& valid) { }
    ostream& print(ostream& os, W64 tag) const;
  };

  template <int linesize>
  inline ostream& operator <<(ostream& os, const CacheLine<linesize>& line) {
    return line.print(os, 0);
  }

  template <int linesize>
  struct CacheLineWithValidMask {
    bitvec<linesize> valid;

    void reset() { valid = 0; }
    void invalidate() { reset(); }
    void fill(W64 tag, const bitvec<linesize>& valid) { this->valid |= valid; }
    ostream& print(ostream& os, W64 tag) const;
  };

  template <int linesize>
  inline ostream& operator <<(ostream& os, const CacheLineWithValidMask<linesize>& line) {
    return line.print(os, 0);
  }

  //
  // L1 data cache
  //
  typedef CacheLineWithValidMask<L1_LINE_SIZE> L1CacheLine;

  struct L1Cache: public AssociativeArray<W64, L1CacheLine, L1_SET_COUNT, L1_WAY_COUNT, L1_LINE_SIZE> {
    L1CacheLine* validate(W64 addr, const bitvec<L1_LINE_SIZE>& valid) {
      addr = tagof(addr);
      L1CacheLine* line = select(addr);
      line->fill(addr, valid);
      return line;
    }
  };

  inline ostream& operator <<(ostream& os, const L1Cache& cache) {
    return os;
  }

  extern L1Cache L1;

  //
  // L1 instruction cache
  //
  typedef CacheLine<L1I_LINE_SIZE> L1ICacheLine;

  struct L1ICache: public AssociativeArray<W64, L1ICacheLine, L1I_SET_COUNT, L1I_WAY_COUNT, L1I_LINE_SIZE> {
    L1ICacheLine* validate(W64 addr, const bitvec<L1I_LINE_SIZE>& valid) {
      addr = tagof(addr);
      L1ICacheLine* line = select(addr);
      line->fill(addr, valid);
      return line;
    }
  };

  inline ostream& operator <<(ostream& os, const L1ICache& cache) {
    return os;
  }

  extern L1ICache L1I;

  //
  // L2 cache
  //
  typedef CacheLineWithValidMask<L2_LINE_SIZE> L2CacheLine;

#define MAX_LOCKED_LINES (L2_SET_COUNT * L2_WAY_COUNT)
  struct L2Cache: public CommitRollbackCache<W64, L2CacheLine, L2_SET_COUNT, L2_WAY_COUNT, L2_LINE_SIZE, MAX_LOCKED_LINES> {

    void validate(W64 addr) {
      L2CacheLine* line = select(addr);
      if (!line) return;
      line->valid.setall();
    }

    void deliver(W64 address);
  };

  extern L2Cache L2;

  inline void prep_sframask_and_reqmask(const SFR* sfr, W64 addr, int sizeshift, bitvec<L1_LINE_SIZE>& sframask, bitvec<L1_LINE_SIZE>& reqmask) {
    sframask = (sfr) ? (bitvec<L1_LINE_SIZE>(sfr->bytemask) << 8*lowbits(sfr->physaddr, log2(L1_LINE_SIZE)-3)) : 0;
    reqmask = bitvec<L1_LINE_SIZE>(bitmask(1 << sizeshift)) << lowbits(addr, log2(L1_LINE_SIZE));
  }

#ifdef USE_TLB
  template <int tlbid, int size>
  struct TranslationLookasideBuffer: public FullyAssociativeTags<W64, size> {
    FullyAssociativeTags<W64, size> tags;

    TranslationLookasideBuffer() { tags.reset(); }

    AddressSpace::SPATChunk** gettop() const;

    bool check(W64 addr) const {
      return asp.fastcheck(addr, gettop());
    }

    int replace(W64 addr) {
      addr = floor(addr, PAGE_SIZE);
      W64 oldaddr;
      int slot = tags.select(addr, oldaddr);
      if (oldaddr != tags.INVALID) asp.make_page_inaccessible((void*)oldaddr, gettop());
      asp.make_page_accessible((void*)addr, gettop());
      tags[slot] = addr;
      return slot;
    }
  };

  typedef TranslationLookasideBuffer<0, DTLB_SIZE> DTLB;
  typedef TranslationLookasideBuffer<1, ITLB_SIZE> ITLB;

  AddressSpace::SPATChunk** TranslationLookasideBuffer<0, DTLB_SIZE>::gettop() const { return asp.dtlbmap; }
  AddressSpace::SPATChunk** TranslationLookasideBuffer<1, ITLB_SIZE>::gettop() const { return asp.itlbmap; }
#endif
};

extern DataCache::DTLB dtlb;
extern DataCache::ITLB itlb;

void issueload_slowpath(IssueState& state, DataCache::L1CacheLine* L1line, W64 addr, W64 origaddr, W64 data, SFR& sfra, W64 lsi);
