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
#include <datastore.h>

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
#define L2_LATENCY   6 // don't include the extra wakeup cycle (waiting->ready state transition) in the LFRQ

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
#define DTLB_SIZE 32

//#define ISSUE_LOAD_STORE_DEBUG
//#define CHECK_LOADS_AND_STORES

// Line Usage Statistics

//#define TRACK_LINE_USAGE

#ifdef TRACK_LINE_USAGE
#define DCACHE_L1_LINE_LIFETIME_INTERVAL   1
#define DCACHE_L1_LINE_DEADTIME_INTERVAL   1
#define DCACHE_L1_LINE_HITCOUNT_INTERVAL   1
#define DCACHE_L1_LINE_LIFETIME_SLOTS      8192
#define DCACHE_L1_LINE_DEADTIME_SLOTS      8192
#define DCACHE_L1_LINE_HITCOUNT_SLOTS      64

#define DCACHE_L1I_LINE_LIFETIME_INTERVAL  16
#define DCACHE_L1I_LINE_DEADTIME_INTERVAL  16
#define DCACHE_L1I_LINE_HITCOUNT_INTERVAL  1
#define DCACHE_L1I_LINE_LIFETIME_SLOTS     8192
#define DCACHE_L1I_LINE_DEADTIME_SLOTS     8192
#define DCACHE_L1I_LINE_HITCOUNT_SLOTS     1024

#define DCACHE_L2_LINE_LIFETIME_INTERVAL   4
#define DCACHE_L2_LINE_DEADTIME_INTERVAL   4
#define DCACHE_L2_LINE_HITCOUNT_INTERVAL   1
#define DCACHE_L2_LINE_LIFETIME_SLOTS      65536
#define DCACHE_L2_LINE_DEADTIME_SLOTS      65536
#define DCACHE_L2_LINE_HITCOUNT_SLOTS      256

#define DCACHE_L3_LINE_LIFETIME_INTERVAL   64
#define DCACHE_L3_LINE_DEADTIME_INTERVAL   64
#define DCACHE_L3_LINE_HITCOUNT_INTERVAL   1
#define DCACHE_L3_LINE_LIFETIME_SLOTS      16384
#define DCACHE_L3_LINE_DEADTIME_SLOTS      16384
#define DCACHE_L3_LINE_HITCOUNT_SLOTS      256
#endif

extern void validate_caches();

namespace DataCache {
  //
  // Cache Line Types
  //
  template <int linesize>
  struct CacheLine {
#ifdef TRACK_LINE_USAGE
    W32 filltime;
    W32 lasttime;
    W32 hitcount;
#else
    byte dummy;
#endif
    void reset() { clearstats(); }
    void invalidate() { reset(); }
    void fill(W64 tag, const bitvec<linesize>& valid) { }

    void clearstats() {
#ifdef TRACK_LINE_USAGE
      filltime = sim_cycle;
      lasttime = sim_cycle;
      hitcount = 0;
#endif
    }

    ostream& print(ostream& os, W64 tag) const;
  };

  template <int linesize>
  inline ostream& operator <<(ostream& os, const CacheLine<linesize>& line) {
    return line.print(os, 0);
  }

  template <int linesize>
  struct CacheLineWithValidMask {
    bitvec<linesize> valid;
#ifdef TRACK_LINE_USAGE
    W32 filltime;
    W32 lasttime;
    W32 hitcount;
#endif

    void clearstats() {
#ifdef TRACK_LINE_USAGE
      filltime = sim_cycle;
      lasttime = sim_cycle;
      hitcount = 0;
#endif
    }

    void reset() { valid = 0; clearstats(); }
    void invalidate() { reset(); }
    void fill(W64 tag, const bitvec<linesize>& valid) { this->valid |= valid; }
    ostream& print(ostream& os, W64 tag) const;
  };

  template <int linesize>
  inline ostream& operator <<(ostream& os, const CacheLineWithValidMask<linesize>& line) {
    return line.print(os, 0);
  }

  typedef CacheLineWithValidMask<L1_LINE_SIZE> L1CacheLine;
  typedef CacheLine<L1I_LINE_SIZE> L1ICacheLine;
  typedef CacheLineWithValidMask<L2_LINE_SIZE> L2CacheLine;
  typedef CacheLine<L3_LINE_SIZE> L3CacheLine;

  //
  // L1 data cache
  //
#ifdef TRACK_LINE_USAGE
  static const char* cache_names[4] = {"L1", "I1", "L2", "L3"};

  template <int uniq, typename V, int LIFETIME_INTERVAL, int LIFETIME_SLOTS, int DEADTIME_INTERVAL, int DEADTIME_SLOTS, int HITCOUNT_INTERVAL, int HITCOUNT_SLOTS>
  struct HistogramAssociativeArrayStatisticsCollector {

    static W64 line_lifetime_histogram[LIFETIME_SLOTS];
    static W64 line_deadtime_histogram[DEADTIME_SLOTS];
    static W64 line_hitcount_histogram[HITCOUNT_SLOTS];

    static const bool FORCE_DEBUG = 0;

    HistogramAssociativeArrayStatisticsCollector() {
      reset();
    }

    static void reset() {
      setzero(line_lifetime_histogram);
      setzero(line_deadtime_histogram);
      setzero(line_hitcount_histogram);
    }

    static void evicted(const V& line, W64 tag) {
      // Line has been evicted: update statistics
      W64s lifetime = line.lasttime - line.filltime;
      assert(lifetime >= 0);
      int lifetimeslot = clipto(lifetime / LIFETIME_INTERVAL, 0, LIFETIME_SLOTS-1);
      line_lifetime_histogram[lifetimeslot]++;

      W64s deadtime = sim_cycle - line.lasttime;
      int deadtimeslot = clipto(deadtime / DEADTIME_INTERVAL, 0, DEADTIME_SLOTS-1);
      line_deadtime_histogram[deadtimeslot]++;

      W64 hitcount = line.hitcount;
      int hitcountslot = clipto(hitcount / HITCOUNT_INTERVAL, 0, HITCOUNT_SLOTS-1);
      line_hitcount_histogram[hitcountslot]++;

      if (logable(1) | FORCE_DEBUG) logfile << "[", cache_names[uniq], "] ", sim_cycle, ": evicted(", (void*)tag, "): lifetime ", lifetime, ", deadtime ", deadtime, ", hitcount ", hitcount, " (line addr ", &line, ")", endl;
    }

    static void filled(V& line, W64 tag) {
      line.filltime = sim_cycle;
      line.lasttime = sim_cycle;
      line.hitcount = 1;

      if (logable(1) | FORCE_DEBUG) logfile << "[", cache_names[uniq], "] ", sim_cycle, ": filled(", (void*)tag, ")", " (line addr ", &line, ")", endl;
    }

    static void inserted(V& line, W64 newtag, int way) {
      filled(line, newtag);
    }

    static void replaced(V& line, W64 oldtag, W64 newtag, int way) {
      evicted(line, oldtag);
      filled(line, newtag);
    }

    static void probed(V& line, W64 tag, int way, bool hit) { 
      if (logable(1) | FORCE_DEBUG) logfile << "[", cache_names[uniq], "] ", sim_cycle, ": probe(", (void*)tag, "): ", (hit ? "HIT" : "miss"), " way ", way, ": hitcount ", line.hitcount, ", filltime ", line.filltime, ", lasttime ", line.lasttime, " (line addr ", &line, ")", endl;
      if (hit) {
        line.hitcount++;
        line.lasttime = sim_cycle;
      }
    }

    static void overflow(W64 tag) { }

    static void locked(V& slot, W64 tag, int way) { }
    static void unlocked(V& slot, W64 tag, int way) { }

    static void invalidated(V& line, W64 oldtag, int way) { evicted(line, oldtag); }

    static void savestats(DataStoreNode& ds) {
      ds.add("lifetime", (W64s*)line_lifetime_histogram, LIFETIME_SLOTS, 0, ((LIFETIME_SLOTS-1) * LIFETIME_INTERVAL), LIFETIME_INTERVAL);
      ds.add("deadtime", (W64s*)line_deadtime_histogram, DEADTIME_SLOTS, 0, ((DEADTIME_SLOTS-1) * DEADTIME_INTERVAL), DEADTIME_INTERVAL);
      ds.add("hitcount", (W64s*)line_hitcount_histogram, HITCOUNT_SLOTS, 0, ((HITCOUNT_SLOTS-1) * HITCOUNT_INTERVAL), HITCOUNT_INTERVAL);
    }
  };

  typedef HistogramAssociativeArrayStatisticsCollector<0, L1CacheLine,
    DCACHE_L1_LINE_LIFETIME_INTERVAL, DCACHE_L1_LINE_LIFETIME_SLOTS, 
    DCACHE_L1_LINE_DEADTIME_INTERVAL, DCACHE_L1_LINE_DEADTIME_SLOTS, 
    DCACHE_L1_LINE_HITCOUNT_INTERVAL, DCACHE_L1_LINE_HITCOUNT_SLOTS> L1StatsCollectorBase;

  typedef HistogramAssociativeArrayStatisticsCollector<1, L1ICacheLine,
    DCACHE_L1I_LINE_LIFETIME_INTERVAL, DCACHE_L1I_LINE_LIFETIME_SLOTS, 
    DCACHE_L1I_LINE_DEADTIME_INTERVAL, DCACHE_L1I_LINE_DEADTIME_SLOTS, 
    DCACHE_L1I_LINE_HITCOUNT_INTERVAL, DCACHE_L1I_LINE_HITCOUNT_SLOTS> L1IStatsCollectorBase;

  typedef HistogramAssociativeArrayStatisticsCollector<2, L2CacheLine,
    DCACHE_L2_LINE_LIFETIME_INTERVAL, DCACHE_L2_LINE_LIFETIME_SLOTS, 
    DCACHE_L2_LINE_DEADTIME_INTERVAL, DCACHE_L2_LINE_DEADTIME_SLOTS, 
    DCACHE_L2_LINE_HITCOUNT_INTERVAL, DCACHE_L2_LINE_HITCOUNT_SLOTS> L2StatsCollectorBase;

  typedef HistogramAssociativeArrayStatisticsCollector<3, L3CacheLine,
    DCACHE_L3_LINE_LIFETIME_INTERVAL, DCACHE_L3_LINE_LIFETIME_SLOTS, 
    DCACHE_L3_LINE_DEADTIME_INTERVAL, DCACHE_L3_LINE_DEADTIME_SLOTS, 
    DCACHE_L3_LINE_HITCOUNT_INTERVAL, DCACHE_L3_LINE_HITCOUNT_SLOTS> L3StatsCollectorBase;

  struct L1StatsCollector: public L1StatsCollectorBase { };
  struct L1IStatsCollector: public L1IStatsCollectorBase { };
  struct L2StatsCollector: public L2StatsCollectorBase { };
  struct L3StatsCollector: public L3StatsCollectorBase { };

#else
  typedef NullAssociativeArrayStatisticsCollector<W64, L1CacheLine> L1StatsCollector;
  typedef NullAssociativeArrayStatisticsCollector<W64, L1ICacheLine> L1IStatsCollector;
  typedef NullAssociativeArrayStatisticsCollector<W64, L2CacheLine> L2StatsCollector;
  typedef NullAssociativeArrayStatisticsCollector<W64, L3CacheLine> L3StatsCollector;
#endif

  template <typename V, int setcount, int waycount, int linesize, typename stats = NullAssociativeArrayStatisticsCollector<W64, V> > 
  struct DataCache: public AssociativeArray<W64, V, setcount, waycount, linesize, stats> {
    typedef AssociativeArray<W64, V, setcount, waycount, linesize, stats> base_t;
    void clearstats() {
#ifdef TRACK_LINE_USAGE
      foreach (set, L1_SET_COUNT) {
        foreach (way, waycount) {
          base_t::sets[set][way].clearstats();
        }
      }
#endif
    }
  };

  struct L1Cache: public DataCache<L1CacheLine, L1_SET_COUNT, L1_WAY_COUNT, L1_LINE_SIZE, L1StatsCollector> {
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

  struct L1ICache: public DataCache<L1ICacheLine, L1I_SET_COUNT, L1I_WAY_COUNT, L1I_LINE_SIZE, L1IStatsCollector> {
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

  typedef DataCache<L2CacheLine, L2_SET_COUNT, L2_WAY_COUNT, L2_LINE_SIZE, L2StatsCollector> L2CacheBase;

  struct L2Cache: public L2CacheBase {
    void validate(W64 addr) {
      L2CacheLine* line = select(addr);
      if (!line) return;
      line->valid.setall();
    }

    void deliver(W64 address);
  };

  extern L2Cache L2;

  //
  // L3 cache
  //

  inline ostream& operator <<(ostream& os, const L3CacheLine& line) {
    return line.print(os, 0);
  }

  struct L3Cache: public DataCache<L3CacheLine, L3_SET_COUNT, L3_WAY_COUNT, L3_LINE_SIZE, L3StatsCollector> {
    L3CacheLine* validate(W64 addr) {
      W64 oldaddr;
      L3CacheLine* line = select(addr, oldaddr);
      return line;
    }
  };

  extern L3Cache L3;

  inline void prep_sframask_and_reqmask(const SFR* sfr, W64 addr, int sizeshift, bitvec<L1_LINE_SIZE>& sframask, bitvec<L1_LINE_SIZE>& reqmask) {
    sframask = (sfr) ? (bitvec<L1_LINE_SIZE>(sfr->bytemask) << 8*lowbits(sfr->physaddr, log2(L1_LINE_SIZE)-3)) : 0;
    reqmask = bitvec<L1_LINE_SIZE>(bitmask(1 << sizeshift)) << lowbits(addr, log2(L1_LINE_SIZE));
  }

  inline void prep_L2_sframask_and_reqmask(const SFR* sfr, W64 addr, int sizeshift, bitvec<L2_LINE_SIZE>& sframask, bitvec<L2_LINE_SIZE>& reqmask) {
    sframask = (sfr) ? (bitvec<L2_LINE_SIZE>(sfr->bytemask) << 8*lowbits(sfr->physaddr, log2(L2_LINE_SIZE)-3)) : 0;
    reqmask = bitvec<L2_LINE_SIZE>(bitmask(1 << sizeshift)) << lowbits(addr, log2(L2_LINE_SIZE));
  }

#ifdef USE_TLB
  //
  // TLB class with one-hot semantics. 36 bit tags are required since
  // virtual addresses are 48 bits, so 48 - 12 (2^12 bytes per page)
  // is 36 bits.
  //
  template <int tlbid, int size>
  struct TranslationLookasideBuffer: public FullyAssociativeTagsNbitOneHot<size, 36> {
    typedef FullyAssociativeTagsNbitOneHot<size, 36> base_t;
    TranslationLookasideBuffer(): base_t() { }

    void reset() {
      base_t::reset();
    }

    bool probe(W64 addr) {
      return (base_t::probe(addr >> 12) >= 0);
    }

    bool insert(W64 addr) {
      addr >>= 12;
      W64 oldtag;
      int way = base_t::select(addr, oldtag);
      if (logable(1)) {
        logfile << "TLB insertion of virt page ", (void*)(Waddr)addr, " (virt addr ", 
          (void*)(Waddr)(addr << 12), ") into way ", way, ": ",
          ((oldtag != addr) ? "evicted old entry" : "already present"), endl;
      }
      return (oldtag != addr);
    }
  };

  template <int tlbid, int size>
  inline ostream& operator <<(ostream& os, const TranslationLookasideBuffer<tlbid, size>& tlb) {
    return tlb.print(os);
  }

  typedef TranslationLookasideBuffer<0, DTLB_SIZE> DTLB;
  typedef TranslationLookasideBuffer<1, ITLB_SIZE> ITLB;
#endif
};

#ifdef USE_TLB
extern DataCache::DTLB dtlb;
extern DataCache::ITLB itlb;
#endif

void issueload_slowpath(IssueState& state, DataCache::L1CacheLine* L1line, W64 addr, W64 origaddr, W64 data, SFR& sfra, W64 lsi);
