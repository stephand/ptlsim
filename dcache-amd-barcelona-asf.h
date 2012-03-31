// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Data Cache
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
// 02110-1301, USA.
//
// Copyright 2000-2006 Matt T. Yourst <yourst@yourst.com>
// Copyright (c) 2007-2012 Advanced Micro Devices, Inc.
// Contributed by Stephan Diestelhorst <stephan.diestelhorst@amd.com>
//

/**
 * Enables cross core cache invalidation and cross core cache forwarding.
 * Only has effect with a proper SMP model, ie. you have to _disable_
 * ENABLE_SMT.
 */
#define POOR_MANS_MESI
#include <ptlsim.h>
//#include <datastore.h>
// XXX number of vcpus, right?
#define MAX_HIERARCHIES 32
struct LoadStoreInfo {
  W16 rob;
  W8  threadid;
#ifdef ENABLE_ASF_CACHE_BASED
  W8  sizeshift:2, aligntype:2, sfrused:1, internal:1, signext:1, asf_spec:1;
#else
  W8  sizeshift:2, aligntype:2, sfrused:1, internal:1, signext:1, pad1:1;
#endif
  W32 pad32;
  RawDataAccessors(LoadStoreInfo, W64);
};

#define per_context_dcache_stats_ref(vcpuid) (*(((PerContextDataCacheStats*)&stats.dcache.vcpu0) + (vcpuid)))
#define per_context_dcache_stats_update(vcpuid, expr) stats.dcache.total.expr, per_context_dcache_stats_ref(vcpuid).expr

namespace CacheSubsystem {
  // How many load wakeups can be driven into the core each cycle:
  const int MAX_WAKEUPS_PER_CYCLE = 2;

#ifndef STATS_ONLY

// non-debugging only:
//#define __RELEASE__
#ifdef __RELEASE__
#undef assert
#define assert(x) (x)
#endif

  //#define CACHE_ALWAYS_HITS
  //#define L2_ALWAYS_HITS

  // 64 KB L1 at 3 cycles
  const int L1_LINE_SIZE = 64;
  const int L1_SET_COUNT = 512;
  const int L1_WAY_COUNT = 2;
#define ENFORCE_L1_DCACHE_BANK_CONFLICTS
  const int L1_DCACHE_BANKS    =  8; // 8x16 byte = 128 bytes > linesize! -> not all lines can interfere w/ each other
  const int L1_DCACHE_BANKSIZE = 16;
#define L1_VIRTUALLY_INDEXED
  // With virtually indexed caches a single memory location could be present
  // twice in the cache, at different virtual indices. If this option below is
  // defined, the cache will ensure that such aliases are detected and removed.
  // This is not strictly necessary for PTLsim, as data is still consistent and
  // checking for aliases costs a significant amount of time!
#define L1_ENFORCE_VIRTUAL_ALIASING

  // 64 KB L1I
  const int L1I_LINE_SIZE = 64;
  const int L1I_SET_COUNT = 512;
  const int L1I_WAY_COUNT = 2;

  // 512 KB L2 at 9 cycles (specs) total (+L1 and issue) ~15 cycles (measured!)
  // TODO: Exclusive, victim-cache!
  const int L2_LINE_SIZE = 64;
  const int L2_SET_COUNT = 512;
  const int L2_WAY_COUNT = 16;
  const int L2_LATENCY   = 13; // don't include the extra wakeup cycle (waiting->ready state transition) in the LFRQ

  // TODO: Share this between cores on the same die!
  // TODO: This is also a victim cache :-/ and has some sharing features!
#define ENABLE_L3_CACHE
#ifdef ENABLE_L3_CACHE
  // 2 MB L3 cache (4096 sets, 16 ways) with 64-byte lines, TODO: latency?
  const int L3_SET_COUNT = 1024;
  const int L3_WAY_COUNT = 16;
  const int L3_LINE_SIZE = 128;
  const int L3_LATENCY   = 35;
#endif
  // Load Fill Request Queue (maximum number of missed loads)
  const int LFRQ_SIZE = 63;

  // Allow up to 16 outstanding lines in the L2 awaiting service:
  const int MISSBUF_COUNT = 16;
  const int MAIN_MEM_LATENCY = 160;

  const int CROSS_CACHE_LATENCY = 100;
  // TLBs
#ifdef PTLSIM_HYPERVISOR
#define USE_TLB
#define USE_L2_TLB
#endif

  // NOTE: This is L1 TLBs!
  const int ITLB_SIZE = 32;
  const int DTLB_SIZE = 48;
  // L2 i-TLB 512 4k entries, 4-way set associative
  const int L2_ITLB_SET_COUNT = 128;
  const int L2_ITLB_WAY_COUNT = 4;
  const int L2_ITLB_LATENCY   = 4;
  // L2 i-TLB 512 4k entries, 4-way set associative (ignore 2MB entries)
  const int L2_DTLB_SET_COUNT = 128;
  const int L2_DTLB_WAY_COUNT = 4;
  const int L2_DTLB_LATENCY   = 4;


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
  static inline ostream& operator <<(ostream& os, const CacheLine<linesize>& line) {
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
  static inline ostream& operator <<(ostream& os, const CacheLineWithValidMask<linesize>& line) {
    return line.print(os, 0);
  }

#ifdef ENABLE_ASF_CACHE_BASED
  template <int linesize>
  struct CacheLineWithValidMaskSpecRead : CacheLineWithValidMask<linesize> {
    typedef CacheLineWithValidMask<linesize> base_t;
    bool sr() const { return sr_; }
    void clear_sr() {sr_ = false; }
    void set_sr()   {sr_ = true; }
    void reset() { base_t::reset(); sr_ = false; }
    void clear_spec_state() { clear_sr(); }
    void invalidate() { reset(); }
    void fill(W64 tag, const bitvec<linesize>& valid, bool spec_read) {
      base_t::fill(tag, valid);
      sr_ |= spec_read;
    }
    ostream& print(ostream& os, W64 tag) const;
    private:
	  bool sr_;
  };

  template <int linesize>
  static inline ostream& operator <<(ostream& os, const CacheLineWithValidMaskSpecRead<linesize>& line) {
    return line.print(os, 0);
  }
  typedef CacheLineWithValidMaskSpecRead<L1_LINE_SIZE> L1CacheLineSpecRead;

#ifdef ENABLE_ASF_CACHE_WRITE_SET
  // TODO: Merge with LLB, move to extra source file.
  template <int linesize>
  class BackupStorage {
    private:
      W64  orig_data[linesize / sizeof(W64)];
      int  written:1, datavalid:1, speculative:1;
      int  refcount;

    public:
      void  reset() {written = 0; refcount = 0; datavalid = 0; speculative = 0;}

      void  copy_from_phys(Waddr physaddr) {
        assert(mask(physaddr, linesize) == 0);
        if (logable(5)) logfile << "Reading from ", (void*) physaddr,": ";
        for (int i = 0; i < linesize / sizeof(W64);
             ++i, physaddr += sizeof(W64)) {
               orig_data[i] = loadphys(physaddr);
               if (logable(5)) logfile << (void*)orig_data[i]," ";
        }
        if (logable(5)) logfile << endl;
        datavalid = true;
      }

      void  copy_to_phys(Waddr physaddr) {
        assert(mask(physaddr, linesize) == 0);
        assert(datavalid);
        if (logable(5)) logfile << "Restoring to ", (void*) physaddr,": ";
        for (int i = 0; i < linesize / sizeof(W64);
             ++i, physaddr += sizeof(W64)) {
               storephys(physaddr, orig_data[i]);
               if (logable(5)) logfile << (void*)orig_data[i]," ";
        }
        if (logable(5)) logfile << endl;
      }

      W64 data(Waddr physaddr) {
        assert(datavalid);
        return orig_data[mask(physaddr, linesize) >> 3];
      }
      BackupStorage() : written(false),refcount(0),datavalid(0),speculative(0) {}
      ostream& toString(ostream& os) const;

      bool is_dirty() const { return written; }
      bool is_data_valid() const { return datavalid; }

      void set_dirty() { written = true; }
      void set_clean() { written = false; }
  };
  template <int linesize>
  struct CacheLineWithValidMaskSpecRW : CacheLineWithValidMaskSpecRead<linesize>, BackupStorage<linesize> {
    typedef CacheLineWithValidMaskSpecRead<linesize> cache_t;
    typedef BackupStorage<linesize> llb_t;

    void reset() { cache_t::reset(); llb_t::reset(); }
    void invalidate() { reset(); }

    void set_sw()   { llb_t::set_dirty();  }
    void clear_sw() { llb_t::set_clean(); }
    bool sw() const { return llb_t::is_dirty(); }
    bool has_backup() const { return llb_t::is_data_valid(); }

    void clear_spec_state() { clear_sw(); cache_t::clear_spec_state(); llb_t::reset(); }
    ostream& print(ostream& os, W64 tag) const;
  };
  typedef CacheLineWithValidMaskSpecRW<L1_LINE_SIZE> L1CacheLineSpecRW;
#endif // ENABLE_ASF_CACHE_WRITE_SET
#endif // ENABLE_ASF_CACHE_BASED

  typedef CacheLineWithValidMask<L1_LINE_SIZE> L1CacheLine;
  typedef CacheLine<L1I_LINE_SIZE> L1ICacheLine;
  typedef CacheLineWithValidMask<L2_LINE_SIZE> L2CacheLine;
#ifdef ENABLE_L3_CACHE
  typedef CacheLine<L3_LINE_SIZE> L3CacheLine;
#endif

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

      if (logable(6) | FORCE_DEBUG) logfile << "[", cache_names[uniq], "] ", sim_cycle, ": evicted(", (void*)tag, "): lifetime ", lifetime, ", deadtime ", deadtime, ", hitcount ", hitcount, " (line addr ", &line, ")", endl;
    }

    static void filled(V& line, W64 tag) {
      line.filltime = sim_cycle;
      line.lasttime = sim_cycle;
      line.hitcount = 1;

      if (logable(6) | FORCE_DEBUG) logfile << "[", cache_names[uniq], "] ", sim_cycle, ": filled(", (void*)tag, ")", " (line addr ", &line, ")", endl;
    }

    static void inserted(V& line, W64 newtag, int way) {
      filled(line, newtag);
    }

    static void replaced(V& line, W64 oldtag, W64 newtag, int way) {
      evicted(line, oldtag);
      filled(line, newtag);
    }

    static void probed(V& line, W64 tag, int way, bool hit) {
      if (logable(6) | FORCE_DEBUG) logfile << "[", cache_names[uniq], "] ", sim_cycle, ": probe(", (void*)tag, "): ", (hit ? "HIT" : "miss"), " way ", way, ": hitcount ", line.hitcount, ", filltime ", line.filltime, ", lasttime ", line.lasttime, " (line addr ", &line, ")", endl;
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

#ifdef ENABLE_L3_CACHE
  typedef HistogramAssociativeArrayStatisticsCollector<3, L3CacheLine,
    DCACHE_L3_LINE_LIFETIME_INTERVAL, DCACHE_L3_LINE_LIFETIME_SLOTS,
    DCACHE_L3_LINE_DEADTIME_INTERVAL, DCACHE_L3_LINE_DEADTIME_SLOTS,
    DCACHE_L3_LINE_HITCOUNT_INTERVAL, DCACHE_L3_LINE_HITCOUNT_SLOTS> L3StatsCollectorBase;
#endif

  struct L1StatsCollector: public L1StatsCollectorBase { };
  struct L1IStatsCollector: public L1IStatsCollectorBase { };
  struct L2StatsCollector: public L2StatsCollectorBase { };
#ifdef ENABLE_L3_CACHE
  struct L3StatsCollector: public L3StatsCollectorBase { };
#endif

#else
  typedef NullAssociativeArrayStatisticsCollector<W64, L1CacheLine> L1StatsCollector;
  typedef NullAssociativeArrayStatisticsCollector<W64, L1ICacheLine> L1IStatsCollector;
  typedef NullAssociativeArrayStatisticsCollector<W64, L2CacheLine> L2StatsCollector;
#ifdef ENABLE_L3_CACHE
  typedef NullAssociativeArrayStatisticsCollector<W64, L3CacheLine> L3StatsCollector;
#endif
#ifdef ENABLE_ASF_CACHE_BASED
  typedef NullAssociativeArrayStatisticsCollector<W64, L1CacheLineSpecRead> L1StatsCollectorSpecRead;
#endif
#endif  // TRACK_LINE_USAGE

  template <typename CacheTrait>
  struct DataCache: protected CacheTrait::assoc {
    typedef typename CacheTrait::assoc base_t;
    typedef typename CacheTrait::T T;
    typedef typename CacheTrait::V V;
    enum {
      linesize = CacheTrait::linesize,
      setcount = CacheTrait::setcount,
      waycount = CacheTrait::waycount
    };
    void clearstats() {
#ifdef TRACK_LINE_USAGE
      foreach (set, setcount) {
        foreach (way, waycount) {
          base_t::sets[set][way].clearstats();
        }
      }
#endif
    }

    V* probe(T physaddr, T ign) { return probe(physaddr); }
    V* probe(T physaddr) {
      V* res =  base_t::probe(physaddr);
      return res;
    }

    V* select(T physaddr, T ign) { return select(physaddr); }
    V* select(T physaddr) {
      T dummy;
      return base_t::select(physaddr);
    }

    void invalidate(T physaddr, T ign) { return invalidate(physaddr); }
    void invalidate(T physaddr) {
      base_t::invalidate(physaddr);
    }

    W64 tagof(T a) { return base_t::tagof(a); }
    void reset() { base_t::reset(); }
  };

  template <typename CacheTrait>
  struct VirtIdxDataCache: protected CacheTrait::assoc {
    typedef typename CacheTrait::assoc base_t;
    typedef typename CacheTrait::T T;
    typedef typename CacheTrait::V V;
    enum {
      linesize = CacheTrait::linesize,
      setcount = CacheTrait::setcount,
      waycount = CacheTrait::waycount
    };
    void clearstats() {
#ifdef TRACK_LINE_USAGE
      foreach (set, setcount) {
        foreach (way, waycount) {
          base_t::sets[set][way].clearstats();
        }
      }
#endif
    }
    /**
     * Probing virtually indexed caches.
     * @param physaddr Physical addres of data to be probed for.
     * @param virtaddr Virtual address of probed item.
     */
    V* probe(T physaddr, T virtaddr) {
      assert(floor(lowbits(physaddr,PAGE_SHIFT), (int)linesize)
          == floor(lowbits(virtaddr,PAGE_SHIFT), (int)linesize));

      V* res =  base_t::sets[base_t::setof(virtaddr)].probe(base_t::tagof(physaddr));
      return res;
    }

    /**
     * Probing virtually indexed caches with just a physaddr causes a look-up
     * of the tag in all possible alias-sets.
     */
    V* probe(T physaddr) {
      const int naliases = (setcount*linesize) >> PAGE_SHIFT;

      if (!naliases) {
        return base_t::probe(physaddr);
      }

      V *cur, *res = NULL;
      int hit = 0;
      int aliasset;
      foreach (i, naliases) {
        aliasset = base_t::setof((i << PAGE_SHIFT) | lowbits(physaddr, PAGE_SHIFT));
        cur = base_t::sets[aliasset].probe(base_t::tagof(physaddr));
        if (cur) {
          hit++;
          res = cur;
        }
      }
#ifdef L1_ENFORCE_VIRTUAL_ALIASING
      assert((hit == 0) || (hit == 1));
#endif
      return res;
    }

    /**
     * Selecting virtually indexed caches, care has to be taken to prevent
     * aliasing! Simple handling here: On a cache miss, probe the other aliases
     * and evict them if present.
     * @param physaddr Physical addres of data to be probed for.
     * @param virtaddr Virtual address of probed item.
     */
    V* select(T physaddr, T virtaddr) {
      if (! (floor(lowbits(physaddr,PAGE_SHIFT), (int)linesize)
          == floor(lowbits(virtaddr,PAGE_SHIFT), (int)linesize))) {
        logfile << __FILE__,__LINE__,"phys: ", (void*) physaddr, " virt: ", (void*) virtaddr, endl;
      assert(floor(lowbits(physaddr,PAGE_SHIFT), (int)linesize)
          == floor(lowbits(virtaddr,PAGE_SHIFT), (int)linesize));
      }

#ifdef L1_ENFORCE_VIRTUAL_ALIASING
      V* res = probe(physaddr, virtaddr);
      if likely (res) return res;

      /* SD: Nothing found, remove potential aliases.
         Aliasing happens in the bits which are part of the index and the
         virtual page number. */
      const int naliases = (setcount*linesize) >> PAGE_SHIFT;
      if (!naliases) return res;
      int this_alias = (virtaddr >> PAGE_SHIFT) & (naliases - 1);

      /* SD: Find all _other_ aliases and remove them */
      int aliasset;
      foreach (i, naliases) {
        if (i == this_alias) continue;
        aliasset = base_t::setof((i << PAGE_SHIFT) | lowbits(virtaddr, PAGE_SHIFT));
        base_t::sets[aliasset].invalidate(base_t::tagof(physaddr));
      }
#endif
      T dummy;
      return base_t::sets[base_t::setof(virtaddr)].select(base_t::tagof(physaddr), dummy);
    }

    /**
     * Invalidate a particular tag, regardless of the index.
     */
    void invalidate(T physaddr) {
      const int naliases = (setcount*linesize) >> PAGE_SHIFT;
      if (!naliases) {
         base_t::sets[base_t::setof(physaddr)].invalidate(base_t::tagof(physaddr));
        return;
      }
      /* SD: Find all aliases & invalidate them, if they have the same physaddr. */
      int aliasset;
      foreach (i, naliases) {
        aliasset = base_t::setof((i << PAGE_SHIFT) | lowbits(physaddr, PAGE_SHIFT));
        base_t::sets[aliasset].invalidate(base_t::tagof(physaddr));
      }
    }

    /**
     * Invalidating virtually indexed caches.
     * @param physaddr Physical addres of data to be invalidated.
     * @param virtaddr Virtual address of data to be invalidated.
     */
    void invalidate(T physaddr, T virtaddr) {
      assert(floor(lowbits(physaddr,PAGE_SHIFT), (int)linesize)
          == floor(lowbits(virtaddr,PAGE_SHIFT), (int)linesize));
#ifdef L1_ENFORCE_VIRTUAL_ALIASING
      const int naliases = (setcount*linesize) >> PAGE_SHIFT;
      if (!naliases) {
         base_t::sets[base_t::setof(virtaddr)].invalidate(base_t::tagof(physaddr));
        return;
      }
      /* SD: Find all aliases & invalidate them, if they have the same physaddr. */
      int aliasset;
      foreach (i, naliases) {
        aliasset = base_t::setof((i << PAGE_SHIFT) | lowbits(virtaddr, PAGE_SHIFT));
        base_t::sets[aliasset].invalidate(base_t::tagof(physaddr));
      }
#else
      base_t::sets[base_t::setof(virtaddr)].invalidate(base_t::tagof(physaddr));
#endif
    }

    W64 tagof(T a) { return base_t::tagof(a); }
    void reset() { base_t::reset(); }
  };

  /* Combines all relevant template parameters for a cache into one, in
   * order to reduce duplication. */
  template <typename V_, int setcount_, int waycount_, int linesize_,
    typename stats_ = NullAssociativeArrayStatisticsCollector<W64, V_> >
  struct DefaultCacheTrait {
    typedef W64    T;
    typedef V_     V;
    typedef stats_ stats;
    enum {linesize = linesize_, setcount = setcount_, waycount = waycount_};
    //typedef LockableAssociativeArray<T, V, setcount, waycount, linesize, stats> base;
    typedef AssociativeArray<T, V, setcount, waycount, linesize, stats> assoc;
    //typedef NotifyAssociativeWrapper<LockableAssociativeArray<T, V, setcount,
    //  waycount, linesize, stats>, T, V > base;
    //typedef NotifyAssociativeWrapper<AssociativeArray<T, V, setcount,
    //  waycount, linesize, stats>, T, V > base;
  };

#ifdef L1_VIRTUALLY_INDEXED
  typedef VirtIdxDataCache<DefaultCacheTrait<L1CacheLine, L1_SET_COUNT,
    L1_WAY_COUNT, L1_LINE_SIZE, L1StatsCollector> > L1CacheBase;
#else
  typedef DataCache<DefaultCacheTrait<L1CacheLine, L1_SET_COUNT, L1_WAY_COUNT,
    L1_LINE_SIZE, L1StatsCollector> > L1CacheBase;
#endif

  struct L1Cache_: public L1CacheBase {
    L1CacheLine* validate(W64 physaddr, W64 virtaddr, const bitvec<L1_LINE_SIZE>& valid) {
      L1CacheLine* line = select(physaddr, virtaddr);

      line->fill(tagof(physaddr), valid);
      return line;
    }
  };
  static inline ostream& operator <<(ostream& os, const L1Cache_& cache) {
    return os;
  }
#if !defined(ENABLE_ASF_CACHE_BASED) && !defined(ENABLE_ASF_CACHE_WRITE_SET)
  typedef L1Cache_ L1Cache;
#endif


#ifdef ENABLE_ASF_CACHE_BASED
  // This L1 cache has additional "speculative read" bits for each cache-line,
  // that can be set by ASF-loads. It also uses the notification wrapper around
  // the cache, ensuring proper information.
  // The cache furthermore provides an interface to query whether it is still
  // consistent.
  template <typename V, int setcount, int waycount, int linesize,
    typename stats = NullAssociativeArrayStatisticsCollector<W64, V> >
  struct ASFCacheTrait : DefaultCacheTrait<V, setcount, waycount, linesize, stats> {
    typedef DefaultCacheTrait<V, setcount, waycount, linesize, stats> base_t;
    typedef NotifyAssociativeWrapper<typename base_t::assoc, W64, V> assoc;
  };

#ifdef L1_VIRTUALLY_INDEXED
  template <class T>
  struct L1CacheSpecBase {
    typedef VirtIdxDataCache<ASFCacheTrait<T, L1_SET_COUNT,L1_WAY_COUNT,
      L1_LINE_SIZE, L1StatsCollector> > Type;
  };
#else
  template <class T>
  struct L1CacheSpecBase {
    typedef DataCache<ASFCacheTrait<T, L1_SET_COUNT,L1_WAY_COUNT,
      L1_LINE_SIZE, L1StatsCollector> > Type;
  };
#endif

  template <class T=L1CacheLineSpecRead>
  class L1CacheSpecRead : public L1CacheSpecBase<T>::Type {
  protected:
    typedef typename L1CacheSpecBase<T>::Type base_t;
    typedef typename base_t::base_t  NotifyAssociativeWrapper;
    typedef typename NotifyAssociativeWrapper::LineNotify LineNotify;
    typedef typename NotifyAssociativeWrapper::Notify     Notify;
  private:
    bool evicted_spec_line;
    bool invalidated_spec_line;
    bool in_spec_region;

    void flash_clear_spec_bits() {
      typename base_t::iterator it = base_t::begin();
      for (; it != base_t::end(); ++it)
        (*it).second.clear_spec_state();
    }

    void reset_spec_state() {
      flash_clear_spec_bits();
      evicted_spec_line     = false;
      invalidated_spec_line = false;
    }
  protected:
    static void callback_evict(void *data, T *line, W64 physaddr) {
      assert(line);
      if (logable(5)) logfile << __FILE__,__LINE__, " CB: Line ", line->sr() ? "spec ":"", line, " evicted, physaddr: ",(void*) physaddr, endl;
      if likely (!line->sr()) return;

      L1CacheSpecRead *cache = (L1CacheSpecRead*)data;
      assert(cache->in_spec_region);
      cache->evicted_spec_line = true;
      line->clear_sr();
    }
    static void callback_inv(void *data, T *line, W64 physaddr) {
      assert(line);
      if (logable(5)) logfile << __FILE__,__LINE__, " CB: Line ", line->sr() ? "spec ":"", line, " invalidated, physaddr: ",(void*) physaddr, endl;
      if likely (!line->sr()) return;

      L1CacheSpecRead *cache = (L1CacheSpecRead*)data;
      assert(cache->in_spec_region);
      cache->invalidated_spec_line = true;
      line->clear_sr();
    }
    static void callback_reset(void *cache) {
      if (logable(5)) logfile << __FILE__,__LINE__," CB: Cache reset. ", endl;
      ((L1CacheSpecRead*)cache)->evicted_spec_line = true;
    }

  public:
    T* validate(W64 physaddr, W64 virtaddr, const bitvec<L1_LINE_SIZE>& valid, bool spec_read) {
      T* line = base_t::select(physaddr, virtaddr);
      assert(line);
      line->fill(base_t::tagof(physaddr), valid, spec_read);
      return line;
    }
    void reset() {
      base_t::reset();
      evicted_spec_line     = false;
      invalidated_spec_line = false;
      in_spec_region        = false;
    }
    L1CacheSpecRead() {
      reset();
      NotifyAssociativeWrapper::set_notifications((void*)this, &callback_evict,
          &callback_inv, NULL, &callback_reset);
    }

    // TODO: Interface for ASF storage!
    // TODO: Optimisation: Switch on call-backs only when inside spec-region!
    void start() { reset_spec_state(); in_spec_region = true; };
    void commit() { assert(in_spec_region); reset_spec_state(); in_spec_region = false; };
    void abort()  { assert(in_spec_region); reset_spec_state(); in_spec_region = false; };
    bool consistency_error() const { return invalidated_spec_line; }
    bool capacity_error() const { return evicted_spec_line; }
  };

  template <class T>
  static inline ostream& operator <<(ostream& os, const L1CacheSpecRead<T>& cache) {
    return os;
  }

#ifdef ENABLE_ASF_CACHE_WRITE_SET
  template <class T = L1CacheLineSpecRW>
  class L1CacheSpecRW : public L1CacheSpecRead<T> {
    typedef L1CacheSpecRead<T> base_t;
    typedef T line_t;
  private:
    bool probed_spec_dirty_line;

#if (0)
    static void callback_probe(void *cache, T *line) {
      assert(line);
      if (logable(5)) logfile << __FILE__,__LINE__, " CB: Line ", line->sr() ? "spec ":"", line, " probed.", endl;

      if (line->sw()) ((L1CacheSpecRW<>*)cache)->probed_spec_dirty_line = true;
      line->set_nonspec();
    }
#endif
    void reset_write_spec_state() {
      probed_spec_dirty_line = false;
    }
    void reset_spec_state() {
      base_t::reset_spec_state();
      reset_write_spec_state();
    }

    void restore_dirty_lines() {
      typename base_t::iterator it = base_t::begin();
      for (; it != base_t::end(); ++it) {
        T&  line     = (*it).second;
        W64 physaddr = (*it).first;
        if unlikely (line.sw()) {
          logfile << __FILE__,__LINE__,(void*)physaddr,endl;
          if (line.has_backup())
            line.copy_to_phys(physaddr);
          line.clear_sw();
        }
      }
    }

    static void callback_evict(void *data, T *line, W64 physaddr) {
      assert(line);
      if (logable(5)) logfile << __FILE__,__LINE__, " CB: Line ", line->sr() ? "spec ":"", line, " evicted, physaddr: ",(void*) physaddr, endl;

      base_t::callback_evict(data, line, physaddr);
      line->clear_spec_state();

      if likely (!line->sw()) return;

      L1CacheSpecRW *cache = (L1CacheSpecRW*)data;
      if (line->has_backup())
        line->copy_to_phys(physaddr);
      //cache->evicted_spec_line = true;
      line->clear_spec_state();
    }
    static void callback_inv(void *data, T *line, W64 physaddr) {
      assert(line);
      if (logable(5)) logfile << __FILE__,__LINE__, " CB: Line ", line->sr() ? "spec ":"", line, " invalidated, physaddr: ",(void*) physaddr, endl;

      base_t::callback_inv(data, line, physaddr);

      if likely (!line->sw()) return;

      L1CacheSpecRW *cache = (L1CacheSpecRW*)data;
      if (line->has_backup())
        line->copy_to_phys(physaddr);
      //cache->invalidated_spec_line = true;
      line->clear_sr();
    }
    static void callback_reset(void *cache) {
      if (logable(5)) logfile << __FILE__,__LINE__," CB: Cache reset. ", endl;
      base_t::callback_reset(cache);
      ((L1CacheSpecRW*)cache)->restore_dirty_lines();
    }


  public:
    L1CacheSpecRW() : base_t()  {
      base_t::NotifyAssociativeWrapper::set_notifications((void*)this, &callback_evict,
          &callback_inv, NULL, &callback_reset);
    }

    bool external_probe(W64 physaddr, bool inv) {
      if (logable(5))
        logfile << __FILE__,__LINE__, " External probe for L1 @ ", (void*) physaddr, " inv: ", inv, endl;

      physaddr = floor(physaddr, L1_LINE_SIZE);

      T* line = base_t::probe(physaddr);
      if (logable(5))
        logfile << __FILE__,__LINE__, " Hit line: ", line, endl;

      if (!line) return false;

      if (logable(5))
        logfile << __FILE__,__LINE__, " SR: ", line->sr(), " SW: ", line->sw(), endl;

      if (line->sw()) {
        probed_spec_dirty_line = true;
        logfile << __FILE__,__LINE__,(void*)physaddr,endl;
        if (line->has_backup())
          line->copy_to_phys(physaddr);
        line->clear_spec_state();

        if (logable(5))
          logfile << __FILE__,__LINE__, " Restoring data to ", (void*)physaddr, endl;

        return true;
      }

      //NOTE: The invalidate_callback handles the eviction of ASF-spec lines!
      if (inv) base_t::invalidate(physaddr);
      return true;
    }
    void start()  { base_t::start(); reset_write_spec_state(); };
    void commit() { base_t::commit(); reset_write_spec_state(); };
    void abort()  { restore_dirty_lines(); base_t::abort(); reset_write_spec_state(); };
    bool consistency_error() const { return base_t::consistency_error() || probed_spec_dirty_line; }
  };
  typedef L1CacheSpecRW<> L1Cache;
#else
  typedef L1CacheSpecRead<> L1Cache;
#endif // ENABLE_ASF_CACHE_WRITE_SET
#endif // ENABLE_ASF_CACHE_BASED

  //
  // L1 instruction cache
  //

  struct L1ICache: public DataCache<DefaultCacheTrait<L1ICacheLine, L1I_SET_COUNT, L1I_WAY_COUNT, L1I_LINE_SIZE, L1IStatsCollector> >{
    L1ICacheLine* validate(W64 addr, const bitvec<L1I_LINE_SIZE>& valid) {
      addr = tagof(addr);
      L1ICacheLine* line = select(addr);
      line->fill(addr, valid);
      return line;
    }
  };

  static inline ostream& operator <<(ostream& os, const L1ICache& cache) {
    return os;
  }

  //
  // L2 cache
  //

  typedef DataCache<DefaultCacheTrait<L2CacheLine, L2_SET_COUNT, L2_WAY_COUNT, L2_LINE_SIZE, L2StatsCollector> >L2CacheBase;

  struct L2Cache: public L2CacheBase {
    void validate(W64 addr) {
      L2CacheLine* line = select(addr);
      if (!line) return;
      line->valid.setall();
    }

    void deliver(W64 address);
  };

  //
  // L3 cache
  //
#ifdef ENABLE_L3_CACHE
  static inline ostream& operator <<(ostream& os, const L3CacheLine& line) {
    return line.print(os, 0);
  }

  struct L3Cache: public DataCache<DefaultCacheTrait<L3CacheLine, L3_SET_COUNT, L3_WAY_COUNT, L3_LINE_SIZE, L3StatsCollector> >{
    L3CacheLine* validate(W64 addr) {
      W64 oldaddr;
      L3CacheLine* line = select(addr, oldaddr);
      return line;
    }
  };
#endif

  static inline void prep_sframask_and_reqmask(const SFR* sfr, W64 addr, int sizeshift, bitvec<L1_LINE_SIZE>& sframask, bitvec<L1_LINE_SIZE>& reqmask) {
    sframask = (sfr) ? (bitvec<L1_LINE_SIZE>(sfr->bytemask) << 8*lowbits(sfr->physaddr, log2(L1_LINE_SIZE)-3)) : 0;
    reqmask = bitvec<L1_LINE_SIZE>(bitmask(1 << sizeshift)) << lowbits(addr, log2(L1_LINE_SIZE));
  }

  static inline void prep_L2_sframask_and_reqmask(const SFR* sfr, W64 addr, int sizeshift, bitvec<L2_LINE_SIZE>& sframask, bitvec<L2_LINE_SIZE>& reqmask) {
    sframask = (sfr) ? (bitvec<L2_LINE_SIZE>(sfr->bytemask) << 8*lowbits(sfr->physaddr, log2(L2_LINE_SIZE)-3)) : 0;
    reqmask = bitvec<L2_LINE_SIZE>(bitmask(1 << sizeshift)) << lowbits(addr, log2(L2_LINE_SIZE));
  }

  //
  // TLB class with one-hot semantics. 36 bit tags are required since
  // virtual addresses are 48 bits, so 48 - 12 (2^12 bytes per page)
  // is 36 bits.
  //
  template <int tlbid, int setcount, int waycount>
  struct TranslationLookasideBuffer {
    typedef FullyAssociativeTagsNbitOneHot<waycount, 40> Set;
    Set sets[setcount];

    TranslationLookasideBuffer() { reset(); }

    void reset() { foreach (set, setcount) sets[set].reset(); }

    // Get the 40-bit TLB tag (36 bit virtual page ID plus 4 bit threadid)
    static W64 tagof(W64 addr, W64 threadid) {
      return bits(addr, 12, 36) | (threadid << 36);
    }
    static int setof(W64 addr) { return lowbits(addr, log2(setcount)); }

    bool probe(W64 addr, int threadid = 0) {
      W64 tag = tagof(addr, threadid);
      return (sets[setof(addr)].probe(tag) >= 0);
    }

    bool insert(W64 addr, int threadid = 0) {
      addr = floor(addr, PAGE_SIZE);
      W64 tag = tagof(addr, threadid);
      W64 set = setof(addr);
      W64 oldtag;
      int way = sets[set].select(tag, oldtag);
      W64 oldaddr = lowbits(oldtag, 36) << 12;
      if (logable(6)) {
        logfile << "TLB insertion of virt page ", (void*)(Waddr)addr, " (virt addr ",
          (void*)(Waddr)(addr), ") into set ", set, " way ", way, ": ",
          ((oldtag != tag) ? "evicted old entry" : "already present"), endl;
      }
      return (oldtag != tag);
    }

    int flush_all() {
      reset();
      return setcount * waycount;
    }

    int flush_thread(W64 threadid) {
      W64 tag = threadid << 36;
      W64 tagmask = 0xfULL << 36;
      int n;
      foreach (set, setcount) {
        bitvec<waycount> slotmask = sets[set].masked_match(tag, tagmask);
        n += slotmask.popcount();
        sets[set].masked_invalidate(slotmask);
      }
      return n;
    }

    int flush_virt(Waddr virtaddr, W64 threadid) {
      return sets[setof(virtaddr)].invalidate(tagof(virtaddr, threadid));
    }

    ostream& print(ostream& os) const {
      os << "TLB<", setcount, " sets, ", waycount, " ways>:", endl;
      foreach (set, setcount) {
        os << "  Set ", set, ":", endl;
        os << sets[set];
      }
      return os;
    }
  };

  template <int tlbid, int setcount, int waycount>
  static inline ostream& operator <<(ostream& os, const TranslationLookasideBuffer<tlbid, setcount, waycount>& tlb) {
    return tlb.print(os);
  }

  typedef TranslationLookasideBuffer<0, 1, DTLB_SIZE> DTLB;
  typedef TranslationLookasideBuffer<1, 1, ITLB_SIZE> ITLB;
  typedef TranslationLookasideBuffer<0, L2_DTLB_SET_COUNT, L2_DTLB_WAY_COUNT> L2_DTLB;
  typedef TranslationLookasideBuffer<1, L2_ITLB_SET_COUNT, L2_ITLB_WAY_COUNT> L2_ITLB;

  struct CacheHierarchy;

  //
  // Load fill request queue (LFRQ) contains any requests for outstanding
  // loads from both the L2 or L1.
  //
  struct LoadFillReq {
    W64 addr;       // physical address
    W64 virtaddr;   // virtual address for virtually indexed caches
    W64 data;       // data already known so far (e.g. from SFR)
    LoadStoreInfo lsi;
    W32  initcycle;
    byte mask;
    byte fillL1:1, fillL2:1;
    W8s  mbidx;

    inline LoadFillReq() { }

    LoadFillReq(W64 addr, W64 virtaddr, W64 data, byte mask, LoadStoreInfo lsi);
    ostream& print(ostream& os) const;
  };

  static inline ostream& operator <<(ostream& os, const LoadFillReq& req) {
    return req.print(os);
  }

  template <int size>
  struct LoadFillReqQueue {
    CacheHierarchy& hierarchy;
    bitvec<size> freemap;                    // Slot is free
    bitvec<size> waiting;                    // Waiting for the line to arrive in the L1
    bitvec<size> ready;                      // Wait to extract/signext and write into register
    bitvec<size> retry;                      // Needs to be retried by the OP
    LoadFillReq reqs[size];
    int count;

    static const int SIZE = size;

    LoadFillReqQueue(): hierarchy(*((CacheHierarchy*)null)) { reset(); }
    LoadFillReqQueue(CacheHierarchy& hierarchy_): hierarchy(hierarchy_) { reset(); }

    // Clear entries belonging to one thread
    void reset(int threadid);

    // Reset all threads
    void reset() {
      freemap.setall();
      ready = 0;
      retry = 0;
      waiting = 0;
      count = 0;
    }

    void changestate(int idx, bitvec<size>& oldstate, bitvec<size>& newstate) {
      oldstate[idx] = 0;
      newstate[idx] = 1;
    }

    void free(int lfrqslot) {
      assert(waiting[lfrqslot]);
      changestate(lfrqslot, waiting, freemap);
      assert(count > 0);
      count--;
    }

    bool full() const {
      return (!freemap);
    }

    int remaining() const {
      return (size - count);
    }

    void annul(int lfrqslot);
#ifdef ENABLE_ASF_CACHE_BASED
    void annul_asf_spec_lfr(int mbidx, int lfrqslot);
#endif
    void restart();

    int add(const LoadFillReq& req);

    void wakeup(W64 address, const bitvec<LFRQ_SIZE>& lfrqmask, bool need_retry = false);

    void clock();

    LoadFillReq& operator [](int idx) { return reqs[idx]; }
    const LoadFillReq& operator [](int idx) const { return reqs[idx]; }

    ostream& print(ostream& os) const;
  };

  template <int size>
  static inline ostream& operator <<(ostream& os, const LoadFillReqQueue<size>& lfrq) {
    return lfrq.print(os);
  }

  enum { STATE_IDLE, STATE_DELIVER_TO_L3, STATE_DELIVER_TO_L2, STATE_DELIVER_TO_L1};
  static const char* missbuf_state_names[] = {"idle", "mem->L3", "L3->L2", "L2->L1"};

  template <int SIZE>
  struct MissBuffer {
    struct Entry {
      W64 addr;     // physical line address we are waiting for
      W64 virtaddr; // virtual line address we are waiting for, for virtually indexed caches
      W16 state;
#ifdef ENABLE_ASF_CACHE_BASED
      W16 dcache:1, icache:1, asf_spec:1;
#else
      W16 dcache:1, icache:1;    // L1I vs L1D
#endif
      W32 cycles;
      W16 rob;
      W8 threadid;

      bitvec<LFRQ_SIZE> lfrqmap;  // which LFRQ entries should this load wake up?
      void reset() {
        lfrqmap = 0;
        addr = 0xffffffffffffffffULL;
        virtaddr = 0xffffffffffffffffULL;
        state = STATE_IDLE;
        cycles = 0;
        icache = 0;
        dcache = 0;
        rob = 0xffff;
        threadid = 0xff;
#ifdef ENABLE_ASF_CACHE_BASED
        asf_spec = 0;
#endif
      }
    };

    MissBuffer(): hierarchy(*((CacheHierarchy*)null)) { reset(); }
    MissBuffer(CacheHierarchy& hierarchy_): hierarchy(hierarchy_) { reset(); }

    CacheHierarchy& hierarchy;
    Entry missbufs[SIZE];
    bitvec<SIZE> freemap;
    int count;

    void reset();
    void reset(int threadid);
    void restart();
    bool full() const { return (!freemap); }
    int remaining() const { return (SIZE - count); }
    int find(W64 addr);
    int initiate_miss(W64 addr, W64 virtaddr, bool hit_in_L2, bool icache = 0, int rob = 0xffff, int threadid = 0xfe);
    int initiate_miss(LoadFillReq& req, bool hit_in_L2, int rob = 0xffff);
    void annul_lfrq(int slot);
    void annul_lfrq(int slot, int threadid);
    void clock();
    void external_probe(W64 physaddr, bool inv);
    ostream& print(ostream& os) const;
  };

  template <int size>
  static inline ostream& operator <<(ostream& os, const MissBuffer<size>& missbuf) {
    return missbuf.print(os);
  }

  struct PerCoreCacheCallbacks {
    virtual void dcache_wakeup(LoadStoreInfo lsi, W64 physaddr);
    virtual void icache_wakeup(LoadStoreInfo lsi, W64 physaddr);
    virtual void external_probe(W64 physaddr, bool invalidating);
  };

  //
  // Prefetcher
  //
  // States for the PrefetchEntry
  enum { PE_INIT, PE_TRANSIENT, PE_STEADY, PE_NOPRED };
  #define PE_MAX_AHEAD (7)
  struct PrefetchEntry {
    W64  state:2, lastaddr:48, ahead:3, target_ahead: 3;
    W16s stride;
    void reset() {
      state        = PE_INIT;
      lastaddr     = 0;
      stride       = 0;
      ahead        = 0;
      target_ahead = 0;
    }
    ostream& print(ostream& os, W64 tag) const;
  };
  static inline ostream& operator <<(ostream& os, const PrefetchEntry& line) {
    return line.print(os, 0);
  }

  template <int entries>
  struct Prefetcher : public FullyAssociativeArray<W64, struct PrefetchEntry, entries> {
    typedef FullyAssociativeArray<W64, struct PrefetchEntry, entries> base_t;
    CacheHierarchy& hier;

    Prefetcher(CacheHierarchy& h):hier(h) { }
    void update(W64 loadrip, W64 loadtargetphys);
    W64 get_next_prefetch(W64 loadrip, bool& havemore);
    void adjust_look_ahead(W64 loadrip, W64 loadtargetphys, bool l1hit);
  };

  struct CacheHierarchy {
    LoadFillReqQueue<LFRQ_SIZE> lfrq;
    MissBuffer<MISSBUF_COUNT> missbuf;
    L1Cache L1;
    L1ICache L1I;
    L2Cache L2;
#ifdef ENABLE_L3_CACHE
    L3Cache L3;
#endif
    DTLB dtlb;
    ITLB itlb;
#ifdef USE_L2_TLB
    L2_DTLB l2dtlb;
    L2_ITLB l2itlb;
#endif

    byte coreid;
    static CacheHierarchy* hierarchies[];

    PerCoreCacheCallbacks* callback;


    CacheHierarchy(int coreid_ = 0): lfrq(*this), missbuf(*this), coreid(coreid_)
    {
      callback = null;
      assert ((0 <= coreid_) && (coreid_ < MAX_HIERARCHIES));
      CacheHierarchy::hierarchies[coreid_] = this;
    }

    bool probe_cache_and_sfr(W64 physaddr, W64 virtaddr, const SFR* sfra, int sizeshift);
    bool probe_cache_and_sfr(W64 physaddr, const SFR* sfra, int sizeshift);
    bool covered_by_sfr(W64 addr, SFR* sfr, int sizeshift);
    void annul_lfrq_slot(int lfrqslot);
    int issueload_slowpath(Waddr physaddr, SFR& sfra, LoadStoreInfo lsi, bool& L2hit);
    int issueload_slowpath(Waddr physaddr, Waddr virtaddr, SFR& sfra, LoadStoreInfo lsi, bool& L2hit);

    int issueload_slowpath(Waddr physaddr, SFR& sfra, LoadStoreInfo lsi) {
      bool L2hit = 0;
      return issueload_slowpath(physaddr, sfra, lsi, L2hit);
    }

    int issueload_slowpath(Waddr physaddr, Waddr virtaddr, SFR& sfra, LoadStoreInfo lsi) {
      bool L2hit = 0;
      return issueload_slowpath(physaddr, virtaddr, sfra, lsi, L2hit);
    }

    int get_lfrq_mb(int lfrqslot) const;
    int get_lfrq_mb_state(int lfrqslot) const;
    bool lfrq_or_missbuf_full() const { return lfrq.full() | missbuf.full(); }

#ifdef POOR_MANS_MESI
    bool probe_other_caches(W64 addr, bool inv);
    bool external_probe(W64 addr, bool inv);
#endif

    W64 commitstore(const SFR& sfr, W64 virtaddr, bool internal = false, int threadid = 0xff, bool perform_actual_write = true);
    W64 speculative_store(const SFR& sfr, W64 virtaddr, int threadid = 0xff);

    void initiate_prefetch(W64 physaddr, W64 virtaddr, int cachelevel, bool invalidating = false, int threadid = 0xfe);

    bool probe_icache(Waddr virtaddr, Waddr physaddr);
    int initiate_icache_miss(W64 addr, int rob = 0xffff, int threadid = 0xff);

    void reset();
    void clock();
    void complete();
    void complete(int threadid);
    ostream& print(ostream& os);
  };
#endif // STATS_ONLY
};

struct PerContextDataCacheStats { // rootnode:
  struct load {
    struct hit { // node: summable
      W64 L1;
      W64 L2;
      W64 L3;
      W64 mem;
    } hit;

    struct dtlb { // node: summable
      W64 l1hits;
      W64 l2hits;
      W64 misses;
    } dtlb;

    struct tlbwalk { // node: summable
      W64 L1_dcache_hit;
      W64 L1_dcache_miss;
      W64 no_lfrq_mb;
    } tlbwalk;
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

    struct tlbwalk { // node: summable
      W64 L1_dcache_hit;
      W64 L1_dcache_miss;
      W64 no_lfrq_mb;
    } tlbwalk;
  } fetch;

  struct store {
    W64 prefetches;
  } store;
};

struct DataCacheStats { // rootnode:
  struct load {
    struct transfer { // node: summable
      W64 L2_to_L1_full;
      W64 L2_to_L1_partial;
      W64 L2_L1I_full;
    } transfer;
  } load;

  struct missbuf {
    W64 inserts;
    struct deliver { // node: summable
      W64 mem_to_L3;
      W64 L3_to_L2;
      W64 L2_to_L1D;
      W64 L2_to_L1I;
    } deliver;
  } missbuf;

  struct prefetch { // node: summable
    W64 in_L1;
    W64 in_L2;
    W64 required;
  } prefetch;

  struct lfrq {
    W64 inserts;
    W64 wakeups;
    W64 annuls;
    W64 resets;
    W64 total_latency;
    double average_latency;
    W64 width[CacheSubsystem::MAX_WAKEUPS_PER_CYCLE+1]; // histo: 0, CacheSubsystem::MAX_WAKEUPS_PER_CYCLE+1, 1
  } lfrq;

  PerContextDataCacheStats total;
  // IMPORTANT: This list MUST be equal in length to the number of active VCPUs (at most MAX_CONTEXTS):
  PerContextDataCacheStats vcpu0;
  PerContextDataCacheStats vcpu1;
  PerContextDataCacheStats vcpu2;
  PerContextDataCacheStats vcpu3;
  PerContextDataCacheStats vcpu4;
  PerContextDataCacheStats vcpu5;
  PerContextDataCacheStats vcpu6;
  PerContextDataCacheStats vcpu7;
  PerContextDataCacheStats vcpu8;
  PerContextDataCacheStats vcpu9;
  PerContextDataCacheStats vcpu10;
  PerContextDataCacheStats vcpu11;
  PerContextDataCacheStats vcpu12;
  PerContextDataCacheStats vcpu13;
  PerContextDataCacheStats vcpu14;
  PerContextDataCacheStats vcpu15;
  PerContextDataCacheStats vcpu16;
  PerContextDataCacheStats vcpu17;
  PerContextDataCacheStats vcpu18;
  PerContextDataCacheStats vcpu19;
  PerContextDataCacheStats vcpu20;
  PerContextDataCacheStats vcpu21;
  PerContextDataCacheStats vcpu22;
  PerContextDataCacheStats vcpu23;
  PerContextDataCacheStats vcpu24;
  PerContextDataCacheStats vcpu25;
  PerContextDataCacheStats vcpu26;
  PerContextDataCacheStats vcpu27;
  PerContextDataCacheStats vcpu28;
  PerContextDataCacheStats vcpu29;
  PerContextDataCacheStats vcpu30;
  PerContextDataCacheStats vcpu31;
};
