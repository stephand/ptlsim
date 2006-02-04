//
// PTLsim: Cycle Accurate x86-64 Simulator
// L1 and L2 Data Caches
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <dcacheint.h>
#include <datastore.h>


void print_dcache();

using namespace DataCache;

#if 1
#define starttimer(timer) timer.start()
#define stoptimer(timer) timer.stop()
#else
#define starttimer(timer) (1)
#define stoptimer(timer) (1)
#endif

CycleTimer load_slowpath_timer("Load slow path");
CycleTimer store_slowpath_timer("Store slow path");
CycleTimer store_flush_timer("Store commit buffer flush");

notify_wakeup_t wakeup_func = null;
notify_wakeup_t icache_wakeup_func = null;

// totals 100%:
W64 load_issue_complete;
W64 load_issue_miss;
W64 load_issue_exception;
W64 load_issue_ordering;
W64 load_issue_unaligned;
W64 load_issue_replay_sfr_addr_and_data_not_ready;
W64 load_issue_replay_sfr_addr_not_ready;
W64 load_issue_replay_sfr_data_not_ready;
W64 load_issue_replay_missbuf_full;

// totals 100%:
W64 load_forward_from_cache;
W64 load_forward_from_sfr;
W64 load_forward_from_sfr_and_cache;

// totals 100%:
W64 load_dependency_independent;
W64 load_dependency_predicted_alias_unresolved;
W64 load_dependency_stq_address_match;

// totals 100%:
W64 load_type_aligned;
W64 load_type_unaligned;
W64 load_type_internal;

// totals 100%:
W64 load_size[4];

// totals 100%:
W64 load_hit_L1;
W64 load_hit_L2;
W64 load_hit_L3;
W64 load_hit_mem;

// totals 100%:
W64 fetch_hit_L1;
W64 fetch_hit_L2;
W64 fetch_hit_L3;
W64 fetch_hit_mem;

// totals 100%:
W64 load_transfer_L2_to_L1_full;
W64 load_transfer_L2_to_L1_partial;

W64 load_transfer_L2_to_L1I_full;

// no specific total:
W64 missbuf_inserts;
W64 missbuf_deliver_mem_to_L3;
W64 missbuf_deliver_L3_to_L2;
W64 missbuf_deliver_L2_to_L1;
W64 missbuf_deliver_L2_to_L1I;

// totals 100%:
W64 store_issue_complete;
W64 store_issue_unaligned;
W64 store_issue_ordering;
W64 store_issue_exception;
W64 store_issue_replay_store_data_not_ready;
W64 store_issue_replay_sfr_data_not_ready;
W64 store_issue_replay_sfr_addr_not_ready;
W64 store_issue_replay_sfr_addr_and_data_not_ready;
W64 store_issue_replay_sfr_addr_and_data_and_data_to_store_not_ready;
W64 store_issue_replay_sfr_addr_and_data_to_store_not_ready;
W64 store_issue_replay_sfr_data_and_data_to_store_not_ready;

// totals 100%
W64 store_forward_from_zero;
W64 store_forward_from_sfr;

// totals 100%:
W64 store_type_aligned;
W64 store_type_unaligned;
W64 store_type_internal;

// totals 100%:
W64 store_size[4];

// n/a:
W64 store_parallel_aliasing;

// totals 100%:
W64 store_commit_direct;
W64 store_commit_deferred;

// no specific total:
W64 store_prefetches;

// totals 100%:
W64 prefetch_already_in_L1;
W64 prefetch_already_in_L2;
W64 prefetch_required;

// independent:
W64 lfrq_inserts;
W64 lfrq_wakeups;
W64 lfrq_wakeup_width_histogram[MAX_WAKEUPS_PER_CYCLE+1];
W64 lfrq_annuls;
W64 lfrq_resets;

W64 lfrq_total_latency;

void dcache_save_stats(DataStoreNode& ds) {
  DataStoreNode& loads = ds("load"); {
    DataStoreNode& issue = loads("issue"); {
      issue.summable = 1;
      issue.add("complete", load_issue_complete);
      issue.add("miss", load_issue_miss);
      issue.add("exception", load_issue_exception);
      issue.add("ordering", load_issue_ordering);
      issue.add("unaligned", load_issue_unaligned);
      DataStoreNode& replay = issue("replay"); {
        replay.summable = 1;
        replay.add("sfr-addr-and-data-not-ready", load_issue_replay_sfr_addr_and_data_not_ready);
        replay.add("sfr-addr-not-ready", load_issue_replay_sfr_addr_not_ready);
        replay.add("sfr-data-not-ready", load_issue_replay_sfr_data_not_ready);
        replay.add("missbuf-full", load_issue_replay_missbuf_full);
      }
    }

    DataStoreNode& hit = loads("hit"); {
      hit.summable = 1;
      hit.add("L1", load_hit_L1);
      hit.add("L2", load_hit_L2);
      hit.add("L3", load_hit_L3);
      hit.add("mem", load_hit_mem);
    }

    DataStoreNode& forward = loads("forward"); {
      forward.summable = 1;
      forward.add("cache", load_forward_from_cache);
      forward.add("sfr", load_forward_from_sfr);
      forward.add("sfr-and-cache", load_forward_from_sfr_and_cache);
    }

    DataStoreNode& dependency = loads("dependency"); {
      dependency.summable = 1;
      dependency.add("independent", load_dependency_independent);
      dependency.add("predicted-alias-unresolved", load_dependency_predicted_alias_unresolved);
      dependency.add("stq-address-match", load_dependency_stq_address_match);
    }

    DataStoreNode& type = loads("type"); {
      type.summable = 1;
      type.add("aligned", load_type_aligned);
      type.add("unaligned", load_type_unaligned);
      type.add("internal", load_type_internal);
    }

    DataStoreNode& size = loads("size"); {
      size.summable = 1;
      size.add("1", load_size[0]);
      size.add("2", load_size[1]);
      size.add("4", load_size[2]);
      size.add("8", load_size[3]);
    }

    DataStoreNode& transfer = loads("transfer-L2-to-L1"); {
      transfer.summable = 1;
      transfer.add("full-L2-to-L1", load_transfer_L2_to_L1_full);
      transfer.add("partial-L2-to-L1", load_transfer_L2_to_L1_partial);
      transfer.add("L2-to-L1I", load_transfer_L2_to_L1I_full);
    }

    DataStoreNode& dtlb = loads("dtlb"); {
      dtlb.summable = 1;
      dtlb.add("hits", dtlb_hits);
      dtlb.add("misses", dtlb_misses);
    }
  }

  DataStoreNode& fetches = ds("fetch"); {
    DataStoreNode& hit = fetches("hit"); {
      hit.summable = 1;
      hit.add("L1", fetch_hit_L1);
      hit.add("L2", fetch_hit_L2);
      hit.add("L3", fetch_hit_L3);
      hit.add("mem", fetch_hit_mem);
    }

    DataStoreNode& itlb = fetches("itlb"); {
      itlb.summable = 1;
      itlb.add("hits", itlb_hits);
      itlb.add("misses", itlb_misses);
    }
  }

  DataStoreNode& prefetches = ds("prefetches"); {
    prefetches.summable = 1;
    prefetches.add("in-L1", prefetch_already_in_L1);
    prefetches.add("in-L2", prefetch_already_in_L2);
    prefetches.add("required", prefetch_required);
  }

  DataStoreNode& missbuf = ds("missbuf"); {
    missbuf.add("inserts", missbuf_inserts);
    DataStoreNode& deliver = missbuf("deliver"); {
      deliver.summable = 1;
      deliver.add("mem-to-L3", missbuf_deliver_mem_to_L3);
      deliver.add("L3-to-L2", missbuf_deliver_L3_to_L2);
      deliver.add("L2-to-L1D", missbuf_deliver_L2_to_L1);
      deliver.add("L2-to-L1I", missbuf_deliver_L2_to_L1I);
    }
  }

  DataStoreNode& lfrq = ds("lfrq"); {
    lfrq.add("inserts", lfrq_inserts);
    lfrq.add("wakeups", lfrq_wakeups);
    lfrq.add("annuls", lfrq_annuls);
    lfrq.add("resets", lfrq_resets);
    lfrq.add("total-latency", lfrq_total_latency);

    double average_latency = (double)lfrq_total_latency / (double)lfrq_wakeups;
    lfrq.addfloat("average-miss-latency", average_latency);

    DataStoreNode& width = lfrq("width"); {
      width.summable = 1;
      foreach (i, MAX_WAKEUPS_PER_CYCLE+1) {
        stringbuf sb; sb << i;
        width.add(sb, lfrq_wakeup_width_histogram[i]);
      }
    }
  }

  DataStoreNode& stores = ds("store"); {
    DataStoreNode& issue = stores("issue"); {
      issue.summable = 1;
      issue.add("complete", store_issue_complete);
      issue.add("exception", store_issue_exception);
      issue.add("ordering", store_issue_ordering);
      issue.add("unaligned", store_issue_unaligned);
      DataStoreNode& replay = issue("replay"); {
        replay.summable = 1;
        replay.add("wait-sfraddr-sfrdata", store_issue_replay_sfr_addr_and_data_not_ready);
        replay.add("wait-sfraddr", store_issue_replay_sfr_addr_not_ready);
        replay.add("wait-sfrdata", store_issue_replay_sfr_data_not_ready);
        replay.add("wait-storedata-sfraddr-sfrdata", store_issue_replay_sfr_addr_and_data_and_data_to_store_not_ready);
        replay.add("wait-storedata-sfraddr", store_issue_replay_sfr_addr_and_data_to_store_not_ready);
        replay.add("wait-storedata-sfrdata", store_issue_replay_sfr_data_and_data_to_store_not_ready);
      }
    }

    DataStoreNode& forward = stores("forward"); {
      forward.summable = 1;
      forward.add("zero", store_forward_from_zero);
      forward.add("sfr", store_forward_from_sfr);
    }

    DataStoreNode& type = stores("type"); {
      type.summable = 1;
      type.add("aligned", store_type_aligned);
      type.add("unaligned", store_type_unaligned);
      type.add("internal", store_type_internal);
    }

    DataStoreNode& size = stores("size"); {
      size.summable = 1;
      size.add("1", store_size[0]);
      size.add("2", store_size[1]);
      size.add("4", store_size[2]);
      size.add("8", store_size[3]);
    }

    stores.add("parallel-aliasing", store_parallel_aliasing);

    DataStoreNode& commit = stores("commit"); {
      commit.summable = 1;
      commit.add("direct", store_commit_direct);
      commit.add("deferred", store_commit_deferred);
    }

    stores.add("prefetches", store_prefetches);
  }

#ifdef TRACK_LINE_USAGE
  DataStoreNode& histograms = ds("histograms"); {
    L1StatsCollector::savestats(histograms("L1"));
    L1IStatsCollector::savestats(histograms("L1I"));
    L2StatsCollector::savestats(histograms("L2"));
    L3StatsCollector::savestats(histograms("L3"));
  }
#endif
}

namespace DataCache {

#ifdef TRACK_LINE_USAGE
  // Lifetime
  template <> W64 L1StatsCollectorBase::line_lifetime_histogram[DCACHE_L1_LINE_LIFETIME_SLOTS] = {};
  template <> W64 L1IStatsCollectorBase::line_lifetime_histogram[DCACHE_L1I_LINE_LIFETIME_SLOTS] = {};
  template <> W64 L2StatsCollectorBase::line_lifetime_histogram[DCACHE_L2_LINE_LIFETIME_SLOTS] = {};
  template <> W64 L3StatsCollectorBase::line_lifetime_histogram[DCACHE_L3_LINE_LIFETIME_SLOTS] = {};

  // Deadtime
  template <> W64 L1StatsCollectorBase::line_deadtime_histogram[DCACHE_L1_LINE_DEADTIME_SLOTS] = {};
  template <> W64 L1IStatsCollectorBase::line_deadtime_histogram[DCACHE_L1I_LINE_DEADTIME_SLOTS] = {};
  template <> W64 L2StatsCollectorBase::line_deadtime_histogram[DCACHE_L2_LINE_DEADTIME_SLOTS] = {};
  template <> W64 L3StatsCollectorBase::line_deadtime_histogram[DCACHE_L3_LINE_DEADTIME_SLOTS] = {};

  // Hit count
  template <> W64 L1StatsCollectorBase::line_hitcount_histogram[DCACHE_L1_LINE_HITCOUNT_SLOTS] = {};
  template <> W64 L1IStatsCollectorBase::line_hitcount_histogram[DCACHE_L1I_LINE_HITCOUNT_SLOTS] = {};
  template <> W64 L2StatsCollectorBase::line_hitcount_histogram[DCACHE_L2_LINE_HITCOUNT_SLOTS] = {};
  template <> W64 L3StatsCollectorBase::line_hitcount_histogram[DCACHE_L3_LINE_HITCOUNT_SLOTS] = {};
#endif

  L1Cache L1;

  L1ICache L1I;

  //
  // NOTE: Prior to issuing any bundle with N loads, we must be SURE there
  // are at least N free load fill requests and and N miss buffers.
  //

  //
  // Load fill request queue (LFRQ) contains any requests for outstanding
  // loads from both the L2 or L1. 
  //
  struct LoadFillReq {
    W64 addr;       // physical address
    W64 data;       // data already known so far (e.g. from SFR)
    LoadStoreInfo lsi;
    W32  initcycle;
    byte mask;
    byte fillL1:1, fillL2:1;
    W16  pad;

    inline LoadFillReq() { }
  
    LoadFillReq(W64 addr, W64 data, byte mask, LoadStoreInfo lsi) {
      this->addr = addr;
      this->data = data;
      this->mask = mask;
      this->lsi = lsi;
      this->fillL1 = 1;
      this->fillL2 = 1;
      this->initcycle = sim_cycle;
    }

    W64 loaddata() {
      int sizeshift = lsi.info.sizeshift;
      W64 cachedata = *((W64*)(Waddr)floor(addr, 8));
      W64 sframask = expand_8bit_to_64bit_lut[mask];
      W64 muxdata = mux64(sframask, cachedata, data);
      W64 data = (sizeshift == 3) ? data : bits(muxdata, 8*lowbits(addr, 3), (8 << sizeshift));
      if (lsi.info.signext) data = signext64(data, 8*sizeshift);
      return data;
    }

    ostream& print(ostream& os) const {
      os << "  ", "0x", hexstring(data, 64), " @ ", (void*)(Waddr)addr, " -> r", lsi.info.rd;
      if (lsi.info.commit) os << ", c", lsi.info.cbslot;
      os << ": shift ", lsi.info.sizeshift, ", signext ", lsi.info.signext, ", mask ", bitstring(mask, 8, true);
      return os;
    }
  };

  static inline ostream& operator <<(ostream& os, const LoadFillReq& req) {
    return req.print(os);
  }

  template <int size>
  struct LoadFillReqQueue {
    // Allow up to 64 outstanding loads across 16 cache lines
    bitvec<size> freemap;                    // Slot is free
    bitvec<size> waiting;                    // Waiting for the line to arrive in the L1
    bitvec<size> ready;                      // Wait to extract/signext and write into register
    LoadFillReq reqs[size];

    static const int SIZE = size;

    LoadFillReqQueue() {
      reset();
    }

    void reset() {
      freemap.setall();
      ready = 0;
      waiting = 0;
    }

    void changestate(int idx, bitvec<size>& oldstate, bitvec<size>& newstate) {
      oldstate[idx] = 0;
      newstate[idx] = 1;
    }

    void free(int lfrqslot) {
      changestate(lfrqslot, waiting, freemap);
    }

    void annul(int lfrqslot);

    void restart() {
      // Clear out any waiting entries (prefetches), including waiting physregs and cbslots,
      // so the next trace doesn't get confused.

      while (!freemap.allset()) {
        int idx = (~freemap).lsb();
        LoadFillReq& req = reqs[idx];
        if (analyze_in_detail()) logfile << "iter ", iterations, ": force final wakeup/reset of LFRQ slot ", idx, ": ", req, endl;
        annul(idx);
      }
      reset();
      lfrq_resets++;
    }

    bool full() {
      return (!freemap);
    }

    //
    // Add an entry to the LFRQ in the waiting state.
    //
    int add(const LoadFillReq& req) {
      if (full()) return -1;
      int idx = freemap.lsb();
      changestate(idx, freemap, waiting);         
      reqs[idx] = req;
      lfrq_inserts++;
      return idx;
    }

    //
    // Move any LFRQ entries in <mask> to the ready state
    // in response to the arrival of the corresponding
    // line at the L1 level. Once a line is delivered,
    // it is copied into the L1 cache and the corresponding
    // miss buffer can be freed.
    // 
    void wakeup(W64 address, const bitvec<LFRQ_SIZE>& lfrqmask) {
      if (analyze_in_detail()) logfile << "LFRQ.wakeup(", (void*)(Waddr)address, ", ", lfrqmask, ")", endl;
      //assert(L2.probe(address));
      waiting &= ~lfrqmask;
      ready |= lfrqmask;
    }

    //
    // Find the first N requests (N = 2) in the READY state,
    // and extract, sign extend and write into their target
    // register, then mark that register as ready.
    //
    // Also mark the entire cache line containing each load
    // as fully valid.
    //
    // Loads will always be allocated a physical register
    // since if the load misses the L1, it will have fallen
    // off the end of the pipeline and into the register file
    // by the earliest time we can receive the data from the
    // L2 cache and/or lower levels.
    //
    void clock() {
      //
      // Process up to MAX_WAKEUPS_PER_CYCLE missed loads per cycle:
      //
      int wakeupcount = 0;
      foreach (i, MAX_WAKEUPS_PER_CYCLE) {
        if (!ready) break;

        int idx = ready.lsb();
        LoadFillReq& req = reqs[idx];

        if (analyze_in_detail()) logfile << "iter ", iterations, ": wakeup LFRQ slot ", idx, ": ", req, endl;
        // wakeup register and/or commitbuf here
        if (true)
        {
          if (analyze_in_detail()) logfile << "  Wakeup physical register r", req.lsi.info.rd, endl;

          W64 delta = LO32(sim_cycle) - LO32(req.initcycle);
          if (delta >= 65536) {
            // avoid overflow induced erroneous values:
            // logfile << "LFRQ: warning: cycle counter wraparound in initcycle latency (current ", sim_cycle, " vs init ", req.initcycle, " = delta ", delta, ")", endl;
          } else {
            lfrq_total_latency += delta;
          }
          lfrq_wakeups++;
          wakeupcount++;
          if (wakeup_func) wakeup_func(req.lsi, req.addr);
        } else {
          if (analyze_in_detail()) logfile << "  Wakeup prefetch", endl;
        }

        changestate(idx, ready, freemap);
      }

      lfrq_wakeup_width_histogram[wakeupcount]++;
    }

    LoadFillReq& operator [](int idx) { return reqs[idx]; }
    const LoadFillReq& operator [](int idx) const { return reqs[idx]; }

    ostream& print(ostream& os) const {
      os << "LoadFillReqQueue<", size, ">:", endl;
      os << "  Free:   ", freemap, endl;
      os << "  Wait:   ", waiting, endl;
      os << "  Ready:  ", ready, endl;
      foreach (i, size) {
        if (!bit(freemap, i)) {
          os << "  slot ", intstring(i, 2), ": ", reqs[i], endl;
        }
      }
      return os;
    }
  };

  template <int size>
  static inline ostream& operator <<(ostream& os, const LoadFillReqQueue<size>& lfrq) {
    return lfrq.print(os);
  }

  LoadFillReqQueue<LFRQ_SIZE> lfrq;

  L3Cache L3;

  enum { STATE_IDLE, STATE_DELIVER_TO_L3, STATE_DELIVER_TO_L2, STATE_DELIVER_TO_L1 };

  static const char* missbuf_state_names[] = {"idle", "mem->L3", "L3->L2", "L2->L1"};

  template <int SIZE>
  struct MissBuffer {
    struct Entry {
      W64 addr;     // physical line address we are waiting for
      W16 state;
      W16 dcache:1, icache:1;    // L1I vs L1D
      W32 cycles;
      bitvec<LFRQ_SIZE> lfrqmap;  // which LFRQ entries should this load wake up?

      void reset() {
        lfrqmap = 0;
        addr = 0xffffffffffffffffLL;
        state = STATE_IDLE;
        cycles = 0;
        icache = 0;
        dcache = 0;
      }
    };

    Entry missbufs[SIZE];
    bitvec<SIZE> freemap;

    MissBuffer() {
      reset();
    }
    
    void reset() {
      foreach (i, SIZE) {
        missbufs[i].reset();
      }
      freemap.setall();
    }

    //
    // Restart the miss buffer after an inter-trace transition.
    // This does NOT remove any in-flight entries, it just makes
    // sure they don't erroneously wake up LFRQ slots used by
    // something else in the new trace.
    //
    void restart() {
      if (!(freemap.allset())) {
        foreach (i, SIZE) {
          missbufs[i].lfrqmap = 0;
        }
      }
    }

    bool full() const {
      return (!freemap);
    }

    int find(W64 addr) {
      W64 match = 0;
      foreach (i, SIZE) {
        if ((missbufs[i].addr == addr) && !freemap[i]) return i;
      }
      return -1;
    }

    //
    // Request fully or partially missed both the L2 and L1
    // caches and needs service from below.
    //
    int initiate_miss(W64 addr, bool hit_in_L2, bool icache = 0) {
      bool DEBUG = analyze_in_detail();

      addr = floor(addr, L1_LINE_SIZE);

      int idx = find(addr);

      if (idx >= 0) {
        // Handle case where dcache miss is already in progress but some 
        // code needed in icache is also stored in that line:
        Entry& mb = missbufs[idx];
        mb.icache |= icache;
        mb.dcache |= (!icache);
        // Handle case where icache miss is already in progress but some
        // data needed in dcache is also stored in that line:
        return idx;
      }

      if (full())
        return -1;

      idx = freemap.lsb();
      freemap[idx] = 0;
      missbuf_inserts++;
      Entry& mb = missbufs[idx];
      mb.addr = addr;
      mb.lfrqmap = 0;
      mb.icache = icache;
      mb.dcache = (!icache);

      if (hit_in_L2) {
        if (DEBUG) logfile << "mb", idx, ": enter state deliver to L1 on ", (void*)(Waddr)addr, " (iter ", iterations, ")", endl;
        mb.state = STATE_DELIVER_TO_L1;
        mb.cycles = L2_LATENCY;

        if (icache) fetch_hit_L2++; else load_hit_L2++;
        return idx;
      }
      
      bool L3hit = L3.probe(addr);
      if (L3hit) {
        if (DEBUG) logfile << "mb", idx, ": enter state deliver to L2 on ", (void*)(Waddr)addr, " (iter ", iterations, ")", endl;
        mb.state = STATE_DELIVER_TO_L2;
        mb.cycles = L3_LATENCY;
        if (icache) fetch_hit_L3++; else load_hit_L3++;
        return idx;
      }

      if (DEBUG) logfile << "mb", idx, ": enter state deliver to L3 on ", (void*)(Waddr)addr, " (iter ", iterations, ")", endl;
      mb.state = STATE_DELIVER_TO_L3;
      mb.cycles = MAIN_MEM_LATENCY;
      if (icache) fetch_hit_mem++; else load_hit_mem++;

      return idx;
    }

    int initiate_miss(const LoadFillReq& req, bool hit_in_L2) {
      int lfrqslot = lfrq.add(req);

      if (analyze_in_detail()) logfile << "missbuf.initiate_miss(req ", req, ", L2hit? ", hit_in_L2, ") -> lfrqslot ", lfrqslot, endl;

      if (lfrqslot < 0)
        return -1;

      int mbidx = initiate_miss(req.addr, hit_in_L2);
      if (mbidx < 0) {
        lfrq.free(lfrqslot);
        return -1;
      }

      Entry& missbuf = missbufs[mbidx];
      missbuf.lfrqmap[lfrqslot] = 1;

      return lfrqslot;
    }

    void clock() {
      if (freemap.allset())
        return;

      bool DEBUG = analyze_in_detail();

      foreach (i, SIZE) {
        Entry& mb = missbufs[i];
        switch (mb.state) {
        case STATE_IDLE:
          break;
        case STATE_DELIVER_TO_L3: {
          if (DEBUG) logfile << "mb", i, ": deliver to L3 (", mb.cycles, " cycles left) (iter ", iterations, ")", endl;
          mb.cycles--;
          if (!mb.cycles) {
            L3.validate(mb.addr);
            mb.cycles = L3_LATENCY;
            mb.state = STATE_DELIVER_TO_L2;
            missbuf_deliver_mem_to_L3++;
          }
          break;
        }
        case STATE_DELIVER_TO_L2: {
          if (DEBUG) logfile << "mb", i, ": deliver to L2 (", mb.cycles, " cycles left) (iter ", iterations, ")", endl;
          mb.cycles--;
          if (!mb.cycles) {
            if (DEBUG) logfile << "mb", i, ": delivered to L2 (map ", mb.lfrqmap, ")", endl;
            L2.validate(mb.addr);
            mb.cycles = L2_LATENCY;
            mb.state = STATE_DELIVER_TO_L1;
            missbuf_deliver_L3_to_L2++;
          }
          break;
        }
        case STATE_DELIVER_TO_L1: {
          if (DEBUG) logfile << "mb", i, ": deliver to L1 (", mb.cycles, " cycles left) (iter ", iterations, ")", endl;
          mb.cycles--;
          if (!mb.cycles) {
            if (DEBUG) logfile << "mb", i, ": delivered to L1 switch (map ", mb.lfrqmap, ")", endl;

            if (mb.dcache) {
              if (DEBUG) logfile << "mb", i, ": delivered ", (void*)mb.addr, " to L1 dcache (map ", mb.lfrqmap, ")", endl;
              // If the L2 line size is bigger than the L1 line size, this will validate multiple lines in the L1 when an L2 line arrives:
              // foreach (i, L2_LINE_SIZE / L1_LINE_SIZE) L1.validate(mb.addr + i*L1_LINE_SIZE, bitvec<L1_LINE_SIZE>().setall());
              L1.validate(mb.addr, bitvec<L1_LINE_SIZE>().setall());
              missbuf_deliver_L2_to_L1++;
              lfrq.wakeup(mb.addr, mb.lfrqmap);
            }
            if (mb.icache) {
              // Sometimes we can initiate an icache miss on an existing dcache line in the missbuf
              if (DEBUG) logfile << "mb", i, ": delivered ", (void*)mb.addr, " to L1 icache", endl;
              // If the L2 line size is bigger than the L1 line size, this will validate multiple lines in the L1 when an L2 line arrives:
              // foreach (i, L2_LINE_SIZE / L1I_LINE_SIZE) L1I.validate(mb.addr + i*L1I_LINE_SIZE, bitvec<L1I_LINE_SIZE>().setall());
              L1I.validate(mb.addr, bitvec<L1I_LINE_SIZE>().setall());
              missbuf_deliver_L2_to_L1I++;
              LoadStoreInfo lsi;
              lsi.data = 0;
              if (icache_wakeup_func) icache_wakeup_func(lsi, mb.addr);
            }

            freemap[i] = 1;
            mb.reset();
          }
          break;
        }
        }
      }
    }

    void annul_lfrq(int slot) {
      foreach (i, SIZE) {
        Entry& mb = missbufs[i];
        mb.lfrqmap[slot] = 0;  // which LFRQ entries should this load wake up?
      }
    }

    ostream& print(ostream& os) const {
      os << "MissBuffer<", SIZE, ">:", endl;
      foreach (i, SIZE) {
        if (freemap[i]) continue;
        const Entry& mb = missbufs[i];

        os << "  slot ", intstring(i, 2), ": ", (void*)(Waddr)mb.addr, " state ", 
          padstring(missbuf_state_names[mb.state], -8), " ", (mb.dcache ? "dcache" : "      "),
          " ", (mb.icache ? "icache" : "      "), " on ", mb.cycles, " cycles -> lfrq ", mb.lfrqmap, endl;
      }
      return os;
    }
  };

  template <int size>
  static inline ostream& operator <<(ostream& os, const MissBuffer<size>& missbuf) {
    return missbuf.print(os);
  }

  MissBuffer<MISSBUF_COUNT> missbuf;
  
  template <int size>
  void LoadFillReqQueue<size>::annul(int lfrqslot) {
    LoadFillReq& req = reqs[lfrqslot];
    if (analyze_in_detail()) logfile << "  Annul physical register r", req.lsi.info.rd, endl;
    lfrq_annuls++;
    missbuf.annul_lfrq(lfrqslot);
    changestate(lfrqslot, ready, freemap);
  }

  L2Cache L2;

  template <int linesize>
  ostream& CacheLine<linesize>::print(ostream& os, W64 tag) const {
#if 0
    const byte* data = (const byte*)(W64)tag;
    foreach (i, linesize/8) {
      os << "    ", bytemaskstring(data + i*8, (W64)-1LL, 8, 8), " ";
      os << endl;
    }
#endif
    return os;
  }

  template <int linesize>
  ostream& CacheLineWithValidMask<linesize>::print(ostream& os, W64 tag) const {
#if 0
    const byte* data = (const byte*)(W64)tag;
    foreach (i, linesize/8) {
      os << "    ", bytemaskstring(data + i*8, valid(i*8, 8).integer(), 8, 8), " ";
      os << endl;
    }
#endif
    return os;
  }

};

int issueload_slowpath(IssueState& state, W64 addr, W64 origaddr, W64 data, SFR& sfra, LoadStoreInfo lsi) {
  //bool DEBUG = analyze_in_detail();
  static const bool DEBUG = 0;

  bool SEQUENTIAL = lsi.info.sequential;
  bool SFRAUSED = lsi.info.sfraused;
  int sizeshift = lsi.info.sizeshift;

  starttimer(load_slowpath_timer);


  L1CacheLine* L1line = L1.probe(addr);

  //
  // Loads and stores that also miss the L2 Stores that
  // miss both the L1 and L2 do not require this since
  // there could not possibly be a previous load or 
  // store within the current trace that accessed that
  // line (otherwise it would already have been allocated
  // and locked in the L2). In this case, allocate a
  // fresh L2 line and wait for the data to arrive.
  //

  if (DEBUG) {
    logfile << "issue_load_slowpath: L1line for ", (void*)(Waddr)addr, " = ", L1line, " validmask ";
    if (L1line) logfile << L1line->valid; else logfile << "(none)";
    logfile << endl;
  }

  if (!L1line) {
    //L1line = L1.select(addr);
    load_transfer_L2_to_L1_full++;
  } else {
    load_transfer_L2_to_L1_partial++;
  }

  int L2hit = 0;
    
  L2CacheLine* L2line = L2.probe(addr);

  if (L2line) {
    //
    // We had at least a partial L2 hit, but is the requested data actually mapped into the line?
    //
    bitvec<L2_LINE_SIZE> sframask, reqmask;
    prep_L2_sframask_and_reqmask((SFRAUSED) ? &sfra : null, addr, sizeshift, sframask, reqmask);
    L2hit = (SFRAUSED) ? ((reqmask & (sframask | L2line->valid)) == reqmask) : ((reqmask & L2line->valid) == reqmask);
#ifdef ISSUE_LOAD_STORE_DEBUG
    logfile << "L2hit = ", L2hit, endl, "  cachemask ", L2line->valid, endl,
      "  sframask  ", sframask, endl, "  reqmask   ", reqmask, endl;
#endif
  } else {
  }

#ifdef CACHE_ALWAYS_HITS
  L1line = L1.select(addr);
  L1line->tag = L1.tagof(addr);
  L1line->valid.setall();
  L2line->tag = L2.tagof(addr);
  L2line->valid.setall();
  L2hit = 1;
#endif

#ifdef L2_ALWAYS_HITS
  L2line = L2.select(addr);
  L2line->tag = L2.tagof(addr);
  L2line->valid.setall();
  L2line->lru = sim_cycle;
  L2hit = 1;
#endif

  //
  // Regardless of whether or not we had a hit somewhere,
  // L1 and L2 lines have been allocated by this point.
  // Slap a lock on the L2 line it so it can't get evicted.
  // Once it's locked up, we can move it into the L1 later.
  //
  // If we did have a hit, but either the L1 or L2 lines
  // were still missing bytes, initiate prefetches to fill
  // them in.
  //

  LoadFillReq req(addr, SFRAUSED ? sfra.data : 0, SFRAUSED ? sfra.bytemask : 0, lsi);

  int lfrqslot = missbuf.initiate_miss(req, L2hit);

  if (lfrqslot < 0) {
    if (DEBUG) logfile << "iteration ", iterations, ": LFRQ or MB has no free entries for L2->L1: forcing LFRQFull rollback", endl;
    state.ldreg.flags = FLAG_INV;
    state.ldreg.rddata = EXCEPTION_LFRQFull;
    stoptimer(load_slowpath_timer);
    return -1;
  }
  
  state.ldreg.flags = FLAG_WAIT;
  state.ldreg.rddata = data;
  stoptimer(load_slowpath_timer);

  return lfrqslot;
}

bool covered_by_sfr(W64 addr, SFR* sfr, int sizeshift) {
  bitvec<L1_LINE_SIZE> sframask, reqmask;
  prep_sframask_and_reqmask(sfr, addr, sizeshift, sframask, reqmask);
  return ((sframask & reqmask) == reqmask);
}

#ifdef USE_TLB
DTLB dtlb;
ITLB itlb;
#endif

W64 dtlb_hits;
W64 dtlb_misses;

W64 itlb_hits;
W64 itlb_misses;

bool probe_cache_and_sfr(W64 addr, const SFR* sfr, int sizeshift) {
  bitvec<L1_LINE_SIZE> sframask, reqmask;
  prep_sframask_and_reqmask(sfr, addr, sizeshift, sframask, reqmask);

  //
  // Short circuit if the SFR covers the entire load: no need for cache probe
  //
  if ((sframask & reqmask) == reqmask)
    return true;

#ifdef USE_TLB
  bool tlbhit = dtlb.check(addr);

  dtlb_hits += tlbhit;
  dtlb_misses += !tlbhit;

  // issueload_slowpath() will check this again:
  if (!tlbhit) {
    dtlb.replace(addr);
  }
#endif

  L1CacheLine* L1line = L1.probe(addr);

  if (!L1line)
    return false;

  //
  // We have a hit on the L1 line itself, but still need to make
  // sure all the data can be filled by some combination of
  // bytes from sfra or the cache data.
  //
  // If not, put this request on the LFRQ and mark it as waiting.
  //

  bool hit = ((reqmask & (sframask | L1line->valid)) == reqmask);

  return hit;
}

void annul_lfrq_slot(int lfrqslot) {
  lfrq.annul(lfrqslot);
}

//
// NOTE: lsi should specify destination of REG_null for prefetches!
//
static const int PREFETCH_STOPS_AT_L2 = 0;

void initiate_prefetch(W64 addr, int cachelevel) {
  //bool DEBUG = analyze_in_detail();
  static const bool DEBUG = 0;

  addr = floor(addr, L1_LINE_SIZE);

  L1CacheLine* L1line = L1.probe(addr);

  if (L1line) {
    prefetch_already_in_L1++;
    return;
  }

  L2CacheLine* L2line = L2.probe(addr);

  if (L2line) {
    prefetch_already_in_L2++;
    if (PREFETCH_STOPS_AT_L2) return; // only move up to L2 level, and it's already there
  }

  if (DEBUG) logfile << "Prefetch requested for ", (void*)(Waddr)addr, " to cache level ", cachelevel, endl;

  missbuf.initiate_miss(addr, L2line);
  prefetch_required++;
}

//
// Instruction cache
//

bool probe_icache(W64 addr) {
  L1ICacheLine* L1line = L1I.probe(addr);
  bool hit = (L1line != null);

#ifdef USE_TLB
  bool tlbhit = itlb.check(addr);

  itlb_hits += tlbhit;
  itlb_misses += !tlbhit;

  // issueload_slowpath() will check this again:
  if (!tlbhit) {
    itlb.replace(addr);
  }
#endif

  return hit;
}

int initiate_icache_miss(W64 addr) {
  addr = floor(addr, L1I_LINE_SIZE);
  bool line_in_L2 = (L2.probe(addr) != null);
  int mb = missbuf.initiate_miss(addr, L2.probe(addr), true);

  if (logable(1))
    logfile << "Initiate icache miss on ", (void*)(Waddr)addr, " to missbuf ", mb, " (", (line_in_L2 ? "in L2" : "not in L2"), ")", endl;

  return mb;
}

static inline W64 storemask(W64 addr, W64 data, byte bytemask) {
  W64& mem = *(W64*)(Waddr)addr;
  mem = mux64(expand_8bit_to_64bit_lut[bytemask], mem, data);
  return data;
}


//
// Commit one store from an SFR to the L2 cache without locking
// any cache lines. The store must have already been checked
// to have no exceptions.
//
W64 commitstore_unlocked(const SFR& sfr) {
  if (sfr.invalid | (sfr.bytemask == 0))
    return 0;

  //bool DEBUG = analyze_in_detail();
  static const bool DEBUG = 0;

  starttimer(store_flush_timer);

  W64 addr = sfr.physaddr << 3;

  L2CacheLine* L2line = L2.select(addr);

  storemask(signext64(sfr.physaddr << 3, 48), sfr.data, sfr.bytemask);
  store_commit_direct++;

  L1CacheLine* L1line = L1.select(addr);

  L1line->valid |= ((W64)sfr.bytemask << lowbits(addr, 6));
  L2line->valid |= ((W64)sfr.bytemask << lowbits(addr, 6));

  if (!L1line->valid.allset()) {
    store_prefetches++;
    missbuf.initiate_miss(addr, L2line->valid.allset());
  }

  stoptimer(store_flush_timer);

  return 0;
}


void dcache_clock() {
  if ((sim_cycle & 0x7fffffff) == 0x7fffffff) {
    // Clear any 32-bit cycle-related counters in the cache to prevent wraparound:
    L1.clearstats();
    L1I.clearstats();
    L2.clearstats();
    L3.clearstats();
    logfile << "Clearing cache statistics to prevent wraparound...", endl, flush;
  }

  lfrq.clock();
  missbuf.clock();
}

void dcache_complete() {
  lfrq.restart();
  missbuf.restart();
}

// Print all modified lines:
void dcache_print_commit() {
#ifdef DEBUG_MODIFIED
  int n = L2.modifiedtail - L2.modified;
  logfile << "Printing ", n, " modified lines:", endl, flush;
  foreach (i, n) {
    const byte* p = L2.modified[i];
    if (!p) continue;
    // Eliminate future dupes:
    for (int j = i+1; j < n; j++) {
      logfile << "Eliminating duplicate line for ", p, " at index ", i, endl;
      if (L2.modified[j] == p) L2.modified[j] = 0;
    }
    logfile << "  L2 line @ ", p, " (write index ", i, "):", endl, flush;
    foreach (i, 8) {
      logfile << "    ", bytemaskstring(p + i*8, 0xffffffffffffffffLL, 8, 8), endl;
    }
  }
#endif
}

W64 virt_addr_mask;
extern bool user_thread_64bit;

void init_cache() {
  virt_addr_mask = (ctx.use64 ? 0xffffffffffffffffLL : 0x00000000ffffffffLL);
}

void print_dcache() {
  logfile << lfrq;
  logfile << missbuf;
  // logfile << L1; 
  // logfile << L2; 
}

/*
  // Generator for expand_8bit_to_64bit_lut:

  foreach (i, 256) {
    byte* m = (byte*)(&expand_8bit_to_64bit_lut[i]);
    m[0] = (bit(i, 0) ? 0xff : 0x00);
    m[1] = (bit(i, 1) ? 0xff : 0x00);
    m[2] = (bit(i, 2) ? 0xff : 0x00);
    m[3] = (bit(i, 3) ? 0xff : 0x00);
    m[4] = (bit(i, 4) ? 0xff : 0x00);
    m[5] = (bit(i, 5) ? 0xff : 0x00);
    m[6] = (bit(i, 6) ? 0xff : 0x00);
    m[7] = (bit(i, 7) ? 0xff : 0x00);
    logfile << "  0x", hexstring(expand_8bit_to_64bit_lut[i], 64), ", ";
    if ((i & 3) == 3) logfile << endl;
  }
*/

