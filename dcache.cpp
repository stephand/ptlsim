//
// PTLsim: Cycle Accurate x86-64 Simulator
// L1 and L2 Data Caches
//
// Copyright 2005-2008 Matt T. Yourst <yourst@yourst.com>
// Copyright (c) 2007-2010 Advanced Micro Devices, Inc.
// Contributed by Stephan Diestelhorst <stephan.diestelhorst@amd.com>
//

#include <dcache.h>
#include <stats.h>

using namespace CacheSubsystem;

#if 0
#define starttimer(timer) timer.start()
#define stoptimer(timer) timer.stop()
#else
#define starttimer(timer) (1)
#define stoptimer(timer) (1)
#endif

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

//
// Load Fill Request Queue
//

template <int size>
void LoadFillReqQueue<size>::restart() {
  while (!freemap.allset()) {
    int idx = (~freemap).lsb();
    LoadFillReq& req = reqs[idx];
    if (logable(6)) logfile << "iter ", iterations, ": force final wakeup/reset of LFRQ slot ", idx, ": ", req, endl;
    annul(idx);
  }
  reset();
  stats.dcache.lfrq.resets++;
}

template <int size>
void LoadFillReqQueue<size>::reset(int threadid) {
  foreach (i, SIZE) {
    LoadFillReq& req = reqs[i];
    if likely ((!freemap[i]) && (req.lsi.threadid == threadid)) {
      if (logable(6)) logfile << "[vcpu ", threadid, "] reset lfrq slot ", i, ": ", req, endl;
      waiting[i] = 0;
      ready[i] = 0;
      retry[i] = 0;
      freemap[i] = 1;
      count--;
      assert(count >= 0);
    }
  }

  stats.dcache.lfrq.resets++;
}

template <int size>
void LoadFillReqQueue<size>::annul(int lfrqslot) {
  LoadFillReq& req = reqs[lfrqslot];
  if (logable(6)) logfile << "  Annul LFRQ slot ", lfrqslot, endl;
  stats.dcache.lfrq.annuls++;
#ifdef ENABLE_ASF_CACHE_BASED
  annul_asf_spec_lfr(req.mbidx, lfrqslot);
#endif
  hierarchy.missbuf.annul_lfrq(lfrqslot);
  reqs[lfrqslot].mbidx = -1;
  assert(!freemap[lfrqslot]);
  changestate(lfrqslot, ready, freemap);
  retry[lfrqslot] = 0;
  count--;
  assert(count >= 0);
}

//
// Add an entry to the LFRQ in the waiting state.
//
template <int size>
int LoadFillReqQueue<size>::add(const LoadFillReq& req) {
  if unlikely (full()) return -1;
#if 0
  // Sanity check: make sure (tid, rob) is unique:
  foreach (i, size) {
    if likely (freemap[i]) continue;
    const LoadFillReq& old = reqs[i];
    if ((old.lsi.threadid == req.lsi.threadid) && (old.lsi.rob == req.lsi.rob)) {
      logfile << "ERROR: during add LFRQ req ", req, ", entry ", i, " (", old, ") already matches at cycle ", sim_cycle, endl;
      logfile << *this;
      logfile << hierarchy.missbuf;
      // assert(false);
    }
  }
#endif
  int idx = freemap.lsb();
  changestate(idx, freemap, waiting);         
  reqs[idx] = req;
  assert(count < size);
  count++;
  stats.dcache.lfrq.inserts++;
  return idx;
}

//
// Move any LFRQ entries in <mask> to the ready state
// in response to the arrival of the corresponding
// line at the L1 level. Once a line is delivered,
// it is copied into the L1 cache and the corresponding
// miss buffer can be freed.
// 
template <int size>
void LoadFillReqQueue<size>::wakeup(W64 address, const bitvec<LFRQ_SIZE>& lfrqmask, bool need_retry) {
  if (logable(6)) logfile << "LFRQ.wakeup(", (void*)(Waddr)address, ", ", lfrqmask, ")", endl;
  //assert(L2.probe(address));
  if unlikely(need_retry) retry |= lfrqmask;
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
template <int size>
void LoadFillReqQueue<size>::clock() {
  //
  // Process up to MAX_WAKEUPS_PER_CYCLE missed loads per cycle:
  //
  int wakeupcount = 0;
  foreach (i, MAX_WAKEUPS_PER_CYCLE) {
    if unlikely (!ready) break;

    int idx = ready.lsb(); // SD NOTE: This can cause deadlocks, thanks to loads with high entries not being woken up!
    LoadFillReq& req = reqs[idx];
    
    if (logable(6)) logfile << "[vcpu ", req.lsi.threadid, "] at cycle ",
      sim_cycle, ": ", retry[idx] ? "retry" : "wakeup", " LFRQ slot ", idx, ": ",
       req, endl;

    W64 delta = LO32(sim_cycle) - LO32(req.initcycle);
    if unlikely (delta >= 65536) {
      // avoid overflow induced erroneous values:
      // logfile << "LFRQ: warning: cycle counter wraparound in initcycle latency (current ", sim_cycle, " vs init ", req.initcycle, " = delta ", delta, ")", endl;
    } else {
      stats.dcache.lfrq.total_latency += delta;
    }
        
    stats.dcache.lfrq.wakeups++;
    wakeupcount++;
    if likely (hierarchy.callback) hierarchy.callback->dcache_wakeup(req.lsi, req.addr, retry[idx]);

    assert(!freemap[idx]);
    changestate(idx, ready, freemap);
    retry[idx] = 0;
    count--;
    assert(count >= 0);
  }

  stats.dcache.lfrq.width[wakeupcount]++;
}

LoadFillReq::LoadFillReq(W64 addr, W64 virtaddr, W64 data, byte mask, LoadStoreInfo lsi) {
  this->addr = addr;
  this->virtaddr = virtaddr;
  this->data = data;
  this->mask = mask;
  this->lsi = lsi;
  this->lsi.threadid = lsi.threadid; 
  this->fillL1 = 1;
  this->fillL2 = 1;
  this->initcycle = sim_cycle;
  this->mbidx = -1;
}

ostream& LoadFillReq::print(ostream& os) const {
  os << "0x", hexstring(data, 64), " @ ", (void*)(Waddr)addr, " -> rob ", lsi.rob, " @ t", lsi.threadid;
  os << ": shift ", lsi.sizeshift, ", signext ", lsi.signext, ", mask ", bitstring(mask, 8, true);
  return os;
}

template <int size>
ostream& LoadFillReqQueue<size>::print(ostream& os) const {
  os << "LoadFillReqQueue<", size, ">: ", count, " of ", size, " entries (", (size - count), " free)", endl;
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

#ifdef ENABLE_ASF_CACHE_BASED
/**
 * Patches up the condensed asf_spec-ness of this MissBufferEntry, whenever
 * a load that was receiving data through this MBE is annulled.
 * This is complicated, because normal and asf-spec loads may use the same
 * MBE to handle the cache miss. Annulling one of them then necessitates the
 * complicated reconstruction logic in here to ensure that the asf_spec flag
 * is disabled, once all asf_spec loads referencing this MBE are annulled.
 *
 * @param mb MissBufferEntry that is currently looked at.
 * @param lfrqslot LoadFillRequest of the annulled load.
 */
template <int size>
void LoadFillReqQueue<size>::annul_asf_spec_lfr(int mbidx, int lfrqslot) {
  assert(reqs[lfrqslot].mbidx == mbidx);
  //assert(!hierarchy.missbuf.freemap[mbidx]);
  /* NOTE: This can happen as the wake-up of the LFR and the MBE occur asynchro-
     nously with each other. The entry is then already present in the cache. */
  if unlikely (hierarchy.missbuf.freemap[mbidx]) return;

  MissBuffer<MISSBUF_COUNT>::Entry &mb = hierarchy.missbuf.missbufs[mbidx];
  if likely (!mb.asf_spec) return;

  if (logable(5))
    logfile << __FILE__, __LINE__, "Annul spec lfr @ MB: ", mbidx, " (addr: ",
      (void*)mb.virtaddr, "/",(void*)mb.addr, ") LFR: ", lfrqslot, endl;

  // Traverse all LFRs in the map and reconstruct asf_spec bit.
  bool rebuild_asf_spec = false;
  int  other_slot       = -1;
  while (true) {
    other_slot = mb.lfrqmap.nextlsb(other_slot);
    if (other_slot == -1) break;
    if (other_slot == lfrqslot) continue;
    rebuild_asf_spec |= reqs[other_slot].lsi.asf_spec;

    if (logable(6))
      logfile << __FILE__, __LINE__, "LFR: ", other_slot, "ASF-spec: ",
        reqs[other_slot].lsi.asf_spec, " rebuild_asf_spec: ", rebuild_asf_spec, endl;
  }
  mb.asf_spec = rebuild_asf_spec;
}
#endif
//
// Miss Buffer
//

template <int SIZE>    
void MissBuffer<SIZE>::reset() {
  foreach (i, SIZE) {
    missbufs[i].reset();
  }
  freemap.setall();
  count = 0;
}


template <int SIZE>    
void MissBuffer<SIZE>::reset(int threadid) {
  foreach (i, SIZE) {
    Entry& mb = missbufs[i];
    if likely (mb.threadid == threadid) {
      if (logable(6)) logfile << "[vcpu ", threadid, "] reset missbuf slot ", i, ": for rob", mb.rob, endl;
      assert(!freemap[i]);
      mb.reset();
      freemap[i] = 1;
      count--;
      assert(count >= 0);

      //
      // If multiple threads depend on the same missbuf but one thread is
      // flushed, we'll wake up a stale LFRQ. We have to make sure after
      // a missbuf reset, all the entries point to a valid lfrqmap.
      //
      if (*mb.lfrqmap) {
        bitvec<LFRQ_SIZE> tmp_lfrqmap = mb.lfrqmap ^ hierarchy.lfrq.waiting;
        if (*tmp_lfrqmap) {
          if (logable(6)) logfile << "Multithread share same missbufs[", i, "] : its lfrqmap is ", mb.lfrqmap, " LFRQ waiting map ", hierarchy.lfrq.waiting, ", diff: ", tmp_lfrqmap, endl;
          mb.lfrqmap &= ~tmp_lfrqmap;
          if (logable(6)) logfile << "after remove stale lfrq entries, its lfrqmap is ", mb.lfrqmap, endl;
        }
      }
    }
  }
}

template <int SIZE>    
void MissBuffer<SIZE>::restart() {
  if likely (!(freemap.allset())) {
    foreach (i, SIZE) {
      missbufs[i].lfrqmap = 0;
    }
  }
}

template <int SIZE>    
int MissBuffer<SIZE>::find(W64 addr) {
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
template <int SIZE>
int MissBuffer<SIZE>::initiate_miss(W64 addr, W64 virtaddr, bool hit_in_L2, bool icache, int rob, int threadid) {
  bool DEBUG = logable(6);

  addr = floor(addr, L1_LINE_SIZE);

  int idx = find(addr);

  // if unlikely (idx >= 0 && threadid == missbufs[idx].threadid) {
  if unlikely (idx >= 0) {
    // Handle case where dcache miss is already in progress but some 
    // code needed in icache is also stored in that line:
    Entry& mb = missbufs[idx];
    mb.icache |= icache;
    mb.dcache |= (!icache);
    // Handle case where icache miss is already in progress but some
    // data needed in dcache is also stored in that line:
    if (DEBUG) logfile << "[vcpu ", threadid, "] miss buffer hit for address ", (void*)(Waddr)addr, ": returning old slot ", idx, endl;
    return idx;
  }

  if unlikely (full()) {
    if (DEBUG) logfile << "[vcpu ", threadid, "] miss buffer full while allocating slot for address ", (void*)(Waddr)addr, endl;
    return -1;
  }

  idx = freemap.lsb();
  freemap[idx] = 0;
  assert(count < SIZE);
  count++;

  stats.dcache.missbuf.inserts++;
  Entry& mb = missbufs[idx];
  mb.addr = addr;
  mb.virtaddr = virtaddr;
  mb.lfrqmap = 0;
  mb.icache = icache;
  mb.dcache = (!icache);
  mb.rob = rob;
  mb.threadid = threadid;
 
  if (DEBUG) logfile << "[vcpu ", mb.threadid, "] mb", idx, ": allocated for address ", (void*)(Waddr)addr, " (iter ", iterations, ")", endl;

  if likely (hit_in_L2) {
    if (DEBUG) logfile << "[vcpu ", mb.threadid, "] mb", idx, ": enter state deliver to L1 on ", (void*)(Waddr)addr, " (iter ", iterations, ")", endl;
    mb.state = STATE_DELIVER_TO_L1;
    mb.cycles = L2_LATENCY;

    if unlikely (icache) per_context_dcache_stats_update(mb.threadid, fetch.hit.L2++); else per_context_dcache_stats_update(mb.threadid, load.hit.L2++);
    return idx;
  }
#ifdef ENABLE_L3_CACHE
  bool L3hit = hierarchy.L3.probe(addr);
  if likely (L3hit) {
    if (DEBUG) logfile << "[vcpu ", mb.threadid, "] mb", idx, ": enter state deliver to L2 on ", (void*)(Waddr)addr, " (iter ", iterations, ")", endl;
    mb.state = STATE_DELIVER_TO_L2;
    mb.cycles = L3_LATENCY;
    if (icache) per_context_dcache_stats_update(mb.threadid, fetch.hit.L3++); else per_context_dcache_stats_update(mb.threadid, load.hit.L3++);
    return idx;
  }

  if (DEBUG) logfile << "[vcpu ", mb.threadid, "] mb", idx, ": enter state deliver to L3 on ", (void*)(Waddr)addr, " (iter ", iterations, ")", endl;
  mb.state = STATE_DELIVER_TO_L3;
#else
  // L3 cache disabled
  if (DEBUG) logfile << "[vcpu ", mb.threadid, "] mb", idx, ": enter state deliver to L2 on ", (void*)(Waddr)addr, " (iter ", iterations, ")", endl;
  mb.state = STATE_DELIVER_TO_L2;
#endif

#ifdef POOR_MANS_MESI
  if (hierarchy.probe_other_caches(addr, virtaddr, false))
    mb.cycles = CROSS_CACHE_LATENCY;
  else
    mb.cycles = MAIN_MEM_LATENCY;
#else
  mb.cycles = MAIN_MEM_LATENCY;
#endif
  if unlikely (icache) per_context_dcache_stats_update(mb.threadid, fetch.hit.mem++); else per_context_dcache_stats_update(mb.threadid, load.hit.mem++);

  return idx;
}

template <int SIZE>
int MissBuffer<SIZE>::initiate_miss(LoadFillReq& req, bool hit_in_L2, int rob) {
  int lfrqslot = hierarchy.lfrq.add(req);

  if (logable(6)) logfile << "[vcpu ", req.lsi.threadid, "] missbuf.initiate_miss(req ", req, ", L2hit? ", hit_in_L2, ") -> lfrqslot ", lfrqslot, endl;

  if unlikely (lfrqslot < 0) return -1;
  
  int mbidx = initiate_miss(req.addr, req.virtaddr, hit_in_L2, 0, rob, req.lsi.threadid);
  if unlikely (mbidx < 0) {
    hierarchy.lfrq.free(lfrqslot);
    return -1;
  }

  Entry& missbuf = missbufs[mbidx];
  missbuf.lfrqmap[lfrqslot] = 1;
  hierarchy.lfrq[lfrqslot].mbidx = mbidx;
  // missbuf.threadid = req.lsi.threadid;
#ifdef ENABLE_ASF_CACHE_BASED
  // For multiple loads the ASF speculative bit is dominant, as the speculative
  // region has to be aborted always if there is a probe hit
  missbuf.asf_spec |= req.lsi.asf_spec;
#endif
  return lfrqslot;
}

template <int SIZE>
void MissBuffer<SIZE>::clock() {
  if likely (freemap.allset()) return;

  bool DEBUG = logable(6);

  foreach (i, SIZE) {
    Entry& mb = missbufs[i];
    switch (mb.state) {
    case STATE_IDLE:
      break;
#ifdef ENABLE_L3_CACHE
    case STATE_DELIVER_TO_L3: {
      if (DEBUG) logfile << "[vcpu ", mb.threadid, "] mb", i, ": deliver ", (void*)(Waddr)mb.addr, " to L3 (", mb.cycles, " cycles left) (iter ", iterations, ")", endl;
      mb.cycles--;
      if unlikely (!mb.cycles) {
        hierarchy.L3.validate(mb.addr);
        mb.cycles = L3_LATENCY;
        mb.state = STATE_DELIVER_TO_L2;
        stats.dcache.missbuf.deliver.mem_to_L3++;
      }
      break;
    }
#endif
    case STATE_DELIVER_TO_L2: {
      if (DEBUG) logfile << "[vcpu ", mb.threadid, "] mb", i, ": deliver ", (void*)(Waddr)mb.addr, " to L2 (", mb.cycles, " cycles left) (iter ", iterations, ")", endl;
      mb.cycles--;
      if unlikely (!mb.cycles) {
        if (DEBUG) logfile << "[vcpu ", mb.threadid, "] mb", i, ": delivered to L2 (map ", mb.lfrqmap, ")", endl;
        hierarchy.L2.validate(mb.addr);
        mb.cycles = L2_LATENCY;
        mb.state = STATE_DELIVER_TO_L1;
        stats.dcache.missbuf.deliver.L3_to_L2++;
      }
      break;
    }
    case STATE_DELIVER_TO_L1: {
      if (DEBUG) logfile << "[vcpu ", mb.threadid, "] mb", i, ": deliver ", (void*)(Waddr)mb.addr, " to L1 (", mb.cycles, " cycles left) (iter ", iterations, ")", endl;
      mb.cycles--;
      if unlikely (!mb.cycles) {
        if (DEBUG) logfile << "[vcpu ", mb.threadid, "] mb", i, ": delivered to L1 switch (map ", mb.lfrqmap, ")", endl;

        if likely (mb.dcache) {
          if (DEBUG) logfile << "[vcpu ", mb.threadid, "] mb", i, ": delivered ", (void*)(Waddr)mb.addr, " to L1 dcache (map ", mb.lfrqmap, ")", endl;
          // If the L2 line size is bigger than the L1 line size, this will validate multiple lines in the L1 when an L2 line arrives:
          // foreach (i, L2_LINE_SIZE / L1_LINE_SIZE) L1.validate(mb.addr + i*L1_LINE_SIZE, bitvec<L1_LINE_SIZE>().setall());
#ifdef ENABLE_ASF_CACHE_BASED
          hierarchy.L1.validate(mb.addr, mb.virtaddr, bitvec<L1_LINE_SIZE>().setall(), mb.asf_spec);
#else
          hierarchy.L1.validate(mb.addr, mb.virtaddr, bitvec<L1_LINE_SIZE>().setall());
#endif
          stats.dcache.missbuf.deliver.L2_to_L1D++;
          hierarchy.lfrq.wakeup(mb.addr, mb.lfrqmap);
        }
        if unlikely (mb.icache) {
          // Sometimes we can initiate an icache miss on an existing dcache line in the missbuf
          if (DEBUG) logfile << "[vcpu ", mb.threadid, "] mb", i, ": delivered ", (void*)(Waddr)mb.addr, " to L1 icache", endl;
          // If the L2 line size is bigger than the L1 line size, this will validate multiple lines in the L1 when an L2 line arrives:
          // foreach (i, L2_LINE_SIZE / L1I_LINE_SIZE) L1I.validate(mb.addr + i*L1I_LINE_SIZE, bitvec<L1I_LINE_SIZE>().setall());
          hierarchy.L1I.validate(mb.addr, bitvec<L1I_LINE_SIZE>().setall());
          stats.dcache.missbuf.deliver.L2_to_L1I++;
          LoadStoreInfo lsi = 0;
          lsi.rob = mb.rob;
          lsi.threadid = mb.threadid;
          if likely (hierarchy.callback) hierarchy.callback->icache_wakeup(lsi, mb.addr);
        }
        /* NOTE: The LFRs may still hold a reference to this MB-entry at this
           point as they wake up asynchronously *and* clear their mbidx
           lazyly! :-/ */
        assert(!freemap[i]);
        freemap[i] = 1;
        mb.reset();
        count--;
        assert(count >= 0);
      }
      break;
    }
    case STATE_INVALIDATED: {
      // This entry has been hit by an external invalidating probe. Notify the
      // consumers to retry and free the entry
      // Other options:
      // TODO: Option 1: Reprobe directly in here -> notify ASF from here, too
      // TODO: Option 2: Send tainted data to the core -> let it retry the load
      hierarchy.lfrq.wakeup(mb.addr, mb.lfrqmap, true);

      // TODO: Stats
      assert(!freemap[i]);
      freemap[i] = 1;
      mb.reset();
      count--;
      assert(count >= 0);
      break;
    }
    }
  }
}

template <int SIZE>
void MissBuffer<SIZE>::annul_lfrq(int slot) {
  foreach (i, SIZE) {
    Entry& mb = missbufs[i];
    mb.lfrqmap[slot] = 0;  // which LFRQ entries should this load wake up?
  }
}

/**
 * Notify the miss-buffer of external probes to cache-line sized objects.
 * @param physaddr Physical address of the probed cache-line, properly aligned!
 * @param inv Invalidating probe?
 */
template <int SIZE>
void MissBuffer<SIZE>::external_probe(W64 physaddr, bool inv) {
  // NonInv probes do not affect the MissBuffer that just contains loads
  if (!inv) return;

  physaddr = floor(physaddr, L1_LINE_SIZE);

  int idx = find(physaddr);

  // No matching in flight request.
  if (idx == -1) return;

  Entry& mbe = missbufs[idx];
  mbe.state = STATE_INVALIDATED;

  if (logable(5)) logfile << "mb", idx, ": hit by inv(", inv,
    ") probe. ", endl;
  // The mb.clock() function will pick up the state change and act accordingly
}

template <int SIZE>
ostream& MissBuffer<SIZE>::print(ostream& os) const {
 
  os << "MissBuffer<", SIZE, ">:", endl;
  foreach (i, SIZE) {
    if likely (freemap[i]) continue;
    const Entry& mb = missbufs[i];
    os << "slot ", intstring(i, 2), ": vcpu ", mb.threadid, ", addr ", (void*)(Waddr)mb.addr, " state ", 
      padstring(missbuf_state_names[mb.state], -8), " ", (mb.dcache ? "dcache" : "      "),
      " ", (mb.icache ? "icache" : "      "), " on ", mb.cycles, " cycles -> lfrq ", mb.lfrqmap, endl;
  }
  return os;
}

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
#ifdef ENABLE_ASF_CACHE_BASED
template <int linesize>
ostream& CacheLineWithValidMaskSpecRead<linesize>::print(ostream& os, W64 tag) const {
#if 0
  const byte* data = (const byte*)(W64)tag;
  foreach (i, linesize/8) {
    os << "    ", bytemaskstring(data + i*8, base_t::valid(i*8, 8).integer(), 8, 8), " ";
    os << endl;
  }
  os << sr;
#endif
  return os;
}
template class CacheSubsystem::CacheLineWithValidMaskSpecRead<L1_LINE_SIZE>;
#endif
/**
 * For virtually indexed caches, set the bits in the index differing
 * between physical frame and virtual page number to zero, as we can't map
 * some physical address back to any virtual one necessarily.
 * HACKALERT: In a real CPU, we quite likely would get the data directly from
 * L2, but this fairly difficult to model in PTLsim.
 */
int CacheHierarchy::issueload_slowpath(Waddr physaddr, SFR& sfra, LoadStoreInfo lsi, bool& L2hit) {
  return issueload_slowpath(physaddr, physaddr & (~PAGE_MASK), sfra, lsi, L2hit);
}
int CacheHierarchy::issueload_slowpath(Waddr physaddr, Waddr virtaddr, SFR& sfra, LoadStoreInfo lsi, bool& L2hit) {
  static const bool DEBUG = 0;

  starttimer(load_slowpath_timer);

  L1CacheLine* L1line = L1.probe(physaddr, virtaddr);

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
    logfile << "issue_load_slowpath: L1line for ", (void*)(Waddr)physaddr, " = ", L1line, " validmask ";
    if (L1line) logfile << L1line->valid; else logfile << "(none)";
    logfile << endl;
  }

  if likely (!L1line) {
    //L1line = L1.select(physaddr);
    stats.dcache.load.transfer.L2_to_L1_full++;
  } else {
    stats.dcache.load.transfer.L2_to_L1_partial++;
  }

  L2hit = 0;
    
  L2CacheLine* L2line = L2.probe(physaddr);

  if likely (L2line) {
    //
    // We had at least a partial L2 hit, but is the requested data actually mapped into the line?
    //
    bitvec<L2_LINE_SIZE> sframask, reqmask;
    prep_L2_sframask_and_reqmask((lsi.sfrused) ? &sfra : null, physaddr, lsi.sizeshift, sframask, reqmask);
    L2hit = (lsi.sfrused) ? ((reqmask & (sframask | L2line->valid)) == reqmask) : ((reqmask & L2line->valid) == reqmask);
#ifdef ISSUE_LOAD_STORE_DEBUG
    logfile << "L2hit = ", L2hit, endl, "  cachemask ", L2line->valid, endl,
      "  sframask  ", sframask, endl, "  reqmask   ", reqmask, endl;
#endif
  }

#ifdef CACHE_ALWAYS_HITS
  L1line = L1.select(physaddr);
  L1line->tag = L1.tagof(physaddr);
  L1line->valid.setall();
  L2line->tag = L2.tagof(physaddr);
  L2line->valid.setall();
  L2hit = 1;
#endif

#ifdef L2_ALWAYS_HITS
  L2line = L2.select(physaddr);
  L2line->tag = L2.tagof(physaddr);
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
  // SD: I doubt that this is true. L1 and L2 lines are allocated when the data
  // arrives. See mb.clock() and the call to validate!
  //
  // If we did have a hit, but either the L1 or L2 lines
  // were still missing bytes, initiate prefetches to fill
  // them in.
  //

  LoadFillReq req(physaddr, virtaddr, lsi.sfrused ? sfra.data : 0, lsi.sfrused ? sfra.bytemask : 0, lsi);

  int lfrqslot = missbuf.initiate_miss(req, L2hit, lsi.rob);

  if unlikely (lfrqslot < 0) {
    if (DEBUG) logfile << "iteration ", iterations, ": LFRQ or MB has no free entries for L2->L1: forcing LFRQFull exception", endl;
    stoptimer(load_slowpath_timer);
    return -1;
  }

  stoptimer(load_slowpath_timer);

  return lfrqslot;
}

int CacheHierarchy::get_lfrq_mb(int lfrqslot) const {
  assert(inrange(lfrqslot, 0, LFRQ_SIZE-1));

  const LoadFillReq& req = lfrq.reqs[lfrqslot];
  return req.mbidx;
}

int CacheHierarchy::get_lfrq_mb_state(int lfrqslot) const {
  assert(inrange(lfrqslot, 0, LFRQ_SIZE-1));

  const LoadFillReq& req = lfrq.reqs[lfrqslot];
  if unlikely (req.mbidx < 0) return -1;

  assert(!missbuf.freemap[req.mbidx]);
  return missbuf.missbufs[req.mbidx].state;
}

bool CacheHierarchy::covered_by_sfr(W64 addr, SFR* sfr, int sizeshift) {
  bitvec<L1_LINE_SIZE> sframask, reqmask;
  prep_sframask_and_reqmask(sfr, addr, sizeshift, sframask, reqmask);
  return ((sframask & reqmask) == reqmask);
}

/**
 * For virtually indexed caches, set the bits in the index differing
 * between physical frame and virtual page number to zero, as we can't map
 * some physical address back to any virtual one necessarily.
 * HACKALERT: In a real CPU, we quite likely would get the data directly from
 * L2, but this fairly difficult to model in PTLsim.
 */
bool CacheHierarchy::probe_cache_and_sfr(W64 physaddr, const SFR* sfr, int sizeshift) {
  return probe_cache_and_sfr(physaddr, physaddr & (~PAGE_MASK), sfr, sizeshift);
}
bool CacheHierarchy::probe_cache_and_sfr(W64 physaddr, W64 virtaddr, const SFR* sfr, int sizeshift) {
  bitvec<L1_LINE_SIZE> sframask, reqmask;
  prep_sframask_and_reqmask(sfr, physaddr, sizeshift, sframask, reqmask);

  //
  // Short circuit if the SFR covers the entire load: no need for cache probe
  //
  if unlikely ((sframask & reqmask) == reqmask) return true;

  L1CacheLine* L1line = L1.probe(physaddr, virtaddr);

  if unlikely (!L1line) return false;

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

void CacheHierarchy::annul_lfrq_slot(int lfrqslot) {
  lfrq.annul(lfrqslot);
}
  
//
// NOTE: lsi should specify destination of REG_null for prefetches!
//
static const int PREFETCH_STOPS_AT_L2 = 0;
  
void CacheHierarchy::initiate_prefetch(W64 physaddr, W64 virtaddr, int cachelevel, bool invalidating) {
  static const bool DEBUG = 0;

  physaddr = floor(physaddr, L1_LINE_SIZE);
  virtaddr = floor(virtaddr, L1_LINE_SIZE);
  L1CacheLine* L1line = L1.probe(physaddr, virtaddr);
    
  if unlikely (L1line) {
    stats.dcache.prefetch.in_L1++;
#ifdef POOR_MANS_MESI
    if (invalidating) probe_other_caches(physaddr, virtaddr, true);
#endif
    return;
  }
    
  L2CacheLine* L2line = L2.probe(physaddr);
    
  if unlikely (L2line) {
    stats.dcache.prefetch.in_L2++;
    if (PREFETCH_STOPS_AT_L2) {
#ifdef POOR_MANS_MESI
      if (invalidating) probe_other_caches(physaddr, virtaddr, true);
#endif
      return; // only move up to L2 level, and it's already there
    }
  }
    
  if (DEBUG) logfile << "Prefetch requested for ", (void*)(Waddr)physaddr, " to cache level ", cachelevel, endl;
    
  // NB: This might actually get the line from another cache, ie with less cycles than full memory latency.
  missbuf.initiate_miss(physaddr, virtaddr, L2line);
  // NB(cont'd): hence we will just invalidate after initiating the miss!
#ifdef POOR_MANS_MESI
  if (invalidating) probe_other_caches(physaddr, (W64)virtaddr, true);
#endif
  stats.dcache.prefetch.required++;
}

//
// Instruction cache
//

bool CacheHierarchy::probe_icache(Waddr virtaddr, Waddr physaddr) {
  L1ICacheLine* L1line = L1I.probe(physaddr);
  bool hit = (L1line != null);
    
  return hit;
}

int CacheHierarchy::initiate_icache_miss(W64 addr, int rob, int threadid) {
  addr = floor(addr, L1I_LINE_SIZE);
  bool line_in_L2 = (L2.probe(addr) != null);
  /* SD: ignore virtual address, as L1I is not virtually indexed
     if it was, getting the virtual address in here would be a TODO!*/
  int mb = missbuf.initiate_miss(addr, 0, L2.probe(addr), true, rob, threadid);
    
  if (logable(6))
    logfile << "[vcpu ", threadid, "] Initiate icache miss on ", (void*)(Waddr)addr, " to missbuf ", mb, " (", (line_in_L2 ? "in L2" : "not in L2"), ")", endl;
    
  return mb;
}

//
// Commit one store from an SFR to the L2 cache without locking
// any cache lines. The store must have already been checked
// to have no exceptions.
//
W64 CacheHierarchy::commitstore(const SFR& sfr, W64 virtaddr, bool internal, int threadid, bool perform_actual_write) {
  if unlikely (sfr.invalid | (sfr.bytemask == 0)) return 0;

  static const bool DEBUG = 0;

  starttimer(store_flush_timer);

  W64 addr = sfr.physaddr << 3;

  // internal stores do not hit the caches
  if unlikely (internal && perform_actual_write) {
    storemask(addr, sfr.data, sfr.bytemask);
    return 0;
  }

  L2CacheLine* L2line = L2.select(addr);

  if likely (perform_actual_write) storemask(addr, sfr.data, sfr.bytemask);
#ifdef POOR_MANS_MESI
  probe_other_caches(addr, virtaddr, true);
#endif

  L1CacheLine* L1line = L1.select(addr, virtaddr);

  L1line->valid |= ((W64)sfr.bytemask << lowbits(addr, 6));
  L2line->valid |= ((W64)sfr.bytemask << lowbits(addr, 6));

  if unlikely (!L1line->valid.allset()) {
    per_context_dcache_stats_update(threadid, store.prefetches++);
    missbuf.initiate_miss(addr, virtaddr, L2line->valid.allset(), false, 0xffff, threadid);
  }

  stoptimer(store_flush_timer);

  return 0;
}

//
// Submit a speculative store that marks the relevant bytes as valid
// so they can be immediately forwarded to loads, but do not actually
// write to the cache itself.
//
W64 CacheHierarchy::speculative_store(const SFR& sfr, W64 virtaddr, int threadid) {
  return commitstore(sfr, virtaddr, false, threadid, false);
}

void CacheHierarchy::clock() {
  if unlikely ((sim_cycle & 0x7fffffff) == 0x7fffffff) {
    // Clear any 32-bit cycle-related counters in the cache to prevent wraparound:
    L1.clearstats();
    L1I.clearstats();
    L2.clearstats();
#ifdef ENABLE_L3_CACHE
    L3.clearstats();
#endif
    logfile << "Clearing cache statistics to prevent wraparound...", endl, flush;
  }

  lfrq.clock();
  missbuf.clock();
}

#ifdef POOR_MANS_MESI

bool CacheHierarchy::external_probe(W64 addr, W64 virtaddr, bool inv) {

  missbuf.external_probe(addr, inv);

  if unlikely (inv) {
    // Invalidations remove the entry from all cache levels
    L1.invalidate(addr, virtaddr);
    L1I.invalidate(addr);
    L2.invalidate(addr);
#ifdef ENABLE_L3_CACHE
    L3.invalidate(addr);
#endif
    return true;
  } else {
    // NonInv probes just probe the outermost cache as those are inclusive
    // in PTLsim!
#ifdef ENABLE_L3_CACHE
    return (L3.probe(addr) != null);
#else
    return (L2.probe(addr) != null);
#endif
  }
}
//
// Probes all other cache hierarchies in the system and checks whether any cache
// in them contains the line with the specified address. Invalidates the line,
// if necessary.
//
bool CacheHierarchy::probe_other_caches(W64 addr, W64 virtaddr, bool inv) {
  CacheHierarchy *other_hier;
  int            other_id;
  int  this_id   = (int) coreid;
  bool crosshit  = false;

  foreach (other_id, MAX_HIERARCHIES) {
    //TODO: Add statistics!
    if (other_id == this_id) continue;

    other_hier = hierarchies[other_id];
    if (!other_hier) continue;

    if (logable(6)) logfile << "[vcpu ", this_id, "] Sending ", inv ? "" : "Non",
      "Inv probe @ ", (void*) virtaddr, " / ", (void*) addr, " to core ", other_id, endl;
    crosshit |= other_hier->external_probe(addr, virtaddr, inv);
    if (!inv && crosshit) break;  //Short-cut read probes
  }
  return crosshit;
}
#endif

void CacheHierarchy::complete() {
  lfrq.restart();
  missbuf.restart();
}

void CacheHierarchy::complete(int threadid) {
  lfrq.reset(threadid);
  missbuf.reset(threadid);
}

void CacheHierarchy::reset() {
  lfrq.reset();
  missbuf.reset();
#ifdef ENABLE_L3_CACHE
  L3.reset();
#endif
  L2.reset();
  L1.reset();
  L1I.reset();
  itlb.reset();
  dtlb.reset();
#ifdef USE_L2_TLB
  l2itlb.reset();
  l2dtlb.reset();
#endif
}

ostream& CacheHierarchy::print(ostream& os) {
  os << "Data Cache Subsystem:", endl;
  os << lfrq;
  os << missbuf;
  // logfile << L1; 
  // logfile << L2; 
  return os;
}

//
// Make sure the templates and vtables get instantiated:
//
void PerCoreCacheCallbacks::dcache_wakeup(LoadStoreInfo lsi, W64 physaddr, bool retry) { }
void PerCoreCacheCallbacks::icache_wakeup(LoadStoreInfo lsi, W64 physaddr) { }

template struct LoadFillReqQueue<LFRQ_SIZE>;
template struct MissBuffer<MISSBUF_COUNT>;

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

CacheHierarchy* CacheHierarchy::hierarchies[MAX_HIERARCHIES] = {null};
