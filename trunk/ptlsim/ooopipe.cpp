//
// PTLsim: Cycle Accurate x86-64 Simulator
// Out-of-Order Core Simulator
// Core Pipeline Stages: Frontend, Writeback, Commit
//
// Copyright 2003-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <elf.h>
#include <ptlsim.h>
#include <branchpred.h>
#include <datastore.h>
#include <logic.h>
#include <dcache.h>

#define INSIDE_OOOCORE
#include <ooocore.h>
#include <stats.h>

#ifndef ENABLE_CHECKS
#undef assert
#define assert(x) (x)
#endif

#ifndef ENABLE_LOGGING
#undef logable
#define logable(level) (0)
#endif

using namespace OutOfOrderModel;

void OutOfOrderCoreCacheCallbacks::icache_wakeup(LoadStoreInfo lsi, W64 physaddr) {
  if (logable(6)) logfile << "I-cache wakeup of physaddr ", (void*)(Waddr)physaddr, endl;
  core.waiting_for_icache_fill = 0;
}

//
// Determine which physical register files can be written
// by a given type of uop.
//
// This must be customized if the physical register files
// are altered in ooohwdef.h.
//
static W32 phys_reg_files_writable_by_uop(const TransOp& uop) {
  W32 c = opinfo[uop.opcode].opclass;

#ifdef UNIFIED_INT_FP_PHYS_REG_FILE
  return
    (c & OPCLASS_STORE) ? OutOfOrderCore::PHYS_REG_FILE_MASK_ST :
    (c & OPCLASS_BRANCH) ? OutOfOrderCore::PHYS_REG_FILE_MASK_BR :
    OutOfOrderCore::PHYS_REG_FILE_MASK_INT;
#else
  return
    (c & OPCLASS_STORE) ? OutOfOrderCore::PHYS_REG_FILE_MASK_ST :
    (c & OPCLASS_BRANCH) ? OutOfOrderCore::PHYS_REG_FILE_MASK_BR :
    (c & (OPCLASS_LOAD | OPCLASS_PREFETCH)) ? ((uop.datatype == DATATYPE_INT) ? OutOfOrderCore::PHYS_REG_FILE_MASK_INT : OutOfOrderCore::PHYS_REG_FILE_MASK_FP) :
    ((c & OPCLASS_FP) | inrange((int)uop.rd, REG_xmml0, REG_xmmh15) | inrange((int)uop.rd, REG_fptos, REG_ctx)) ? OutOfOrderCore::PHYS_REG_FILE_MASK_FP :
    OutOfOrderCore::PHYS_REG_FILE_MASK_INT;
#endif
}

void OutOfOrderCore::annul_fetchq() {
  //
  // There may be return address stack (RAS) updates from calls and returns
  // in the fetch queue that never made it to renaming, so they have no ROB
  // that the core can annul normally. Therefore, we must go backwards in
  // the fetch queue to annul these updates, in addition to checking the ROB.
  //
  foreach_backward (fetchq, i) {
    FetchBufferEntry& fetchbuf = fetchq[i];
    if unlikely (isbranch(fetchbuf.opcode) && (fetchbuf.predinfo.bptype & (BRANCH_HINT_CALL|BRANCH_HINT_RET))) {
      eventlog.add(EVENT_ANNUL_FETCHQ_RAS, fetchbuf);
      branchpred.annulras(fetchbuf.predinfo);
    }
    // Also release the reference to the uop's basic block
    OutOfOrderCoreEvent* event = eventlog.add(EVENT_ANNUL_FETCHQ, fetchbuf);
    event->annul.bb = fetchbuf.bb; event->annul.bb_refcount = fetchbuf.bb->refcount;
    fetchbuf.bb->release();
  }
}

//
// Flush entire pipeline immediately, reset all processor
// structures to their initial state, and resume from the
// state saved in ctx.commitarf.
//
void OutOfOrderCore::flush_pipeline() {
  caches.complete();
  annul_fetchq();
  foreach_forward(ROB, i) {
    ReorderBufferEntry& rob = ROB[i];
    // Release our lock on the cached basic block containing each uop
    OutOfOrderCoreEvent* event = eventlog.add(EVENT_ANNUL_FLUSH, &rob);
    event->annul.bb = rob.uop.bb; event->annul.bb_refcount = rob.uop.bb->refcount;
    rob.uop.bb->release();
  }

  reset_fetch_unit(ctx.commitarf[REG_rip]);
  rob_states.reset();
  // physreg_states.reset();

  ROB.reset();
  foreach (i, ROB_SIZE) {
    ROB[i].coreid = coreid;
    ROB[i].changestate(rob_free_list);
  }
  LSQ.reset();
  foreach (i, LSQ_SIZE) {
    LSQ[i].coreid = coreid;
  }
  loads_in_flight = 0;
  stores_in_flight = 0;

  foreach (i, PHYS_REG_FILE_COUNT) physregfiles[i].reset();

  foreach_issueq(reset(coreid));

  dispatch_deadlock_countdown = DISPATCH_DEADLOCK_COUNTDOWN_CYCLES;
  last_commit_at_cycle = sim_cycle;

  external_to_core_state();
}

// call this in response to a branch mispredict:
void OutOfOrderCore::reset_fetch_unit(W64 realrip) {
  if (current_basic_block) {
    // Release our lock on the cached basic block we're currently fetching
    current_basic_block->release();
    current_basic_block = null;
  }

  fetchrip = realrip;
  fetchrip.update(ctx);
  stall_frontend = 0;
  waiting_for_icache_fill = 0;
  fetchq.reset();
  current_basic_block_transop_index = 0;
}

//
// Process any pending self-modifying code invalidate requests.
// This must be called on all cores *after* flushing all pipelines,
// to ensure no stale BBs are referenced, thus preventing them
// from being freed.
//
void OutOfOrderCore::invalidate_smc() {
  if unlikely (smc_invalidate_pending) {
    if (logable(5)) logfile << "SMC invalidate pending on ", smc_invalidate_rvp, endl;
    bbcache.invalidate_page(smc_invalidate_rvp.mfnlo, INVALIDATE_REASON_SMC);
    if unlikely (smc_invalidate_rvp.mfnlo != smc_invalidate_rvp.mfnhi) bbcache.invalidate_page(smc_invalidate_rvp.mfnhi, INVALIDATE_REASON_SMC);
    smc_invalidate_pending = 0;
  }
}

//
// Copy external archregs to physregs and reset all rename tables
//
void OutOfOrderCore::external_to_core_state() {
  foreach (i, PHYS_REG_FILE_COUNT) {
    PhysicalRegisterFile& rf = physregfiles[i];
    PhysicalRegister* zeroreg = rf.alloc(PHYS_REG_NULL);
    zeroreg->addref();
    zeroreg->commit();
    zeroreg->data = 0;
    zeroreg->flags = 0;
    zeroreg->archreg = REG_zero;
  }

  // Always start out on cluster 0:
  PhysicalRegister* zeroreg = &physregfiles[0][PHYS_REG_NULL];

  //
  // Allocate and commit each architectural register
  //
  foreach (i, ARCHREG_COUNT) {
    //
    // IMPORTANT! If using some register file configuration other
    // than (integer, fp), this needs to be changed!
    //
#ifdef UNIFIED_INT_FP_PHYS_REG_FILE
    int rfid = (i == REG_rip) ? PHYS_REG_FILE_BR : PHYS_REG_FILE_INT;
#else
    bool fp = inrange((int)i, REG_xmml0, REG_xmmh15) | (inrange((int)i, REG_fptos, REG_ctx));
    int rfid = (fp) ? PHYS_REG_FILE_FP : (i == REG_rip) ? PHYS_REG_FILE_BR : PHYS_REG_FILE_INT;
#endif
    PhysicalRegisterFile& rf = physregfiles[rfid];
    PhysicalRegister* physreg = (i == REG_zero) ? zeroreg : rf.alloc();
    physreg->data = ctx.commitarf[i];
    physreg->flags = 0;
    commitrrt[i] = physreg;
  }

  commitrrt[REG_flags]->flags = (W16)commitrrt[REG_flags]->data;

  //
  // Internal translation registers are never used before
  // they are written for the first time:
  //
  for (int i = ARCHREG_COUNT; i < TRANSREG_COUNT; i++) {
    commitrrt[i] = zeroreg;
  }

  //
  // Set renamable flags
  // 
  commitrrt[REG_zf] = commitrrt[REG_flags];
  commitrrt[REG_cf] = commitrrt[REG_flags];
  commitrrt[REG_of] = commitrrt[REG_flags];

  //
  // Copy commitrrt to specrrt and update refcounts
  //
  foreach (i, TRANSREG_COUNT) {
    commitrrt[i]->commit();
    specrrt[i] = commitrrt[i];
    specrrt[i]->addspecref(i);
    commitrrt[i]->addcommitref(i);
  }

#ifdef ENABLE_TRANSIENT_VALUE_TRACKING
  specrrt.renamed_in_this_basic_block.reset();
  commitrrt.renamed_in_this_basic_block.reset();
#endif
}

//
// Re-dispatch all uops in the ROB that have not yet generated
// a result or are otherwise stalled.
//
void OutOfOrderCore::redispatch_deadlock_recovery() {
  if (logable(6)) dump_ooo_state(logfile);

  stats.ooocore.dispatch.redispatch.deadlock_flushes++;

  flush_pipeline();

  /*
  //
  // This is a more selective scheme than the full pipeline flush.
  // Presently it does not work correctly with some combinations
  // of user-modifiable parameters, so it's disabled to ensure
  // deadlock-free operation in every configuration.
  //

  ReorderBufferEntry* prevrob = null;
  bitvec<MAX_OPERANDS> noops = 0;

  foreach_forward(ROB, robidx) {
  ReorderBufferEntry& rob = ROB[robidx];

  //
  // Only re-dispatch those uops that have not yet generated a value
  // or are guaranteed to produce a value soon without tying up resources.
  // This must occur in program order to avoid deadlock!
  // 
  // bool recovery_required = (rob.current_state_list->flags & ROB_STATE_IN_ISSUE_QUEUE) || (rob.current_state_list == &rob_ready_to_dispatch_list);
  bool recovery_required = 1; // for now, just to be safe

  if (recovery_required) {
  rob.redispatch(noops, prevrob);
  prevrob = &rob;
  stats.ooocore.dispatch.redispatch.deadlock_uops_flushed++;
  }
  }

  if (logable(6)) dump_ooo_state();
  */
}


//
// Fetch Stage
//
// Fetch a stream of x86 instructions from the L1 i-cache along predicted
// branch paths.
//
// Internally, up to N uops per clock corresponding to instructions in
// the current basic block are fetched per cycle and placed in the uopq
// as TransOps. When we run out of uops in one basic block, we proceed
// to lookup or translate the next basic block.
//

//
// Used to debug crashes when cycle to start logging can't be determined:
//
static RIPVirtPhys fetch_bb_address_ringbuf[256];
static W64 fetch_bb_address_ringbuf_head = 0;

static void print_fetch_bb_address_ringbuf(ostream& os) {
  os << "Head: ", fetch_bb_address_ringbuf_head, endl;
  foreach (i, lengthof(fetch_bb_address_ringbuf)) {
    int j = (fetch_bb_address_ringbuf_head + i) % lengthof(fetch_bb_address_ringbuf);
    const RIPVirtPhys& addr = fetch_bb_address_ringbuf[j];
    os << "  ", intstring(i, 16), ": ", addr, endl;
  }
}

bool OutOfOrderCore::fetch() {
  int fetchcount = 0;
  int taken_branch_count = 0;

  OutOfOrderCoreEvent* event;

  if unlikely (stall_frontend) {
    eventlog.add(EVENT_FETCH_STALLED);
    stats.ooocore.fetch.stop.stalled++;
    return true;
  }

  if unlikely (waiting_for_icache_fill) {
    eventlog.add(EVENT_FETCH_ICACHE_WAIT);
    stats.ooocore.fetch.stop.icache_miss++;
    return true;
  }

  TransOpBuffer unaligned_ldst_buf;

  while ((fetchcount < FETCH_WIDTH) && (taken_branch_count == 0)) {
    if unlikely (!fetchq.remaining()) {
      if (!fetchcount) eventlog.add(EVENT_FETCH_FETCHQ_FULL);
      stats.ooocore.fetch.stop.fetchq_full++;
      break;
    }

    if unlikely ((fetchrip.rip == config.start_log_at_rip) && (fetchrip.rip != 0xffffffffffffffffULL)) {
      config.start_log_at_iteration = 0;
      logenable = 1;
    }

    if unlikely ((!current_basic_block) || (current_basic_block_transop_index >= current_basic_block->count)) {
      fetch_bb_address_ringbuf[fetch_bb_address_ringbuf_head] = fetchrip;
      fetch_bb_address_ringbuf_head = add_index_modulo(fetch_bb_address_ringbuf_head, +1, lengthof(fetch_bb_address_ringbuf));
      fetch_or_translate_basic_block(ctx, fetchrip);
    }

    if unlikely (current_basic_block->invalidblock) {
      eventlog.add(EVENT_FETCH_BOGUS_RIP, fetchrip);
      stats.ooocore.fetch.stop.bogus_rip++;
      //
      // Keep fetching - the decoder has injected assist microcode that
      // branches to the invalid opcode or exec page fault handler.
      //
    }

#ifdef PTLSIM_HYPERVISOR
    Waddr physaddr = (fetchrip.mfnlo << 12) + lowbits(fetchrip, 12);
#else
    Waddr physaddr = fetchrip;
#endif

    W64 req_icache_block = floor(physaddr, ICACHE_FETCH_GRANULARITY);
    if ((!current_basic_block->invalidblock) && (req_icache_block != current_icache_block)) {
      bool hit = caches.probe_icache(fetchrip, physaddr);
      hit |= config.perfect_cache;
      if unlikely (!hit) {
        int missbuf = caches.initiate_icache_miss(physaddr);
        eventlog.add(EVENT_FETCH_ICACHE_MISS, fetchrip)->fetch.missbuf = missbuf;

        if unlikely (missbuf < 0) {
          // Try to re-allocate a miss buffer on the next cycle
          break;
        }
        waiting_for_icache_fill = 1;
        stats.ooocore.fetch.stop.icache_miss++;
        break;
      }

      stats.ooocore.fetch.blocks++;
      current_icache_block = req_icache_block;
      stats.ooocore.dcache.fetch.hit.L1++;
    }

    FetchBufferEntry& transop = *fetchq.alloc();
    uopimpl_func_t synthop = null;

    assert(current_basic_block->synthops);

    if likely (!unaligned_ldst_buf.get(transop, synthop)) {
      transop = current_basic_block->transops[current_basic_block_transop_index];
      synthop = current_basic_block->synthops[current_basic_block_transop_index];
    }

    transop.rip = fetchrip;
    transop.uuid = fetch_uuid;

    //
    // Handle loads and stores marked as unaligned in the basic block cache.
    // These uops are split into two parts (ld.lo, ld.hi or st.lo, st.hi)
    // and the parts are put into a 2-entry buffer (unaligned_ldst_pair).
    // Fetching continues from this buffer instead of the basic block
    // until both uops are forced into the pipeline.
    //
    if unlikely (transop.unaligned) {
      eventlog.add(EVENT_FETCH_SPLIT, transop);
      split_unaligned(transop, unaligned_ldst_buf);
      assert(unaligned_ldst_buf.get(transop, synthop));
    }

    assert(transop.bbindex == current_basic_block_transop_index);
    transop.bb = current_basic_block;
    transop.bb->acquire();
    transop.synthop = synthop;

    current_basic_block_transop_index += (unaligned_ldst_buf.empty());

    stats.ooocore.fetch.user_insns += transop.som;

    if unlikely (isclass(transop.opcode, OPCLASS_BARRIER)) {
      // We've hit an assist: stall the frontend until we resume or redirect
      eventlog.add(EVENT_FETCH_ASSIST, transop);
      stall_frontend = 1;      
    }

    stats.ooocore.fetch.uops++;

    Waddr predrip = 0;
    bool redirectrip = false;

    transop.rip = fetchrip;
    transop.uuid = fetch_uuid++;

    if (isbranch(transop.opcode)) {
      transop.predinfo.uuid = transop.uuid;
      transop.predinfo.bptype = 
        (isclass(transop.opcode, OPCLASS_COND_BRANCH) << log2(BRANCH_HINT_COND)) |
        (isclass(transop.opcode, OPCLASS_INDIR_BRANCH) << log2(BRANCH_HINT_INDIRECT)) |
        (bit(transop.extshift, log2(BRANCH_HINT_PUSH_RAS)) << log2(BRANCH_HINT_CALL)) |
        (bit(transop.extshift, log2(BRANCH_HINT_POP_RAS)) << log2(BRANCH_HINT_RET));

      // SMP/SMT: Fill in with target thread ID (if the predictor supports this):
      transop.predinfo.ctxid = 0;
      transop.predinfo.ripafter = fetchrip + transop.bytes;
      predrip = branchpred.predict(transop.predinfo, transop.predinfo.bptype, transop.predinfo.ripafter, transop.riptaken);
      redirectrip = 1;
      stats.ooocore.branchpred.predictions++;
    }

    // Set up branches so mispredicts can be calculated correctly:
    if unlikely (isclass(transop.opcode, OPCLASS_COND_BRANCH)) {
      if unlikely (predrip != transop.riptaken) {
        assert(predrip == transop.ripseq);
        transop.cond = invert_cond(transop.cond);
        //
        // We need to be careful here: we already looked up the synthop for this
        // uop according to the old condition, so redo that here so we call the
        // correct code for the swapped condition.
        //
        transop.synthop = get_synthcode_for_cond_branch(transop.opcode, transop.cond, transop.size, 0);
        swap(transop.riptaken, transop.ripseq);
      }
    } else if unlikely (isclass(transop.opcode, OPCLASS_INDIR_BRANCH)) {
      transop.riptaken = predrip;
      transop.ripseq = predrip;
    }

    stats.ooocore.fetch.opclass[opclassof(transop.opcode)]++;

    event = eventlog.add(EVENT_FETCH_OK, transop);
    event->fetch.bb = current_basic_block;
    event->fetch.predrip = predrip;

    if likely (transop.eom) {
      fetchrip.rip += transop.bytes;
      fetchrip.update(ctx);

      if unlikely (isbranch(transop.opcode) && (transop.predinfo.bptype & (BRANCH_HINT_CALL|BRANCH_HINT_RET)))
                    branchpred.updateras(transop.predinfo, transop.predinfo.ripafter);

      if unlikely (redirectrip) {
        // follow to target, then end fetching for this cycle if predicted taken
        bool taken = (predrip != fetchrip);
        taken_branch_count += taken;
        fetchrip = predrip;
        fetchrip.update(ctx);
        if (taken) {
          stats.ooocore.fetch.stop.branch_taken++;
          break;
        }
      }
    }

    fetchcount++;
  }

  stats.ooocore.fetch.stop.full_width += (fetchcount == FETCH_WIDTH);
  stats.ooocore.fetch.width[fetchcount]++;

  return true;
}

BasicBlock* OutOfOrderCore::fetch_or_translate_basic_block(Context& ctx, const RIPVirtPhys& rvp) {  
  if likely (current_basic_block) {
    // Release our ref to the old basic block being fetched
    current_basic_block->release();
    current_basic_block = null;
  }

  BasicBlock* bb = bbcache(rvp);

  if likely (bb) {
    current_basic_block = bb;
  } else {
    current_basic_block = bbcache.translate(ctx, rvp);
    assert(current_basic_block);
    OutOfOrderCoreEvent* event = eventlog.add(EVENT_FETCH_TRANSLATE, rvp);
    event->fetch.bb = current_basic_block; event->fetch.bb_uop_count = current_basic_block->count;
  }

  //
  // Acquire a reference to the new basic block being fetched.
  // This must be done right away so future allocations do not
  // reclaim the BB while we still have a reference to it.
  //
  current_basic_block->acquire();
  current_basic_block->use(sim_cycle);  

  if unlikely (!current_basic_block->synthops) synth_uops_for_bb(*current_basic_block);
  assert(current_basic_block->synthops);
  
  current_basic_block_transop_index = 0;
  assert(current_basic_block->rip == rvp);

  return current_basic_block;
}

//
// Allocate and Rename Stages
//

void OutOfOrderCore::rename() {
  int prepcount = 0;

  while (prepcount < FRONTEND_WIDTH) {
    if unlikely (fetchq.empty()) {
      if likely (!prepcount) eventlog.add(EVENT_RENAME_FETCHQ_EMPTY);
      stats.ooocore.frontend.status.fetchq_empty++;
      break;
    } 

    if unlikely (!ROB.remaining()) {
      if likely (!prepcount) eventlog.add(EVENT_RENAME_ROB_FULL);
      stats.ooocore.frontend.status.rob_full++;
      break;
    }

    FetchBufferEntry& fetchbuf = *fetchq.peek();

    int phys_reg_file = -1;

    W32 acceptable_phys_reg_files = phys_reg_files_writable_by_uop(fetchbuf);

    foreach (i, PHYS_REG_FILE_COUNT) {
      int reg_file_to_check = add_index_modulo(round_robin_reg_file_offset, i, PHYS_REG_FILE_COUNT);
      if likely (bit(acceptable_phys_reg_files, reg_file_to_check) && physregfiles[reg_file_to_check].remaining()) {
        phys_reg_file = reg_file_to_check; break;
      }
    }

    if (phys_reg_file < 0) {
      if likely (!prepcount) eventlog.add()->fill(EVENT_RENAME_PHYSREGS_FULL);
      stats.ooocore.frontend.status.physregs_full++;
      break;
    }

    bool ld = isload(fetchbuf.opcode);
    bool st = isstore(fetchbuf.opcode);
    bool br = isbranch(fetchbuf.opcode);

    if unlikely (ld && (loads_in_flight >= LDQ_SIZE)) {
      if likely (!prepcount) eventlog.add(EVENT_RENAME_LDQ_FULL);
      stats.ooocore.frontend.status.ldq_full++;
      break;
    }

    if unlikely (st && (stores_in_flight >= STQ_SIZE)) {
      if likely (!prepcount) eventlog.add(EVENT_RENAME_STQ_FULL);
      stats.ooocore.frontend.status.stq_full++;
      break;
    }

    if unlikely ((ld|st) && (!LSQ.remaining())) {
      if likely (!prepcount) eventlog.add(EVENT_RENAME_MEMQ_FULL);
      break;
    }

    stats.ooocore.frontend.status.complete++;

    FetchBufferEntry& transop = *fetchq.dequeue();
    ReorderBufferEntry& rob = *ROB.alloc();
    PhysicalRegister* physreg = null;

    LoadStoreQueueEntry* lsqp = (ld|st) ? LSQ.alloc() : null;
    LoadStoreQueueEntry& lsq = *lsqp;

    rob.reset();
    rob.uop = transop;
    rob.entry_valid = 1;
    rob.cycles_left = FRONTEND_STAGES;
    rob.lsq = null;
    if unlikely (ld|st) {
      rob.lsq = &lsq;
      lsq.rob = &rob;
      lsq.store = st;
      lsq.datavalid = 0;
      lsq.addrvalid = 0;
      lsq.invalid = 0;
    }

    stats.ooocore.frontend.alloc.reg += (!(ld|st|br));
    stats.ooocore.frontend.alloc.ldreg += ld;
    stats.ooocore.frontend.alloc.sfr += st;
    stats.ooocore.frontend.alloc.br += br;

    //
    // Rename operands:
    //

    rob.operands[RA] = specrrt[transop.ra];
    rob.operands[RB] = specrrt[transop.rb];
    rob.operands[RC] = specrrt[transop.rc];
    rob.operands[RS] = &physregfiles[0][PHYS_REG_NULL]; // used for loads and stores only

    // See notes above on Physical Register Recycling Complications
    foreach (i, MAX_OPERANDS) {
      rob.operands[i]->addref(rob);
      assert(rob.operands[i]->state != PHYSREG_FREE);

      if likely ((rob.operands[i]->state == PHYSREG_WAITING) |
                 (rob.operands[i]->state == PHYSREG_BYPASS) |
                 (rob.operands[i]->state == PHYSREG_WRITTEN)) {
        rob.operands[i]->rob->consumer_count = min(rob.operands[i]->rob->consumer_count + 1, 255);
      }
    }

    //
    // Select a physical register file based on desired
    // heuristics. We only consider a given register
    // file N if bit N in the acceptable_phys_reg_files
    // bitmap is set (otherwise it is off limits for
    // the type of functional unit or cluster the uop
    // must execute on).
    //
    // The phys_reg_file variable should be set to the
    // register file ID selected by the heuristics.
    //

    //
    // Default heuristics from above: phys_reg_file is already
    // set to the first acceptable physical register file ID
    // which has free registers.
    //
    rob.executable_on_cluster_mask = uop_executable_on_cluster[transop.opcode];

    // This is used if there is exactly one physical register file per cluster:
    // rob.executable_on_cluster_mask = (1 << phys_reg_file);

    // For assignment only:
    assert(bit(acceptable_phys_reg_files, phys_reg_file));

    //
    // Allocate the physical register
    //

    physreg = physregfiles[phys_reg_file].alloc();
    assert(physreg);
    physreg->flags = FLAG_WAIT;
    physreg->data = 0xdeadbeefdeadbeefULL;
    physreg->rob = &rob;
    physreg->archreg = rob.uop.rd;
    rob.physreg = physreg;

    //
    // Logging
    //

    OutOfOrderCoreEvent* event = eventlog.add(EVENT_RENAME_OK, &rob);
    foreach (i, MAX_OPERANDS) rob.operands[i]->fill_operand_info(event->rename.opinfo[i]);

    if likely (archdest_can_commit[transop.rd]) {
      event->rename.oldphys = specrrt[transop.rd]->index();
      event->rename.oldzf = specrrt[REG_zf]->index();
      event->rename.oldcf = specrrt[REG_cf]->index();
      event->rename.oldof = specrrt[REG_of]->index();
    }

    bool renamed_reg = 0;
    bool renamed_flags = 0;

    if likely (archdest_can_commit[transop.rd]) {
#ifdef ENABLE_TRANSIENT_VALUE_TRACKING
      PhysicalRegister* oldmapping = specrrt[transop.rd];
      if ((oldmapping->current_state_list == &physreg_waiting_list) |
          (oldmapping->current_state_list == &physreg_ready_list)) {
        oldmapping->rob->dest_renamed_before_writeback = 1;
      }

      if ((oldmapping->current_state_list == &physreg_waiting_list) |
          (oldmapping->current_state_list == &physreg_ready_list) | 
          (oldmapping->current_state_list == &physreg_written_list)) {
        oldmapping->rob->no_branches_between_renamings = specrrt.renamed_in_this_basic_block[transop.rd];
      }

      specrrt.renamed_in_this_basic_block[transop.rd] = 1;
#endif

      specrrt[transop.rd]->unspecref(transop.rd);
      specrrt[transop.rd] = rob.physreg;
      rob.physreg->addspecref(transop.rd);
      renamed_reg = archdest_is_visible[transop.rd];
    }

    if unlikely (!transop.nouserflags) {
      if (transop.setflags & SETFLAG_ZF) {
        specrrt[REG_zf]->unspecref(REG_zf);
        specrrt[REG_zf] = rob.physreg;
        rob.physreg->addspecref(REG_zf);
      }
      if (transop.setflags & SETFLAG_CF) {
        specrrt[REG_cf]->unspecref(REG_cf);
        specrrt[REG_cf] = rob.physreg;
        rob.physreg->addspecref(REG_cf);
      }
      if (transop.setflags & SETFLAG_OF) {
        specrrt[REG_of]->unspecref(REG_of);
        specrrt[REG_of] = rob.physreg;
        rob.physreg->addspecref(REG_of);
      }
      renamed_flags = (transop.setflags != 0);
    }

    foreach (i, MAX_OPERANDS) {
      assert(rob.operands[i]->allocated());
    }

#ifdef ENABLE_TRANSIENT_VALUE_TRACKING
    if unlikely (br) specrrt.renamed_in_this_basic_block.reset();
#endif

    stats.ooocore.frontend.renamed.none += ((!renamed_reg) && (!renamed_flags));
    stats.ooocore.frontend.renamed.reg += ((renamed_reg) && (!renamed_flags));
    stats.ooocore.frontend.renamed.flags += ((!renamed_reg) && (renamed_flags));
    stats.ooocore.frontend.renamed.reg_and_flags += ((renamed_reg) && (renamed_flags));

    rob.changestate(rob_frontend_list);

    prepcount++;
  }

  stats.ooocore.frontend.width[prepcount]++;
}

void OutOfOrderCore::frontend() {
  ReorderBufferEntry* rob;
  
  foreach_list_mutable(rob_frontend_list, rob, entry, nextentry) {
    if unlikely (rob->cycles_left <= 0) {
      rob->cycles_left = -1;
      rob->changestate(rob_ready_to_dispatch_list);
    } else {
      OutOfOrderCoreEvent* event = eventlog.add(EVENT_FRONTEND, rob);
      event->frontend.cycles_left = rob->cycles_left;
    }
    
    rob->cycles_left--;
  }
}

//
// Dispatch and Cluster Selection
//
static byte bit_indices_set_8bits[1<<8][8] = {
  {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0},  
  {1, 1, 1, 1, 1, 1, 1, 1}, {0, 1, 0, 1, 0, 1, 0, 1},
  {2, 2, 2, 2, 2, 2, 2, 2}, {0, 2, 0, 2, 0, 2, 0, 2},
  {1, 2, 1, 2, 1, 2, 1, 2}, {0, 1, 2, 0, 1, 2, 0, 1},
  {3, 3, 3, 3, 3, 3, 3, 3}, {0, 3, 0, 3, 0, 3, 0, 3},
  {1, 3, 1, 3, 1, 3, 1, 3}, {0, 1, 3, 0, 1, 3, 0, 1},
  {2, 3, 2, 3, 2, 3, 2, 3}, {0, 2, 3, 0, 2, 3, 0, 2},
  {1, 2, 3, 1, 2, 3, 1, 2}, {0, 1, 2, 3, 0, 1, 2, 3},
  {4, 4, 4, 4, 4, 4, 4, 4}, {0, 4, 0, 4, 0, 4, 0, 4},
  {1, 4, 1, 4, 1, 4, 1, 4}, {0, 1, 4, 0, 1, 4, 0, 1},
  {2, 4, 2, 4, 2, 4, 2, 4}, {0, 2, 4, 0, 2, 4, 0, 2},
  {1, 2, 4, 1, 2, 4, 1, 2}, {0, 1, 2, 4, 0, 1, 2, 4},
  {3, 4, 3, 4, 3, 4, 3, 4}, {0, 3, 4, 0, 3, 4, 0, 3},
  {1, 3, 4, 1, 3, 4, 1, 3}, {0, 1, 3, 4, 0, 1, 3, 4},
  {2, 3, 4, 2, 3, 4, 2, 3}, {0, 2, 3, 4, 0, 2, 3, 4},
  {1, 2, 3, 4, 1, 2, 3, 4}, {0, 1, 2, 3, 4, 0, 1, 2},
  {5, 5, 5, 5, 5, 5, 5, 5}, {0, 5, 0, 5, 0, 5, 0, 5},
  {1, 5, 1, 5, 1, 5, 1, 5}, {0, 1, 5, 0, 1, 5, 0, 1},
  {2, 5, 2, 5, 2, 5, 2, 5}, {0, 2, 5, 0, 2, 5, 0, 2},
  {1, 2, 5, 1, 2, 5, 1, 2}, {0, 1, 2, 5, 0, 1, 2, 5},
  {3, 5, 3, 5, 3, 5, 3, 5}, {0, 3, 5, 0, 3, 5, 0, 3},
  {1, 3, 5, 1, 3, 5, 1, 3}, {0, 1, 3, 5, 0, 1, 3, 5},
  {2, 3, 5, 2, 3, 5, 2, 3}, {0, 2, 3, 5, 0, 2, 3, 5},
  {1, 2, 3, 5, 1, 2, 3, 5}, {0, 1, 2, 3, 5, 0, 1, 2},
  {4, 5, 4, 5, 4, 5, 4, 5}, {0, 4, 5, 0, 4, 5, 0, 4},
  {1, 4, 5, 1, 4, 5, 1, 4}, {0, 1, 4, 5, 0, 1, 4, 5},
  {2, 4, 5, 2, 4, 5, 2, 4}, {0, 2, 4, 5, 0, 2, 4, 5},
  {1, 2, 4, 5, 1, 2, 4, 5}, {0, 1, 2, 4, 5, 0, 1, 2},
  {3, 4, 5, 3, 4, 5, 3, 4}, {0, 3, 4, 5, 0, 3, 4, 5},
  {1, 3, 4, 5, 1, 3, 4, 5}, {0, 1, 3, 4, 5, 0, 1, 3},
  {2, 3, 4, 5, 2, 3, 4, 5}, {0, 2, 3, 4, 5, 0, 2, 3},
  {1, 2, 3, 4, 5, 1, 2, 3}, {0, 1, 2, 3, 4, 5, 0, 1},
  {6, 6, 6, 6, 6, 6, 6, 6}, {0, 6, 0, 6, 0, 6, 0, 6},
  {1, 6, 1, 6, 1, 6, 1, 6}, {0, 1, 6, 0, 1, 6, 0, 1},
  {2, 6, 2, 6, 2, 6, 2, 6}, {0, 2, 6, 0, 2, 6, 0, 2},
  {1, 2, 6, 1, 2, 6, 1, 2}, {0, 1, 2, 6, 0, 1, 2, 6},
  {3, 6, 3, 6, 3, 6, 3, 6}, {0, 3, 6, 0, 3, 6, 0, 3},
  {1, 3, 6, 1, 3, 6, 1, 3}, {0, 1, 3, 6, 0, 1, 3, 6},
  {2, 3, 6, 2, 3, 6, 2, 3}, {0, 2, 3, 6, 0, 2, 3, 6},
  {1, 2, 3, 6, 1, 2, 3, 6}, {0, 1, 2, 3, 6, 0, 1, 2},
  {4, 6, 4, 6, 4, 6, 4, 6}, {0, 4, 6, 0, 4, 6, 0, 4},
  {1, 4, 6, 1, 4, 6, 1, 4}, {0, 1, 4, 6, 0, 1, 4, 6},
  {2, 4, 6, 2, 4, 6, 2, 4}, {0, 2, 4, 6, 0, 2, 4, 6},
  {1, 2, 4, 6, 1, 2, 4, 6}, {0, 1, 2, 4, 6, 0, 1, 2},
  {3, 4, 6, 3, 4, 6, 3, 4}, {0, 3, 4, 6, 0, 3, 4, 6},
  {1, 3, 4, 6, 1, 3, 4, 6}, {0, 1, 3, 4, 6, 0, 1, 3},
  {2, 3, 4, 6, 2, 3, 4, 6}, {0, 2, 3, 4, 6, 0, 2, 3},
  {1, 2, 3, 4, 6, 1, 2, 3}, {0, 1, 2, 3, 4, 6, 0, 1},
  {5, 6, 5, 6, 5, 6, 5, 6}, {0, 5, 6, 0, 5, 6, 0, 5},
  {1, 5, 6, 1, 5, 6, 1, 5}, {0, 1, 5, 6, 0, 1, 5, 6},
  {2, 5, 6, 2, 5, 6, 2, 5}, {0, 2, 5, 6, 0, 2, 5, 6},
  {1, 2, 5, 6, 1, 2, 5, 6}, {0, 1, 2, 5, 6, 0, 1, 2},
  {3, 5, 6, 3, 5, 6, 3, 5}, {0, 3, 5, 6, 0, 3, 5, 6},
  {1, 3, 5, 6, 1, 3, 5, 6}, {0, 1, 3, 5, 6, 0, 1, 3},
  {2, 3, 5, 6, 2, 3, 5, 6}, {0, 2, 3, 5, 6, 0, 2, 3},
  {1, 2, 3, 5, 6, 1, 2, 3}, {0, 1, 2, 3, 5, 6, 0, 1},
  {4, 5, 6, 4, 5, 6, 4, 5}, {0, 4, 5, 6, 0, 4, 5, 6},
  {1, 4, 5, 6, 1, 4, 5, 6}, {0, 1, 4, 5, 6, 0, 1, 4},
  {2, 4, 5, 6, 2, 4, 5, 6}, {0, 2, 4, 5, 6, 0, 2, 4},
  {1, 2, 4, 5, 6, 1, 2, 4}, {0, 1, 2, 4, 5, 6, 0, 1},
  {3, 4, 5, 6, 3, 4, 5, 6}, {0, 3, 4, 5, 6, 0, 3, 4},
  {1, 3, 4, 5, 6, 1, 3, 4}, {0, 1, 3, 4, 5, 6, 0, 1},
  {2, 3, 4, 5, 6, 2, 3, 4}, {0, 2, 3, 4, 5, 6, 0, 2},
  {1, 2, 3, 4, 5, 6, 1, 2}, {0, 1, 2, 3, 4, 5, 6, 0},
  {7, 7, 7, 7, 7, 7, 7, 7}, {0, 7, 0, 7, 0, 7, 0, 7},
  {1, 7, 1, 7, 1, 7, 1, 7}, {0, 1, 7, 0, 1, 7, 0, 1},
  {2, 7, 2, 7, 2, 7, 2, 7}, {0, 2, 7, 0, 2, 7, 0, 2},
  {1, 2, 7, 1, 2, 7, 1, 2}, {0, 1, 2, 7, 0, 1, 2, 7},
  {3, 7, 3, 7, 3, 7, 3, 7}, {0, 3, 7, 0, 3, 7, 0, 3},
  {1, 3, 7, 1, 3, 7, 1, 3}, {0, 1, 3, 7, 0, 1, 3, 7},
  {2, 3, 7, 2, 3, 7, 2, 3}, {0, 2, 3, 7, 0, 2, 3, 7},
  {1, 2, 3, 7, 1, 2, 3, 7}, {0, 1, 2, 3, 7, 0, 1, 2},
  {4, 7, 4, 7, 4, 7, 4, 7}, {0, 4, 7, 0, 4, 7, 0, 4},
  {1, 4, 7, 1, 4, 7, 1, 4}, {0, 1, 4, 7, 0, 1, 4, 7},
  {2, 4, 7, 2, 4, 7, 2, 4}, {0, 2, 4, 7, 0, 2, 4, 7},
  {1, 2, 4, 7, 1, 2, 4, 7}, {0, 1, 2, 4, 7, 0, 1, 2},
  {3, 4, 7, 3, 4, 7, 3, 4}, {0, 3, 4, 7, 0, 3, 4, 7},
  {1, 3, 4, 7, 1, 3, 4, 7}, {0, 1, 3, 4, 7, 0, 1, 3},
  {2, 3, 4, 7, 2, 3, 4, 7}, {0, 2, 3, 4, 7, 0, 2, 3},
  {1, 2, 3, 4, 7, 1, 2, 3}, {0, 1, 2, 3, 4, 7, 0, 1},
  {5, 7, 5, 7, 5, 7, 5, 7}, {0, 5, 7, 0, 5, 7, 0, 5},
  {1, 5, 7, 1, 5, 7, 1, 5}, {0, 1, 5, 7, 0, 1, 5, 7},
  {2, 5, 7, 2, 5, 7, 2, 5}, {0, 2, 5, 7, 0, 2, 5, 7},
  {1, 2, 5, 7, 1, 2, 5, 7}, {0, 1, 2, 5, 7, 0, 1, 2},
  {3, 5, 7, 3, 5, 7, 3, 5}, {0, 3, 5, 7, 0, 3, 5, 7},
  {1, 3, 5, 7, 1, 3, 5, 7}, {0, 1, 3, 5, 7, 0, 1, 3},
  {2, 3, 5, 7, 2, 3, 5, 7}, {0, 2, 3, 5, 7, 0, 2, 3},
  {1, 2, 3, 5, 7, 1, 2, 3}, {0, 1, 2, 3, 5, 7, 0, 1},
  {4, 5, 7, 4, 5, 7, 4, 5}, {0, 4, 5, 7, 0, 4, 5, 7},
  {1, 4, 5, 7, 1, 4, 5, 7}, {0, 1, 4, 5, 7, 0, 1, 4},
  {2, 4, 5, 7, 2, 4, 5, 7}, {0, 2, 4, 5, 7, 0, 2, 4},
  {1, 2, 4, 5, 7, 1, 2, 4}, {0, 1, 2, 4, 5, 7, 0, 1},
  {3, 4, 5, 7, 3, 4, 5, 7}, {0, 3, 4, 5, 7, 0, 3, 4},
  {1, 3, 4, 5, 7, 1, 3, 4}, {0, 1, 3, 4, 5, 7, 0, 1},
  {2, 3, 4, 5, 7, 2, 3, 4}, {0, 2, 3, 4, 5, 7, 0, 2},
  {1, 2, 3, 4, 5, 7, 1, 2}, {0, 1, 2, 3, 4, 5, 7, 0},
  {6, 7, 6, 7, 6, 7, 6, 7}, {0, 6, 7, 0, 6, 7, 0, 6},
  {1, 6, 7, 1, 6, 7, 1, 6}, {0, 1, 6, 7, 0, 1, 6, 7},
  {2, 6, 7, 2, 6, 7, 2, 6}, {0, 2, 6, 7, 0, 2, 6, 7},
  {1, 2, 6, 7, 1, 2, 6, 7}, {0, 1, 2, 6, 7, 0, 1, 2},
  {3, 6, 7, 3, 6, 7, 3, 6}, {0, 3, 6, 7, 0, 3, 6, 7},
  {1, 3, 6, 7, 1, 3, 6, 7}, {0, 1, 3, 6, 7, 0, 1, 3},
  {2, 3, 6, 7, 2, 3, 6, 7}, {0, 2, 3, 6, 7, 0, 2, 3},
  {1, 2, 3, 6, 7, 1, 2, 3}, {0, 1, 2, 3, 6, 7, 0, 1},
  {4, 6, 7, 4, 6, 7, 4, 6}, {0, 4, 6, 7, 0, 4, 6, 7},
  {1, 4, 6, 7, 1, 4, 6, 7}, {0, 1, 4, 6, 7, 0, 1, 4},
  {2, 4, 6, 7, 2, 4, 6, 7}, {0, 2, 4, 6, 7, 0, 2, 4},
  {1, 2, 4, 6, 7, 1, 2, 4}, {0, 1, 2, 4, 6, 7, 0, 1},
  {3, 4, 6, 7, 3, 4, 6, 7}, {0, 3, 4, 6, 7, 0, 3, 4},
  {1, 3, 4, 6, 7, 1, 3, 4}, {0, 1, 3, 4, 6, 7, 0, 1},
  {2, 3, 4, 6, 7, 2, 3, 4}, {0, 2, 3, 4, 6, 7, 0, 2},
  {1, 2, 3, 4, 6, 7, 1, 2}, {0, 1, 2, 3, 4, 6, 7, 0},
  {5, 6, 7, 5, 6, 7, 5, 6}, {0, 5, 6, 7, 0, 5, 6, 7},
  {1, 5, 6, 7, 1, 5, 6, 7}, {0, 1, 5, 6, 7, 0, 1, 5},
  {2, 5, 6, 7, 2, 5, 6, 7}, {0, 2, 5, 6, 7, 0, 2, 5},
  {1, 2, 5, 6, 7, 1, 2, 5}, {0, 1, 2, 5, 6, 7, 0, 1},
  {3, 5, 6, 7, 3, 5, 6, 7}, {0, 3, 5, 6, 7, 0, 3, 5},
  {1, 3, 5, 6, 7, 1, 3, 5}, {0, 1, 3, 5, 6, 7, 0, 1},
  {2, 3, 5, 6, 7, 2, 3, 5}, {0, 2, 3, 5, 6, 7, 0, 2},
  {1, 2, 3, 5, 6, 7, 1, 2}, {0, 1, 2, 3, 5, 6, 7, 0},
  {4, 5, 6, 7, 4, 5, 6, 7}, {0, 4, 5, 6, 7, 0, 4, 5},
  {1, 4, 5, 6, 7, 1, 4, 5}, {0, 1, 4, 5, 6, 7, 0, 1},
  {2, 4, 5, 6, 7, 2, 4, 5}, {0, 2, 4, 5, 6, 7, 0, 2},
  {1, 2, 4, 5, 6, 7, 1, 2}, {0, 1, 2, 4, 5, 6, 7, 0},
  {3, 4, 5, 6, 7, 3, 4, 5}, {0, 3, 4, 5, 6, 7, 0, 3},
  {1, 3, 4, 5, 6, 7, 1, 3}, {0, 1, 3, 4, 5, 6, 7, 0},
  {2, 3, 4, 5, 6, 7, 2, 3}, {0, 2, 3, 4, 5, 6, 7, 0},
  {1, 2, 3, 4, 5, 6, 7, 1}, {0, 1, 2, 3, 4, 5, 6, 7},
};

static inline int find_random_set_bit(W32 v, int randsource) {
  return bit_indices_set_8bits[v & 0xff][randsource & 0x7];
}

//
// This function locates the source operands for a uop and prepares to add the
// uop to its cluster's issue queue.
//
// If an operand is already ready at dispatch time, the issue queue associative
// array slot for that operand is marked as unused; otherwise it is marked
// as valid so the operand's ROB index can be matched when broadcast.
//
// returns: 1 iff all operands were ready at dispatch time
//
bool ReorderBufferEntry::find_sources() {
  int operands_still_needed = 0;

  issueq_tag_t uopids[MAX_OPERANDS];
  issueq_tag_t preready[MAX_OPERANDS];

  foreach (operand, MAX_OPERANDS) {
    PhysicalRegister& source_physreg = *operands[operand];
    ReorderBufferEntry& source_rob = *source_physreg.rob;

    if likely (source_physreg.state == PHYSREG_WAITING) {
      uopids[operand] = source_rob.index();
      preready[operand] = 0;
      operands_still_needed++;
    } else {
      // No need to wait for it
      uopids[operand] = 0;
      preready[operand] = 1;
    }

    if likely (source_physreg.nonnull()) {
      per_physregfile_stats_update(stats.ooocore.dispatch.source, source_physreg.rfid, [source_physreg.state]++);
    }
  }

  //
  // Stores are special: we can issue a store even if its rc operand (the value
  // to store) is not yet ready. In this case the store uop just checks for
  // exceptions, establishes an STQ entry and gets replayed as a second phase
  // store (this time around with the rc dependency required)
  //
  if unlikely (isstore(uop.opcode) && !load_store_second_phase) {
    preready[RC] = 1;
  }

  bool ok;
  issueq_operation_on_cluster_with_result(getcore(), cluster, ok, insert(index(), uopids, preready));
  assert(ok);

  return operands_still_needed;
}

int ReorderBufferEntry::select_cluster() {
  if (MAX_CLUSTERS == 1) {
    int cluster_issue_queue_avail_count[MAX_CLUSTERS];
    getcore().sched_get_all_issueq_free_slots(cluster_issue_queue_avail_count);
    return (cluster_issue_queue_avail_count[0] > 0) ? 0 : -1;
  }

  W32 executable_on_cluster = executable_on_cluster_mask;

  int cluster_operand_tally[MAX_CLUSTERS];
  foreach (i, MAX_CLUSTERS) { cluster_operand_tally[i] = 0; }
  foreach (i, MAX_OPERANDS) {
    PhysicalRegister& r = *operands[i];
    if ((&r) && ((r.state == PHYSREG_WAITING) || (r.state == PHYSREG_BYPASS)) && (r.rob->cluster >= 0)) cluster_operand_tally[r.rob->cluster]++;
  }

  assert(executable_on_cluster);

  // If a given cluster's issue queue is full, try another cluster:
  int cluster_issue_queue_avail_count[MAX_CLUSTERS];
  W32 cluster_issue_queue_avail_mask = 0;

  getcore().sched_get_all_issueq_free_slots(cluster_issue_queue_avail_count);

  foreach (i, MAX_CLUSTERS) {
    cluster_issue_queue_avail_mask |= ((cluster_issue_queue_avail_count[i] > 0) << i);
  }

  executable_on_cluster &= cluster_issue_queue_avail_mask;

  OutOfOrderCoreEvent* event = getcore().eventlog.add(EVENT_CLUSTER_OK, this);
  event->select_cluster.allowed_clusters = executable_on_cluster_mask;
  foreach (i, MAX_CLUSTERS) event->select_cluster.iq_avail[i] = cluster_issue_queue_avail_count[i];

  if unlikely (!executable_on_cluster) {
    event->type = EVENT_CLUSTER_NO_CLUSTER;
    return -1;
  }
  
  int n = 0;
  int cluster = find_random_set_bit(executable_on_cluster, sim_cycle);
  
  foreach (i, MAX_CLUSTERS) {
    if ((cluster_operand_tally[i] > n) && bit(executable_on_cluster, i)) {
      n = cluster_operand_tally[i];
      cluster = i;
    }
  }

  stats.ooocore.dispatch.cluster[cluster]++;

  event->cluster = cluster;

  return cluster;
}

//
// Dispatch any uops in the rob_ready_to_dispatch_list by locating
// their source operands and adding entries to the issue queues.
//
int OutOfOrderCore::dispatch() {
  int dispatchcount = 0;
  OutOfOrderCoreEvent* event;
  ReorderBufferEntry* rob;

  foreach_list_mutable(rob_ready_to_dispatch_list, rob, entry, nextentry) {
    if unlikely (dispatchcount >= DISPATCH_WIDTH) break;

    // All operands start out as valid, then get put on wait queues if they are not actually ready.

    rob->cluster = rob->select_cluster();

    //
    // An available cluster could not be found. This only happens 
    // when all applicable cluster issue queues are full. Since
    // we are still processing instructions in order at this point,
    // abort dispatching for this cycle.
    //
    if unlikely (rob->cluster < 0) {
      event = eventlog.add(EVENT_DISPATCH_NO_CLUSTER, rob);
      foreach (i, MAX_OPERANDS) rob->operands[i]->fill_operand_info(event->dispatch.opinfo[i]);
      continue; // try the next uop to avoid deadlock on re-dispatches
    }

    int operands_still_needed = rob->find_sources();

    if likely (operands_still_needed) {
      rob->changestate(rob_dispatched_list[rob->cluster]);
    } else {
      rob->changestate(rob->get_ready_to_issue_list());
    }

    event = eventlog.add(EVENT_DISPATCH_OK, rob);
    foreach (i, MAX_OPERANDS) rob->operands[i]->fill_operand_info(event->dispatch.opinfo[i]);

    dispatchcount++;
  }

  stats.ooocore.dispatch.width[dispatchcount]++;

  if likely (dispatchcount) {
    dispatch_deadlock_countdown = DISPATCH_DEADLOCK_COUNTDOWN_CYCLES;
  } else if unlikely (!rob_ready_to_dispatch_list.empty()) {
    dispatch_deadlock_countdown--;
    if (!dispatch_deadlock_countdown) {
      if (logable(6)) logfile << "Dispatch deadlock at cycle ", sim_cycle, ", commits ", total_user_insns_committed, ": recovering...", endl;
      redispatch_deadlock_recovery();
      dispatch_deadlock_countdown = DISPATCH_DEADLOCK_COUNTDOWN_CYCLES;
      return -1;
    }
  }

  return dispatchcount;
}

//
// Issue Stage
// (see oooexec.cpp for issue stages)
//

//
// Complete Stage
//
// Process any ROB entries that just finished producing a result, forwarding
// data within the same cluster directly to the waiting instructions.
//
// Note that we use the target physical register as a temporary repository
// for the data. In a modern hardware implementation, this data would exist
// only "on the wire" such that back to back ALU operations within a cluster
// can occur using local forwarding.
//
int OutOfOrderCore::complete(int cluster) {
  int completecount = 0;
  ReorderBufferEntry* rob;

  // 
  // Check the list of issued ROBs. If a given ROB is complete (i.e., is ready
  // for writeback and forwarding), move it to rob_completed_list.
  //
  foreach_list_mutable(rob_issued_list[cluster], rob, entry, nextentry) {
    rob->cycles_left--;

    if unlikely (rob->cycles_left <= 0) {
      eventlog.add(EVENT_COMPLETE, rob);
      rob->changestate(rob_completed_list[cluster]);
      rob->physreg->complete();
      rob->forward_cycle = 0;
      rob->fu = 0;
      completecount++;
    }
  }

  return 0;
}

//
// Transfer Stage
//
// Process ROBs in flight between completion and global forwarding/writeback.
//
int OutOfOrderCore::transfer(int cluster) {
  int wakeupcount = 0;
  ReorderBufferEntry* rob;

  foreach_list_mutable(rob_completed_list[cluster], rob, entry, nextentry) {
    rob->forward();
    rob->forward_cycle++;
    if unlikely (rob->forward_cycle > MAX_FORWARDING_LATENCY) {
      rob->forward_cycle = MAX_FORWARDING_LATENCY;
      rob->changestate(rob_ready_to_writeback_list[rob->cluster]);
    }
  }

  return 0;
}

//
// Writeback Stage
//
// Writeback at most WRITEBACK_WIDTH ROBs on rob_ready_to_writeback_list.
//
int OutOfOrderCore::writeback(int cluster) {
  int writecount = 0;
  int wakeupcount = 0;
  ReorderBufferEntry* rob;

  foreach_list_mutable(rob_ready_to_writeback_list[cluster], rob, entry, nextentry) {
    if unlikely (writecount >= WRITEBACK_WIDTH)
                  break;

    //
    // Gather statistics
    //
    bool transient = 0;

#ifdef ENABLE_TRANSIENT_VALUE_TRACKING
    if likely (!isclass(rob->uop.opcode, OPCLASS_STORE|OPCLASS_BRANCH)) {
      transient =
        (rob->dest_renamed_before_writeback) &&
        (rob->consumer_count <= 1) &&
        (rob->physreg->all_consumers_sourced_from_bypass) &&
        (rob->no_branches_between_renamings);

      writeback_transient += transient;
      writeback_persistent += (!transient);
    }

    rob->transient = transient;
#endif

    if (!isclass(rob->uop.opcode, OPCLASS_STORE|OPCLASS_BRANCH)) {
      OutOfOrderCoreEvent* event = eventlog.add(EVENT_WRITEBACK, rob);
      event->writeback.data = rob->physreg->data;
      event->writeback.flags = rob->physreg->flags;
      event->writeback.consumer_count = rob->consumer_count;
      event->writeback.transient = transient;
      event->writeback.all_consumers_sourced_from_bypass = rob->physreg->all_consumers_sourced_from_bypass;
      event->writeback.no_branches_between_renamings = rob->no_branches_between_renamings;
      event->writeback.dest_renamed_before_writeback = rob->dest_renamed_before_writeback;
    }

    //
    // Catch corner case where dependent uop was scheduled
    // while producer waited in ready_to_writeback state:
    //
    wakeupcount += rob->forward();

    writecount++;

    //
    // For simulation purposes, final value is already in rob->physreg,
    // so we don't need to actually write anything back here.
    //

    rob->physreg->writeback();
    rob->cycles_left = -1;

    rob->changestate(rob_ready_to_commit_queue);

    stats.ooocore.writeback.total_writebacks++;
  }

  per_cluster_stats_update(stats.ooocore.writeback.width, cluster, [writecount]++);

  return writecount;
}

//
// Commit Stage
//
// Commit at most COMMIT_WIDTH ready to commit instructions from ROB queue,
// and commits any stores by writing to the L1 cache with write through.
//
// Returns:
//    -1 if we are supposed to abort the simulation
//  >= 0 for the number of instructions actually committed
//
// Physical Register Recycling Complications
//
// Consider the following scenario:
//
// - uop U3 is renamed and found to depend on physical register R from an earlier uop U1.
// - U1 commits to architectural register A and moves R to the arch state
// - U2, which updates the same architectural register A as U1, also commits. Since the
//   mapping of A is being logically overwritten by U2, U1's physical register R is freed.
// - U3 finally issues, but finds that operand physical register R for U1 no longer exists.
//
// Additionally, in x86 processors the flags attached to a given physical register may 
// be referenced by three additional rename table entries (for ZAPS, CF, OF) so simply
// freeing the old physical register mapping when the RRT is updated doesn't work.
//
// For these reasons, we need to prevent U2's register from being freed if it is still
// referenced by anything still in the pipeline; the normal reorder buffer mechanism
// cannot always handle this situation in a very long pipeline.
//
// The solution is to give each physical register a reference counter. As each uop operand
// is renamed, the counter for the corresponding physical register is incremented. As each
// uop commits, the counter for each of its operands is decremented, but the counter for
// the target physical register itself is incremented before that register is moved to
// the arch state during commitment (since the committed state now owns that register).
//
// As we update the committed RRT during the commit stage, the old register R mapped
// to the destination architectural register A of the uop being committed is examined.
// The register R is only moved to the free state iff its reference counter is zero.
// Otherwise, it is moved to the pendingfree state. The hardware examines all counters
// every cycle and moves physical registers to the free state only when their counters
// become zero and they are in the pendingfree state.
//
// An additional complication arises for x86 since we maintain three separate rename 
// table entries for the ZAPS, CF, OF flags in addition to the register rename table
// entry. Therefore, each speculative RRT and commit RRT entry adds to the refcount.
//
// Hardware Implementation
//
// The hardware implementation of this scheme is straightforward and low complexity.
// The counters can have a very small number of bits since it is very unlikely a given
// physical register would be referenced by all 100+ uops in the ROB; 3 bits should be
// enough to handle the typical maximum of < 8 uops sharing a given operand. Counter
// overflows can simply stall renaming or flush the pipeline since they are so rare.
//
// The counter table can be updated in bulk each cycle by adding/subtracting the
// appropriate sum or just adding zero if the corresponding register wasn't used.
// Since there are several stages between renaming and commit, the same counter is never
// both incremented and decremented in the same cycle, so race conditions are not an 
// issue. 
//
// In real processors, the Pentium 4 uses a scheme similar to this one but uses bit
// vectors instead. For smaller physical register files, this may be a better solution.
// Each physical register has a bit vector with one bit per ROB entry. If a given
// physical register P is still used by ROB entry E in the pipeline, P's bit vector
// bit R is set. Register P cannot be freed until all bits in its vector are zero.
//
int OutOfOrderCore::commit() {
  foreach (rfid, PHYS_REG_FILE_COUNT) {
    StateList& statelist = physregfiles[rfid].states[PHYSREG_PENDINGFREE];
    PhysicalRegister* physreg;
    foreach_list_mutable(statelist, physreg, entry, nextentry) {
      if unlikely (!physreg->referenced()) {
        eventlog.add(EVENT_RECLAIM_PHYSREG)->physreg = physreg->index();
        physreg->free();
        stats.ooocore.commit.free_regs_recycled++;
      }
    }
  }

  //
  // Commit ROB entries *in program order*, stopping at the first ROB that is 
  // not ready to commit or has an exception.
  //
  int commitcount = 0;

  int rc = COMMIT_RESULT_OK;

  foreach_forward(ROB, i) {
    ReorderBufferEntry& rob = ROB[i];

    if unlikely (commitcount >= COMMIT_WIDTH) break;
    rc = rob.commit();
    if likely (rc == COMMIT_RESULT_OK) {
      commitcount++;
      last_commit_at_cycle = sim_cycle;
      if (total_user_insns_committed >= config.stop_at_user_insns) {
        rc = COMMIT_RESULT_STOP;
        break;
      }
    } else {
      break;
    }
  }

  stats.ooocore.commit.width[commitcount]++;

  return rc;
}

int ReorderBufferEntry::commit() {
  OutOfOrderCore& core = getcore();
  Context& ctx = core.ctx;

  bool all_ready_to_commit = true;
  bool macro_op_has_exceptions = false;

  //
  // Create an event log entry
  //
  OutOfOrderCoreEvent* event;

  //
  // Each x86 instruction may be composed of multiple uops; none of the uops
  // may commit until ALL uops are ready to commit (either correctly or
  // if one or more uops have exceptions). 
  //
  // This is accomplished by checking if the uop at the head of the ROB (next
  // to commit) has its SOM (start of macro-op) bit set. If so, the ROB is 
  // scanned forwards from the SOM uop to the EOM (end of macro-op) uop. If
  // all uops in this range are ready to commit and are exception-free, the
  // SOM uop allowed to commit. 
  //
  // Any exceptions in the macro-op uop range immediately signals an exception
  // to the user code, and no part of the uop is committed. In any case,
  // asynchronous interrupts are only taken after committing or excepting the
  // EOM uop in a macro-op.
  //
  foreach_forward_from(core.ROB, this, j) {
    ReorderBufferEntry& subrob = core.ROB[j];

    if unlikely (!subrob.ready_to_commit()) {
      all_ready_to_commit = false;
      break;
    }

#ifdef PTLSIM_HYPERVISOR
    if unlikely ((subrob.uop.is_sse|subrob.uop.is_x87) && (core.ctx.cr0.ts | (subrob.uop.is_x87 & core.ctx.cr0.em))) {
      subrob.physreg->data = EXCEPTION_FloatingPointNotAvailable;
      subrob.physreg->flags = FLAG_INV;
      if unlikely (subrob.lsq) subrob.lsq->invalid = 1;
    }
#endif

    if unlikely (subrob.physreg->flags & FLAG_INV) {
      //
      // The exception is definitely going to happen, since the
      // excepting instruction is at the head of the ROB. However,
      // we don't know which uop within the instruction actually
      // had the problem, e.g. if it's a load-alu-store insn, the
      // load is OK but the store has PageFaultOnWrite. We take
      // the first exception in uop order.
      //
      core.ctx.exception = LO32(subrob.physreg->data);
      core.ctx.error_code = HI32(subrob.physreg->data);
#ifdef PTLSIM_HYPERVISOR
      // Capture the faulting virtual address for page faults
      if ((core.ctx.exception == EXCEPTION_PageFaultOnRead) |
          (core.ctx.exception == EXCEPTION_PageFaultOnWrite)) {
        core.ctx.cr2 = subrob.origvirt;
      }
#endif

      core.eventlog.add_commit(EVENT_COMMIT_EXCEPTION_DETECTED, &subrob);

      macro_op_has_exceptions = true;
      break;
    }
    
    if likely (subrob.uop.eom) break;
  }

  if unlikely (!all_ready_to_commit) {
    stats.ooocore.commit.result.none++;
    return COMMIT_RESULT_NONE;
  }

  assert(ready_to_commit());

  PhysicalRegister* oldphysreg = core.commitrrt[uop.rd];

  //
  // Update architectural state
  //

  bool ld = isload(uop.opcode);
  bool st = isstore(uop.opcode);
  bool br = isbranch(uop.opcode);

  stats.ooocore.commit.opclass[opclassof(uop.opcode)]++;

  if unlikely (macro_op_has_exceptions) {
    event = core.eventlog.add_commit(EVENT_COMMIT_EXCEPTION_ACKNOWLEDGED, this);

    // See notes in handle_exception():
    if likely (isclass(uop.opcode, OPCLASS_CHECK) & (ctx.exception == EXCEPTION_SkipBlock)) {
      core.chk_recovery_rip = ctx.commitarf[REG_rip] + uop.bytes;
      event->type = EVENT_COMMIT_SKIPBLOCK;
      stats.ooocore.commit.result.skipblock++;
    } else {
      stats.ooocore.commit.result.exception++;
    }

    return COMMIT_RESULT_EXCEPTION;
  }

  //
  // Check for self modifying code (SMC) by checking if any previous
  // instruction has dirtied the page(s) on which the current instruction
  // resides. The SMC check is done first since it's perfectly legal for a
  // store to overwrite its own instruction bytes, but this update only
  // becomes visible after the store has committed.
  //
  if unlikely (smc_isdirty(uop.rip.mfnlo) | (smc_isdirty(uop.rip.mfnhi))) {
    core.eventlog.add_commit(EVENT_COMMIT_SMC_DETECTED, this);

    //
    // Invalidate the pages only after the pipeline is flushed: we may still
    // hold refs to the affected basic blocks in the pipeline. Queue the
    // updates for later.
    //
    core.smc_invalidate_pending = 1;
    core.smc_invalidate_rvp = uop.rip;

    stats.ooocore.commit.result.smc++;
    return COMMIT_RESULT_SMC;
  }
  
  if (st) assert(lsq->addrvalid && lsq->datavalid);

  W64 result = physreg->data;

  if likely (uop.som) assert(ctx.commitarf[REG_rip] == uop.rip); 

  //
  // The commit of all uops in the x86 macro-op is guaranteed to happen after this point
  //
  event = core.eventlog.add_commit(EVENT_COMMIT_OK, this);

  if likely (archdest_can_commit[uop.rd]) {
    core.commitrrt[uop.rd]->uncommitref(uop.rd);
    core.commitrrt[uop.rd] = physreg;
    core.commitrrt[uop.rd]->addcommitref(uop.rd);

    if likely (uop.rd < ARCHREG_COUNT) ctx.commitarf[uop.rd] = physreg->data;

    physreg->rob = null;
  }

  if likely (uop.eom) {
    if unlikely (uop.rd == REG_rip) {
      assert(isbranch(uop.opcode));
      ctx.commitarf[REG_rip] = physreg->data;
    } else {
      assert(!isbranch(uop.opcode));
      ctx.commitarf[REG_rip] += uop.bytes;
    }
    event->commit.target_rip = ctx.commitarf[REG_rip];
  }

  if unlikely (!uop.nouserflags) {
    W64 flagmask = setflags_to_x86_flags[uop.setflags];
    ctx.commitarf[REG_flags] = (ctx.commitarf[REG_flags] & ~flagmask) | (physreg->flags & flagmask);

    stats.ooocore.commit.setflags.no += (uop.setflags == 0);
    stats.ooocore.commit.setflags.yes += (uop.setflags != 0);

    event->commit.state.reg.rdflags = ctx.commitarf[REG_flags];

    if likely (uop.setflags & SETFLAG_ZF) {
      core.commitrrt[REG_zf]->uncommitref(REG_zf);
      core.commitrrt[REG_zf] = physreg;
      core.commitrrt[REG_zf]->addcommitref(REG_zf);
    }
    if likely (uop.setflags & SETFLAG_CF) {
      core.commitrrt[REG_cf]->uncommitref(REG_cf);
      core.commitrrt[REG_cf] = physreg;
      core.commitrrt[REG_cf]->addcommitref(REG_cf);
    }
    if likely (uop.setflags & SETFLAG_OF) {
      core.commitrrt[REG_of]->uncommitref(REG_of);
      core.commitrrt[REG_of] = physreg;
      core.commitrrt[REG_of]->addcommitref(REG_of);
    }
  }

  if unlikely (st) {
    Waddr mfn = (lsq->physaddr << 3) >> 12;
    smc_setdirty(mfn);
    if (lsq->bytemask) assert(core.caches.commitstore(*lsq) == 0);
  }

  if unlikely (pteupdate) {
    ctx.update_pte_acc_dirty(origvirt, pteupdate);
  }

  //
  // Free physical registers, load/store queue entries, etc.
  //
  if unlikely (ld|st) {
    core.loads_in_flight -= (lsq->store == 0);
    core.stores_in_flight -= (lsq->store == 1);
    lsq->reset();
    core.LSQ.commit(lsq);
  }

  assert(archdest_can_commit[uop.rd]);
  assert(oldphysreg->state == PHYSREG_ARCH);

  event->commit.oldphysreg = -1;
  if likely (oldphysreg->nonnull()) {
    event->commit.oldphysreg = oldphysreg->index();
    event->commit.oldphysreg_refcount = oldphysreg->refcount;

    if unlikely (oldphysreg->referenced()) {
      oldphysreg->changestate(PHYSREG_PENDINGFREE); 
      stats.ooocore.commit.freereg.pending++;
    } else  {
      oldphysreg->free();
      stats.ooocore.commit.freereg.free++;
    }
  }

  if likely (!(br|st)) {
    int k = clipto((int)consumer_count, 0, lengthof(stats.ooocore.frontend.consumer_count));
    stats.ooocore.frontend.consumer_count[k]++;
  }

  physreg->changestate(PHYSREG_ARCH);

  //
  // Unlock operand physregs since we no longer need to worry about speculation recovery
  // Technically this can be done after the issue queue entry is released, but we do it
  // here for simplicity.
  //
  foreach (i, MAX_OPERANDS) {
    operands[i]->unref(*this);
  }

  //
  // Update branch prediction
  //
  if unlikely (isclass(uop.opcode, OPCLASS_BRANCH)) {
    assert(uop.eom);
    //
    // NOTE: Technically the "branch address" refers to the rip of the *next* 
    // x86 instruction after the branch; we use this consistently since x86
    // instructions vary in length and we cannot easily calculate the next
    // instruction in sequence from within the branch predictor logic.
    //
    W64 end_of_branch_x86_insn = uop.rip + uop.bytes;
    bool taken = (ctx.commitarf[REG_rip] != end_of_branch_x86_insn);
    bool predtaken = (uop.riptaken != end_of_branch_x86_insn);

    event->commit.taken = taken;
    event->commit.predtaken = predtaken;

    core.branchpred.update(uop.predinfo, end_of_branch_x86_insn, ctx.commitarf[REG_rip]);
    stats.ooocore.branchpred.updates++;
  }

  // Release our lock on the cached basic block containing this uop
  uop.bb->release();

  if likely (uop.eom) {
    total_user_insns_committed++;
    stats.ooocore.commit.total_user_insns_committed++;
    stats.summary.insns++;
  }

  total_uops_committed++;
  stats.ooocore.commit.total_uops_committed++;

  changestate(core.rob_free_list);
  reset();
  core.ROB.commit(*this);

  if unlikely (isclass(uop.opcode, OPCLASS_BARRIER)) {
    core.eventlog.add(EVENT_COMMIT_ASSIST, RIPVirtPhys(ctx.commitarf[REG_rip]));
    stats.ooocore.commit.result.barrier++;
    return COMMIT_RESULT_BARRIER;
  }

  stats.ooocore.commit.result.ok++;
  return COMMIT_RESULT_OK;
}

namespace OutOfOrderModel {
  const byte archdest_is_visible[TRANSREG_COUNT] = {
    // Integer registers
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    // SSE registers, low 64 bits
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    // SSE registers, high 64 bits
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    // x87 FP / MMX / special
    1, 1, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    // The following are ONLY used during the translation and renaming process:
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
  };

  const byte archdest_can_commit[TRANSREG_COUNT] = {
    // Integer registers
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    // SSE registers, low 64 bits
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    // SSE registers, high 64 bits
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    // x87 FP / MMX / special
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 0,
    // The following are ONLY used during the translation and renaming process:
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
  };
};
