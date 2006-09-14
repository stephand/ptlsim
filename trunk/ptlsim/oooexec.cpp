//
// PTLsim: Cycle Accurate x86-64 Simulator
// Out-of-Order Core Simulator
// Execution Pipeline Stages: Scheduling, Execution, Broadcast
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

//
// Issue Queue
//
template <int size, int operandcount>
void IssueQueue<size, operandcount>::reset(int coreid) {
  this->coreid = coreid;
  count = 0;
  valid = 0;
  issued = 0;
  allready = 0;
  foreach (i, operandcount) {
    tags[i].reset();
  }
  uopids.reset();
}

template <int size, int operandcount>
void IssueQueue<size, operandcount>::clock() {
  allready = (valid & (~issued));
  foreach (operand, operandcount) {
    allready &= ~tags[operand].valid;
  }
}

template <int size, int operandcount>
bool IssueQueue<size, operandcount>::insert(tag_t uopid, const tag_t* operands, const tag_t* preready) {
  if unlikely (count == size)
                return false;
  
  int slot = count++;
  assert(!bit(valid, slot));
  
  uopids.insertslot(slot, uopid);
  
  valid[slot] = 1;
  issued[slot] = 0;
  
  foreach (operand, operandcount) {
    if likely (preready[operand])
      tags[operand].invalidateslot(slot);
    else tags[operand].insertslot(slot, operands[operand]);
  }
  
  return true;
}

template <int size, int operandcount>
void IssueQueue<size, operandcount>::tally_broadcast_matches(IssueQueue<size, operandcount>::tag_t sourceid, const bitvec<size>& mask, int operand) const {
  if likely (!logable(5)) return;

  OutOfOrderCore& core = getcore();
  const ReorderBufferEntry* source = &core.ROB[sourceid];

  bitvec<size> temp = mask;

  while (*temp) {
    int slot = temp.lsb();
    int robid = uopof(slot);
    assert(inrange(robid, 0, ROB_SIZE-1));
    const ReorderBufferEntry* target = &core.ROB[robid];

    OutOfOrderCoreEvent* event = core.eventlog.add(EVENT_FORWARD, source);
    event->forwarding.operand = operand;
    event->forwarding.forward_cycle = source->forward_cycle;
    event->forwarding.target_uuid = target->uop.uuid;
    event->forwarding.target_rob = target->index();
    event->forwarding.target_physreg = target->physreg->index();
    event->forwarding.target_rfid = target->physreg->rfid;
    event->forwarding.target_cluster = target->cluster;
    bool target_st = isstore(target->uop.opcode);
    event->forwarding.target_st = target_st;
    if (target_st) event->forwarding.target_lsq = target->lsq->index();
    event->forwarding.target_operands_ready = 0;
    foreach (i, MAX_OPERANDS) event->forwarding.target_operands_ready |= ((target->operands[i]->ready()) << i);
    event->forwarding.target_all_operands_ready = target->ready_to_issue();

    temp[slot] = 0;
  }
}

template <int size, int operandcount>
bool IssueQueue<size, operandcount>::broadcast(tag_t uopid) {
  vec_t tagvec = assoc_t::prep(uopid);
  
  if (logable(6)) {
    foreach (operand, operandcount) {
      bitvec<size> mask = tags[operand].invalidate(tagvec);
      tally_broadcast_matches(uopid, mask, operand);
    }
  } else {
    foreach (operand, operandcount) tags[operand].invalidate(tagvec);
  }
  return true;
}

//
// Select one ready slot and move it to the issued state.
// This function returns the slot id. The returned slot
// id becomes invalid after the next call to remove()
// before the next uop can be processed in any way.
//
template <int size, int operandcount>
int IssueQueue<size, operandcount>::issue() {
  if (!allready) return -1;
  int slot = allready.lsb();
  issued[slot] = 1;
  return slot;
}

//
// Replay a uop that has already issued once.
// The caller may add or reset dependencies here as needed.
//
template <int size, int operandcount>
bool IssueQueue<size, operandcount>::replay(int slot, const tag_t* operands, const tag_t* preready) {
  assert(valid[slot]);
  assert(issued[slot]);
  
  issued[slot] = 0;
  
  foreach (operand, operandcount) {
    if (preready[operand])
      tags[operand].invalidateslot(slot);
    else tags[operand].insertslot(slot, operands[operand]);
  }
  
  return true;
}

// NOTE: This is a fairly expensive operation:
template <int size, int operandcount>
bool IssueQueue<size, operandcount>::remove(int slot) {
  uopids.collapse(slot);

  foreach (i, operandcount) {
    tags[i].collapse(slot);
  }
  
  valid = valid.remove(slot, 1);
  issued = issued.remove(slot, 1);
  allready = allready.remove(slot, 1);
  
  count--;
  assert(count >= 0);
  return true;
}

template <int size, int operandcount>
ostream& IssueQueue<size, operandcount>::print(ostream& os) const {
  os << "IssueQueue: count = ", count, ":", endl;
  foreach (i, size) {
    os << "  uop ";
    uopids.printid(os, i);
    os << ": ",
      ((valid[i]) ? 'V' : '-'), ' ',
      ((issued[i]) ? 'I' : '-'), ' ',
      ((allready[i]) ? 'R' : '-'), ' ';
    foreach (j, operandcount) {
      if (j) os << ' ';
      tags[j].printid(os, i);
    }
    os << endl;
  }
  return os;
}

// Instantiate all methods in the specific IssueQueue sizes we're using:
declare_issueq_templates;

//
// Issue a single ROB. 
//
// Returns:
//  +1 if issue was successful
//   0 if no functional unit was available
//  -1 if there was an exception and we should stop issuing this cycle
//
int ReorderBufferEntry::issue() {
  OutOfOrderCore& core = getcore();
  OutOfOrderCoreEvent* event;

  W32 executable_on_fu = opinfo[uop.opcode].fu & clusters[cluster].fu_mask & core.fu_avail;

  // Are any FUs available in this cycle?
  if unlikely (!executable_on_fu) {
    event = core.eventlog.add(EVENT_ISSUE_NO_FU, this);
    event->issue.fu_avail = core.fu_avail;
    stats.ooocore.issue.result.no_fu++;
    //
    // When this (very rarely) happens, stop issuing uops to this cluster
    // and try again with the problem uop on the next cycle. In practice
    // this scenario rarely happens.
    //
    issueq_operation_on_cluster(core, cluster, replay(iqslot));
    return ISSUE_NEEDS_REPLAY;
  }

  PhysicalRegister& ra = *operands[RA];
  PhysicalRegister& rb = *operands[RB];
  PhysicalRegister& rc = *operands[RC];

  //
  // Check if any other resources are missing that we didn't
  // know about earlier, and replay like we did above if
  // needed. This is our last chance to do so.
  //

  stats.summary.uops++;

  fu = lsbindex(executable_on_fu);
  clearbit(core.fu_avail, fu);
  core.robs_on_fu[fu] = this;
  cycles_left = opinfo[uop.opcode].latency;

  changestate(core.rob_issued_list[cluster]);

  IssueState state;
  state.reg.rdflags = 0;

  W64 radata = ra.data;
  W64 rbdata = (uop.rb == REG_imm) ? uop.rbimm : rb.data;
  W64 rcdata = (uop.rc == REG_imm) ? uop.rcimm : rc.data;

  bool ld = isload(uop.opcode);
  bool st = isstore(uop.opcode);
  bool br = isbranch(uop.opcode);

  assert(operands[RA]->ready());
  if likely (uop.rb != REG_imm) assert(rb.ready());
  if likely ((!st || (st && load_store_second_phase)) && (uop.rc != REG_imm)) assert(rc.ready());
  if likely (!st) assert(operands[RS]->ready());

  if likely (ra.nonnull()) {
    ra.get_state_list().issue_source_counter++;
    ra.all_consumers_sourced_from_bypass &= (ra.state == PHYSREG_BYPASS);
  }

  if likely ((!uop.rbimm) & (rb.nonnull())) { 
    rb.get_state_list().issue_source_counter++;
    rb.all_consumers_sourced_from_bypass &= (rb.state == PHYSREG_BYPASS);
  }

  if unlikely ((!uop.rcimm) & (rc.nonnull())) {
    rc.get_state_list().issue_source_counter++;
    rc.all_consumers_sourced_from_bypass &= (rc.state == PHYSREG_BYPASS);
  }

  bool propagated_exception = 0;
  if unlikely ((ra.flags | rb.flags | rc.flags) & FLAG_INV) {
    //
    // Invalid data propagated through operands: mark output as
    // invalid and don't even execute the uop at all.
    //
    state.st.invalid = 1;
    state.reg.rdflags = FLAG_INV;
    state.reg.rddata = EXCEPTION_Propagate;
    propagated_exception = 1;
  } else {
    stats.ooocore.issue.opclass[opclassof(uop.opcode)]++;

    if unlikely (ld|st) {
      int completed = (ld) ? issueload(*lsq, origvirt, radata, rbdata, rcdata, pteupdate) : issuestore(*lsq, origvirt, radata, rbdata, rcdata, operands[2]->ready(), pteupdate);
      if unlikely (completed == ISSUE_MISSPECULATED) {
        stats.ooocore.issue.result.misspeculated++;
        return -1;
      }
      if unlikely (completed == ISSUE_NEEDS_REFETCH) {
        stats.ooocore.issue.result.refetch++;
        return -1;
      }
      state.reg.rddata = lsq->data;
      state.reg.rdflags = (lsq->invalid << log2(FLAG_INV)) | ((!lsq->datavalid) << log2(FLAG_WAIT));
      if unlikely (completed == ISSUE_NEEDS_REPLAY) {
        stats.ooocore.issue.result.replay++;
        return 0;
      }
    } else {
      if unlikely (br) {
        state.brreg.riptaken = uop.riptaken;
        state.brreg.ripseq = uop.ripseq;
      }
      uop.synthop(state, radata, rbdata, rcdata, ra.flags, rb.flags, rc.flags); 
    }
  }

  physreg->flags = state.reg.rdflags;
  physreg->data = state.reg.rddata;

  if unlikely (!physreg->valid()) {
    //
    // If the uop caused an exception, force it directly to the commit
    // state and not through writeback (this keeps dependencies waiting until 
    // they can be properly annulled by the speculation logic.) The commit 
    // stage will detect the exception and take appropriate action.
    //
    // If the exceptional uop was speculatively executed beyond a
    // branch, it will never reach commit anyway since the branch would
    // have to commit before the exception was ever seen.
    //
    cycles_left = 0;
    changestate(core.rob_ready_to_commit_queue);
    //
    // NOTE: The frontend should not necessarily be stalled on exceptions
    // when extensive speculation is in use, since re-dispatch can be used
    // without refetching to resolve these situations.
    //
    // stall_frontend = true;
  }

  bool mispredicted = (physreg->data != uop.riptaken);

  if unlikely (propagated_exception | (!(ld|st))) {
    event = core.eventlog.add(EVENT_ISSUE_OK, this);
    event->issue.state = state;
    event->issue.cycles_left = cycles_left;
    event->issue.operand_data[0] = radata;
    event->issue.operand_data[1] = rbdata;
    event->issue.operand_data[2] = rcdata;
    event->issue.operand_flags[0] = ra.flags;
    event->issue.operand_flags[1] = rb.flags;
    event->issue.operand_flags[2] = rc.flags;
    event->issue.mispredicted = br & mispredicted;
    event->issue.predrip = uop.riptaken;
  }

  //
  // Release the issue queue entry, since we are beyond the point of no return:
  // the uop cannot possibly be replayed at this point, but may still be annulled
  // or re-dispatched in case of speculation failures.
  //
  release();

  if likely (physreg->valid()) {
    if unlikely (br) {
      int bptype = uop.predinfo.bptype;

      bool cond = bit(bptype, log2(BRANCH_HINT_COND));
      bool indir = bit(bptype, log2(BRANCH_HINT_INDIRECT));
      bool ret = bit(bptype, log2(BRANCH_HINT_RET));
        
      if unlikely (mispredicted) {
        stats.ooocore.branchpred.cond[MISPRED] += cond;
        stats.ooocore.branchpred.indir[MISPRED] += (indir & !ret);
        stats.ooocore.branchpred.ret[MISPRED] += ret;
        stats.ooocore.branchpred.summary[MISPRED]++;

        W64 realrip = physreg->data;

        //
        // Correct the branch directions and cond code field.
        // This is required since the branch may again be
        // re-dispatched if we mis-identified a mispredict
        // due to very deep speculation.
        //
        // Basically the riptaken field must always point
        // to the correct next instruction in the ROB after
        // the branch.
        //
        if likely (isclass(uop.opcode, OPCLASS_COND_BRANCH)) {
          assert(realrip == uop.ripseq);
          uop.cond = invert_cond(uop.cond);
          
          //
          // We need to be careful here: we already looked up the synthop for this
          // uop according to the old condition, so redo that here so we call the
          // correct code for the swapped condition.
          //
          uop.synthop = get_synthcode_for_cond_branch(uop.opcode, uop.cond, uop.size, 0);
          swap(uop.riptaken, uop.ripseq);
        } else if unlikely (isclass(uop.opcode, OPCLASS_INDIR_BRANCH)) {
          uop.riptaken = realrip;
          uop.ripseq = realrip;
        } else if unlikely (isclass(uop.opcode, OPCLASS_UNCOND_BRANCH)) { // unconditional branches need no special handling
          assert(realrip == uop.riptaken);
        }

        //
        // Early misprediction handling. Annul everything after the
        // branch and restart fetching in the correct direction
        //
        core.annul_fetchq();
        annul_after();

        //
        // The fetch queue is reset and fetching is redirected to the
        // correct branch direction.
        //
        // Note that we do NOT just reissue the branch - this would be
        // pointless as we already know the correct direction since
        // it has already been issued once. Just let it writeback and
        // commit like it was predicted perfectly in the first place.
        //
        core.reset_fetch_unit(realrip);
        stats.ooocore.issue.result.branch_mispredict++;

        return -1;
      } else {
        stats.ooocore.branchpred.cond[CORRECT] += cond;
        stats.ooocore.branchpred.indir[CORRECT] += (indir & !ret);
        stats.ooocore.branchpred.ret[CORRECT] += ret;
        stats.ooocore.branchpred.summary[CORRECT]++;
        stats.ooocore.issue.result.complete++;
      }
    } else {
      stats.ooocore.issue.result.complete++;
    }
  } else {
    stats.ooocore.issue.result.exception++;
  }

  return 1;
}

//
// Address generation common to both loads and stores
//
void* ReorderBufferEntry::addrgen(LoadStoreQueueEntry& state, Waddr& origaddr, W64 ra, W64 rb, W64 rc, PTEUpdate& pteupdate, Waddr& addr, int& exception, PageFaultErrorCode& pfec, bool& annul) {
  Context& ctx = getcore().ctx;
  bool st = isstore(uop.opcode);

  int sizeshift = uop.size;
  int aligntype = uop.cond;
  bool internal = uop.internal;
  bool signext = (uop.opcode == OP_ldx);

  addr = (st) ? (ra + rb) : ((aligntype == LDST_ALIGN_NORMAL) ? (ra + rb) : ra);
  //
  // x86-64 requires virtual addresses to be canonical: if bit 47 is set, 
  // all upper 16 bits must be set. If this is not true, we need to signal
  // a general protection fault.
  //
  addr = (W64)signext64(addr, 48);
  addr &= ctx.virt_addr_mask;
  origaddr = addr;
  annul = 0;

  switch (aligntype) {
  case LDST_ALIGN_NORMAL:
    break;
  case LDST_ALIGN_LO:
    addr = floor(addr, 8); break;
  case LDST_ALIGN_HI:
    //
    // Is the high load ever even used? If not, don't check for exceptions;
    // otherwise we may erroneously flag page boundary conditions as invalid
    //
    addr = floor(addr, 8);
    annul = (floor(origaddr + ((1<<sizeshift)-1), 8) == addr);
    addr += 8; 
    break;
  }

  state.physaddr = addr >> 3;
  state.invalid = 0;
  //
  // Notice that datavalid is not set until both the rc operand to
  // store is ready AND any inherited SFR data is ready to merge.
  //
  state.addrvalid = 1;
  state.datavalid = 0;

  //
  // Special case: if no part of the actual user load/store falls inside
  // of the high 64 bits, do not perform the access and do not signal
  // any exceptions if that page was invalid.
  //
  // However, we must be extremely careful if we're inheriting an SFR
  // from an earlier store: the earlier store may have updated some
  // bytes in the high 64-bit chunk even though we're not updating
  // any bytes. In this case we still must do the write since it
  // could very well be the final commit to that address. In any
  // case, the SFR mismatch and LSAT must still be checked.
  //
  // The store commit code checks if the bytemask is zero and does
  // not attempt the actual store if so. This will always be correct
  // for high stores as described in this scenario.
  //

  exception = 0;

  // For debugging use only:
  // if (logable(6)) logfile << intstring(uop.uuid, 20), " adrgen", " rip ", (void*)(Waddr)uop.rip, ": origaddr ", (void*)(Waddr)origaddr, ", virtaddr ", (void*)(Waddr)addr, endl;

  void* mapped = (annul) ? null : ctx.check_and_translate(addr, uop.size, st, uop.internal, exception, pfec, pteupdate);
  return mapped;
}

bool ReorderBufferEntry::handle_common_load_store_exceptions(LoadStoreQueueEntry& state, Waddr& origaddr, Waddr& addr, int& exception, PageFaultErrorCode& pfec) {
  OutOfOrderCore& core = getcore();

  bool st = isstore(uop.opcode);
  int aligntype = uop.cond;

  state.invalid = 1;
  state.data = exception | ((W64)pfec << 32);
  state.datavalid = 1;

  core.eventlog.add_load_store((st) ? EVENT_STORE_EXCEPTION : EVENT_LOAD_EXCEPTION, this, null, addr);

  if unlikely (exception == EXCEPTION_UnalignedAccess) {
    //
    // If we have an unaligned access, locate the excepting uop in the
    // basic block cache through the uop.origop pointer. Directly set
    // the unaligned bit in the uop, and restart fetching at the start
    // of the x86 macro-op. The frontend will then split the uop into
    // low and high parts as it is refetched.
    //
    core.eventlog.add_load_store(EVENT_ALIGNMENT_FIXUP, this, null, addr);

    uop.bb->transops[uop.bbindex].unaligned = 1;

    core.annul_fetchq();
    W64 recoveryrip = annul_after_and_including();
    core.reset_fetch_unit(recoveryrip);

    W64& stat = (st) ? stats.ooocore.dcache.store.issue.unaligned : stats.ooocore.dcache.load.issue.unaligned;
    stat++;

    return false;
  }

  if unlikely (((exception == EXCEPTION_PageFaultOnRead) | (exception == EXCEPTION_PageFaultOnWrite)) & (aligntype == LDST_ALIGN_HI)) {
    //
    // If we have a page fault on an unaligned access, and this is the high
    // half (ld.hi / st.hi) of that access, the page fault address recorded
    // in CR2 must be at the very first byte of the second page the access
    // overlapped onto (otherwise the kernel will repeatedly fault in the
    // first page, even though that one is already present.
    //
    origaddr = addr;
  }

  W64& stat = (st) ? stats.ooocore.dcache.store.issue.exception : stats.ooocore.dcache.load.issue.exception;
  stat++;

  return true;
}

//
// Stores have special dependency rules: they may issue as soon as operands ra and rb are ready,
// even if rc (the value to store) or rs (the store buffer to inherit from) is not yet ready or
// even known.
//
// After both ra and rb are ready, the store is moved to [ready_to_issue] as a first phase store.
// When the store issues, it generates its physical address [ra+rb] and establishes an SFR with
// the address marked valid but the data marked invalid.
//
// The sole purpose of doing this is to allow other loads and stores to create an rs dependency
// on the SFR output of the store.
//
// The store is then marked as a second phase store, since the address has been generated.
// When the store is replayed and rescheduled, it must now have all operands ready this time.
//
int ReorderBufferEntry::issuestore(LoadStoreQueueEntry& state, Waddr& origaddr, W64 ra, W64 rb, W64 rc, bool rcready, PTEUpdate& pteupdate) {
  OutOfOrderCore& core = getcore();
  OutOfOrderCoreEvent* event;

  int sizeshift = uop.size;
  int aligntype = uop.cond;
  
  Waddr addr;
  int exception = 0;
  PageFaultErrorCode pfec;
  bool annul;
  
  void* mapped = addrgen(state, origaddr, ra, rb, rc, pteupdate, addr, exception, pfec, annul);

  if unlikely (exception) {
    return (handle_common_load_store_exceptions(state, origaddr, addr, exception, pfec)) ? ISSUE_COMPLETED : ISSUE_MISSPECULATED;
  }

  stats.ooocore.dcache.store.type.aligned += ((!uop.internal) & (aligntype == LDST_ALIGN_NORMAL));
  stats.ooocore.dcache.store.type.unaligned += ((!uop.internal) & (aligntype != LDST_ALIGN_NORMAL));
  stats.ooocore.dcache.store.type.internal += uop.internal;
  stats.ooocore.dcache.store.size[sizeshift]++;

  state.physaddr = (annul) ? 0xffffffffffffffffULL : (mapped_virt_to_phys(mapped) >> 3);

  //
  // The STQ is then searched for the most recent prior store S to same 64-bit block. If found, U's
  // rs dependency is set to S by setting the ROB's rs field to point to the prior store's physreg
  // and hence its ROB. If not found, U's rs dependency remains unset (i.e. to PHYS_REG_NULL).
  // If some prior stores are ambiguous (addresses not resolved yet), we assume they are a match
  // to ensure correctness yet avoid additional checks; the store is replayed and tries again 
  // when the ambiguous reference resolves.
  //
  LoadStoreQueueEntry* sfra = null;

  foreach_backward_before(core.LSQ, lsq, i) {
    LoadStoreQueueEntry& stbuf = core.LSQ[i];

    if unlikely (stbuf.store && (!stbuf.addrvalid || (stbuf.addrvalid && (stbuf.physaddr == state.physaddr)))) {
      assert(stbuf.rob->uop.uuid < uop.uuid);
      sfra = &stbuf;
      break;
    }
  }

  //
  // Always update deps in case redispatch is required
  // because of a future speculation failure: we must
  // know which loads and stores inherited bogus values
  //
  operands[RS]->unref(*this);
  operands[RS] = (sfra) ? sfra->rob->physreg : &core.physregfiles[0][PHYS_REG_NULL];
  operands[RS]->addref(*this);

  bool ready = (!sfra || (sfra && sfra->addrvalid && sfra->datavalid)) && rcready;

  //
  // If any of the following are true:
  // - Prior store S with same address is found but its data is not ready
  // - Prior store S with unknown address is found
  // - Data to store (rc operand) is not yet ready
  //
  // Then the store is moved back into [ready_to_dispatch], where this time all operands are checked.
  // The replay() function will put the newly selected prior store S's ROB as the rs dependency
  // of the current store before replaying it.
  //
  // When the current store wakes up again, it will rescan the STQ to see if any intervening stores
  // slipped in, and may repeatedly go back to sleep on the new store until the entire chain of stores
  // to a given location is resolved in the correct order. This does not mean all stores must issue in
  // program order - it simply means stores to the same address (8-byte chunk) are serialized in
  // program order, but out of order w.r.t. unrelated stores. This is similar to the constraints on
  // store buffer merging in Pentium 4 and AMD K8.
  //

  if unlikely (!ready) {
    event = core.eventlog.add_load_store(EVENT_STORE_WAIT, this, sfra, addr);
    event->loadstore.rcready = rcready;

    replay();
    load_store_second_phase = 1;

    stats.ooocore.dcache.store.issue.replay.sfr_addr_and_data_and_data_to_store_not_ready += ((!rcready) & (sfra && (!sfra->addrvalid) & (!sfra->datavalid)));
    stats.ooocore.dcache.store.issue.replay.sfr_addr_and_data_to_store_not_ready += ((!rcready) & (sfra && (!sfra->addrvalid)));
    stats.ooocore.dcache.store.issue.replay.sfr_data_and_data_to_store_not_ready += ((!rcready) & (sfra && sfra->addrvalid && (!sfra->datavalid)));

    stats.ooocore.dcache.store.issue.replay.sfr_addr_and_data_not_ready += (rcready & (sfra && (!sfra->addrvalid) & (!sfra->datavalid)));
    stats.ooocore.dcache.store.issue.replay.sfr_addr_not_ready += (rcready & (sfra && ((!sfra->addrvalid) & (sfra->datavalid))));
    stats.ooocore.dcache.store.issue.replay.sfr_data_not_ready += (rcready & (sfra && (sfra->addrvalid & (!sfra->datavalid))));

    return ISSUE_NEEDS_REPLAY;
  }

  //
  // Load/Store Aliasing Prevention
  //
  // We always issue loads as soon as possible even if some entries in the
  // store queue have unresolved addresses. If a load gets erroneously
  // issued before an earlier store in program order to the same address,
  // this is considered load/store aliasing.
  // 
  // Aliasing is detected when stores issue: the load queue is scanned
  // for earlier loads in program order which collide with the store's
  // address. In this case all uops in program order after and including
  // the store (and by extension, the colliding load) must be annulled.
  //
  // To keep this from happening repeatedly, whenever a collision is
  // detected, the store looks up the rip of the colliding load and adds
  // it to a small table called the LSAP (load/store alias predictor).
  //
  // Loads query the LSAP with the rip of the load; if a matching entry
  // is found in the LSAP and the store address is unresolved, the load
  // is not allowed to proceed.
  //
  // Check all later loads in LDQ to see if any have already issued
  // and have already obtained their data but really should have 
  // depended on the data generated by this store. If so, mark the
  // store as invalid (EXCEPTION_LoadStoreAliasing) so it annuls
  // itself and the load after it in program order at commit time.
  //
  foreach_forward_after (core.LSQ, lsq, i) {
    LoadStoreQueueEntry& ldbuf = core.LSQ[i];
    //
    // (see notes on Load Replay Conditions below)
    //

    if unlikely ((!ldbuf.store) & ldbuf.addrvalid & (ldbuf.physaddr == state.physaddr)) {
      //
      // Check for the extremely rare case where:
      // - load is in the ready_to_load state at the start of the simulated 
      //   cycle, and is processed by load_issue()
      // - that load gets its data forwarded from a store (i.e., the store
      //   being handled here) scheduled for execution in the same cycle
      // - the load and the store alias each other
      //
      // Handle this by checking the list of addresses for loads processed
      // in the same cycle, and only signal a load speculation failure if
      // the aliased load truly came at least one cycle before the store.
      //
      int i;
      int parallel_forwarding_match = 0;
      foreach (i, core.loads_in_this_cycle) {
        parallel_forwarding_match |= (core.load_to_store_parallel_forwarding_buffer[i] == state.physaddr);
      }

      if unlikely (parallel_forwarding_match) {
        event = core.eventlog.add_load_store(EVENT_STORE_PARALLEL_FORWARDING_MATCH, this, &ldbuf, addr);
        stats.ooocore.dcache.store.parallel_aliasing++;
        continue;
      }

      state.invalid = 1;
      state.data = EXCEPTION_LoadStoreAliasing;
      state.datavalid = 1;

      event = core.eventlog.add_load_store(EVENT_STORE_ALIASED_LOAD, this, &ldbuf, addr);

      // Add the rip to the load to the load/store alias predictor:
      core.lsap.select(ldbuf.rob->uop.rip);
      //
      // The load as dependent on this store. Add a new dependency
      // on the store to the load so the normal redispatch mechanism
      // will find this.
      //
      ldbuf.rob->operands[RS]->unref(*this);
      ldbuf.rob->operands[RS] = physreg;
      ldbuf.rob->operands[RS]->addref(*this);

      redispatch_dependents();

      stats.ooocore.dcache.store.issue.ordering++;

      return ISSUE_MISSPECULATED;
    }
  }

  //
  // At this point all operands are valid, so merge the data and mark the store as valid.
  //

  byte bytemask = 0;

  switch (aligntype) {
  case LDST_ALIGN_NORMAL:
  case LDST_ALIGN_LO:
    bytemask = ((1 << (1 << sizeshift))-1) << (lowbits(origaddr, 3));
    rc <<= 8*lowbits(origaddr, 3);
    break;
  case LDST_ALIGN_HI:
    bytemask = ((1 << (1 << sizeshift))-1) >> (8 - lowbits(origaddr, 3));
    rc >>= 8*(8 - lowbits(origaddr, 3));
  }

  state.invalid = 0;
  state.data = (sfra) ? mux64(expand_8bit_to_64bit_lut[bytemask], sfra->data, rc) : rc;
  state.bytemask = (sfra) ? (sfra->bytemask | bytemask) : bytemask;
  state.datavalid = 1;

  stats.ooocore.dcache.store.forward.zero += (sfra == null);
  stats.ooocore.dcache.store.forward.sfr += (sfra != null);
  stats.ooocore.dcache.store.datatype[uop.datatype]++;

  event = core.eventlog.add_load_store(EVENT_STORE_ISSUED, this, sfra, addr);
  event->loadstore.data_to_store = rc;

  load_store_second_phase = 1;

  stats.ooocore.dcache.store.issue.complete++;

  return ISSUE_COMPLETED;
}

static inline W64 extract_bytes(void* target, int SIZESHIFT, bool SIGNEXT) {
  W64 data;
  switch (SIZESHIFT) {
  case 0:
    data = (SIGNEXT) ? (W64s)(*(W8s*)target) : (*(W8*)target); break;
  case 1:
    data = (SIGNEXT) ? (W64s)(*(W16s*)target) : (*(W16*)target); break;
  case 2:
    data = (SIGNEXT) ? (W64s)(*(W32s*)target) : (*(W32*)target); break;
  case 3:
    data = *(W64*)target; break;
  }
  return data;
}

int ReorderBufferEntry::issueload(LoadStoreQueueEntry& state, Waddr& origaddr, W64 ra, W64 rb, W64 rc, PTEUpdate& pteupdate) {
  OutOfOrderCore& core = getcore();
  OutOfOrderCoreEvent* event;

  int sizeshift = uop.size;
  int aligntype = uop.cond;
  bool signext = (uop.opcode == OP_ldx);

  Waddr addr;
  int exception = 0;
  PageFaultErrorCode pfec;
  bool annul;
  
  void* mapped = addrgen(state, origaddr, ra, rb, rc, pteupdate, addr, exception, pfec, annul);

  if unlikely (exception) {
    return (handle_common_load_store_exceptions(state, origaddr, addr, exception, pfec)) ? ISSUE_COMPLETED : ISSUE_MISSPECULATED;
  }

  stats.ooocore.dcache.load.type.aligned += ((!uop.internal) & (aligntype == LDST_ALIGN_NORMAL));
  stats.ooocore.dcache.load.type.unaligned += ((!uop.internal) & (aligntype != LDST_ALIGN_NORMAL));
  stats.ooocore.dcache.load.type.internal += uop.internal;
  stats.ooocore.dcache.load.size[sizeshift]++;

  state.physaddr = (annul) ? 0xffffffffffffffffULL : (mapped_virt_to_phys(mapped) >> 3);

  //
  // For simulation purposes only, load the data immediately
  // so it is easier to track. In the hardware this obviously
  // only arrives later, but it saves us from having to copy
  // cache lines around...
  //
  barrier();
  W64 data = (annul) ? 0 : *((W64*)(Waddr)floor(signext64((Waddr)mapped, 48), 8));

  LoadStoreQueueEntry* sfra = null;

  bool load_is_known_to_alias_with_store = (core.lsap(uop.rip) >= 0);

  foreach_backward_before(core.LSQ, lsq, i) {
    LoadStoreQueueEntry& stbuf = core.LSQ[i];

    if likely (!stbuf.store) continue;

    if unlikely ((load_is_known_to_alias_with_store & (!stbuf.addrvalid)) || ((stbuf.physaddr == state.physaddr) & stbuf.addrvalid)) {
      stats.ooocore.dcache.load.dependency.predicted_alias_unresolved += (load_is_known_to_alias_with_store);
      stats.ooocore.dcache.load.dependency.stq_address_match += (!load_is_known_to_alias_with_store);
      sfra = &stbuf;
      break;
    }
  }

  stats.ooocore.dcache.load.dependency.independent += (sfra == null);

  bool ready = (!sfra || (sfra && sfra->addrvalid && sfra->datavalid));

  //
  // Always update deps in case redispatch is required
  // because of a future speculation failure: we must
  // know which loads and stores inherited bogus values
  //
  operands[RS]->unref(*this);
  operands[RS] = (sfra) ? sfra->rob->physreg : &core.physregfiles[0][PHYS_REG_NULL];
  operands[RS]->addref(*this);

  if unlikely (!ready) {
    //
    // Load Replay Conditions:
    //
    // - Earlier store is known to alias (based on rip) yet its address is not yet resolved
    // - Earlier store to the same 8-byte chunk was found but its data has not yet arrived
    //
    // In these cases we create an rs dependency on the earlier store and replay the load uop
    // back to the dispatched state. It will be re-issued once the earlier store resolves.
    //
    // Consider the following sequence of events:
    // - Load B issues
    // - Store A issues and detects aliasing with load B; both A and B annulled
    // - Load B attempts to re-issue but aliasing is predicted, so it creates a dependency on store A
    // - Store A issues but sees that load B has already attempted to issue, so an aliasing replay is taken
    //
    // This becomes an infinite loop unless we clear both the addrvalid and datavalid fields of loads
    // when they replay; clearing both suppresses the aliasing replay the second time around.
    //

    assert(sfra);

    event = core.eventlog.add_load_store(EVENT_LOAD_WAIT, this, sfra, addr);
    event->loadstore.predicted_alias = (load_is_known_to_alias_with_store && sfra && (!sfra->addrvalid));

    stats.ooocore.dcache.load.issue.replay.sfr_addr_and_data_not_ready += ((!sfra->addrvalid) & (!sfra->datavalid));
    stats.ooocore.dcache.load.issue.replay.sfr_addr_not_ready += ((!sfra->addrvalid) & (sfra->datavalid));
    stats.ooocore.dcache.load.issue.replay.sfr_data_not_ready += ((sfra->addrvalid) & (!sfra->datavalid));

    replay();
    load_store_second_phase = 1;
    return ISSUE_NEEDS_REPLAY;
  }

  state.addrvalid = 1;

  if unlikely (aligntype == LDST_ALIGN_HI) {
    //
    // Concatenate the aligned data from a previous ld.lo uop provided in rb
    // with the currently loaded data D as follows:
    //
    // rb | D
    //
    // Example:
    //
    // floor(a) floor(a)+8
    // ---rb--  --DD---
    // 0123456701234567
    //    XXXXXXXX
    //    ^ origaddr
    //
    if likely (!annul) {
      if unlikely (sfra) data = mux64(expand_8bit_to_64bit_lut[sfra->bytemask], data, sfra->data);
      
      struct {
        W64 lo;
        W64 hi;
      } aligner;
      
      aligner.lo = rb;
      aligner.hi = data;
      
      W64 offset = lowbits(origaddr - floor(origaddr, 8), 4);

      data = extract_bytes(((byte*)&aligner) + offset, sizeshift, signext);
    } else {
      //
      // annulled: we need no data from the high load anyway; only use the low data
      // that was already checked for exceptions and forwarding:
      //
      W64 offset = lowbits(origaddr, 3);
      state.data = extract_bytes(((byte*)&rb) + offset, sizeshift, signext);
      state.invalid = 0;
      state.datavalid = 1;

      core.eventlog.add_load_store(EVENT_LOAD_HIGH_ANNULLED, this, sfra, addr);

      return ISSUE_COMPLETED;
    }
  } else {
    if unlikely (sfra) data = mux64(expand_8bit_to_64bit_lut[sfra->bytemask], data, sfra->data);
    data = extract_bytes(((byte*)&data) + lowbits(addr, 3), sizeshift, signext);
  }

  // shift is how many bits to shift the 8-bit bytemask left by within the cache line;
  bool covered = core.caches.covered_by_sfr(addr, sfra, sizeshift);
  stats.ooocore.dcache.load.forward.cache += (sfra == null);
  stats.ooocore.dcache.load.forward.sfr += ((sfra != null) & covered);
  stats.ooocore.dcache.load.forward.sfr_and_cache += ((sfra != null) & (!covered));
  stats.ooocore.dcache.load.datatype[uop.datatype]++;

  //
  // NOTE: Technically the data is valid right now for simulation purposes
  // only; in reality it may still be arriving from the cache.
  //
  state.data = data;
  state.invalid = 0;
  state.bytemask = 0xff;
  bool L1hit = (config.perfect_cache) ? 1 : core.caches.probe_cache_and_sfr(addr, sfra, sizeshift);

  if likely (L1hit) {    
    cycles_left = LOADLAT;

    core.eventlog.add_load_store(EVENT_LOAD_HIT, this, sfra, addr);

    assert(core.loads_in_this_cycle < LOAD_FU_COUNT);
    core.load_to_store_parallel_forwarding_buffer[core.loads_in_this_cycle++] = floor(addr, 8);
    
    load_store_second_phase = 1;
    state.datavalid = 1;

    stats.ooocore.dcache.load.issue.complete++;
    stats.ooocore.dcache.load.hit.L1++;
    return ISSUE_COMPLETED;
  }

  stats.ooocore.dcache.load.issue.miss++;

  cycles_left = 0;
  changestate(core.rob_cache_miss_list);

  LoadStoreInfo lsi;
  lsi.rob = index();
  lsi.tid = 0; // for SMT
  lsi.sizeshift = sizeshift;
  lsi.aligntype = aligntype;
  lsi.sfrused = (sfra != null);
  lsi.internal = uop.internal;
  lsi.signext = signext;

  //
  // NOTE: this state is not really used anywhere since load misses
  // will fill directly into the physical register instead.
  //
  IssueState tempstate;
  lfrqslot = core.caches.issueload_slowpath(tempstate, addr, origaddr, data, *sfra, lsi);

  event = core.eventlog.add_load_store(EVENT_LOAD_MISS, this, sfra, addr);

  if unlikely (lfrqslot < 0) {
    core.eventlog.add_load_store(EVENT_LOAD_LFRQ_FULL, this, null, addr);
    stats.ooocore.dcache.load.issue.replay.missbuf_full++;

    state.addrvalid = 0;
    replay();
    return ISSUE_NEEDS_REPLAY;
  }

  assert(core.loads_in_this_cycle < LOAD_FU_COUNT);
  core.load_to_store_parallel_forwarding_buffer[core.loads_in_this_cycle++] = floor(addr, 8);

  return ISSUE_COMPLETED;
}

//
// Data cache has delivered a load: wake up corresponding ROB/LSQ/physreg entries
//
void OutOfOrderCoreCacheCallbacks::dcache_wakeup(LoadStoreInfo lsi, W64 physaddr) {
  ReorderBufferEntry& rob = core.ROB[lsi.rob];
  assert(rob.current_state_list == &core.rob_cache_miss_list);
  rob.loadwakeup();
}

void ReorderBufferEntry::loadwakeup() {
  getcore().eventlog.add_load_store(EVENT_LOAD_WAKEUP, this);

  physreg->flags &= ~FLAG_WAIT;
  physreg->complete();

  lsq->datavalid = 1;

  changestate(getcore().rob_completed_list[cluster]);
  cycles_left = 0;
  lfrqslot = -1;
  forward_cycle = 0;
  fu = 0;
}

//
// Replay the uop by recirculating it back to the dispatched
// state so it can wait for additional dependencies not known
// when it was originally dispatched, e.g. waiting on store
// queue entries or value to store, etc.
//
// This involves re-initializing the uop's operands in its
// already assigned issue queue slot and returning that slot
// to the dispatched but not issued state.
//
// This must be done here instead of simply sending the uop
// back to the dispatch state since otherwise we could have 
// a deadlock if there is not enough room in the issue queue.
//
void ReorderBufferEntry::replay() {
  OutOfOrderCore& core = getcore();

  OutOfOrderCoreEvent* event = core.eventlog.add(EVENT_REPLAY, this);
  foreach (i, MAX_OPERANDS) {
    operands[i]->fill_operand_info(event->replay.opinfo[i]);
    event->replay.ready |= (operands[i]->ready()) << i;
  }

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
  }

  if unlikely (operands_still_needed) {
    changestate(core.rob_dispatched_list[cluster]);
  } else {
    changestate(get_ready_to_issue_list());
  }

  issueq_operation_on_cluster(core, cluster, replay(iqslot, uopids, preready));
}

//
// Release the ROB from the issue queue after there is
// no possibility it will need to be pulled back for
// replay or annulment.
//
void ReorderBufferEntry::release() {
  issueq_operation_on_cluster(getcore(), cluster, release(iqslot));
  iqslot = -1;
}

//
// Process the ready to issue queue and issue as many ROBs as possible
//
int OutOfOrderCore::issue(int cluster) {
  int issuecount = 0;
  ReorderBufferEntry* rob;

  int maxwidth = clusters[cluster].issue_width;

  while (issuecount < maxwidth) {
    int iqslot;
    issueq_operation_on_cluster_with_result(getcore(), cluster, iqslot, issue());
  
    // Is anything ready?
    if unlikely (iqslot < 0) break;

    int robid;
    issueq_operation_on_cluster_with_result(getcore(), cluster, robid, uopof(iqslot));
    assert(inrange(robid, 0, ROB_SIZE-1));
    ReorderBufferEntry& rob = ROB[robid];
    rob.iqslot = iqslot;
    int rc = rob.issue();
    // Stop issuing from this cluster once something replays or has a mis-speculation
    issuecount++;
    if unlikely (rc <= 0) break;
  }

  per_cluster_stats_update(stats.ooocore.issue.width, cluster, [min(issuecount, MAX_ISSUE_WIDTH)]++);

  return issuecount;
}

//
// Forward the result of ROB 'result' to any other waiting ROBs
// dispatched to the issue queues. This is done by broadcasting
// the ROB tag to all issue queues in clusters reachable within
// N cycles after the uop issued, where N is forward_cycle. This
// technique is used to model arbitrarily complex multi-cycle
// forwarding networks.
//
int ReorderBufferEntry::forward() {
  ReorderBufferEntry* target;
  int wakeupcount = 0;

  assert(inrange((int)forward_cycle, 0, (MAX_FORWARDING_LATENCY+1)-1));

  W32 targets = forward_at_cycle_lut[cluster][forward_cycle];
  foreach (i, MAX_CLUSTERS) {
    if likely (!bit(targets, i)) continue;
    OutOfOrderCoreEvent* event = getcore().eventlog.add(EVENT_BROADCAST, this);
    event->forwarding.target_cluster = i;
    event->forwarding.forward_cycle = forward_cycle;

    issueq_operation_on_cluster(getcore(), i, broadcast(index()));
  }

  return 0;
}

//
// Exception recovery and redispatch
//
//
// Remove any and all ROBs that entered the pipeline after and
// including the misspeculated uop. Because we move all affected
// ROBs to the free state, they are instantly taken out of 
// consideration for future pipeline stages and will be dropped on 
// the next cycle.
//
// Normally this means that mispredicted branch uops are annulled 
// even though only the code after the branch itself is invalid.
// In this special case, the recovery rip is set to the actual
// target of the branch rather than refetching the branch insn.
//
// We must be extremely careful to annul all uops in an
// x86 macro-op; otherwise half the x86 instruction could
// be executed twice once refetched. Therefore, if the
// first uop to annul is not also the first uop in the x86
// macro-op, we may have to scan backwards in the ROB until
// we find the first uop of the macro-op. In this way, we
// ensure that we can annul the entire macro-op. All uops
// comprising the macro-op are guaranteed to still be in 
// the ROB since none of the uops commit until the entire
// macro-op can commit.
//
// Note that this does not apply if the final uop in the
// macro-op is a branch and that branch uop itself is
// being retained as occurs with mispredicted branches.
//

W64 ReorderBufferEntry::annul(bool keep_misspec_uop, bool return_first_annulled_rip) {
  OutOfOrderCore& core = getcore();
  OutOfOrderCoreEvent* event;

  int idx;

  //
  // Pass 0: determine macro-op boundaries around uop
  //
  int somidx = index();
  while (!core.ROB[somidx].uop.som) somidx = add_index_modulo(somidx, -1, ROB_SIZE);
  int eomidx = index();
  while (!core.ROB[eomidx].uop.eom) eomidx = add_index_modulo(eomidx, +1, ROB_SIZE);

  // Find uop to start annulment at
  int startidx = (keep_misspec_uop) ? add_index_modulo(eomidx, +1, ROB_SIZE) : somidx;
  if unlikely (startidx == core.ROB.tail) {
    // The uop causing the mis-speculation was the only uop in the ROB:
    // no action is necessary (but in practice this is generally not possible)
    OutOfOrderCoreEvent* event = core.eventlog.add(EVENT_ANNUL_NO_FUTURE_UOPS, this);
    event->annul.somidx = somidx; event->annul.eomidx = eomidx;

    return uop.rip;
  }

  // Find uop to stop annulment at (later in program order)
  int endidx = add_index_modulo(core.ROB.tail, -1, ROB_SIZE);

  // For branches, branch must always terminate the macro-op
  if (keep_misspec_uop) assert(eomidx == index());

  event = core.eventlog.add(EVENT_ANNUL_MISSPECULATION, this);
  event->annul.startidx = startidx; event->annul.endidx = endidx;
  event->annul.somidx = somidx; event->annul.eomidx = eomidx;

  //
  // Pass 1: invalidate issue queue slot for the annulled ROB
  //
  idx = endidx;
  for (;;) {
    ReorderBufferEntry& annulrob = core.ROB[idx];
    issueq_operation_on_cluster(core, annulrob.cluster, annuluop(annulrob.index()));
    annulrob.iqslot = -1;
    if unlikely (idx == startidx) break;
    idx = add_index_modulo(idx, -1, ROB_SIZE);
  }

  int annulcount = 0;

  //
  // Pass 2: reconstruct the SpecRRT as it existed just before (or after)
  // the mis-speculated operation. This is done using the fast flush with
  // pseudo-commit method as follows:
  //
  // First overwrite the SpecRRT with the CommitRRT.
  //
  // Then, simulate the commit of all non-speculative ROBs up to the branch
  // by updating the SpecRRT as if it were the CommitRRT. This brings the
  // speculative RRT to the same state as if all in flight nonspeculative
  // operations before the branch had actually committed. Resume instruction 
  // fetch at the correct branch target.
  //
  // Other methods (like backwards walk) are difficult to impossible because
  // of the requirement that flag rename tables be restored even if some
  // of the required physical registers with attached flags have since been
  // freed. Therefore we don't do this.
  //
  // Technically RRT checkpointing could be used but due to the load/store
  // replay mechanism in use, this would require a checkpoint at every load
  // and store as well as branches.
  //
  foreach (i, TRANSREG_COUNT) { core.specrrt[i]->unspecref(i); }
  core.specrrt = core.commitrrt;
  foreach (i, TRANSREG_COUNT) { core.specrrt[i]->addspecref(i); }

  // if (logable(6)) logfile << "Restored SpecRRT from CommitRRT; walking forward from:", endl, core.specrrt, endl;

  idx = core.ROB.head;
  for (idx = core.ROB.head; idx != startidx; idx = add_index_modulo(idx, +1, ROB_SIZE)) {
    ReorderBufferEntry& rob = core.ROB[idx];
    rob.pseudocommit();
  }

  // if (logable(6)) logfile << "Recovered SpecRRT:", endl, core.specrrt, endl;

  //
  // Pass 3: For each speculative ROB, reinitialize and free speculative ROBs
  //

  ReorderBufferEntry* lastrob = null;

  idx = endidx;
  for (;;) {
    ReorderBufferEntry& annulrob = core.ROB[idx];

    lastrob = &annulrob;

    event = core.eventlog.add(EVENT_ANNUL_EACH_ROB, &annulrob);
    event->annul.annulras = 0;

    //
    // Free the speculatively allocated physical register
    // See notes above on Physical Register Recycling Complications
    //
    foreach (j, MAX_OPERANDS) { annulrob.operands[j]->unref(annulrob); }
    annulrob.physreg->free();

    if unlikely (isclass(annulrob.uop.opcode, OPCLASS_LOAD|OPCLASS_STORE)) {
      core.loads_in_flight -= (annulrob.lsq->store == 0);
      core.stores_in_flight -= (annulrob.lsq->store == 1);
      annulrob.lsq->reset();
      core.LSQ.annul(annulrob.lsq);
    }

    if unlikely (annulrob.lfrqslot >= 0) {
      core.caches.annul_lfrq_slot(annulrob.lfrqslot);
    }

    if unlikely (isbranch(annulrob.uop.opcode) && (annulrob.uop.predinfo.bptype & (BRANCH_HINT_CALL|BRANCH_HINT_RET))) {
      //
      // Return Address Stack (RAS) correction:
      // Example calls and returns in pipeline
      //
      // C1
      //   C2
      //   R2 
      //   BR (mispredicted branch)
      //   C3
      //     C4
      //
      // BR mispredicts, so everything after BR must be annulled.
      // RAS contains: C1 C3 C4, so we need to annul [C4 C3].
      //
      event->annul.annulras = 1;
      core.branchpred.annulras(annulrob.uop.predinfo);
    }

    // Release our lock on the cached basic block containing this uop
    event->annul.bb = annulrob.uop.bb;
    event->annul.bb_refcount = annulrob.uop.bb->refcount;
    annulrob.uop.bb->release();

    annulrob.reset();
    core.ROB.annul(annulrob);

    annulrob.changestate(core.rob_free_list);
    annulcount++;

    if (idx == startidx) break;
    idx = add_index_modulo(idx, -1, ROB_SIZE);
  }

  assert(core.ROB[startidx].uop.som);

  if (return_first_annulled_rip) return core.ROB[startidx].uop.rip;

  return (keep_misspec_uop) ? core.ROB[startidx].uop.riptaken : (Waddr)core.ROB[startidx].uop.rip;
}

//
// Return the specified uop back to the ready_to_dispatch state.
// All structures allocated to the uop are reset to the same state
// they had immediately after allocation.
//
// This function is used to handle various types of mis-speculations
// in which only the values are invalid, rather than the actual uops
// as with branch mispredicts and unaligned accesses. It is also
// useful for various kinds of value speculation.
//
// The normal "fast" replay mechanism is still used for scheduler
// related replays - this is much more expensive.
//
// If this function is called for a given uop U, all of U's
// consumers must also be re-dispatched. The redispatch_dependents()
// function automatically does this.
//
// The <prevrob> argument should be the previous ROB, in program
// order, before this one. If this is the first ROB being
// re-dispatched, <prevrob> should be null.
//

void ReorderBufferEntry::redispatch(const bitvec<MAX_OPERANDS>& dependent_operands, ReorderBufferEntry* prevrob) {
  OutOfOrderCore& core = getcore();
  OutOfOrderCoreEvent* event = core.eventlog.add(EVENT_REDISPATCH_EACH_ROB, this);
  event->redispatch.current_state_list = current_state_list;
  event->redispatch.dependent_operands = dependent_operands.integer();
  foreach (i, MAX_OPERANDS) operands[i]->fill_operand_info(event->redispatch.opinfo[i]);

  stats.ooocore.dispatch.redispatch.trigger_uops++;

  // Remove from issue queue, if it was already in some issue queue
  if unlikely (cluster >= 0) {
    bool found = 0;
    issueq_operation_on_cluster_with_result(getcore(), cluster, found, annuluop(index()));
    event->redispatch.iqslot = found;
    cluster = -1;
  }

  if unlikely (lfrqslot >= 0) {
    core.caches.annul_lfrq_slot(lfrqslot);
    lfrqslot = -1;
  }

  if unlikely (lsq) {
    lsq->physaddr = 0;
    lsq->addrvalid = 0;
    lsq->datavalid = 0;
    lsq->mbtag = -1;
    lsq->data = 0;
    lsq->physaddr = 0;
    lsq->invalid = 0;

    if (operands[RS]->nonnull()) {
      operands[RS]->unref(*this);
      operands[RS] = &core.physregfiles[0][PHYS_REG_NULL];
      operands[RS]->addref(*this);
    }
  }

  // Return physreg to state just after allocation
  physreg->data = 0;
  physreg->flags = FLAG_WAIT;
  physreg->changestate(PHYSREG_WAITING);

  // Force ROB to be re-dispatched in program order
  cycles_left = 0;
  forward_cycle = 0;
  load_store_second_phase = 0;
  changestate(core.rob_ready_to_dispatch_list, true, prevrob);
}

//
// Find all uops dependent on the specified uop, and 
// redispatch each of them.
//
void ReorderBufferEntry::redispatch_dependents(bool inclusive) {
  OutOfOrderCore& core = getcore();

  bitvec<ROB_SIZE> depmap;
  depmap = 0;
  depmap[index()] = 1;

  OutOfOrderCoreEvent* event = core.eventlog.add(EVENT_REDISPATCH_DEPENDENTS, this);

  //
  // Go through the ROB and identify the slice of all uops
  // depending on this one, through the use of physical
  // registers as operands.
  //
  int count = 0;

  ReorderBufferEntry* prevrob = null;

  foreach_forward_from(core.ROB, this, robidx) {
    ReorderBufferEntry& reissuerob = core.ROB[robidx];

    if (!inclusive) {
      depmap[reissuerob.index()] = 1;
      continue;
    }

    bitvec<MAX_OPERANDS> dependent_operands;
    dependent_operands = 0;

    foreach (i, MAX_OPERANDS) {
      const PhysicalRegister* operand = reissuerob.operands[i];
      dependent_operands[i] = (operand->rob && depmap[operand->rob->index()]);
    }

    //
    // We must also redispatch all stores, since in pathological cases, there may
    // be store-store ordering cases we don't know about, i.e. if some store
    // inherits from a previous store, but that previous store actually has the
    // wrong address because of some other bogus uop providing its address.
    //
    bool dep = (*dependent_operands) | (robidx == index()) | isstore(uop.opcode);

    if unlikely (dep) {
      count++;
      depmap[reissuerob.index()] = 1;
      reissuerob.redispatch(dependent_operands, prevrob);
      prevrob = &reissuerob;
    }
  }

  assert(inrange(count, 1, ROB_SIZE));
  stats.ooocore.dispatch.redispatch.dependent_uops[count-1]++;

  event = core.eventlog.add(EVENT_REDISPATCH_DEPENDENTS_DONE, this);
  event->redispatch.count = count;
}

int ReorderBufferEntry::pseudocommit() {
  OutOfOrderCore& core = getcore();
  core.eventlog.add(EVENT_ANNUL_PSEUDOCOMMIT, this);

  if likely (archdest_can_commit[uop.rd]) {
    core.specrrt[uop.rd]->unspecref(uop.rd);
    core.specrrt[uop.rd] = physreg;
    core.specrrt[uop.rd]->addspecref(uop.rd);
  }

  if likely (!uop.nouserflags) {
    if (uop.setflags & SETFLAG_ZF) {
      core.specrrt[REG_zf]->unspecref(REG_zf);
      core.specrrt[REG_zf] = physreg;
      core.specrrt[REG_zf]->addspecref(REG_zf);
    }
    if (uop.setflags & SETFLAG_CF) {
      core.specrrt[REG_cf]->unspecref(REG_cf);
      core.specrrt[REG_cf] = physreg;
      core.specrrt[REG_cf]->addspecref(REG_cf);
    }
    if (uop.setflags & SETFLAG_OF) {
      core.specrrt[REG_of]->unspecref(REG_of);
      core.specrrt[REG_of] = physreg;
      core.specrrt[REG_of]->addspecref(REG_of);
    }
  }

  if unlikely (isclass(uop.opcode, OPCLASS_BARRIER))
                return COMMIT_RESULT_BARRIER;

  return COMMIT_RESULT_OK;
}
