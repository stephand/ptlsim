//
// PTLsim: Cycle Accurate x86-64 Simulator
// Out-of-Order Core Simulator
//
// Copyright 2003-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <elf.h>
#include <ptlsim.h>
#include <branchpred.h>
#include <datastore.h>
#include <logic.h>

#define DECLARE_STRUCTURES
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

byte uop_executable_on_cluster[OP_MAX_OPCODE];

W32 forward_at_cycle_lut[MAX_CLUSTERS][MAX_FORWARDING_LATENCY+1];

static void init_luts() {
  // Initialize opcode maps
  foreach (i, OP_MAX_OPCODE) {
    W32 allowedfu = opinfo[i].fu;
    W32 allowedcl = 0;
    foreach (cl, MAX_CLUSTERS) {
      if (clusters[cl].fu_mask & allowedfu) setbit(allowedcl, cl);
    }
    uop_executable_on_cluster[i] = allowedcl;
  }
  
  // Initialize forward-at-cycle LUTs
  foreach (srcc, MAX_CLUSTERS) {
    foreach (destc, MAX_CLUSTERS) {
      foreach (lat, MAX_FORWARDING_LATENCY+1) {
        if (lat == intercluster_latency_map[srcc][destc]) {
          setbit(forward_at_cycle_lut[srcc][lat], destc);
        }
      }
    }
  }
}

template <typename T> 
void print_list_of_state_lists(ostream& os, const ListOfStateLists& lol, const char* title) {
  os << title, ":", endl;
  foreach (i, lol.count) {
    StateList& list = *lol[i];
    if (!list.count) continue;
    os << list.name, " (", list.count, " entries):", endl;
    int n = 0;
    T* obj;
    foreach_list_mutable(list, obj, entry, nextentry) {
      if ((n % 16) == 0) os << " ";
      os << " ", intstring(obj->index(), -3);
      if (((n % 16) == 15) || (n == list.count-1)) os << endl;
      n++;
    }
    os << endl;
    // list.validate();
  }
}

void StateList::checkvalid() {
#if 0
  int realcount = 0;
  selfqueuelink* obj;
  foreach_list_mutable(*this, obj, entry, nextentry) {
    realcount++;
  }
  assert(count == realcount);
#endif
}

void PhysicalRegisterFile::init(const char* name, int coreid, int rfid, int size) {
  assert(rfid < PHYS_REG_FILE_COUNT);
  assert(size <= MAX_PHYS_REG_FILE_SIZE);
  this->size = size;
  this->coreid = coreid;
  this->rfid = rfid;
  this->name = name;
  this->allocations = 0;
  this->frees = 0;

  foreach (i, MAX_PHYSREG_STATE) {
    states[i].init(physreg_state_names[i], coreof(coreid).physreg_states);
  }

  foreach (i, size) {
    (*this)[i].init(coreid, rfid, i);
  }
}

void PhysicalRegisterFile::reset() {
  foreach (i, MAX_PHYSREG_STATE) {
    states[i].reset();
  }

  foreach (i, size) {
    (*this)[i].reset();
  }
}

StateList& PhysicalRegister::get_state_list(int s) const {
  return coreof(coreid).physregfiles[rfid].states[s];
}

ostream& operator <<(ostream& os, const PhysicalRegister& physreg) {
  stringbuf sb;
  print_value_and_flags(sb, physreg.data, physreg.flags);

  os << "  r", intstring(physreg.index(), -3), " state ", padstring(physreg.get_state_list().name, -12), " ", sb;
  if (physreg.rob) os << " rob ", physreg.rob->index(), " (uuid ", physreg.rob->uop.uuid, ")";
  os << " refcount ", physreg.refcount;

  return os;
}

//
// Process any ROB entries that just finished producing a result, forwarding
// data within the same cluster directly to the waiting instructions.
//
// Note that we use the target physical register as a temporary repository
// for the data. In a modern hardware implementation, this data would exist
// only "on the wire" such that back to back ALU operations within a cluster
// can occur using local forwarding.
//

CycleTimer ctcomplete;

int OutOfOrderCore::complete(int cluster) {
  int completecount = 0;
  ReorderBufferEntry* rob;

  start_timer(ctcomplete);

  // 
  // Check the list of issued ROBs. If a given ROB is complete (i.e., is ready
  // for writeback and forwarding), move it to rob_completed_list.
  //
  foreach_list_mutable(rob_issued_list[cluster], rob, entry, nextentry) {
    rob->cycles_left--;

    if unlikely (rob->cycles_left <= 0) {
      if (logable(6)) {
        stringbuf rdstr; print_value_and_flags(rdstr, rob->physreg->data, rob->physreg->flags);
        logfile << intstring(rob->uop.uuid, 20), " complt rob ", intstring(rob->index(), -3), " on ", padstring(FU[rob->fu].name, -4), ": r", intstring(rob->physreg->index(), -3), " = ", rdstr, endl;
      }

      rob->changestate(rob_completed_list[cluster]);
      rob->physreg->complete();
      rob->forward_cycle = 0;
      rob->fu = 0;
      completecount++;
    }
  }

  stop_timer(ctcomplete);
  return 0;
}

//
// Process ROBs in flight between completion and global forwarding/writeback.
//

int OutOfOrderCore::transfer(int cluster) {
  int wakeupcount = 0;
  ReorderBufferEntry* rob;

  start_timer(cttransfer);

  foreach_list_mutable(rob_completed_list[cluster], rob, entry, nextentry) {
    rob->forward();
    rob->forward_cycle++;
    if unlikely (rob->forward_cycle > MAX_FORWARDING_LATENCY) {
      rob->forward_cycle = MAX_FORWARDING_LATENCY;
      rob->changestate(rob_ready_to_writeback_list[rob->cluster]);
    }
  }

  stop_timer(cttransfer);

  return 0;
}


//
// Execute one cycle of the entire core state machine
//
bool OutOfOrderCore::runcycle() {
  bool exiting = 0;

  // All FUs are available at top of cycle:
  fu_avail = bitmask(FU_COUNT);
  loads_in_this_cycle = 0;
#ifndef PERFECT_CACHE
  dcache_clock();
#endif
  int commitrc = commit();
    
  for_each_cluster(i) { writeback(i); }
  for_each_cluster(i) { transfer(i); }
    
  for_each_cluster(i) { issue(i); complete(i); }
    
  int dispatchrc = dispatch();
    
  if likely ((!stall_frontend) && (dispatchrc >= 0)) {
    frontend();
    rename();
    fetch();
  }
    
  if likely (dispatchrc >= 0) { foreach_issueq(clock()); }
    
#ifdef ENABLE_CHECKS
  // This significantly slows down simulation; only enable it if absolutely needed:
  //check_refcounts();
#endif
    
  if unlikely (commitrc == COMMIT_RESULT_BARRIER) {
    exiting = !handle_barrier();
  } else if unlikely (commitrc == COMMIT_RESULT_EXCEPTION) {
    exiting = !handle_exception();
  } else if unlikely (commitrc == COMMIT_RESULT_SMC) {
    core_to_external_state();
    flush_pipeline(ctx.commitarf[REG_rip]);
    exiting = 0;
  } else if (commitrc == COMMIT_RESULT_STOP) {
    exiting = 1;
  }

  if unlikely ((sim_cycle - last_commit_at_cycle) > 1024) {
    stringbuf sb;
    sb << "WARNING: At cycle ", sim_cycle, ", ", total_user_insns_committed, 
      " user commits: no instructions have committed for ", (sim_cycle - last_commit_at_cycle),
      " cycles; the pipeline could be deadlocked", endl;
    logfile << sb, flush;
    cerr << sb, flush;
    exiting = 1;
  }

  return exiting;
}

//
// ReorderBufferEntry
//
void ReorderBufferEntry::init(int idx) {
  this->idx = idx;
  entry_valid = 0;
  selfqueuelink::reset();
  current_state_list = null;
  reset();
}

//
// Clean out various fields from the ROB entry that are 
// expected to be zero when allocating a new ROB entry.
//
void ReorderBufferEntry::reset() {
  int latency, operand;
  // Deallocate ROB entry
  entry_valid = false;
  cycles_left = 0;
  physreg = (PhysicalRegister*)null;
  lfrqslot = -1;
  lsq = 0;
  load_store_second_phase = 0;
  consumer_count = 0;
  executable_on_cluster_mask = 0;
#ifdef ENABLE_TRANSIENT_VALUE_TRACKING
  dest_renamed_before_writeback = 0;
  no_branches_between_renamings = 0;
#endif
}

bool ReorderBufferEntry::ready_to_issue() const {
  bool raready = operand_ready(0);
  bool rbready = operand_ready(1);
  bool rcready = operand_ready(2);
  bool rsready = operand_ready(3);
  
  if (isstore(uop.opcode)) {
    return (load_store_second_phase) ? (raready & rbready & rcready & rsready) : (raready & rbready);
  } else if (isload(uop.opcode)) {
    return (load_store_second_phase) ? (raready & rbready & rcready & rsready) : (raready & rbready & rcready);
  } else {
    return (raready & rbready & rcready & rsready);
  }
}

bool ReorderBufferEntry::ready_to_commit() const {
  return (current_state_list == &coreof(coreid).rob_ready_to_commit_queue);
}

StateList& ReorderBufferEntry::get_ready_to_issue_list() const {
  OutOfOrderCore& core = coreof(coreid);
  return 
    isload(uop.opcode) ? core.rob_ready_to_load_list[cluster] :
    isstore(uop.opcode) ? core.rob_ready_to_store_list[cluster] :
    core.rob_ready_to_issue_list[cluster];
}

bool ReorderBufferEntry::has_exception() const {
  return ((physreg->flags & FLAG_INV) != 0);
}

bool ReorderBufferEntry::operand_ready(int operand) const {
  return operands[operand]->ready();
}


stringbuf& ReorderBufferEntry::get_operand_info(stringbuf& sb, int operand) const {
  PhysicalRegister& physreg = *operands[operand];
  ReorderBufferEntry& sourcerob = *physreg.rob;

  sb << "r", physreg.index();
  if (PHYS_REG_FILE_COUNT > 1) sb << "@", coreof(coreid).physregfiles[physreg.rfid].name;

  switch (physreg.state) {
  case PHYSREG_WRITTEN:
    sb << " (written)"; break;
  case PHYSREG_BYPASS:
    sb << " (ready)"; break;
  case PHYSREG_WAITING:
    sb << " (wait rob ", sourcerob.index(), " uuid ", sourcerob.uop.uuid, ")"; break;
  case PHYSREG_ARCH: break;
    if (physreg.index() == PHYS_REG_NULL)  sb << " (zero)"; else sb << " (arch ", arch_reg_names[physreg.archreg], ")"; break;
  case PHYSREG_PENDINGFREE:
    sb << " (pending free for ", arch_reg_names[physreg.archreg], ")"; break;
  default:
    // Cannot be in free state!
    sb << " (FREE)"; assert(false); break;
  }

  return sb;
}

ostream& ReorderBufferEntry::print_operand_info(ostream& os, int operand) const {
  stringbuf sb;
  get_operand_info(sb, operand);
  os << sb;
  return os;
}

ostream& ReorderBufferEntry::print(ostream& os) const {
  stringbuf name, rainfo, rbinfo, rcinfo;
  nameof(name, uop);
  get_operand_info(rainfo, 0);
  get_operand_info(rbinfo, 1);
  get_operand_info(rcinfo, 2);

  os << "rob ", intstring(index(), -3), " uuid ", intstring(uop.uuid, 16), " ", padstring(current_state_list->name, -24), " @ ", padstring((cluster >= 0) ? clusters[cluster].name : "???", -4), " ", padstring(name, -12), " r", 
    intstring(physreg->index(), -3), " ", padstring(arch_reg_names[uop.rd], -6);
  if (isload(uop.opcode)) 
    os << " ld", intstring(lsq->index(), -3);
  else if (isstore(uop.opcode))
    os << " st", intstring(lsq->index(), -3);
  else os << "      ";

  os << " = ";
  os << padstring(rainfo, -30);
  os << padstring(rbinfo, -30);
  os << padstring(rcinfo, -30);

  return os;
}

void OutOfOrderCore::print_rob(ostream& os) {
  os << "ROB head ", ROB.head, " to tail ", ROB.tail, " (", ROB.count, " entries):", endl;
  foreach_forward(ROB, i) {
    ReorderBufferEntry& rob = ROB[i];
    os << "  ", rob, endl;
  }
}

void OutOfOrderCore::print_lsq(ostream& os) {
  os << "LSQ head ", LSQ.head, " to tail ", LSQ.tail, " (", LSQ.count, " entries):", endl;
  foreach_forward(LSQ, i) {
    LoadStoreQueueEntry& lsq = LSQ[i];
    os << "  ", lsq, endl;
  }
}

void OutOfOrderCore::print_rename_tables(ostream& os) {
  os << "SpecRRT:", endl;
  os << specrrt;
  os << "CommitRRT:", endl;
  os << commitrrt;
}

void OutOfOrderCore::log_forwarding(const ReorderBufferEntry* source, const ReorderBufferEntry* target, int operand) {
  if (config.loglevel <= 0) return;

  PhysicalRegister* physreg = source->physreg;

  stringbuf rdstr; print_value_and_flags(rdstr, physreg->data, physreg->flags);
  logfile << intstring(source->uop.uuid, 20), " forwd", source->forward_cycle, " rob ", intstring(source->index(), -3), 
    " (", clusters[source->cluster].name, ") r", intstring(physreg->index(), -3), 
    " => ", "uuid ", target->uop.uuid, " rob ", target->index(), " (", clusters[target->cluster].name, ") r", target->physreg->index(), " operand ", operand;
  if (isstore(target->uop.opcode)) logfile << " => st", target->lsq->index();
  logfile << " [still waiting?";
  foreach (i, MAX_OPERANDS) { if (!target->operand_ready(i)) logfile << " r", (char)('a' + i); }
  if (target->ready_to_issue()) logfile << " READY";
  logfile << "]";
  logfile << endl;
}

void OutOfOrderCore::dump_ooo_state() {
  print_rename_tables(logfile);
  print_rob(logfile);
  print_list_of_state_lists<PhysicalRegister>(logfile, physreg_states, "Physical register states");
  print_list_of_state_lists<ReorderBufferEntry>(logfile, rob_states, "ROB entry states");
  print_lsq(logfile);
  logfile << "Issue Queues:", endl;
  foreach_issueq(print(logfile));
  foreach (i, PHYS_REG_FILE_COUNT) {
    logfile << physregfiles[i];
  }
#ifndef PERFECT_CACHE
  dcache_print(logfile);
#endif
  logfile << flush;
}

//
// Validate the physical register reference counters against what
// is really accessible from the various tables and operand fields.
//
// This is for debugging only.
//
void OutOfOrderCore::check_refcounts() {
  int refcounts[PHYS_REG_FILE_COUNT][MAX_PHYS_REG_FILE_SIZE];
  memset(refcounts, 0, sizeof(refcounts));

  foreach (rfid, PHYS_REG_FILE_COUNT) {
    // Null physreg in each register file is special and can never be freed:
    refcounts[rfid][PHYS_REG_NULL]++;
  }

  foreach_forward(ROB, i) {
    ReorderBufferEntry& rob = ROB[i];
    foreach (j, MAX_OPERANDS) {
      refcounts[rob.operands[j]->rfid][rob.operands[j]->index()]++;
    }
  }

  foreach (i, TRANSREG_COUNT) {
    refcounts[commitrrt[i]->rfid][commitrrt[i]->index()]++;
    refcounts[specrrt[i]->rfid][specrrt[i]->index()]++;
  }

  bool errors = 0;

  foreach (rfid, PHYS_REG_FILE_COUNT) {
    PhysicalRegisterFile& physregs = physregfiles[rfid];
    foreach (i, physregs.size) {
      if unlikely (physregs[i].refcount != refcounts[rfid][i]) {
        logfile << "ERROR: r", i, " refcount is ", physregs[i].refcount, " but should be ", refcounts[rfid][i], endl;
        
        foreach_forward(ROB, r) {
          ReorderBufferEntry& rob = ROB[r];
          foreach (j, MAX_OPERANDS) {
            if ((rob.operands[j]->index() == i) & (rob.operands[j]->rfid == rfid)) logfile << "  ROB ", r, " operand ", j, endl;
          }
        }
        
        foreach (j, TRANSREG_COUNT) {
          if ((commitrrt[j]->index() == i) & (commitrrt[j]->rfid == rfid)) logfile << "  CommitRRT ", arch_reg_names[j], endl;
          if ((specrrt[j]->index() == i) & (specrrt[j]->rfid == rfid)) logfile << "  SpecRRT ", arch_reg_names[j], endl;
        }
        
        errors = 1;
      }
    }
  }

  if (errors) assert(false);
}

void OutOfOrderCore::check_rob() {
  foreach (i, ROB_SIZE) {
    ReorderBufferEntry& rob = ROB[i];
    if (!rob.entry_valid) continue;
    assert(inrange((int)rob.forward_cycle, 0, (MAX_FORWARDING_LATENCY+1)-1));
  }

  foreach (i, rob_states.count) {
    StateList& list = *rob_states[i];
    ReorderBufferEntry* rob;
    foreach_list_mutable(list, rob, entry, nextentry) {
      assert(inrange(rob->index(), 0, ROB_SIZE-1));
      assert(rob->current_state_list == &list);
      if (!((rob->current_state_list != &rob_free_list) ? rob->entry_valid : (!rob->entry_valid))) {
        logfile << "ROB ", rob->index(), " list = ", rob->current_state_list->name, " entry_valid ", rob->entry_valid, endl, flush;
        dump_ooo_state();
        assert(false);
      }
    }
  }
}

ostream& LoadStoreQueueEntry::print(ostream& os) const {
  os << (store ? "st" : "ld"), intstring(index(), -3), " ";
  os << "uuid ", intstring(rob->uop.uuid, 10), " ";
  os << "rob ", intstring(rob->index(), -3), " ";
  os << "r", intstring(rob->physreg->index(), -3);
  if (PHYS_REG_FILE_COUNT > 1) os << "@", coreof(coreid).physregfiles[rob->physreg->rfid].name;
  os << " ";
  if (invalid) {
    os << "< Invalid: fault 0x", hexstring(data, 8), " > ";
  } else {
    if (datavalid)
      os << bytemaskstring((const byte*)&data, bytemask, 8);
    else os << "<    Data Invalid     >";
    os << " @ ";
    if (addrvalid)
      os << "0x", hexstring(physaddr << 3, 48);
    else os << "< Addr Inval >";
  }    
  return os;
}

//
// Barriers must flush the fetchq and stall the frontend until
// after the barrier is consumed. Execution resumes at the address
// in internal register nextrip (rip after the instruction) after
// handling the barrier in microcode.
//
bool OutOfOrderCore::handle_barrier() {
  core_to_external_state();
  assist_func_t assist = (assist_func_t)(Waddr)ctx.commitarf[REG_rip];
  
  if (logable(4)) {
    logfile << "Barrier (", (void*)assist, " ", assist_name(assist), " called from ",
      (RIPVirtPhys(ctx.commitarf[REG_selfrip]).update(ctx)), "; return to ", (void*)(Waddr)ctx.commitarf[REG_nextrip],
      ") at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits", endl, flush;
  }
  
  if (logable(6)) logfile << "Calling assist function at ", (void*)assist, "...", endl, flush; 
  
  update_assist_stats(assist);
  if (logable(6)) {
    logfile << "Before assist:", endl, ctx, endl;
#ifdef PTLSIM_HYPERVISOR
    logfile << sshinfo, endl;
#endif
  }
  
  assist(ctx);
  
  if (logable(6)) {
    logfile << "Done with assist", endl;
    logfile << "New state:", endl;
    logfile << ctx;
#ifdef PTLSIM_HYPERVISOR
    logfile << sshinfo;
#endif
  }

  flush_pipeline(ctx.commitarf[REG_rip]);

#ifndef PTLSIM_HYPERVISOR
  if (requested_switch_to_native) {
    logfile << "PTL call requested switch to native mode at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], endl;
    return false;
  }
#endif
  return true;
}

bool OutOfOrderCore::handle_exception() {
  core_to_external_state();

  if (logable(4)) {
    logfile << "Exception ", exception_name(ctx.exception), " called from rip ", (void*)(Waddr)ctx.commitarf[REG_rip], 
      " at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits", endl, flush;
  }

  //
  // CheckFailed and SkipBlock exceptions are raised by the chk uop.
  // This uop is used at the start of microcoded instructions to assert
  // that certain conditions are true so complex corrective actions can
  // be taken if the check fails.
  //
  // SkipBlock is a special case used for checks at the top of REP loops.
  // Specifically, if the %rcx register is zero on entry to the REP, no
  // action at all is to be taken; the rip should simply advance to
  // whatever is in chk_recovery_rip and execution should resume.
  //
  // CheckFailed exceptions usually indicate the processor needs to take
  // evasive action to avoid a user visible exception. For instance, 
  // CheckFailed is raised when an inlined floating point operand is
  // denormal or otherwise cannot be handled by inlined fastpath uops,
  // or when some unexpected segmentation or page table conditions
  // arise.
  //
  if (ctx.exception == EXCEPTION_SkipBlock) {
    ctx.commitarf[REG_rip] = chk_recovery_rip;
    if (logable(6)) logfile << "SkipBlock pseudo-exception: skipping to ", (void*)(Waddr)ctx.commitarf[REG_rip], endl, flush;
    flush_pipeline(ctx.commitarf[REG_rip]);
    cttotal.start();
    return true;
  }

#ifdef PTLSIM_HYPERVISOR
  //
  // Map PTL internal hardware exceptions to their x86 equivalents,
  // depending on the context. The error_code field should already
  // be filled out.
  //
  // Exceptions not listed here are propagated by microcode
  // rather than the processor itself.
  //
  switch (ctx.exception) {
  case EXCEPTION_PageFaultOnRead:
  case EXCEPTION_PageFaultOnWrite:
  case EXCEPTION_PageFaultOnExec:
    ctx.x86_exception = EXCEPTION_x86_page_fault; break;
  case EXCEPTION_FloatingPointNotAvailable:
    ctx.x86_exception = EXCEPTION_x86_fpu_not_avail; break;
  case EXCEPTION_FloatingPoint:
    ctx.x86_exception = EXCEPTION_x86_fpu; break;
  default:
    logfile << "Unsupported internal exception type ", exception_name(ctx.exception), endl, flush;
    abort();
  }

  if (logable(4)) {
    logfile << ctx;
    logfile << sshinfo;
  }

  ctx.propagate_x86_exception(ctx.x86_exception, ctx.error_code, ctx.cr2);

  flush_pipeline(ctx.commitarf[REG_rip]);

  return true;
#else
  if (logable(6)) 
    logfile << "Exception (", exception_name(ctx.exception), " called from ", (void*)(Waddr)ctx.commitarf[REG_rip], 
      ") at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits", endl, flush;

  stringbuf sb;
  logfile << exception_name(ctx.exception), " detected at fault rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " @ ", 
    total_user_insns_committed, " commits (", total_uops_committed, " uops): genuine user exception (",
    exception_name(ctx.exception), "); aborting", endl;
  logfile << ctx, endl;
  logfile << flush;

  logfile << "Aborting...", endl, flush;
  cerr << "Aborting...", endl, flush;

  abort();
  return false;
#endif
}

#ifdef PTLSIM_HYPERVISOR
bool OutOfOrderCore::handle_interrupt() {
  core_to_external_state();

  if (logable(6)) {
    logfile << "Interrupts pending at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits", endl, flush;
    logfile << "Context at interrupt:", endl;
    logfile << ctx;
    logfile << sshinfo;
    logfile.flush();
  }

  ctx.event_upcall();

  if (logable(6)) {
    logfile << "After interrupt redirect:", endl;
    logfile << ctx;
    logfile << sshinfo;
    logfile.flush();
  }

  flush_pipeline(ctx.commitarf[REG_rip]);

  return true;
}
#endif

struct OutOfOrderMachine: public PTLsimMachine {
  OutOfOrderCore* cores[MAX_CONTEXTS];

  OutOfOrderMachine(const char* name) {
    // Add to the list of available core types
    addmachine(name, this);
  }

  //
  // Construct all the structures necessary to configure
  // the cores. This function is only called once, after
  // all other PTLsim subsystems are brought up.
  //
  virtual bool init(PTLsimConfig& config) {
    foreach (i, contextcount) {
      cores[i] = new OutOfOrderCore(i, contextof(i));
      logfile << "cores[", i, "] = ", cores[i], " (size ", sizeof(OutOfOrderCore), ", issueq at ", &cores[i]->issueq_int0, endl;
      cores[i]->init();
      //
      // Note: in a real cycle accurate model, config may
      // specify various ways of slicing contextcount up
      // into threads, cores and sockets; the appropriate
      // interconnect and cache hierarchy parameters may
      // be specified here.
      //
    }

    init_luts();
    return true;
  }

  //
  // Run the processor model, until a stopping point
  // is hit (as configured elsewhere in config).
  //
  virtual int run(PTLsimConfig& config) {
    logfile << "Starting out-of-order core toplevel loop", endl, flush;

    // wakeup_func = load_filled_callback;
    // icache_wakeup_func = icache_filled_callback;

    foreach (i, contextcount) {
      OutOfOrderCore& core =* cores[i];
      Context& ctx = contextof(i);

      core.flush_pipeline(ctx.commitarf[REG_rip]);

      if (logable(6)) {
        logfile << "VCPU ", i, " initial state:", endl;
        // core.print_state(logfile);
        logfile << endl;
      }
    }

    W64 last_printed_status_at_cycle = 0;
    bool exiting = false;

    while ((iterations < config.stop_at_iteration) & (total_user_insns_committed < config.stop_at_user_insns)) {
      if unlikely (iterations >= config.start_log_at_iteration) {
        if unlikely (!logenable) logfile << "Start logging at level ", config.loglevel, " in cycle ", iterations, endl, flush;
        logenable = 1;
      }

      if unlikely ((sim_cycle - last_printed_status_at_cycle) >= 1000000) {
        logfile << "Completed ", sim_cycle, " cycles, ", total_user_insns_committed, " total commits", endl, flush;
        last_printed_status_at_cycle = sim_cycle;
      }

      //if (logable(6)) logfile << "Cycle ", sim_cycle, ((stall_frontend) ? " (frontend stalled)" : ""), ": commit rip ", (void*)(Waddr)ctx.commitarf[REG_rip], endl;
      if (logable(6)) logfile << "Cycle ", sim_cycle, ":", endl;

      inject_events();

      foreach (i, contextcount) {
        OutOfOrderCore& core =* cores[i];
        Context& ctx = contextof(i);

#ifdef PTLSIM_HYPERVISOR
        if unlikely (ctx.check_events()) core.handle_interrupt();
        if unlikely (!ctx.running) continue;
#endif
        exiting |= core.runcycle();
      }
#ifdef PTLSIM_HYPERVISOR
      exiting |= check_for_async_sim_break();
#endif
      sim_cycle++;
      iterations++;

      if unlikely (exiting) break;
    }

    logfile << "Exiting sequential mode at ", total_user_insns_committed, " commits, ", total_uops_committed, " uops and ", iterations, " iterations (cycles)", endl;

    foreach (i, contextcount) {
      OutOfOrderCore& core =* cores[i];
      Context& ctx = contextof(i);

      core.core_to_external_state();

      if (logable(6) | ((sim_cycle - core.last_commit_at_cycle) > 1024)) {
        logfile << "Core State at end:", endl;
        logfile << ctx;
        core.dump_ooo_state();
      }
    }

    return exiting;
  }
};

OutOfOrderMachine ooomodel("ooo");

OutOfOrderCore& coreof(int coreid) {
  return *ooomodel.cores[coreid];
}
