// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Out-of-Order Core Simulator Configuration
//
// Copyright 2003-2006 Matt T. Yourst <yourst@yourst.com>
//

// With these disabled, simulation is faster
#define ENABLE_CHECKS
#define ENABLE_LOGGING

#ifndef _OOOCORE_H_
#define _OOOCORE_H_

#define ENABLE_SIM_TIMING
#ifdef ENABLE_SIM_TIMING
#define start_timer(ct) ct.start()
#define stop_timer(ct) ct.stop()
#else
#define start_timer(ct)
#define stop_timer(ct)
#endif

#define MAX_OPERANDS 4
#define RA 0
#define RB 1
#define RC 2
#define RS 3

#define PERFECT_CACHE

namespace OutOfOrderModel {
  //
  // NOTE: This file only specifies the configuration for the out of order core;
  // the uops and functional units are declared in ptlhwdef.h and ptlhwdef.cpp
  //
  
  //
  // Global limits
  //
  
  const int MAX_ISSUE_WIDTH = 8;
  
  // Largest size of any physical register file or the store queue:
  const int MAX_PHYS_REG_FILE_SIZE = 128;
  const int PHYS_REG_NULL = 0;
  
  //
  // IMPORTANT! If you change this to be greater than 256, you MUST
  // #define BIG_ROB below to use the correct associative search logic
  // (16-bit tags vs 8-bit tags).
  //
  //#define BIG_ROB
  
  const int ROB_SIZE = 128;
  
  // Maximum number of branches in the pipeline at any given time
  const int MAX_BRANCHES_IN_FLIGHT = 16;
  
  // Set this to combine the integer and FP phys reg files:
  // #define UNIFIED_INT_FP_PHYS_REG_FILE
  
#ifdef UNIFIED_INT_FP_PHYS_REG_FILE
  // unified, br, st
  const int PHYS_REG_FILE_COUNT = 3;
#else
  // int, fp, br, st
  const int PHYS_REG_FILE_COUNT = 4;
#endif
  
  //
  // Load and Store Queues
  //
  const int LDQ_SIZE = 32;
  const int STQ_SIZE = 32;

  //
  // Fetch
  //
  const int FETCH_QUEUE_SIZE = 32;
  const int FETCH_WIDTH = 4;

  //
  // Frontend (Rename and Decode)
  //
  const int FRONTEND_WIDTH = 4;
  const int FRONTEND_STAGES = 1;

  //
  // Dispatch
  //
  const int DISPATCH_WIDTH = 4;

  //
  // Writeback
  //
  const int WRITEBACK_WIDTH = 4;

  //
  // Commit
  //
  const int COMMIT_WIDTH = 4;

  //
  // Clustering, Issue Queues and Bypass Network
  //
  const int MAX_FORWARDING_LATENCY = 2;
  const int MAX_CLUSTERS = 4;

  enum { PHYSREG_NONE, PHYSREG_FREE, PHYSREG_WAITING, PHYSREG_BYPASS, PHYSREG_WRITTEN, PHYSREG_ARCH, PHYSREG_PENDINGFREE, MAX_PHYSREG_STATE };
  static const char* physreg_state_names[MAX_PHYSREG_STATE] = {"none", "free", "waiting", "bypass", "written", "arch", "pendingfree"};

#ifndef STATS_ONLY

  struct OutOfOrderCore;
  OutOfOrderCore& coreof(int coreid);

  struct ReorderBufferEntry;

  //
  // Issue queue based scheduler with broadcast
  //
#ifdef BIG_ROB
  typedef W16 issueq_tag_t;
#else
  typedef byte issueq_tag_t;
#endif

  template <int size, int operandcount = MAX_OPERANDS>
  struct IssueQueue {
#ifdef BIG_ROB
    typedef FullyAssociativeTags16bit<size, size> assoc_t;
    typedef vec8w vec_t;
#else
    typedef FullyAssociativeTags8bit<size, size> assoc_t;
    typedef vec16b vec_t;
#endif

    typedef issueq_tag_t tag_t;

    static const int SIZE = size;

    assoc_t uopids;
    assoc_t tags[operandcount];

    // States:
    //             V I
    // free        0 0
    // dispatched  1 0
    // issued      1 1
    // complete    0 1

    bitvec<size> valid;
    bitvec<size> issued;
    bitvec<size> allready;
    int count;
    byte coreid;

    bool remaining() const { return (size - count); }
    bool empty() const { return (!count); }
    bool full() const { return (!remaining()); }

    int uopof(int slot) const {
      return uopids[slot];
    }

    int slotof(int uopid) const {
      return uopids.search(uopid);
    }

    void reset(int coreid);
    void clock();
    bool insert(tag_t uopid, const tag_t* operands, const tag_t* preready);
    bool broadcast(tag_t uopid);
    int issue();
    bool replay(int slot, const tag_t* operands, const tag_t* preready);
    bool remove(int slot);
    ostream& print(ostream& os) const;
    void tally_broadcast_matches(tag_t sourceid, const bitvec<size>& mask, int operand) const;

    //
    // Replay a uop that has already issued once.
    // The caller may add or reset dependencies here as needed.
    //
    bool replay(int slot) {
      issued[slot] = 0;
      return true;
    }

    //
    // Remove an entry from the issue queue after it has completed,
    // or in the process of annulment.
    //
    bool release(int slot) {
      remove(slot);
      return true;
    }

    bool annul(int slot) {
      remove(slot);
      return true;
    }

    bool annuluop(int uopid) {
      int slot = slotof(uopid);
      if (slot < 0) return false;
      remove(slot);
      return true;
    }

    OutOfOrderCore& getcore() const { return coreof(coreid); }
  };

  template <int size, int operandcount>
  static inline ostream& operator <<(ostream& os, const IssueQueue<size, operandcount>& issueq) {
    return issueq.print(os);
  }

  //
  // Iterate through a linked list of objects where each object directly inherits
  // only from the selfqueuelink class or otherwise has a selfqueuelink object
  // as the first member.
  //
  // This iterator supports mutable lists, meaning the current entry (obj) may
  // be safely removed from the list and/or moved to some other list without
  // affecting the next object processed.
  //
  // This does NOT mean you can remove any object from the list other than the
  // current object obj - to do this, copy the list of pointers to an array and
  // then process that instead.
  //
#define foreach_list_mutable_linktype(L, obj, entry, nextentry, linktype) \
  linktype* entry; \
  linktype* nextentry; \
  for (entry = (L).next, nextentry = entry->next, prefetch(entry->next), obj = (typeof(obj))entry; \
    entry != &(L); entry = nextentry, nextentry = entry->next, prefetch(nextentry), obj = (typeof(obj))entry)

#define foreach_list_mutable(L, obj, entry, nextentry) foreach_list_mutable_linktype(L, obj, entry, nextentry, selfqueuelink)

  struct StateList;

  struct ListOfStateLists: public array<StateList*, 64> {
    int count;

    int add(StateList* list);
    void reset();
  };

  struct StateList: public selfqueuelink {
    const char* name;
    int count;
    int listid;
    W64 dispatch_source_counter;
    W64 issue_source_counter;
    W32 flags;

    StateList() { }

    void init(const char* name, ListOfStateLists& lol, W32 flags = 0) {
      reset();
      this->name = name;
      this->flags = flags;
      count = 0;
      listid = lol.add(this);
      dispatch_source_counter = 0;
      issue_source_counter = 0;
    }

    StateList(const char* name, ListOfStateLists& lol, W32 flags = 0) {
      init(name, lol, flags);
    }

    // simulated asymmetric c++ array constructor:
    StateList& operator ()(const char* name, ListOfStateLists& lol, W32 flags = 0) {
      init(name, lol, flags);
      return *this;
    }

    void reset() {
      selfqueuelink::reset();
      count = 0;
    }

    selfqueuelink* dequeue() {
      if (empty())
        return null;
      count--;
      selfqueuelink* obj = removehead();
      return obj;
    }

    selfqueuelink* enqueue(selfqueuelink* entry) {
      entry->addtail(this);
      count++;
      return entry;
    }

    selfqueuelink* enqueue_after(selfqueuelink* entry, selfqueuelink* preventry) {
      if (preventry) entry->addhead(preventry); else entry->addhead(this);
      count++;
      return entry;
    }

    selfqueuelink* remove(selfqueuelink* entry) {
      assert(entry->linked());
      entry->unlink();
      count--;
      return entry;
    }

    selfqueuelink* peek() {
      return (empty()) ? null : head();
    }

    void checkvalid();
  };

  int ListOfStateLists::add(StateList* list) {
    assert(count < lengthof(data));
    data[count] = list;
    return count++;
  }

  void ListOfStateLists::reset() {
    foreach (i, count) {
      data[i]->reset();
    }
  }

  template <typename T> 
  static void print_list_of_state_lists(ostream& os, const ListOfStateLists& lol, const char* title);

  //
  // Fetch Buffers
  //
  struct BranchPredictorUpdateInfo: public PredictorUpdate {
    int stack_recover_idx;
    int bptype;
    W64 ripafter;
  };

  struct FetchBufferEntry: public TransOp {
    RIPVirtPhys rip;
    W64 uuid;
    TransOp* origop;
    uopimpl_func_t synthop;
    BranchPredictorUpdateInfo predinfo;
    BasicBlock* bb;
    W16 index;

    int init(int index) { this->index = index; return 0; }
    void validate() { }

    FetchBufferEntry() { }
    
    FetchBufferEntry(const TransOp& transop) {
      *((TransOp*)this) = transop;
      origop = null;
    }
  };

  //
  // ReorderBufferEntry
  //

  struct OutOfOrderCore;
  struct PhysicalRegister;
  struct LoadStoreQueueEntry;

  //
  // Reorder Buffer (ROB) structure, used for tracking all uops in flight.
  // This same structure is used to represent both dispatched but not yet issued 
  // uops as well as issued uops.
  //
  struct ReorderBufferEntry: public selfqueuelink {
    FetchBufferEntry uop;
    struct StateList* current_state_list;
    PhysicalRegister* physreg;
    PhysicalRegister* operands[MAX_OPERANDS];
    LoadStoreQueueEntry* lsq;
    W16s idx;
    W16s cycles_left; // execution latency counter, decremented every cycle when executing
    W16s forward_cycle; // forwarding cycle after completion
    W16s lfrqslot;
    W16s iqslot;
    W16  executable_on_cluster_mask;
    W8s  cluster;
    W8   coreid;
    byte fu;
    byte consumer_count;
    PTEUpdate pteupdate;
    Waddr origvirt;
    byte entry_valid:1, load_store_second_phase:1, all_consumers_off_bypass:1, dest_renamed_before_writeback:1, no_branches_between_renamings:1, transient:1;

    int index() const { return idx; }
    void validate() { entry_valid = true; }

    void changestate(StateList& newqueue, bool place_at_head = false, ReorderBufferEntry* prevrob = null) {
      if (current_state_list)
        current_state_list->remove(this);
      current_state_list = &newqueue;
      if (place_at_head) newqueue.enqueue_after(this, prevrob); else newqueue.enqueue(this);
    }

    void init(int idx);
    void reset();
    bool ready_to_issue() const;
    bool ready_to_commit() const;
    StateList& get_ready_to_issue_list() const;
    bool find_sources();
    int forward();
    int select_cluster();
    int issue();
    void* addrgen(LoadStoreQueueEntry& state, Waddr& origaddr, W64 ra, W64 rb, W64 rc, PTEUpdate& pteupdate, Waddr& addr, int& exception, PageFaultErrorCode& pfec, bool& annul);
    bool handle_common_load_store_exceptions(LoadStoreQueueEntry& state, Waddr& origaddr, Waddr& addr, int& exception, PageFaultErrorCode& pfec);
    int issuestore(LoadStoreQueueEntry& state, Waddr& origvirt, W64 ra, W64 rb, W64 rc, bool rcready, PTEUpdate& pteupdate);
    int issueload(LoadStoreQueueEntry& state, Waddr& origvirt, W64 ra, W64 rb, W64 rc, PTEUpdate& pteupdate);
    void release();
    W64 annul(bool keep_misspec_uop, bool return_first_annulled_rip = false);
    W64 annul_after() { return annul(true); }
    W64 annul_after_and_including() { return annul(false); }
    int commit();
    void replay();
    int pseudocommit();
    void redispatch(const bitvec<MAX_OPERANDS>& dependent_operands, ReorderBufferEntry* prevrob);
    void redispatch_dependents(bool inclusive = true);
    void loadwakeup();
    ostream& print(ostream& os) const;
    stringbuf& get_operand_info(stringbuf& sb, int operand) const;
    ostream& print_operand_info(ostream& os, int operand) const;

    OutOfOrderCore& getcore() const { return coreof(coreid); }
  };

  static inline ostream& operator <<(ostream& os, const ReorderBufferEntry& rob) {
    return rob.print(os);
  }

  //
  // Load/Store Queue
  //
#define LSQ_SIZE (LDQ_SIZE + STQ_SIZE)

  struct LoadStoreQueueEntry: public SFR {
    ReorderBufferEntry* rob;
    W16 idx;
    byte coreid;
    W8s mbtag;
    W8 store:1, entry_valid:1;
    W32 padding;

    LoadStoreQueueEntry() { }

    int index() const { return idx; }

    void reset() {
      int oldidx = idx;
      setzero(*this);
      idx = oldidx;
      mbtag = -1;
    }

    void init(int idx) {
      this->idx = idx;
      reset();
    }

    void validate() { entry_valid = 1; }
  
    ostream& print(ostream& os) const;

    LoadStoreQueueEntry& operator =(const SFR& sfr) {
      *((SFR*)this) = sfr;
      return *this;
    }

    OutOfOrderCore& getcore() const { return coreof(coreid); }
  };

  static inline ostream& operator <<(ostream& os, const LoadStoreQueueEntry& lsq) {
    return lsq.print(os);
  }

  //
  // Physical Register File
  //
  struct PhysicalRegister: public selfqueuelink {
    ReorderBufferEntry* rob;
    W64 data;
    W16 flags;
    W16 idx;
    W8  coreid;
    W8  rfid;
    W8  state;
    W8  archreg;
    W8  all_consumers_sourced_from_bypass:1;
    W16s refcount;

    StateList& get_state_list(int state) const;
    StateList& get_state_list() const { return get_state_list(this->state); }

    void changestate(int newstate) {
      if likely (state != PHYSREG_NONE) get_state_list(state).remove(this);
      state = newstate;
      get_state_list(state).enqueue(this);
    }

    void init(int coreid, int rfid, int idx) {
      this->coreid = coreid;
      this->rfid = rfid;
      this->idx = idx;
      reset();
    }

    void addref() { refcount++; }
    void unref() { refcount--; assert(refcount >= 0); }
    void addref(const ReorderBufferEntry& rob) { addref(); }
    void unref(const ReorderBufferEntry& rob) { unref(); }
    void addspecref(int archreg) { addref(); }
    void unspecref(int archreg) { unref(); }
    void addcommitref(int archreg) { addref(); }
    void uncommitref(int archreg) { unref(); }
    bool referenced() const { return (refcount > 0); }
    bool nonnull() const { return (index() != PHYS_REG_NULL); }
    bool allocated() const { return (state != PHYSREG_FREE); }
    void commit() { changestate(PHYSREG_ARCH); }
    void complete() { changestate(PHYSREG_BYPASS); }
    void writeback() { changestate(PHYSREG_WRITTEN); }

    void free() {
      changestate(PHYSREG_FREE);
      rob = 0;
      refcount = 0;
      all_consumers_sourced_from_bypass = 1;
    }

    void reset() {
      selfqueuelink::reset();
      state = PHYSREG_NONE;
      free();
    }

    int index() const { return idx; }
    bool valid() const { return ((flags & FLAG_INV) == 0); }
    bool ready() const { return ((flags & FLAG_WAIT) == 0); }

    OutOfOrderCore& getcore() const { return coreof(coreid); }
  };

  ostream& operator <<(ostream& os, const PhysicalRegister& physreg);

  struct PhysicalRegisterFile: public array<PhysicalRegister, MAX_PHYS_REG_FILE_SIZE> {
    byte coreid;
    byte rfid;
    W16 size;
    const char* name;
    StateList states[MAX_PHYSREG_STATE];
    W64 allocations;
    W64 frees;

    PhysicalRegisterFile() { }

    PhysicalRegisterFile(const char* name, int coreid, int rfid, int size) {
      init(name, coreid, rfid, size); reset();
    }

    PhysicalRegisterFile& operator ()(const char* name, int coreid, int rfid, int size) {
      init(name, coreid, rfid, size); reset(); return *this;
    }

    void init(const char* name, int coreid, int rfid, int size);
    bool remaining() const { return (!states[PHYSREG_FREE].empty()); }
    PhysicalRegister* alloc(int r = -1);
    void reset();
    ostream& print(ostream& os) const;

    OutOfOrderCore& getcore() const { return coreof(coreid); }
  };

  static inline ostream& operator <<(ostream& os, const PhysicalRegisterFile& physregs) {
    return physregs.print(os);
  }

  //
  // Register Rename Table
  //
  struct RegisterRenameTable: public array<PhysicalRegister*, TRANSREG_COUNT> {
#ifdef ENABLE_TRANSIENT_VALUE_TRACKING
    bitvec<TRANSREG_COUNT> renamed_in_this_basic_block;
#endif
    ostream& print(ostream& os) const;
  };

  static inline ostream& operator <<(ostream& os, const RegisterRenameTable& rrt) {
    return rrt.print(os);
  }

  enum {
    ISSUE_COMPLETED = 1,      // issued correctly
    ISSUE_NEEDS_REPLAY = 0,   // fast scheduling replay
    ISSUE_MISSPECULATED = -1, // mis-speculation: redispatch dependent slice
    ISSUE_NEEDS_REFETCH = -2, // refetch from RIP of bad insn
  };

  enum {
    COMMIT_RESULT_NONE = 0,   // no instructions committed: some uops not ready
    COMMIT_RESULT_OK = 1,     // committed
    COMMIT_RESULT_EXCEPTION = 2, // exception
    COMMIT_RESULT_BARRIER = 3,// barrier; branch to microcode (brp uop)
    COMMIT_RESULT_SMC = 4,    // self modifying code detected
    COMMIT_RESULT_STOP = 5    // stop processor model (shutdown)
  };

  // Branch predictor outcomes:
  enum { MISPRED = 0, CORRECT = 1 };

  //
  // Lookup tables (LUTs):
  //
  struct Cluster {
    char* name;
    W16 issue_width;
    W32 fu_mask;
  };

  extern const Cluster clusters[MAX_CLUSTERS];
  extern byte uop_executable_on_cluster[OP_MAX_OPCODE];
  extern W32 forward_at_cycle_lut[MAX_CLUSTERS][MAX_FORWARDING_LATENCY+1];
  extern const byte archdest_can_commit[TRANSREG_COUNT];
  extern const byte archdest_is_visible[TRANSREG_COUNT];

  //
  // Out-of-order core
  //
  struct OutOfOrderCore {
    int coreid;
    Context& ctx;
    BranchPredictorInterface branchpred;
    ListOfStateLists rob_states;
    ListOfStateLists physreg_states;
    ListOfStateLists lsq_states;

    //
    // Issue Queues (one per cluster)
    //
    IssueQueue<16> issueq_int0;
    IssueQueue<16> issueq_int1;
    IssueQueue<16> issueq_ld;
    IssueQueue<16> issueq_fp;

    // Instantiate any issueq sizes used above:
#define declare_issueq_templates template struct IssueQueue<16>

#define foreach_issueq(expr) { issueq_int0.expr; issueq_int1.expr; issueq_ld.expr; issueq_fp.expr; }
  
    void sched_get_all_issueq_free_slots(int* a) {
      a[0] = issueq_int0.remaining();
      a[1] = issueq_int1.remaining();
      a[2] = issueq_ld.remaining();
      a[3] = issueq_fp.remaining();
    }

#define issueq_operation_on_cluster_with_result(core, cluster, rc, expr) \
  switch (cluster) { \
  case 0: rc = core.issueq_int0.expr; break; \
  case 1: rc = core.issueq_int1.expr; break; \
  case 2: rc = core.issueq_ld.expr; break; \
  case 3: rc = core.issueq_fp.expr; break; \
  }

#define per_cluster_stats_update(prefix, cluster, expr) \
  switch (cluster) { \
  case 0: prefix.int0 expr; break; \
  case 1: prefix.int1 expr; break; \
  case 2: prefix.ld expr; break; \
  case 3: prefix.fp expr; break; \
  }

#define per_physregfile_stats_update(prefix, rfid, expr) \
  switch (rfid) { \
  case 0: prefix.integer expr; break; \
  case 1: prefix.fp expr; break; \
  case 2: prefix.st expr; break; \
  case 3: prefix.br expr; break; \
  }

#define issueq_operation_on_cluster(core, cluster, expr) { int dummyrc; issueq_operation_on_cluster_with_result(core, cluster, dummyrc, expr); }

#define for_each_cluster(iter) foreach (iter, MAX_CLUSTERS)
#define for_each_operand(iter) foreach (iter, MAX_OPERANDS)

    //
    // Each ROB's state can be linked into at most one of the
    // following rob_xxx_list lists at any given time; the ROB's
    // current_state_list points back to the list it belongs to.
    //
    StateList rob_free_list;                             // Free ROB entyry
    StateList rob_frontend_list;                         // Frontend in progress (artificial delay)
    StateList rob_ready_to_dispatch_list;                // Ready to dispatch
    StateList rob_dispatched_list[MAX_CLUSTERS];         // Dispatched but waiting for operands
    StateList rob_ready_to_issue_list[MAX_CLUSTERS];     // Ready to issue (all operands ready)
    StateList rob_ready_to_store_list[MAX_CLUSTERS];     // Ready to store (all operands except possibly rc are ready)
    StateList rob_ready_to_load_list[MAX_CLUSTERS];      // Ready to load (all operands ready)
    StateList rob_issued_list[MAX_CLUSTERS];             // Issued and in progress (or for loads, returned here after address is generated)
    StateList rob_completed_list[MAX_CLUSTERS];          // Completed and result in transit for local and global forwarding
    StateList rob_ready_to_writeback_list[MAX_CLUSTERS]; // Completed; result ready to writeback in parallel across all cluster register files
    StateList rob_cache_miss_list;                       // Loads only: wait for cache miss to be serviced
    StateList rob_ready_to_commit_queue;                 // Ready to commit

    enum {
      ROB_STATE_READY = (1 << 0),
      ROB_STATE_IN_ISSUE_QUEUE = (1 << 1),
      ROB_STATE_PRE_READY_TO_DISPATCH = (1 << 2)
    };

#define InitClusteredROBList(name, description, flags) \
  name[0](description "-int0", rob_states, flags); \
  name[1](description "-int1", rob_states, flags); \
  name[2](description "-ld", rob_states, flags); \
  name[3](description "-fp", rob_states, flags)

    // Default constructor to bind a core to a specific hardware context
    OutOfOrderCore(int coreid_, Context& ctx_): coreid(coreid_), ctx(ctx_) { }

    //
    // Initialize all structures for the first time
    //
    void init() {
      //
      // ROB states
      //
      rob_free_list("free", rob_states, 0);
      rob_frontend_list("frontend", rob_states, ROB_STATE_PRE_READY_TO_DISPATCH);
      rob_ready_to_dispatch_list("ready-to-dispatch", rob_states, 0);
      InitClusteredROBList(rob_dispatched_list, "dispatched", ROB_STATE_IN_ISSUE_QUEUE),
        InitClusteredROBList(rob_ready_to_issue_list, "ready-to-issue", ROB_STATE_IN_ISSUE_QUEUE);
      InitClusteredROBList(rob_ready_to_store_list, "ready-to-store", ROB_STATE_IN_ISSUE_QUEUE);
      InitClusteredROBList(rob_ready_to_load_list, "ready-to-load", ROB_STATE_IN_ISSUE_QUEUE);
      InitClusteredROBList(rob_issued_list, "issued", 0);
      InitClusteredROBList(rob_completed_list, "completed", ROB_STATE_READY);
      InitClusteredROBList(rob_ready_to_writeback_list, "ready-to-write", ROB_STATE_READY);
      rob_cache_miss_list("cache-miss", rob_states, 0);
      rob_ready_to_commit_queue("ready-to-commit", rob_states, ROB_STATE_READY);
      //
      // Physical register files
      //
      physregfiles[0]("int", coreid, 0, 128);
      physregfiles[1]("fp", coreid, 1, 128);
      physregfiles[2]("st", coreid, 2, STQ_SIZE);
      physregfiles[3]("br", coreid, 3, MAX_BRANCHES_IN_FLIGHT);
      //
      // Miscellaneous
      //
      branchpred.init();
      fetch_uuid = 0;
      current_icache_block = 0;
      round_robin_reg_file_offset = 0;
      smc_invalidate_pending = 0;
    }

    //
    // Physical Registers
    //

    enum { PHYS_REG_FILE_INT, PHYS_REG_FILE_FP, PHYS_REG_FILE_ST, PHYS_REG_FILE_BR };

    enum {  
      PHYS_REG_FILE_MASK_INT = (1 << 0),
      PHYS_REG_FILE_MASK_FP  = (1 << 1),
      PHYS_REG_FILE_MASK_ST  = (1 << 2),
      PHYS_REG_FILE_MASK_BR  = (1 << 3)
    };

    // Major core structures
    PhysicalRegisterFile physregfiles[PHYS_REG_FILE_COUNT];
    Queue<ReorderBufferEntry, ROB_SIZE> ROB;
    Queue<LoadStoreQueueEntry, LSQ_SIZE> LSQ;
    RegisterRenameTable specrrt;
    RegisterRenameTable commitrrt;

    // Fetch-related structures
    Queue<FetchBufferEntry, FETCH_QUEUE_SIZE> fetchq;
    RIPVirtPhys fetchrip;
    BasicBlock* current_basic_block;
    int current_basic_block_transop_index;
    int bytes_in_current_insn;
    int uop_in_basic_block;
    bool stall_frontend;
    bool waiting_for_icache_fill;
    // How many bytes of x86 code to fetch into decode buffer at once
    static const int ICACHE_FETCH_GRANULARITY = 16;
    // Last block in icache we fetched into our buffer
    W64 current_icache_block;
    W64 fetch_uuid;
    int loads_in_flight;
    int stores_in_flight;

    // Dispatch
    int round_robin_reg_file_offset;
    static const int DISPATCH_DEADLOCK_COUNTDOWN_CYCLES = 64;
    int dispatch_deadlock_countdown;

    // Issue
    W32 fu_avail;
    ReorderBufferEntry* robs_on_fu[FU_COUNT];
    struct LoadStoreAliasPredictor: public FullyAssociativeTags<W64, 8> { };
    LoadStoreAliasPredictor lsap;
    int loads_in_this_cycle;
    W32 load_to_store_parallel_forwarding_buffer[LOAD_FU_COUNT];

    // Commit
    W64 chk_recovery_rip;
    W64 last_commit_at_cycle;
    bool smc_invalidate_pending;
    RIPVirtPhys smc_invalidate_rvp;

    // Pipeline Stages
    bool runcycle();
    void fetch();
    void rename();
    void frontend();
    int dispatch();
    int issue(int cluster);
    int complete(int cluster);
    int transfer(int cluster);
    int writeback(int cluster);
    int commit();

    // Pipeline Flush Handling
    bool handle_barrier();
    bool handle_exception();
    bool handle_interrupt();

    // Pipeline Control and Fetching
    void reset_fetch_unit(W64 realrip);
    void flush_pipeline(W64 realrip);
    void external_to_core_state();
    void core_to_external_state() { }
    void annul_ras_updates_in_fetchq();
    BasicBlock* fetch_or_translate_basic_block(Context& ctx, const RIPVirtPhys& rvp);
    void redispatch_deadlock_recovery();

    // Debugging
    void dump_ooo_state();
    void print_rob(ostream& os);
    void print_lsq(ostream& os);
    void check_refcounts();
    void check_rob();
    void print_rename_tables(ostream& os);
    void log_forwarding(const ReorderBufferEntry* source, const ReorderBufferEntry* target, int operand);
    OutOfOrderCore& getcore() const { return coreof(coreid); }
  };

#endif // STATS_ONLY

#ifdef DECLARE_STRUCTURES
  //
  // The following configuration has two integer/store clusters with a single cycle
  // latency between them, but both clusters can access the load pseudo-cluster with
  // no extra cycle. The floating point cluster is two cycles from everything else.
  //

  const Cluster clusters[MAX_CLUSTERS] = {
    {"int0",  2, (FU_ALU0|FU_STU0)},
    {"int1",  2, (FU_ALU1|FU_STU1)},
    {"ld",    2, (FU_LDU0|FU_LDU1)},
    {"fp",    2, (FU_FPU0|FU_FPU1)},
  };

  const byte intercluster_latency_map[MAX_CLUSTERS][MAX_CLUSTERS] = {
    // I0 I1 LD FP <-to
    {0, 1, 0, 2}, // from I0
    {1, 0, 0, 2}, // from I1
    {0, 0, 0, 2}, // from LD
    {2, 2, 2, 0}, // from FP
  };

  const byte intercluster_bandwidth_map[MAX_CLUSTERS][MAX_CLUSTERS] = {
    // I0 I1 LD FP <-to
    {2, 2, 1, 1}, // from I0
    {2, 2, 1, 1}, // from I1
    {1, 1, 2, 2}, // from LD
    {1, 1, 1, 2}, // from FP
  };
#endif // DECLARE_STRUCTURES

  //
  // This part is used when parsing stats.h to build the
  // data store template; these must be in sync with the
  // corresponding definitions elsewhere.
  //
#ifdef DSTBUILD
  static const char* cluster_names[MAX_CLUSTERS] = {"int0", "int1", "ld", "fp"};
#endif
};

#endif // _OOOCORE_H_
