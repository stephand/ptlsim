//
// PTLsim: Cycle Accurate x86-64 Simulator
// Out-of-Order Core Simulator Configuration
//
// Copyright 2003-2005 Matt T. Yourst <yourst@yourst.com>
//

//
// NOTE: This file only specifies the configuration for the out of order core;
// the uops and functional units are declared in ptlhwdef.h and ptlhwdef.cpp
//

//
// Important Limitations:
//
// - The ROB and physical register file may each have at most 256 entries.
// - The combined load and store queue sizes are limited to 256 entries.
//
// These limits are the result of the 8-bit quantities used for fast parallel
// associative maching; they should be sufficient for any realistic processor
// configuration. 
//
// If more capacity is required, 16-bit associative structures can be enabled,
// but this is not tested yet.
//

//
// Reorder Buffer
//
// IMPORTANT! If you change this to be greater than 256, you MUST
// #define BIG_ROB in ooocore.cpp to use the correct associative
// search logic (16-bit tags vs 8-bit tags).
//

#define MAX_PHYS_REG_FILE_SIZE 256

//
// IMPORTANT! Define this if you are using tags bigger than 255,
// i.e. if ROB_SIZE > 256. This is defined later in ooohwdef.h
// but we need it now.
//
// #define BIG_ROB

#define ROB_SIZE 192

#define PHYS_REG_FILE_COUNT 2
#define PHYS_REG_NULL 0

//
// Load and Store Queues
//
#define LDQ_SIZE 48
#define STQ_SIZE 32

//
// Fetch
//
#define FETCH_QUEUE_SIZE 18
#define FETCH_WIDTH 6

//
// Frontend (Rename and Decode)
//
#define FRONTEND_WIDTH 4
#define FRONTEND_STAGES 4

//
// Dispatch
//
#define DISPATCH_WIDTH 4

//
// Clustering, Issue Queues and Bypass Network
//
#define MAX_ISSUE_WIDTH 8
#define MAX_FORWARDING_LATENCY 1
#define MAX_CLUSTERS 2

#ifdef DECLARE_CLUSTERS
const Cluster clusters[MAX_CLUSTERS] = {
  {"int0", 4, (FU_ALU0|FU_LDU0|FU_STU0|FU_FPU0)},
  {"int1", 4, (FU_ALU1|FU_LDU0|FU_STU1|FU_FPU1)},
};

static const byte intercluster_latency_map[MAX_CLUSTERS][MAX_CLUSTERS] = {
// I0 I1 FP <-to
  {0, 1}, // from I0
  {1, 0}, // from I1
};

static const byte intercluster_bandwidth_map[MAX_CLUSTERS][MAX_CLUSTERS] = {
// I0 I1 LD FP <-to
  {4, 4}, // from I0
  {4, 4}, // from I1
};

IssueQueue<16> issueq_int0;
IssueQueue<16> issueq_int1;

#define foreach_issueq(expr) { issueq_int0.expr; issueq_int1.expr; }

void sched_get_all_issueq_free_slots(int* a) {
  a[0] = issueq_int0.remaining();
  a[1] = issueq_int1.remaining();
}

#define issueq_operation_on_cluster_with_result(cluster, rc, expr) \
  switch (cluster) { \
  case 0: rc = issueq_int0.expr; break; \
  case 1: rc = issueq_int1.expr; break; \
  }

#define DeclareClusteredROBList(name, description) StateList name[MAX_CLUSTERS] = { \
  StateList("" description "-int0", rob_states), \
  StateList("" description "-int1", rob_states) }

#endif // DECLARE_CLUSTERS

#ifdef DECLARE_PHYS_REG_FILES

//
// Physical register file parameters
//

PhysicalRegisterFile physregfiles[PHYS_REG_FILE_COUNT] = {
  PhysicalRegisterFile("int0", 0, 128),
  PhysicalRegisterFile("int1", 1, 128),
};

#define PHYS_REG_FILE_MASK_A (1 << 0)
#define PHYS_REG_FILE_MASK_B (1 << 1)

const W32 phys_reg_files_accessible_from_cluster[MAX_CLUSTERS] = {
  PHYS_REG_FILE_MASK_A, // int0
  PHYS_REG_FILE_MASK_B, // int1
};

#endif // DECLARE_PHYS_REG_FILES

//
// Writeback
//
#define WRITEBACK_WIDTH 4

//
// Commit
//
#define COMMIT_WIDTH 4

