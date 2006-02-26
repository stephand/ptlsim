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
// Global limits
//

#define MAX_ISSUE_WIDTH 8
#define MAX_PHYS_REG_FILE_SIZE 256
#define PHYS_REG_NULL 0

//
// IMPORTANT! If you change this to be greater than 256, you MUST
// #define BIG_ROB below to use the correct associative search logic
// (16-bit tags vs 8-bit tags).
//
//#define BIG_ROB

#define ROB_SIZE 192

#define PHYS_REG_FILE_COUNT 2

//
// Load and Store Queues
//
#define LDQ_SIZE 96
#define STQ_SIZE 48

//
// Fetch
//
#define FETCH_QUEUE_SIZE 18
#define FETCH_WIDTH 6

//
// Frontend (Rename and Decode)
//
#define FRONTEND_WIDTH 3
#define FRONTEND_STAGES 4

//
// Dispatch
//
#define DISPATCH_WIDTH 3

//
// Writeback
//
#define WRITEBACK_WIDTH 3

//
// Commit
//
#define COMMIT_WIDTH 3

//
// Clustering, Issue Queues and Bypass Network
//
#define MAX_FORWARDING_LATENCY 2
#define MAX_CLUSTERS 4

#ifdef DECLARE_CLUSTERS

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

static const byte intercluster_latency_map[MAX_CLUSTERS][MAX_CLUSTERS] = {
// I0 I1 LD FP <-to
  {0, 1, 0, 2}, // from I0
  {1, 0, 0, 2}, // from I1
  {0, 0, 0, 2}, // from LD
  {2, 2, 2, 0}, // from FP
};

static const byte intercluster_bandwidth_map[MAX_CLUSTERS][MAX_CLUSTERS] = {
// I0 I1 LD FP <-to
  {2, 2, 1, 1}, // from I0
  {2, 2, 1, 1}, // from I1
  {1, 1, 2, 2}, // from LD
  {1, 1, 1, 2}, // from FP
};

IssueQueue<16> issueq_int0;
IssueQueue<16> issueq_int1;
IssueQueue<16> issueq_ld;
IssueQueue<16> issueq_fp;

#define foreach_issueq(expr) { issueq_int0.expr; issueq_int1.expr; issueq_ld.expr; issueq_fp.expr; }

void sched_get_all_issueq_free_slots(int* a) {
  a[0] = issueq_int0.remaining();
  a[1] = issueq_int1.remaining();
  a[2] = issueq_ld.remaining();
  a[3] = issueq_fp.remaining();
}

#define issueq_operation_on_cluster_with_result(cluster, rc, expr) \
  switch (cluster) { \
  case 0: rc = issueq_int0.expr; break; \
  case 1: rc = issueq_int1.expr; break; \
  case 2: rc = issueq_ld.expr; break; \
  case 3: rc = issueq_fp.expr; break; \
  }

#define DeclareClusteredROBList(name, description, flags) StateList name[MAX_CLUSTERS] = { \
  StateList("" description "-int0", rob_states, flags), \
  StateList("" description "-int1", rob_states, flags), \
  StateList("" description "-ld", rob_states, flags), \
  StateList("" description "-fp", rob_states, flags) }

#endif // DECLARE_CLUSTERS

#ifdef DECLARE_PHYS_REG_FILES

//
// Physical register file parameters
//

PhysicalRegisterFile physregfiles[PHYS_REG_FILE_COUNT] = {
  PhysicalRegisterFile("int", 0, 128),
  PhysicalRegisterFile("fp", 1, 128),
};

#define PHYS_REG_FILE_MASK_INT (1 << 0)
#define PHYS_REG_FILE_MASK_FP (1 << 1)

const W32 phys_reg_files_accessible_from_cluster[MAX_CLUSTERS] = {
  PHYS_REG_FILE_MASK_INT, // int0
  PHYS_REG_FILE_MASK_INT, // int1
  PHYS_REG_FILE_MASK_INT, // ld
  PHYS_REG_FILE_MASK_FP,  // fp
};

#endif
