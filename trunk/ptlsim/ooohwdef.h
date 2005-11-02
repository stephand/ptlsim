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

#define MAX_ISSUE_WIDTH 8

//
// Reorder Buffer
//
#define ROB_SIZE 128

//
// Physical Register File
//
#define PHYS_REG_FILE_SIZE 192
#define PHYS_REG_NULL (PHYS_REG_FILE_SIZE - 1)
#define PHYS_REG_ARCH_BASE (PHYS_REG_FILE_SIZE - 64) // 256 - 64 = 192

//
// Load and Store Queues
//
#define LDQ_SIZE 32
#define STQ_SIZE 24

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
// Clustering, Issue Queues and Bypass Network
//
#define MAX_FORWARDING_LATENCY 2
#define MAX_CLUSTERS 4

//
// IMPORTANT: 
// 
// The clusters and issue queues must be arranged such that in each 
// cycle, all stores issue befor all loads. This ordering ensures 
// parallel store-to-load forwarding can be simulated without extra
// effort and avoids infinite replay loops when loads and stores in
// the same cycle alias each other.
//
// This requirement implies that loads be routed into a separate
// issue queue(s), even if that issue queue is shared between
// clusters. This approach is used by the Pentium 4 and AMD K8.
//

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

//
// Writeback
//
#define WRITEBACK_WIDTH 3

//
// Commit
//
#define COMMIT_WIDTH 3

