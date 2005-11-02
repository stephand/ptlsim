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

#define MAX_ISSUE_WIDTH 4

//
// Reorder Buffer
//
#define ROB_SIZE 256

//
// Physical Register File
//
#define PHYS_REG_FILE_SIZE 256
#define PHYS_REG_NULL (PHYS_REG_FILE_SIZE - 1)
#define PHYS_REG_ARCH_BASE (PHYS_REG_FILE_SIZE - 64) // 256 - 64 = 192

//
// Load and Store Queues
//
#define LDQ_SIZE 32
#define STQ_SIZE 32

//
// Fetch
//
#define FETCH_QUEUE_SIZE 24
#define FETCH_WIDTH 4

//
// Frontend (Rename and Decode)
//
#define FRONTEND_WIDTH 4
#define FRONTEND_STAGES 9

//
// Dispatch
//
#define DISPATCH_WIDTH 4

//
// Clustering, Issue Queues and Bypass Network
//
#define MAX_FORWARDING_LATENCY 2
#define MAX_CLUSTERS 1

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
  {"int0",  4, (FU_ALU0|FU_STU0|FU_ALU1|FU_STU1|FU_FPU0|FU_FPU1|FU_LDU0|FU_LDU1)},
};

static const byte intercluster_latency_map[MAX_CLUSTERS][MAX_CLUSTERS] = {
// I0 LD <-to
  {0}, // from I0
};

static const byte intercluster_bandwidth_map[MAX_CLUSTERS][MAX_CLUSTERS] = {
// I0 LD <-to
  {4}, // from I0
};

IssueQueue<64> issueq_int0;

#define foreach_issueq(expr) { issueq_int0.expr; }

void sched_get_all_issueq_free_slots(int* a) {
  a[0] = issueq_int0.remaining();
}

#define issueq_operation_on_cluster_with_result(cluster, rc, expr) \
  switch (cluster) { \
  case 0: rc = issueq_int0.expr; break; \
  }

//
// Writeback
//
#define WRITEBACK_WIDTH 4

//
// Commit
//
#define COMMIT_WIDTH 4

