/**
 * Record definitions for a file containing trace events.
 * @author stephan.diestelhorst@amd.com
 * @date 9.10.2009
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * Copyright (c) 2009-2012 Advanced Micro Devices, Inc.
 * Contributed by Stephan Diestelhorst <stephan.diestelhorst@amd.com>
 *
 */

#include <stdint.h>
struct TraceEvent {
  uint64_t cycle;
  uint64_t rip;
  uint8_t  coreid;
  uint8_t  threadid;
} __attribute__((packed));

#if (0)
struct FlexibleTraceEventHeader {
  uint64_t cycle;
  uint64_t rip;
  uint16_t length;
  uint8_t  coreid;
  uint8_t  threadid;
  enum {
    DISPATCH_STAGE,
    COMMIT_STAGE,
  } pipestage;
  enum {
    LOAD,
    STORE,
    PREFETCH,
    SPECULATE,
    COMMIT,
    RELEASE,
    ABORT,
    STATS,
  }  event;
} __attribute__((packed));

union FlexibleTraceEventVarSection {
  struct LoadStore {
    uint64_t physaddr;
    uint64_t virtaddr;
    uint64_t data;
    uint8_t  size;
  } __attribute__((packed));

  struct Prefetch {
    uint64_t physaddr;
    uint64_t virtaddr;
  } __attribute__((packed));

  struct Prefetch {
    uint64_t physaddr;
    uint64_t virtaddr;
  } __attribute__((packed));

  struct SpecCommit {
    // Nothing.
  } __attribute__((packed));

  struct Abort {
    uint64_t abortreason;
  } __attribute__((packed));

  struct Stat {
    uint64_t instrcount;
  } __attribute__((packed));
};

struct FlexibleTraceEvent {
  struct FlexibleTraceEventHeader     hdr;
  struct FlexibleTraceEventVarSection var;
} __attribute__ ((packed));
#endif
