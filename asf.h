/**
 * Support for AMD's experimental Advanced Synchronization Facility (ASF) for
 * PTLsim's out-of-order core model.
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
 * Copyright (c) 2008-2010 Advanced Micro Devices, Inc.
 * Contributed by Stephan Diestelhorst <stephan.diestelhorst@amd.com>
 *
 * @author stephan.diestelhorst@amd.com
 * @date 01.12.2008
 */
#ifndef __ASF_H__
#define __ASF_H__

#include <ptlsim.h>
//#include <ooocore.h>
#include <dcache.h>

namespace OutOfOrderModel {
  struct ThreadContext;
  struct OutOfOrderCore;
  struct ReorderBufferEntry;
  struct LoadStoreQueueEntry;
  struct LockedLineBuffer;
}

/**
* This class captures all context related to ASF.
*/
using OutOfOrderModel::LockedLineBuffer;

const int ASF_MAX_NESTING_DEPTH = 256;
class ASFContext {

  public:
    enum ASFStatusCode {ASF_SUCCESS = 0, ASF_CONTENTION = 16, ASF_ABORT = 18, ASF_FAR = 19,
                        ASF_DISALLOWED_OP = -2, ASF_CAPACITY = -1};
    enum ASFErrorFlags {ASF_IMPRECISE = 1l << 32};

    bool to_sim_context(Context& c, bool is_assist);
    void reset();

    void enter_spec_region(const Context& c);
    void leave_spec_region();
    bool const in_spec_region() { return in_spec_reg; }
    bool has_error() { return status_code != ASF_SUCCESS; }
    /* Methods to create particular errors */
    void capacity_error(W64 rip, Waddr addr);
    void interrupt(W64 rip);
    void exception(W64 rip);
    void disallowed(W64 rip);
    void contention(W64 rip, Waddr addr);
    void user_abort(W64 rip, W64 abort_code);
    ASFContext(LockedLineBuffer *l, OutOfOrderModel::OutOfOrderCore& core);

  protected:
    LockedLineBuffer                *llb;
#ifdef ENABLE_ASF_CACHE_BASED
    CacheSubsystem::L1CacheSpecRead *l1_spec_read;
#endif
    bool          in_spec_reg;
    W16           software_abort;
    int           nest_level;
    ASFStatusCode status_code;
    /* Roll-back information */
    RIPVirtPhys   abort_rip;
    W64           saved_rsp;
    /* Imprecise exceptions */
    W64           real_fault_rip;
    bool          imprecise;
    const int     vcpuid_;
    int vcpuid() const { return vcpuid_; }
    bool is_hard_error(ASFStatusCode err) { return (err < 0); }
};

namespace OutOfOrderModel {
  const int ASF_MAX_LINES         = 256;
  const int ASF_MAX_SPEC_LINES    = 4;
  const int LLB_LINE_SIZE         = CacheSubsystem::L1_LINE_SIZE;

  class LockedLineBuffer;
  class LLBLine {
    friend class LockedLineBuffer;
    protected:
      W64  orig_data[LLB_LINE_SIZE / sizeof(W64)];
      int  written:1, datavalid:1, speculative:1;
      int  refcount;

    public:
      void  reset() {written = 0; refcount = 0; datavalid = 0; speculative = 0;}

      void  copy_from_phys(Waddr physaddr) {
        assert(mask(physaddr, LLB_LINE_SIZE) == 0);
        for (int i = 0; i < LLB_LINE_SIZE / sizeof(W64);
             ++i, physaddr += sizeof(W64)) {
               orig_data[i] = loadphys(physaddr);
        }
      }

      void  copy_to_phys(Waddr physaddr) {
        assert(mask(physaddr, LLB_LINE_SIZE) == 0);
        for (int i = 0; i < LLB_LINE_SIZE / sizeof(W64);
             ++i, physaddr += sizeof(W64)) {
               storephys(physaddr, orig_data[i]);
        }
      }

      W64 data(Waddr physaddr) {
        assert(datavalid);
        return orig_data[mask(physaddr, LLB_LINE_SIZE) >> 3];
      }
      LLBLine() : written(false),refcount(0),datavalid(0),speculative(0) {}
      ostream& toString(ostream& os) const;

      bool is_dirty() const { return written; }
  };

  class LockedLineBuffer: public FullyAssociativeArray<Waddr, LLBLine, ASF_MAX_SPEC_LINES + ASF_MAX_LINES> {
    typedef FullyAssociativeArray<Waddr, LLBLine, ASF_MAX_SPEC_LINES + ASF_MAX_LINES > base_t;
    protected:
      ThreadContext& thread;
      int num_spec_locations;
      int num_nonspec_locations;
      W64 lasterr;

    public:
      LockedLineBuffer(ThreadContext& _thread): base_t(), thread(_thread) {}

      LLBLine* add_location(Waddr addr, bool spec = true);
      bool     mark_nonspec(LLBLine* line);
      int      get_refcount(LLBLine* line) const { return line->refcount; };
      void     remove_ref(LLBLine* line, int n_refs = 1);

      void clear();
      void snapshot(LLBLine *llbline);
      void undo();

      void commit() {clear(); lasterr = 0;};
      void abort() { undo(); /*clear();*/ lasterr = 0; };

      bool contains(Waddr addr) { return probe(floor(addr, LLB_LINE_SIZE)); }
      bool empty() const { return (num_spec_locations + num_nonspec_locations == 0); }
      int  size() const { return num_spec_locations + num_nonspec_locations; }
      LLBLine* external_probe(Waddr addr, bool invalidating);
      LLBLine* probe_other_LLBs(Waddr addr, bool invalidating);
      bool mark_clean(Waddr addr);
      bool mark_clean_others(Waddr addr);
      void mark_written(Waddr addr);

      bool at_spec_capacity_limit()   const {return num_spec_locations >= ASF_MAX_SPEC_LINES; }
      bool at_nonspec_capacity_limit() const {return num_nonspec_locations >= ASF_MAX_LINES; }
      bool at_capacity_limit (bool spec) const {
        return (spec) ? at_spec_capacity_limit() : at_nonspec_capacity_limit();
      }
      int get_spec_locations() const { return num_spec_locations; }
      int get_nonspec_locations() const { return num_nonspec_locations; }
      W64  consistency_error() {
        return lasterr;
      }
  };

  /**
   * This class ties ASF into the processor pipeline.
   **/
  class ASFPipelineIntercept {
    protected:
      ASFContext       *asf_context;
      LockedLineBuffer *llb;
      ThreadContext    *thread;

    public:
      int  issue(ReorderBufferEntry& rob, IssueState& state, W64 radata, W64 rbdata, W64 rcdata);
      int  issue_load(ReorderBufferEntry& rob, LoadStoreQueueEntry& state, LoadStoreQueueEntry* sfra) {return issue_mem(rob, state, sfra); }
      int  issue_store(ReorderBufferEntry& rob, LoadStoreQueueEntry& state) {return issue_mem(rob, state, null); }
      bool commit(const Context &ctx, ReorderBufferEntry& rob);
      bool issue_probe_and_merge(W64 physaddr, bool invalidating, W64& out_data);
      int  pre_commit(Context& ctx, int i);
      int  post_commit(Context& ctx, int i);
      void annul_replay_redispatch(ReorderBufferEntry& rob);
      void reprobe_load(ReorderBufferEntry& rob);
      ASFPipelineIntercept(ASFContext* ac, LockedLineBuffer* l, ThreadContext* t) : asf_context(ac), llb(l), thread(t) {};

    private:
      int  issue_mem(ReorderBufferEntry& rob, LoadStoreQueueEntry& state, LoadStoreQueueEntry* sfra);
      int  issue_release(ReorderBufferEntry& rob, LoadStoreQueueEntry& state,
          Waddr& origaddr, W64 ra, W64 rb, W64 rc, PTEUpdate& pteupdate);
      bool commit_load(ReorderBufferEntry& rob, Waddr physaddr, Waddr virtaddr);
      bool commit_store(ReorderBufferEntry& rob, Waddr physaddr, Waddr virtaddr);
      int  vcpuid() const;
      int  check_conflicts(Context &ctx, int commitrc);
      int  handle_far_control_transfer(Context &ctx, int commitrc);
      void rollback();
  };

}

#endif // __ASF_H__
