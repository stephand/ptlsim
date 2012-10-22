/**
 * Reads a binary trace produced by PTLsim and dumps the ASCII information in it.
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
 * Copyright (c) 2010-2012 Advanced Micro Devices, Inc.
 * Contributed by Stephan Diestelhorst <stephan.diestelhorst@amd.com>
 *
 * @author stephan.diestelhorst@amd.com
 * @date   24.11.2010
 */
//#include "ooocore-amd-barcelona-asf.h"
#include <iostream>
#include <stdint.h>
#define ENABLE_ASF
#include "show_flexible_trace_ptlsim_types.h"
#include <set>
#include <list>
#include <map>
#include <algorithm>

using namespace std;

template <class T>
class ContextFreeTrigger {
public:
  virtual bool trigger(const T&) = 0;
};

template <class T, class C>
class ContextSensitiveTrigger {
public:
  virtual bool trigger(const T&, const C&) = 0;
};

template <class T>
class ContextInterface {
public:
  virtual void notify_start(const T&) = 0;
  virtual void parse_event(const T& e) = 0;
  virtual void notify_end(const T&) = 0;
};

template <class T>
class EventProcessingInterface {
public:
  virtual void begin() = 0;
  virtual void parse_event(const T& e) = 0;
  virtual void end() = 0;
};

template <class T, class C>
class RangeTracker : public EventProcessingInterface<T> {
  set<C*>                              in_flight_regions;
  set<ContextFreeTrigger<T>*>          start_trig;
  set<ContextSensitiveTrigger<T, C>*>  end_trig;

  void process_ends(const T& e) {
    // Go through all the active regions and check if they are finnished
    typename set<C*>::iterator                             region_it;
    typename set<ContextSensitiveTrigger<T, C>*>::iterator trig_it;

    for (region_it = in_flight_regions.begin(); region_it != in_flight_regions.end(); ++region_it)
      for (trig_it = end_trig.begin(); trig_it != end_trig.end(); ++trig_it)
        if ((*trig_it)->trigger(e, **region_it)) {
          // End the active region
          (*region_it)->notify_end(e);
          delete *region_it;
          in_flight_regions.erase(region_it);
        }
  }

  void process_starts(const T& e) {
    // Go through all the activation triggers and check if they create any new region
    typename set<ContextFreeTrigger<T>*>::iterator trig_it;

    for (trig_it = start_trig.begin(); trig_it != start_trig.end(); ++trig_it)
      if ((*trig_it)->trigger(e)) {
        C* r = new C();
        in_flight_regions.insert(r);
        r->notify_start(e);
      }
  }

public:
  bool inside() const;
  void parse_event(const T& e) {
    process_ends(e);

    // Send events to in-flight regions
    typename set<C*>::iterator region_it;
    for (region_it = in_flight_regions.begin(); region_it != in_flight_regions.end(); ++region_it)
      (*region_it)->parse_event(e);

    process_starts(e);
  }
  void begin() {}
  void end() {}
  bool add_start_trigger(ContextFreeTrigger<T>* t) { return start_trig.insert(t).second; }
  bool add_start_trigger(ContextFreeTrigger<T>& t) { return add_start_trigger(&t); }
  bool add_end_trigger(ContextSensitiveTrigger<T, C>* t) { return end_trig.insert(t).second; }
  bool add_end_trigger(ContextSensitiveTrigger<T, C>& t) { return add_end_trigger(&t); }
};

//
// Small example: Start and end of speculative regions
//
template <class T>
class CoreIDTracker : public EventProcessingInterface<T> {
  int coreid;

public:
  int get_coreid() const {return coreid;}
  void parse_event(const T& e) {
    if (e.type != EVENT_META_COREID) return;
    const MetadataCoreidEvent &c = *((MetadataCoreidEvent*)&e);
    if (coreid == c.coreid) return;
    coreid = c.coreid;
    //cout << "CoreID is now " << c.coreid << "\n";
  }
  void begin() { coreid = -1;}
  void end() {}

};

CoreIDTracker<OutOfOrderCoreEvent> the_coreid_tracker;

// Cache parameters
const W64 cache_line_size = 64;
const W64 cache_line_mask = ~(cache_line_size - 1);

struct ASFSpecRegionContext : public ContextInterface<OutOfOrderCoreEvent>{
  uint32_t start_cycle;
  uint64_t committed_insns;

  int disp_ld;
  int disp_st;
  int disp_pf; // TODO: Differenciate between prefetches / prefetchws and the bogus loads inserted
  int ret_ld;
  int ret_st;
  int ret_pf;

  int asf_disp_ld;
  int asf_disp_st;
  int asf_disp_pf;
  int asf_ret_ld;
  int asf_ret_st;
  int asf_ret_pf;

  int lock_disp_ld;
  int lock_disp_st;
  int lock_disp_pf;
  int lock_ret_ld;
  int lock_ret_st;
  int lock_ret_pf;

  set<W64> read_set;
  set<W64> write_set;
  set<W64> asf_read_set;
  set<W64> asf_write_set;

  int coreid;
  int get_coreid() const { return coreid;}

  void notify_start(const OutOfOrderCoreEvent& e) {
    disp_ld = 0; disp_st = 0; disp_pf = 0; ret_ld = 0; ret_st = 0; ret_pf = 0;
    asf_disp_ld = 0; asf_disp_st = 0; asf_disp_pf = 0; asf_ret_ld = 0; asf_ret_st = 0; asf_ret_pf = 0;
    lock_disp_ld = 0; lock_disp_st = 0; lock_ret_ld  = 0; lock_ret_st  = 0;

    start_cycle     = e.cycle;
    committed_insns = e.commit.total_insns_committed;
    coreid = the_coreid_tracker.get_coreid();
//    cout << "Start of speculative region in cycle " << e.cycle << " on core "
//         << coreid << " insns: " << committed_insns
//         << "\n";
  }
  void notify_end(const OutOfOrderCoreEvent& e) {
    uint32_t dur   = e.cycle - start_cycle;
    uint64_t insns = ((e.type != EVENT_ASF_ABORT) ? e.commit.total_insns_committed : e.abort.total_insns_committed) - committed_insns;

    set<W64> mixed_read_set;
    set<W64> mixed_write_set;
    set_intersection(asf_read_set.begin(), asf_read_set.end(), read_set.begin(),
      read_set.end(), inserter(mixed_read_set, mixed_read_set.begin()));
    set_intersection(asf_write_set.begin(), asf_write_set.end(), write_set.begin(),
      write_set.end(), inserter(mixed_write_set, mixed_write_set.begin()));

#if(0)
    if (e.type == EVENT_ASF_ABORT)
      cout << "ABORT Reason: " << (void*)e.abort.abort_reason << " status: " << (e.abort.abort_reason & 0x7F) << " hard: " << (e.abort.abort_reason & 0x80) << " nest: " << ((e.abort.abort_reason >> 8) & 0xFF) << " SW Abort: " << ((e.abort.abort_reason >> 16) & 0xFFFF) << "\n";
    
    cout << "End of speculative region in cycle " << e.cycle << " on core " << coreid
         << " Duration: " << dur << " Reason: " << ((e.type == EVENT_ASF_ABORT) ? "ABORT" : "COMMIT")
         << " Instructions: " << insns << " IPC: " << ((double)insns) / dur
         << "\n"
         << " Cache-lines touched:" <<"\n"
         << "   Loads:  ASF: " << asf_read_set.size()  << " non-ASF: " << read_set.size()
         << " Mixed: " << mixed_read_set.size()<< "\n"
         << "   Stores: ASF: " << asf_write_set.size() << " non-ASF: " << write_set.size()
         << " Mixed: " << mixed_write_set.size()<< "\n"
         << " Dispatched:" << "\n"
         << "   Loads:  ASF: " << asf_disp_ld << " non-ASF: " << disp_ld << " LOCKed: " << lock_disp_ld << "\n"
         << "   Stores: ASF: " << asf_disp_st << " non-ASF: " << disp_st << " LOCKed: " << lock_disp_st << "\n"
         << "   Prefet: ASF: " << asf_disp_pf << " non-ASF: " << disp_pf << "\n"
         << " Retired:" << "\n"
         << "   Loads:  ASF: " << asf_ret_ld << " non-ASF: " << ret_ld << " LOCKed: " << lock_ret_ld << "\n"
         << "   Stores: ASF: " << asf_ret_st << " non-ASF: " << ret_st << " LOCKed: " << lock_ret_st << "\n"
         << "   Prefet: ASF: " << asf_ret_pf << " non-ASF: " << ret_pf << "\n"
         << "\n";
    cout << "XXX: " << dur << " " << insns << " " << ((e.type == EVENT_ASF_ABORT) ? "ABORT" : "COMMIT")
             << " " << asf_read_set.size()  << " " << read_set.size()
             << " " << mixed_read_set.size()
             << " " << asf_write_set.size() << " " << write_set.size()
             << " " << mixed_write_set.size()
             << " " << asf_disp_ld << " " << disp_ld << " " << lock_disp_ld
             << " " << asf_disp_st << " " << disp_st << " " << lock_disp_st
             << " " << asf_disp_pf << " " << disp_pf
             << " " << asf_ret_ld << " " << ret_ld << " " << lock_ret_ld
             << " " << asf_ret_st << " " << ret_st << " " << lock_ret_st
             << " " << asf_ret_pf << " " << ret_pf << "\n";
#endif
  }
  void parse_event(const OutOfOrderCoreEvent& e) {
    if (the_coreid_tracker.get_coreid() != get_coreid()) return;
    if (!isclass(e.uop.opcode, OPCLASS_MEM)) return;

    if (e.type == EVENT_DISPATCH_OK) {
      if (e.uop.locked) {
//        cout << "LOCKed DISPATCH @ " << (void*) e.rip.rip << "\n";
        if (isload(e.uop.opcode))
          lock_disp_ld++;
        if (isstore(e.uop.opcode))
          lock_disp_st++;
      } else if (e.uop.is_asf) {
        if (isload(e.uop.opcode))
          asf_disp_ld++;
        if (isstore(e.uop.opcode))
          asf_disp_st++;
        if (isprefetch(e.uop.opcode))
          asf_disp_pf++;
      } else {
        if (isload(e.uop.opcode))
          disp_ld++;
        if (isstore(e.uop.opcode))
          disp_st++;
        if (isprefetch(e.uop.opcode))
          disp_pf++;
      }
    }      
    else if (e.type == EVENT_COMMIT_OK) {
      if (e.uop.locked) {
//        cout << "LOCKed COMMIT @ " << (void*) e.rip.rip << "\n";
        if (isload(e.uop.opcode))
          lock_ret_ld++;
        if (isstore(e.uop.opcode))
          lock_ret_st++;
      } else if (e.uop.is_asf) {
        if (isload(e.uop.opcode))
          asf_ret_ld++;
        if (isstore(e.uop.opcode))
          asf_ret_st++;
        if (isprefetch(e.uop.opcode))
          asf_ret_pf++;
      } else {
        if (isload(e.uop.opcode))
          ret_ld++;
        if (isstore(e.uop.opcode))
          ret_st++;
        if (isprefetch(e.uop.opcode))
          ret_pf++;
      }
    }

    // Add the entry to the repsective tracking set
    // NOTE: Tweak to capture different ASF mechanisms
    if ((e.type == EVENT_COMMIT_OK) && e.uop.is_asf) {
      if (isload(e.uop.opcode) || isprefetch(e.uop.opcode))
        asf_read_set.insert(e.commit.state.ldreg.physaddr & cache_line_mask);
      if (isstore(e.uop.opcode))
        asf_write_set.insert((e.commit.state.st.physaddr << 3) & cache_line_mask);
    }
    if ((e.type == EVENT_COMMIT_OK) && !e.uop.is_asf) {
      if (isload(e.uop.opcode) || isprefetch(e.uop.opcode))
        read_set.insert(e.commit.state.ldreg.physaddr & cache_line_mask);
      if (isstore(e.uop.opcode))
        write_set.insert((e.commit.state.st.physaddr << 3) & cache_line_mask);
    }

#if (0)
    if (e.type == EVENT_DISPATCH_OK)
      cout << " Dispatch ";
    else if (e.type == EVENT_COMMIT_OK)
      cout << " Commit ";
    else
      return;
    cout << (isload(e.uop.opcode) ? "LOAD" : "") << (isstore(e.uop.opcode) ? "STORE":"") << endl;
#endif
  }

};
class ASFSpecRegionStart : public ContextFreeTrigger<OutOfOrderCoreEvent> {
  bool trigger(const OutOfOrderCoreEvent& e) { return ((e.uop.opcode == OP_spec)||(e.uop.opcode == OP_spec_inv)) && (e.type ==EVENT_COMMIT_OK); }
};
class ASFSpecRegionEnd : public ContextSensitiveTrigger<OutOfOrderCoreEvent, ASFSpecRegionContext> {
  bool trigger(const OutOfOrderCoreEvent& e, const ASFSpecRegionContext& c) {
    if (the_coreid_tracker.get_coreid() != c.get_coreid()) return false;
    return
      ((e.uop.opcode == OP_com) && (e.type == EVENT_COMMIT_OK))
       ||
      (e.type == EVENT_ASF_ABORT);
  }
};
//
// End example
//

int main() {
  uint16_t size;
  int records = 0;
  long pos = 0;

  OutOfOrderCoreEvent e;

  RangeTracker<OutOfOrderCoreEvent, ASFSpecRegionContext> stats;
  ASFSpecRegionStart asf_start;
  ASFSpecRegionEnd   asf_end;
  stats.add_start_trigger(asf_start);
  stats.add_end_trigger(asf_end);

  list<EventProcessingInterface<OutOfOrderCoreEvent>*> analyzers;
  
//  analyzers.push_back(&stats);
  analyzers.push_back(&the_coreid_tracker);
  
  list<EventProcessingInterface<OutOfOrderCoreEvent>*>::iterator stat_it;

  for (stat_it = analyzers.begin(); stat_it != analyzers.end(); ++stat_it)
    (*stat_it)->begin();
  

  map<int, uint32_t> old_cycle;
  map<int, uint64_t> cycle_offset;
 
  while (!std::cin.eof() && !std::cin.fail()) {
    std::cin.read((char*)&size, sizeof(size));

    //int fixed_size = offsetof(OutOfOrderCoreEvent, start_flexible);
    //std::cin.read((char*)&e, fixed_size);
    //std::cin.ignore(size - fixed_size - sizeof(size));
    std::cin.read((char*)&e, size - sizeof(size));

//    std::cout << "Record " << records << " @ " << (void*) pos << "\n";
//    std::cout << "  Cycle: " << e.cycle << "\n";
//    std::cout << "  UUID: " << e.uuid << "\n";
//    std::cout << "  RIP: " << (void*) e.rip.rip << "\n";
//    std::cout << "  ROB: " << e.rob << "\n";
//    std::cout << "  Type: " << e.type << "\n";
//    std::cout << "  Thread: " << (int)e.threadid << "\n";

    for (stat_it = analyzers.begin(); stat_it != analyzers.end(); ++stat_it)
      (*stat_it)->parse_event(e);

#if (0)
    /* De-overflow the 32bit cycle value */
    int coreid = the_coreid_tracker.get_coreid();
    if (old_cycle.find(coreid) == old_cycle.end())
      old_cycle[coreid] = e.cycle;
    if (old_cycle.find(coreid) == old_cycle.end())
      old_cycle[coreid] = e.cycle;

    /* Allow cycles to be off by 2^30 to account for async write-out */
    if ( (int32_t) (e.cycle - old_cycle) < -(1L<<30)) {
      cycle_offset += 1LL << 32;
    }
#endif
    uint64_t deoverflowed_cycle = e.cycle;

    if (e.type == EVENT_COMMIT_OK) {
      cout << the_coreid_tracker.get_coreid() << " " << deoverflowed_cycle << " " << (void*)e.rip.rip << "\n";
      if (e.uop.opcode == OP_spec_inv)
          cout << the_coreid_tracker.get_coreid() << " " << deoverflowed_cycle << " SPECULATE\n";
      if (e.uop.opcode == OP_com)
          cout << the_coreid_tracker.get_coreid() << " " << deoverflowed_cycle << " COMMIT\n";
    }
    else if (e.type == EVENT_ASF_ABORT)
      cout << the_coreid_tracker.get_coreid() << " " << deoverflowed_cycle << " ABORT" << (int)((signed char)(e.abort.abort_reason & 0xFF)) << "\n";
    else if (e.type == EVENT_ASF_CONFLICT)
      cout << "Conflict cycle " << deoverflowed_cycle << " " 
           << (int)e.conflict.src_id << " -> " << (int)e.conflict.dst_id
           << " inv: " << (bool)e.conflict.inv << " phys: " << (void*)e.conflict.phys_addr
           << " virt: " << (void*)e.conflict.virt_addr << " rip: " << (void*)e.rip.rip << "\n";
    else if (e.type == EVENT_ASF_NESTLEVEL)
      cout << the_coreid_tracker.get_coreid() << " " << deoverflowed_cycle << " New nesting level: " << e.nestlevel.nest_level << "\n";

    records ++;
    pos += size;
    //old_cycle = e.cycle;
  }
  for (stat_it = analyzers.begin(); stat_it != analyzers.end(); ++stat_it)
    (*stat_it)->end();

}

