/**
 * ticket_counter.h
 *
 * Implements a simple ticket counter without locking with support
 * for withdrawl of tickets.
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
 * Author:     stephan.diestelhorst@amd.com
 * Created on: 22.02.2010
 */


#ifndef TICKET_COUNTER_H_
#define TICKET_COUNTER_H_

template <typename T, int MAX_CLIENTS>
class TicketCounter {
public:
  void withdraw(T id);
  void enqueue(T id);
  bool has_queuers() const { return !waiting.iszero();}
  bool serve(T id);
  void reset();
  TicketCounter() { reset(); }
  ostream& print(ostream&);

private:
  T cur_ticket;
  T tickets[MAX_CLIENTS];
  bitvec<MAX_CLIENTS> waiting;
};

template <typename T, int MAX_CLIENTS>
bool TicketCounter<T,MAX_CLIENTS>::serve(T id) {
  if (!waiting[id]) return false;

  if(tickets[id] == cur_ticket) {
    cur_ticket++;
    waiting[id] = false;
    return true;
  } else {
    return false;
  }
}

template <typename T, int MAX_CLIENTS>
void TicketCounter<T,MAX_CLIENTS>::withdraw(T id) {
  if (!waiting[id]) return;

  waiting[id] = false;

  // Adjust all other tickets.
  T w = tickets[id];
  T c = cur_ticket;
  bitvec<MAX_CLIENTS> adjust = waiting;
  while(!adjust.iszero()) {
    T &i = tickets[adjust.lsb()];
    // Overflow arithmetic is fun :-/
    if ((T)(i-c) > (T)(w-c)) i--;
    //if (((c<=w) && (w<i)) || ((i<c) && (c<=w)) || ((w<i) && (i<c))) i--;
    adjust[adjust.lsb()] = false;
  }
}

template <typename T, int MAX_CLIENTS>
void TicketCounter<T,MAX_CLIENTS>::enqueue(T id) {
  if (waiting[id]) return;
  waiting[id] = true;
  tickets[id] = cur_ticket + waiting.popcount() - 1;
}

template <typename T, int MAX_CLIENTS>
ostream& TicketCounter<T,MAX_CLIENTS>::print(ostream& os) {
  os << "TicketCounter: ", this, endl;
  os << "  Cur. ticket: ", cur_ticket, endl;
  os << "  Waiting: ", waiting, endl;
  for (int i = 0; i < MAX_CLIENTS; i++)
    os << "  tickets[", i, "]=", tickets[i], waiting[i] ? "" : "(free)", endl;
  return os;
}

template <typename T, int MAX_CLIENTS>
ostream& operator<<(ostream& os, TicketCounter<T,MAX_CLIENTS> tc) {
  return tc.print(os);
}

template <typename T, int MAX_CLIENTS>
void TicketCounter<T,MAX_CLIENTS>::reset() {
  waiting.reset();
  cur_ticket = 0;
}
#endif /* TICKET_COUNTER_H_ */
