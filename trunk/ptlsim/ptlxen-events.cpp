//
// PTLsim: Cycle Accurate x86-64 Simulator
// Time and interrupt management for Xen subsystem
//
// Copyright 2005-2008 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>
#include <ptlxen.h>
#include <mm.h>
#include <ptlsim.h>
#include <stats.h>
#include <xen/io/console.h>

//
// PTLsim event and timer control
//

#define active_evtchns(cpu,sh,idx) ((sh).evtchn_pending[idx] & ~(sh).evtchn_mask[idx])

void mask_evtchn(int port) {
  shinfo_evtchn_mask[port].atomicset();
}

void force_evtchn_callback() {
  // Xen processes pending events on every hypercall:
  (void)HYPERVISOR_xen_version(0, 0);
}

void unmask_evtchn(int port) {
  struct vcpu_info& vcpu_info = shinfo.vcpu_info[0];

  shinfo_evtchn_mask[port].atomicclear();
  
  //
  // The following is basically the equivalent of 'hw_resend_irq'. Just like
  // a real IO-APIC we 'lose the interrupt edge' if the channel is masked.
  //
  if (shinfo_evtchn_pending[port] && (!(shinfo_evtchn_pending_sel(0)[port / (sizeof(unsigned long) * 8)].atomicset()))) {
    vcpu_info.evtchn_upcall_pending = 1;
    if (!vcpu_info.evtchn_upcall_mask) force_evtchn_callback();
  }
}

void cli() {
  shinfo.vcpu_info[0].evtchn_upcall_mask = 1;
	barrier();
}

void sti() {
	barrier();
  struct vcpu_info& vcpu = shinfo.vcpu_info[0];
	vcpu.evtchn_upcall_mask = 0;
	barrier(); // unmask then check (avoid races)
	if (vcpu.evtchn_upcall_pending) {
    force_evtchn_callback();
  }
}

void clear_evtchn(int port) {
  shinfo_evtchn_pending[port].atomicclear();
}

bitvec<4096> always_mask_port;

void handle_event(int port, int vcpu) {
  // Can't use anything that makes host calls in here!
  if likely (port == bootinfo.hostcall_port) {
    // No action: will automatically unblock and return to hostcall caller
  } else if unlikely (port == bootinfo.upcall_port) {
    // Upcall: check at next iteration of main loop
  } else {
    // some user port: copy to virtualized shared info page and notify simulation loop
    if likely (!always_mask_port[port]) {
      if likely (!config.mask_interrupts) shadow_evtchn_set_pending(port);
    }
  }

	clear_evtchn(port);
}

asmlinkage void xen_event_callback(W64* regs) {
  int vcpu = current_vcpuid();
  struct vcpu_info& vcpu_info = shinfo.vcpu_info[vcpu];
  W64  l1, l2;
  unsigned int l1i, l2i, port;

  vcpu_info.evtchn_upcall_pending = 0;
  l1 = xchg(vcpu_info.evtchn_pending_sel, 0UL);

  while (l1) {
    l1i = lsbindex(l1);
    l1 &= ~(1 << l1i);

    while ((l2 = active_evtchns(vcpu, shinfo, l1i))) {
      l2i = lsbindex(l2);
      l2 &= ~(1 << l2i);
      port = (l1i * BITS_PER_LONG) + l2i;
      handle_event(port, vcpu);
    }
    shinfo.evtchn_pending[l1i] = 0;
  }
}

//
// Shadow Event Channels
//
W8s port_to_vcpu_cache[NR_EVENT_CHANNELS];

evtchn_status_t evtchn_get_status(int port) {
  evtchn_status_t status;
  status.dom = DOMID_SELF;
  status.port = port;
  HYPERVISOR_event_channel_op(EVTCHNOP_status, &status);
  return status;
}

//
// Convert a port to the VCPU it's bound to, if any.
// We use the evtchn_status hypercall to determine this,
// then cache the lookup results.
//
inline int port_to_vcpu(int port) {
  W8s& vcpu = port_to_vcpu_cache[port];
  if likely (vcpu >= 0) return vcpu;

  evtchn_status_t status = evtchn_get_status(port);

  vcpu = status.vcpu;
  if (!inrange(vcpu, W8s(0), W8s(contextcount-1))) vcpu = 0;

  return vcpu;
}

int shadow_evtchn_unmask(unsigned int port) {
  if (port >= NR_EVENT_CHANNELS) return 0;

  int vcpu_to_notify = port_to_vcpu(port);

  if (vcpu_to_notify < 0) {
    logfile << "unmask_evtchn: port ", port, " is not bound to any VCPU", endl;
    return 0;
  }

  // Equivalent to xen/common/event_channel.c evtchn_unmask():

  if (sshinfo_evtchn_mask[port].testclear() &&
      sshinfo_evtchn_pending[port] &&
      (!(sshinfo_evtchn_pending_sel(vcpu_to_notify)[port / (sizeof(unsigned long) * 8)].testset()))) {
    if (!xchg(sshinfo.vcpu_info[vcpu_to_notify].evtchn_upcall_pending, (byte)1)) {
      if (logable(1)) logfile << "shadow_evtchn_unmask(", port, "): event delivery: making vcpu ", vcpu_to_notify, " runnable", endl;
      return 1;
    }
  }

  return 0;
}

bool shadow_evtchn_set_pending(unsigned int port) {
  if unlikely (port >= 4096) return false;
  int vcpu_to_notify = port_to_vcpu(port);

  if unlikely (vcpu_to_notify < 0) {
    // Not bound to any VCPU
    return false;
  }

  if unlikely (sshinfo_evtchn_pending[port].testset()) {
    // Already pending
    return false;
  }

  bool masked = sshinfo_evtchn_mask[port];

  if unlikely (masked) {
    // Event masked
    return false;
  }

  if unlikely (sshinfo_evtchn_pending_sel(vcpu_to_notify)[port / (sizeof(unsigned long) * 8)].testset()) {
    // Event already pending in evtchn_pending_sel
    return false;
  }

  if likely (!xchg(sshinfo.vcpu_info[vcpu_to_notify].evtchn_upcall_pending, (byte)1)) {
    // Kick vcpu
    return true;
  } else {
    // VCPU already running
    return false;
  }
}

ostream& operator <<(ostream& os, const xencons_interface& console) {
  os << "Console page:", endl;
  os << "  Input  ring (console -> guest): head ", intstring(console.in_cons, 4),  " to tail ", intstring(console.in_prod, 4), endl;
  os << "  Output ring (guest -> console): head ", intstring(console.out_cons, 4), " to tail ", intstring(console.out_prod, 4), endl;

  os << "  Input data:", endl, flush;

  foreach (i, lengthof(console.in)) {
    if ((i % 128) == 0) os << "  ", intstring(i, 4), " '";
    char c = console.in[i];
    os << ((c >= 32) ? console.in[i] : '.');
    if ((i % 128) == 127) os << "'", endl;
  }

  os << "  Output data:", endl, flush;
  foreach (i, lengthof(console.out)) {
    if ((i % 128) == 0) os << "  ", intstring(i, 4), " '";
    char c = console.out[i];
    os << ((c >= 32) ? console.out[i] : '.');
    if ((i % 128) == 127) os << "'", endl;
  }

  os << flush;
  return os;
}

W64 timer_interrupt_period_in_cycles = infinity;
W64 timer_interrupt_last_sent_at_cycle = 0;

//
// Update time fields (tsc_timestamp, system_time, tsc_to_system_mul, tsc_shift) in shinfo
//
struct RealTimeInfo {
  W64 wc_sec;
  W64 wc_nsec;
};

RealTimeInfo initial_realtime_info;

//
// Initialize times after switching to simulation mode.
//
// It is expected that the guest kernel is just coming out of
// sleep mode and will re-init all VIRQs, etc. for us.
//

static inline W32 div_frac(W32 dividend, W32 divisor) {
  W32 quotient, remainder;

  if (divisor == dividend)
    return 0xffffffff; // a.k.a. 0.99999, as close as we can

  if (!divisor)
    return 0; // avoid divide-by-zero at all costs

  assert(dividend < divisor);
  asm("divl %4" : "=a" (quotient), "=d" (remainder) : "0" (0), "1" (dividend), "r" (divisor));
  return quotient;
}

#define MILLISECS(_ms) ((W64)((_ms) * 1000000ULL))

static void compute_time_scale(W32& tsc_to_system_mul, W8s& tsc_shift, W64 hz) {
  W64 tps64 = hz;
  int shift = 0;

  while (tps64 > (MILLISECS(1000)*2)) {
    tps64 >>= 1;
    shift--;
  }
  
  W32 tps32 = (W32)tps64;
  while (tps32 < (W32)MILLISECS(1000)) {
    tps32 <<= 1;
    shift++;
  }
  
  tsc_to_system_mul = div_frac(MILLISECS(1000), tps32);
  tsc_shift = shift;
}

//
// Compute core frequency from an existing shared info struct
//
W64 get_core_freq_hz(const vcpu_time_info_t& timeinfo) {
  W64 core_freq_hz = ((1000000000ULL << 32) / timeinfo.tsc_to_system_mul);

  if (timeinfo.tsc_shift >= 0)
    core_freq_hz >>= timeinfo.tsc_shift;
  else core_freq_hz <<= -timeinfo.tsc_shift;

  return core_freq_hz;
}

//
// Get the core frequency of the current physical processor
//
// This assumes the frequency is fixed at bootup and does not
// change dynamically; currently PTLsim is unable to get accurate
// timing info from non-monotonic TSCs like those used in cpufreq
// capable processors from Intel and AMD (at least prior to some
// very recent cores exposing this via rdpmc).
//
// Technically Xen provides info accurate to 10 milisec (100/sec)
// in the time.system_time or wc_sec/wc_nsec fields, but these
// are only updated 100 times per second; forcing an update
// via a hypercall would take too long.
//
W64 get_core_freq_hz() {
  return get_core_freq_hz(shinfo.vcpu_info[0].time);
}

void get_virtualized_tsc_bias(int vcpuid, W64s& tsc_timestamp_bias, W64s& system_time_bias) {
  vcpu_timestamp_bias_t bias;
  HYPERVISOR_vcpu_op(VCPUOP_get_timestamp_bias, vcpuid, &bias);
  tsc_timestamp_bias = bias.tsc_timestamp_bias;
  system_time_bias = bias.system_time_bias;
}

void set_virtualized_tsc_bias(int vcpuid, W64s tsc_timestamp_bias, W64s system_time_bias) {
  vcpu_timestamp_bias_t bias;
  bias.tsc_timestamp_bias = tsc_timestamp_bias;
  bias.system_time_bias = system_time_bias;
  HYPERVISOR_vcpu_op(VCPUOP_set_timestamp_bias, vcpuid, &bias);
}

void disable_virtualized_tsc(int vcpuid) {
  set_virtualized_tsc_bias(vcpuid, 0, 0);
}

void capture_initial_timestamps() {
  //
  // The PTLsim/X hypervisor code in do_contextswap() atomically captures the
  // timestamps (system_time, tsc_timestamp and rdtsc) the instant the domain is
  // frozen, and PTLmon puts these into Context, so no action is needed here.
  //
  // We disable TSC virtualization since PTLsim itself does not care about this;
  // it must have a very fast rdtsc implementation and that implementation must be
  // the physical TSC (so as to enable a safe return to native mode).
  //
  // From now on, during the simualtion, the rdtsc microcode uses base_tsc + sim_cycle
  // for the value reported to the user code.
  //
  // In theory, the initial per-vcpu system_time can be derived from the current TSC.
  // However, some processors do dynamic frequency scaling, so this will not work
  // correctly if the hardware TSC is non-monotonic. Therefore, we also store the
  // base system_time and hope the frequency does not change during the run.
  //
  // We do not recommend running PTLsim on a processor that does dynamic frequency
  // scaling. Turn this off (i.e. stop cpufreqd or equivalent in domain 0) before
  // starting the target domain! 
  //
  // We assume the hypervisor has synchronized the TSC of all processors to within
  // a few cycles using the usual ping-pong algorithm; this way we only read
  // the TSC on vcpu 0 and it should be roughly the same everywhere.
  //
  initial_realtime_info.wc_sec = sshinfo.wc_sec;
  initial_realtime_info.wc_nsec = sshinfo.wc_nsec;

  foreach (i, contextcount) {
    Context& ctx = contextof(i);
    disable_virtualized_tsc(i);

    //
    // The base_system_time can be zero if this VCPU has never run before,
    // such as when booting a new domain or resuming from a checkpoint.
    //
    ctx.base_system_time = sshinfo.vcpu_info[i].time.system_time;

    if (!ctx.base_system_time)
      ctx.base_system_time = shinfo.vcpu_info[0].time.system_time;

    // This should never be required, since base_tsc is the capture time tsc:
    if (!ctx.base_tsc) ctx.base_tsc = rdtsc();
  }
}

int real_timer_port[MAX_VIRT_CPUS];

//
// Early event initialization
//
void events_init() {
  foreach (i, MAX_VIRT_CPUS) real_timer_port[i] = -1;

  foreach (vcpu, contextcount) {
    Context& ctx = contextof(vcpu);

    foreach (virq, NR_VIRQS) {
      int port = ctx.virq_to_port[virq];
      if (!port) continue;
      assert(inrange(port, 0, 4095));
      port_to_vcpu_cache[port] = vcpu;
      if (virq == VIRQ_TIMER) {
        //
        // Let timer interrupts through, to let us do periodic events
        // However, we do not pass this on to the target domain.
        //
        unmask_evtchn(port);
        always_mask_port[port] = 1;
        real_timer_port[ctx.vcpuid] = port;
      }
    }
  }
}

//
// Reconstruct VIRQ bindings based on ctx.virq_to_port as captured
// by the hypervisor when we context swapped into PTLsim.
//
void reconstruct_virq_to_port_mappings() {
  logfile << "Interrupt mappings:", endl;
  foreach (vcpu, contextcount) {
    Context& ctx = contextof(vcpu);

    foreach (virq, NR_VIRQS) {
      int port = ctx.virq_to_port[virq];
      if (!port) continue;
      assert(inrange(port, 0, 4095));
      port_to_vcpu_cache[port] = vcpu;
      logfile << "  vcpu ", vcpu, ": virq ", virq, " -> port ", port, endl;
      if (virq == VIRQ_TIMER) {
        logfile << "  - Timer virq: mask and generate internally", endl;
        //
        // Let timer interrupts through, to let us do periodic events
        // However, we do not pass this on to the target domain.
        //
        unmask_evtchn(port);
        always_mask_port[port] = 1;
        real_timer_port[ctx.vcpuid] = port;
      }
    }
  }
}

ostream& operator <<(ostream& os, const evtchn_status_t& status) {
  static const char* evtchn_status_names[] = {"closed", "unbound", "inter", "pirq", "virq", "ipi"};

  os << padstring(evtchn_status_names[status.status], -8), " -> vcpu ", status.vcpu;
  switch (status.status) {
  case EVTCHNSTAT_unbound:
    os << ", remote domain ", status.u.unbound.dom;
    break;
  case EVTCHNSTAT_interdomain:
    os << ", remote domain ", status.u.interdomain.dom,
      ", remote port ", status.u.interdomain.port;
    break;
  case EVTCHNSTAT_pirq:
    os << ", physical irq ", status.u.pirq;
    break;
  case EVTCHNSTAT_virq:
    os << ", virq ", status.u.virq;
    break;
  default:
    break;
  }

  return os;
}

//
// This is called any time we resume from native mode (or at startup).
// It can be called at an arbitrary time after the context switch
// into PTLsim,since all the timing critical work is done in
// capture_initial_timestamps().
//
static bool first_time_calibration_after_boot = 1;

void time_and_virq_resume() {
  logfile << "Calibrate initial time conversions:", endl;

  W64 core_freq_hz = (config.core_freq_hz) ? config.core_freq_hz : get_core_freq_hz(shinfo.vcpu_info[0].time);

  //
  // Reset sim_cycle whenever we switch from native mode back to simulation
  // mode. This is needed for run lengths (-stop, etc.) to make any sense.
  //
  sim_cycle = 0;

  W64 phys_tsc = rdtsc();

  vcpu_time_info_t& localtimeinfo = shinfo.vcpu_info[0].time;

  foreach (i, contextcount) {
    Context& ctx = contextof(i);
    ctx.core_freq_hz = core_freq_hz;

    vcpu_time_info_t& timeinfo = sshinfo.vcpu_info[i].time;
    compute_time_scale(timeinfo.tsc_to_system_mul, timeinfo.tsc_shift, ctx.core_freq_hz);

    if unlikely (first_time_calibration_after_boot) {
      //
      // In SMP configurations, some VCPUs (other than vcpu 0)
      // may not be up and running when time_and_virq_resume()
      // is called; this means tsc_timestamp and system_time 
      // are uninitialized.
      //
      // We solve this by copying PTLsim's notion of these
      // timestamps into the shadow shared info page. Since
      // PTLsim always gets control before the domain's
      // kernel ever sees these values, we can set them
      // to whatever we want.
      //
      logfile << "Initialize VCPU ", i, " to PTLsim timestamps (tsc_timestamp ",
        localtimeinfo.tsc_timestamp, ", system_time ", localtimeinfo.system_time, ")", endl;
      timeinfo.tsc_timestamp = localtimeinfo.tsc_timestamp;
      timeinfo.system_time = localtimeinfo.system_time;
    }

    if (config.pseudo_real_time_clock) {
      timeinfo.tsc_timestamp = 0;
      timeinfo.system_time = 0;
    }

    timeinfo.version &= ~1ULL; // bit 0 == 0 means update all done

    ctx.sys_time_cycles_to_nsec_coeff = 1. / ((double)ctx.core_freq_hz / 1000000000.);
    ctx.timer_cycle = infinity;
    ctx.poll_timer_cycle = infinity;

    logfile << "VCPU ", i, ":", endl;
    logfile << "  base_tsc:               ", intstring(ctx.base_tsc, 20), endl;
    logfile << "  sim_cycle:              ", intstring(sim_cycle, 20), endl;
    logfile << "  rdtsc (virtualized):    ", intstring(ctx.base_tsc + sim_cycle, 20), endl;
    logfile << "  rdtsc (physical):       ", intstring(phys_tsc, 20), endl;
    logfile << "  system_time (virtual):  ", intstring(ctx.base_system_time, 20), endl;
    logfile << "  system_time (physical): ", intstring(shinfo.vcpu_info[0].time.system_time, 20), endl;

    RunstateInfo& runstate = ctx.runstate;
    runstate.state_entry_time = (W64)ctx.base_system_time;
    setzero(runstate.time);
    // Don't do this: some VCPUs may not yet be up
    // runstate.state = RUNSTATE_running;
    // ctx.running = 1;
  }

  first_time_calibration_after_boot = 0;

  if (config.pseudo_real_time_clock) {
    initial_realtime_info.wc_sec = 0;
    initial_realtime_info.wc_nsec = 0;
  }

  double timer_period_sec = 1. / ((double)config.timer_interrupt_freq_hz);
  timer_interrupt_period_in_cycles = contextof(0).core_freq_hz / config.timer_interrupt_freq_hz;
  timer_interrupt_last_sent_at_cycle = 0;

  //
  // Initially all ports go to undefined VCPUs; we use the
  // evtchn_status hypercall to lazily resolve this.
  //
  memset(port_to_vcpu_cache, 0xff, NR_EVENT_CHANNELS);
  always_mask_port.reset();

  reconstruct_virq_to_port_mappings();

  logfile << "Timer interrupts will be delivered every 1/", config.timer_interrupt_freq_hz,
    " sec = every ", timer_interrupt_period_in_cycles, " cycles", endl;

  // Summarize the low 256 events (this is advisory only - generally there are fewer than 256 events)
  logfile << "Summary of event channels:", endl;
  foreach (port, 256) {    
    evtchn_status_t status = evtchn_get_status(port);
    if (status.status == EVTCHNSTAT_closed) continue;
    logfile << "  Port ", intstring(port, 4), ": ", status, endl;
  }

  if (config.mask_interrupts) {
    logfile << "Deterministic event masking enabled: clearing all non-internal IRQs", endl;
    foreach (i, contextcount) {
      struct vcpu_info& vcpu_info = sshinfo.vcpu_info[0];
      vcpu_info.evtchn_upcall_pending = 0;
      vcpu_info.evtchn_pending_sel = 0;
    }
    setzero(sshinfo.evtchn_pending);
  }

  if (logable(1)) {
    logfile << "Current shared info:", endl, shinfo, endl;
    logfile << "Current shadow shared info:", endl, sshinfo, endl;
  }

  // Let PTLsim see all events on all VCPUs even if the guest masks them...
  setzero(shinfo.evtchn_mask);
}

//
// Set the timestamp biases before switching to native mode.
//
// This function must be called as close as possible to where we
// switch to native mode to ensure maximum timestamp accuracy.
//
void virtualize_time_for_native_mode() {
  foreach (i, contextcount) {
    Context& ctx = contextof(i);
    if (ctx.user_runstate) {
      vcpu_register_runstate_memory_area req;
      req.addr.v = (vcpu_runstate_info_t*)ctx.user_runstate;
      int rc = HYPERVISOR_vcpu_op(VCPUOP_register_runstate_memory_area, i, &req);
    }
  }

  //
  // Assume global TSC synchronization across all physical cores (guaranteed by hypervisor)
  //
  W64 phys_tsc = rdtsc();

  foreach (i, contextcount) {
    //
    // Re-bias the virtualized timestamp counter so rdtsc in native mode
    // appears to start ticking from exactly where we left off in simulated
    // time, rather than the much larger value in real time.
    //
    Context& ctx = contextof(i);
    vcpu_time_info_t& time = sshinfo.vcpu_info[i].time;

    W64 virtual_tsc = ctx.base_tsc + sim_cycle;
    W64s tsc_timestamp_bias = virtual_tsc - phys_tsc;
    W64 virtual_system_time = (config.realtime) ? shinfo.vcpu_info[0].time.system_time : 
      ctx.base_system_time;
    W64 phys_system_time = time.system_time;
    W64s system_time_bias = virtual_system_time - phys_system_time;

    //
    // Disable for now: newer kernels seem to auto-resync when the TSC and system time
    // jump ahead. It may be required for other kernels though.
    //
    // set_virtualized_tsc_bias(i, tsc_timestamp_bias, system_time_bias);

    if (1) {
      // Disable by default since all this printing can skew timing
      logfile << "Time Virtualization on VCPU ", i, ":", endl;
      logfile << "  base_tsc:               ", intstring(ctx.base_tsc, 20), endl;
      logfile << "  sim_cycle:              ", intstring(sim_cycle, 20), endl;
      logfile << "  rdtsc (virtualized):    ", intstring(ctx.base_tsc + sim_cycle, 20), endl;
      logfile << "  rdtsc (physical):       ", intstring(phys_tsc, 20), endl;
      logfile << "  tsc_timestamp_bias:     ", intstring(tsc_timestamp_bias, 20), endl;
      logfile << "  system_time (virtual):  ", intstring(virtual_system_time, 20), endl;
      logfile << "  system_time (physical): ", intstring(phys_system_time, 20), endl;
      logfile << "  system_time_bias:       ", intstring(system_time_bias, 20), endl;
      logfile << flush;
    }
  }
}

//
// Update time info in shinfo page
//
void update_time() {
  //
  // Important! We do *not* update tsc_timestamp and system_time
  // in the shinfo page: the values remain fixed at whatever
  // they were when we context swapped the domain.
  //
  // This is absolutely necessary since Xen itself only updates
  // the base timestamps once every few seconds: the guest is
  // expected to interpolate the correct time from the TSC.
  // If we update the base timestamps during the simulation,
  // all kinds of problems appear in guest kernels.
  //

  W64 nsecs_since_epoch;

  if likely (config.realtime) {
    sshinfo.wc_sec = shinfo.wc_sec;
    sshinfo.wc_nsec = shinfo.wc_nsec;
  } else {
    // Simulated time dilation
    nsecs_since_epoch = (initial_realtime_info.wc_sec * 1000000000ULL) +
      initial_realtime_info.wc_nsec;
    nsecs_since_epoch += (W64)(sim_cycle * contextof(0).sys_time_cycles_to_nsec_coeff);

    sshinfo.wc_sec = nsecs_since_epoch / 1000000000ULL;
    sshinfo.wc_nsec = nsecs_since_epoch % 1000000000ULL;
  }
}

//
// Inject events from the event replay queue.
// Returns true if an upcall is needed.
//
// The caller should call ctx.check_events()
// and possibly ctx.event_upcall() on each
// VCPU to actually process the events.
//
// Cores should call inject_events() every
// cycle, as well as after any assist.
//

bool Context::change_runstate(int newstate) {
  if (runstate.state == newstate) return false;

  update_time();

  W64 current_time_nsec = sshinfo.vcpu_info[vcpuid].time.system_time;
  W64 delta_nsec = current_time_nsec - runstate.state_entry_time;
  runstate.time[runstate.state] += delta_nsec;

  static const char* runstate_names[] = {"running", "runnable", "blocked", "offline"};

  if (logable(1)) logfile << "[vcpu ", vcpuid, "] change_vcpu_runstate at cycle ", sim_cycle, ": ", runstate_names[runstate.state],
    " -> ", runstate_names[newstate], " (delta nsec ", delta_nsec, ")", endl;

  runstate.state_entry_time = current_time_nsec;
  runstate.state = newstate;

  W64 delta_cycles, delta_insns;
  reset_mode_switch_delta_cycles_and_insns(delta_cycles, delta_insns);

  if (newstate == RUNSTATE_running) {
    //
    // Change from blocked -> running
    //
    assert(!running);

    stats.external.cycles_in_mode.idle += delta_cycles;
    stats.external.insns_in_mode.idle += delta_insns;

    if (logable(2)) {
      logfile << "[vcpu ", vcpuid, "] Wakeup at ", sim_cycle, " cycles, ", total_user_insns_committed, " insns",
        " (previous mode idle: delta ", delta_cycles, " cycles, ", delta_insns, " insns)", endl;
    }
  } else {
    //
    // Change from running -> blocked
    // Block or yield requires a hypercall or HLT: those only work in kernel mode
    //
    // assert(newstate == RUNSTATE_blocked);
    assert(kernel_mode);
    assert(use64);

    if (logable(2)) {
      logfile << "[vcpu ", vcpuid, "] Idle at ", sim_cycle, " cycles, ", total_user_insns_committed, " insns",
        " (previous mode ", "kernel64", ": delta ", delta_cycles, " cycles, ", delta_insns, " insns)", endl;
    }
    
    stats.external.cycles_in_mode.kernel64 += delta_cycles;
    stats.external.insns_in_mode.kernel64 += delta_insns;
  }

  running = (newstate == RUNSTATE_running);

  if likely (user_runstate) {
    int n = copy_to_user((Waddr)user_runstate, &runstate, sizeof(vcpu_runstate_info_t));
    if unlikely (n != sizeof(vcpu_runstate_info_t)) {
      if (logable(1)) logfile << "change_vcpu_runstate: warning: only copied ", n,
        " bytes to mapped runstate pointer ", user_runstate, endl;
    }
  }

  return true;
}

static bool deliver_timer_interrupt_to_vcpu(int vcpuid, bool forced) {
  Context& ctx = contextof(vcpuid);

  int port = ctx.virq_to_port[VIRQ_TIMER];

  if unlikely (port < 0) return false;
  if (logable(1)) {
    logfile << "[vcpu ", vcpuid, "] Deliver ", ((forced) ? "forced" : "periodic"), " timer interrupt on port ",
      port, " at abs cycle ", (sim_cycle + ctx.base_tsc), " (rel cycle ", sim_cycle, "); ",
      " masked? ", sshinfo.vcpu_info[vcpuid].evtchn_upcall_mask, ", pending? ", 
      sshinfo.vcpu_info[vcpuid].evtchn_upcall_pending, ", state? ", ctx.runstate.state, " (running? ", ctx.running, ")", endl;
  }

  shadow_evtchn_set_pending(port);
  return ctx.check_events();
}

bitvec<MAX_VIRT_CPUS> old_vcpu_has_pending_events;

void print_pending_events(ostream& os) {
  foreach (i, 1024) {
    if unlikely (sshinfo_evtchn_pending[i]) {
      os << " [", i;
      if (sshinfo_evtchn_mask[i]) os << " masked";
      os << "]";
    }
  }
}

//
// Inject any pending events into all VCPUs and queue
// upcalls if required. The interrupt upcall is not
// actually taken until the core acknowledges it,
// for instance at the boundary between x86 instructions.
//
// NOTE: This function is on the critical path since it is
// called every cycle by the selected core. Keep it fast!
//
int inject_events() {
  W64 delta = sim_cycle - timer_interrupt_last_sent_at_cycle;

  bool needs_upcall = false;

  if unlikely (delta >= timer_interrupt_period_in_cycles) {
    timer_interrupt_last_sent_at_cycle = sim_cycle;
    update_time();

    foreach (i, contextcount) {
      needs_upcall |= deliver_timer_interrupt_to_vcpu(i, false);
    }
  }

  foreach (i, contextcount) {
    Context& ctx = contextof(i);
    if unlikely ((ctx.base_tsc + sim_cycle) >= ctx.timer_cycle) {
      ctx.timer_cycle = infinity;
      update_time();
      needs_upcall |= deliver_timer_interrupt_to_vcpu(i, true);
    }

    bool pending = sshinfo.vcpu_info[i].evtchn_upcall_pending;

    if unlikely ((!old_vcpu_has_pending_events[i]) & pending) {
      if (logable(1)) {
        logfile << "[vcpu ", ctx.vcpuid, "] Edge triggered events in cycle ", sim_cycle, " (abs cycle ", (sim_cycle + ctx.base_tsc), "); "
          "masked? ", sshinfo.vcpu_info[ctx.vcpuid].evtchn_upcall_mask, ", pending? ", 
          sshinfo.vcpu_info[ctx.vcpuid].evtchn_upcall_pending, ", state? ", ctx.runstate.state, " (running? ", ctx.running, ") => ";
        print_pending_events(logfile);
        logfile << "; upcall? ", ctx.check_events(), endl;
      }
    }

    needs_upcall |= ctx.check_events();

    old_vcpu_has_pending_events[i] = pending;
  }

  return needs_upcall;
}

//
// Timer and event channel hypercalls
//
#define getreq(type) type req; if (ctx.copy_from_user(&req, (Waddr)arg, sizeof(type)) != sizeof(type)) { return W64(-EFAULT); }
#define putreq(type) ctx.copy_to_user((Waddr)arg, &req, sizeof(type))

W64 handle_event_channel_op_hypercall(Context& ctx, int op, void* arg, bool debug = 0) {
  int rc = 0;

  switch (op) {
  case EVTCHNOP_alloc_unbound: {
    getreq(evtchn_alloc_unbound);
    rc = HYPERVISOR_event_channel_op(op, &req);
    if (debug) logfile << "evtchn_alloc_unbound {dom = ", req.dom, ", remote_dom = ", req.remote_dom, "} => {port = ", req.port, "}", ", rc ", rc, endl;
    putreq(evtchn_alloc_unbound);
    break;
  }
  case EVTCHNOP_bind_interdomain: {
    getreq(evtchn_bind_interdomain);
    rc = HYPERVISOR_event_channel_op(op, &req);
    if (debug) logfile << "evtchn_bind_interdomain {remote_dom = ", req.remote_dom, ", remote_port = ", req.remote_port, "} => {local_port = ", req.local_port, "}", ", rc ", rc, endl;
    putreq(evtchn_bind_interdomain);
    break;
  }
  case EVTCHNOP_bind_virq: {
    //
    // PTLsim needs to monitor attempts to bind the VIRQ_TIMER interrupt so we can
    // correctly deliver internal timer events at the appropriate rate.
    //
    getreq(evtchn_bind_virq);
    rc = HYPERVISOR_event_channel_op(op, &req);

    if (debug) logfile << "evtchn_bind_virq {virq = ", req.virq, ", vcpu = ", req.vcpu, "} => {port = ", req.port, "}", ", rc ", rc, endl;

    if (rc == 0) {
      assert(req.vcpu < contextcount);
      assert(req.virq < lengthof(contextof(req.vcpu).virq_to_port));
      contextof(req.vcpu).virq_to_port[req.virq] = req.port;
      assert(req.port < NR_EVENT_CHANNELS);
      port_to_vcpu_cache[req.port] = req.vcpu;
      // PTLsim generates its own timer interrupts
      if (req.virq == VIRQ_TIMER) {
        if (debug) logfile << "Assigned timer VIRQ ", req.virq, " on VCPU ", req.vcpu, " to port ", req.port, endl;
        unmask_evtchn(req.port); // PTLsim will not pass it on, but it still uses the timer virq internally
        always_mask_port[req.port] = 1;
        real_timer_port[ctx.vcpuid] = req.port;
      }
    }
    putreq(evtchn_bind_virq);
    break;
  }
  case EVTCHNOP_bind_ipi: {
    getreq(evtchn_bind_ipi);
    rc = HYPERVISOR_event_channel_op(op, &req);
    if (debug) logfile << "evtchn_bind_ipi {vcpu = ", req.vcpu, "} => {port = ", req.port, "}", ", rc ", rc, endl;
    if (rc == 0) port_to_vcpu_cache[req.port] = req.vcpu;
    putreq(evtchn_bind_ipi);
    break;
  }
  case EVTCHNOP_close: {
    getreq(evtchn_close);
    rc = HYPERVISOR_event_channel_op(op, &req);
    if (debug) logfile << "evtchn_close {port = ", req.port, "}", ", rc ", rc, endl;
    putreq(evtchn_close);
    break;
  }
  case EVTCHNOP_send: {
    getreq(evtchn_send);
    evtchn_status_t status = evtchn_get_status(req.port);
    if (status.status == EVTCHNSTAT_ipi) {
      shadow_evtchn_set_pending(req.port);
      rc = 0;
    } else {
      rc = HYPERVISOR_event_channel_op(op, &req);
    }
    if (debug) logfile << "evtchn_send {port = ", req.port, "} => ", status, ", rc ", rc, endl;
    putreq(evtchn_send);
    break;
  }
  case EVTCHNOP_status: {
    getreq(evtchn_status);
    rc = HYPERVISOR_event_channel_op(op, &req);
    if (debug) logfile << "evtchn_status {port ", req.port, "} => ", req, ", rc ", rc, endl;
    putreq(evtchn_status);
    break;
  }
  case EVTCHNOP_bind_vcpu: {
    getreq(evtchn_bind_vcpu);
    rc = HYPERVISOR_event_channel_op(op, &req);
    if (debug) logfile << "evtchn_bind_vcpu {port = ", req.port, ", vcpu = ", req.vcpu, "}", ", rc ", rc, endl;
    if (rc == 0) port_to_vcpu_cache[req.port] = req.vcpu;
    putreq(evtchn_bind_vcpu);
    break;
  }
  case EVTCHNOP_unmask: {
    //
    // Unmask is special since we need to redirect it to our
    // virtual shinfo page, and potentially simulate an upcall.
    //
    getreq(evtchn_unmask);
    if (debug) logfile << "evtchn_unmask {port = ", req.port, "}, rc ", rc, endl;
    shadow_evtchn_unmask(req.port);
    rc = 0;
    putreq(evtchn_unmask);
    break;
  }
  default:
    rc = -ENOSYS;
    break;
  }

  return rc;
}

W64 handle_set_timer_op_hypercall(Context& ctx, W64 timeout, bool debug) {
  if (timeout) {
    update_time();

    vcpu_time_info_t& time = sshinfo.vcpu_info[ctx.vcpuid].time;
    W64 trigger_nsecs_since_boot = timeout;
    W64 current_cycle = (ctx.base_tsc + sim_cycle);
    W64 current_nsecs_since_boot = time.system_time + W64s((current_cycle - time.tsc_timestamp) * ctx.sys_time_cycles_to_nsec_coeff);
    W64s delta_nsecs = trigger_nsecs_since_boot - current_nsecs_since_boot;
    W64s delta_cycles = W64s(delta_nsecs / ctx.sys_time_cycles_to_nsec_coeff);
    W64 trigger_cycles_since_boot = current_cycle + delta_cycles;

    ctx.timer_cycle = trigger_cycles_since_boot;
    
    //
    // If problems arise with negative timer values, force this to be a fixed timer interrupt period:
    // NOTE: the hypervisor itself now contains an equivalent workaround, so disable this: 
    //
    // if (delta_cycles < timer_interrupt_period_in_cycles)
    //   ctx.timer_cycle = ctx.base_tsc + sim_cycle + timer_interrupt_period_in_cycles;

    if unlikely (delta_cycles < 100000)
      ctx.timer_cycle = ctx.base_tsc + sim_cycle + 100000;

    delta_cycles = ctx.timer_cycle - (ctx.base_tsc + sim_cycle);

    if (debug) {
      logfile << "set_timer_op: trigger ", trigger_nsecs_since_boot, " nsecs vs current nsecs ",
        current_nsecs_since_boot, " (delta ", delta_nsecs, " nsecs in future) => delta ", delta_cycles,
        " cycles in future => final trigger cycle ", trigger_cycles_since_boot, endl;
    }
  } else {
    ctx.timer_cycle = infinity;
    if (debug) logfile << "set_timer_op: cancel timer", endl;
  }
  return 0;
}

bool vcpu_online_map_changed = 0;

W64 handle_vcpu_op_hypercall(Context& ctx, W64 arg1, W64 arg2, W64 arg3, bool debug) {
  int vcpuid = arg2;
  if (arg2 >= contextcount) { return W64(-EINVAL); }

  Context& vctx = contextof(vcpuid);

  switch (arg1) {
  case VCPUOP_register_runstate_memory_area: {
    //
    // This is a virtual address not currently mapped by PTLsim:
    // Xen will get a silent fault (ignored) every time it tries to
    // update this data until it returns to the guest in which
    // this address is valid.
    //
    // Therefore, we don't set it until we switch to native mode.
    //
    vcpu_register_runstate_memory_area req;
    if (ctx.copy_from_user(&req, (Waddr)arg3, sizeof(req)) != sizeof(req)) { return W64(-EFAULT); }
    if (debug) logfile << "vcpu_op: register_runstate_memory_area: registered virt ", req.addr.v, " for runstate info on vcpu ", vcpuid, endl, flush;
    // Since this is virtual, we need to check it every time we "reschedule" the VCPU:
    vctx.user_runstate = (RunstateInfo*)req.addr.v;
    return 0;
  }
  case VCPUOP_is_up: {
    if (debug) logfile << "vcpu_op: is_up: vcpu ", vcpuid, " is ", ((vctx.runstate.state != RUNSTATE_offline) ? "up" : "offline"), endl;
    return (vctx.runstate.state != RUNSTATE_offline);
  }
  case VCPUOP_initialise: {
    if (debug) logfile << "vcpu_op: initialize vcpu ", vcpuid, ": xenctx @ ", (void*)arg3, endl;
    vcpu_guest_context_t xenctx;
    if (ctx.copy_from_user(&xenctx, (Waddr)arg3, sizeof(xenctx)) != sizeof(xenctx)) { return W64(-EFAULT); }
    vctx.restorefrom(xenctx);
    vctx.init(); // refill segment descriptor caches
    vctx.running = 0; // not running until VCPUOP_up is called

    if (debug) logfile << "VCPU ", vcpuid, " context at initialize is:", endl, vctx, endl;

    return 0;
  }
  case VCPUOP_up: {
    if (debug) logfile << "vcpu_op: up: bring up vcpu ", vcpuid, endl;
    if (debug) logfile << "VCPU ", vcpuid, " context at bringup is:", endl, vctx, endl;
    //
    // The VCPU is coming up for the first time after booting or being
    // taken offline by the user.
    //
    // Force the active core model to flush any cached (uninitialized)
    // internal state (like register file copies) it might have, since
    // it did not know anything about this VCPU prior to now: if it
    // suddenly gets marked as running without this, the core model
    // will try to execute from bogus state data.
    //
    vctx.dirty = 1;
    vctx.change_runstate(RUNSTATE_running);
    vcpu_online_map_changed = 1;

    //
    // At this point we also need to bring up the real VCPU
    // on which PTLsim will run its interrupt redirector.
    //
    bring_up_secondary_vcpu(vcpuid);

    return 0;
  }
  case VCPUOP_down: {
    if (debug) logfile << "vcpu_op: bring down vcpu ", vcpuid, endl;
    vcpu_online_map_changed = 1;
    vctx.change_runstate(RUNSTATE_offline);
    return 0;
  }
  case VCPUOP_set_singleshot_timer: {
    //++MTY TODO: add support for this newer hypercall:
    if (debug) logfile << "vcpu_op: set singleshot timer on ", vcpuid, " not supported", endl;
    return -ENOSYS;
  }
  default:
    logfile << "vcpu_op ", arg1, " not implemented!", endl, flush;
    break;
  }

  return 0;
}

W64 handle_sched_op_hypercall(Context& ctx, W64 op, void* arg, bool debug) {
  switch (op) {
  case SCHEDOP_yield: {
    // Take no action: under PTLsim, the guest VCPU appears to run continuously
    if (debug) logfile << "sched_op: yield VCPU ", ctx.vcpuid, endl, flush;
    return 0;
  }
  case SCHEDOP_block: {
    //
    // Block the VCPU. The specified core model is responsible for checking
    // ctx.running and if zero, no instructions will be dispatched from that
    // hardware thread or core. However, inject_events() must still be called
    // so it will unblock when an interrupt arrives.
    //
    // Xen implicitly unmasks events when we do this. 
    // 
    if (debug) logfile << "sched_op: blocking VCPU ", ctx.vcpuid, endl, flush;
    ctx.change_runstate(RUNSTATE_blocked);
    sshinfo.vcpu_info[ctx.vcpuid].evtchn_upcall_mask = 0;
    return 0;
  }
  case SCHEDOP_shutdown: {
    getreq(sched_shutdown_t);
    if (debug) logfile << "sched_op: shutdown (reason ", req.reason, ")", endl, flush;
    inject_upcall("-kill", 5, true);
    return 0;
  }
  case SCHEDOP_poll: {
    // Not currently used by Linux guests:
    assert(false);
    return -EINVAL;
  }
  default: {
    return -EINVAL;
  }
  }
  return 0;
}
