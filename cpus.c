/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* Needed early for CONFIG_BSD etc. */
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "monitor/monitor.h"
#include "qapi/qmp/qerror.h"
#include "qemu/error-report.h"
#include "sysemu/sysemu.h"
#include "sysemu/block-backend.h"
#include "exec/gdbstub.h"
#include "sysemu/dma.h"
#include "sysemu/kvm.h"
#include "qmp-commands.h"
#include "exec/exec-all.h"

#include "qemu/thread.h"
#include "sysemu/cpus.h"
#include "sysemu/qtest.h"
#include "qemu/main-loop.h"
#include "qemu/bitmap.h"
#include "qemu/seqlock.h"
#include "qapi-event.h"
#include "hw/nmi.h"
#include "sysemu/replay.h"

#ifndef _WIN32
#include "qemu/compatfd.h"
#endif

#ifdef CONFIG_LINUX

#include <sys/prctl.h>

#ifndef PR_MCE_KILL
#define PR_MCE_KILL 33
#endif

#ifndef PR_MCE_KILL_SET
#define PR_MCE_KILL_SET 1
#endif

#ifndef PR_MCE_KILL_EARLY
#define PR_MCE_KILL_EARLY 1
#endif

#endif /* CONFIG_LINUX */

static CPUState *next_cpu;
int64_t max_delay;
int64_t max_advance;

/* vcpu throttling controls */
static QEMUTimer *throttle_timer;
static unsigned int throttle_percentage;

#define CPU_THROTTLE_PCT_MIN 1
#define CPU_THROTTLE_PCT_MAX 99
#define CPU_THROTTLE_TIMESLICE_NS 10000000

bool cpu_is_stopped(CPUState *cpu)
{
    return cpu->stopped || !runstate_is_running();
}

static bool cpu_thread_is_idle(CPUState *cpu)
{
    if (cpu->stop || cpu->queued_work_first) {
        return false;
    }
    if (cpu_is_stopped(cpu)) {
        return true;
    }
    if (!cpu->halted || cpu_has_work(cpu) ||
        kvm_halt_in_kernel()) {
        return false;
    }
    return true;
}

static bool all_cpu_threads_idle(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (!cpu_thread_is_idle(cpu)) {
            return false;
        }
    }
    return true;
}

/***********************************************************/
/* guest cycle counter */

/* Protected by TimersState seqlock */

static bool icount_sleep = true;
static int64_t vm_clock_warp_start = -1;
/* Conversion factor from emulated instructions to virtual clock ticks.  */
static int icount_time_shift;
/* Arbitrarily pick 1MIPS as the minimum allowable speed.  */
#define MAX_ICOUNT_SHIFT 10

static QEMUTimer *icount_rt_timer;
static QEMUTimer *icount_vm_timer;
static QEMUTimer *icount_warp_timer;

typedef struct TimersState {
    /* Protected by BQL.  */
    int64_t cpu_ticks_prev;
    int64_t cpu_ticks_offset;

    /* cpu_clock_offset can be read out of BQL, so protect it with
     * this lock.
     */
    QemuSeqLock vm_clock_seqlock;
    int64_t cpu_clock_offset;
    int32_t cpu_ticks_enabled;
    int64_t dummy;

    /* Compensate for varying guest execution speed.  */
    int64_t qemu_icount_bias;
    /* Only written by TCG thread */
    int64_t qemu_icount;
} TimersState;

static TimersState timers_state;

int64_t cpu_get_icount_raw(void)
{
    int64_t icount;
    CPUState *cpu = current_cpu;

    icount = timers_state.qemu_icount;
    if (cpu) {
        if (!cpu->can_do_io) {
            fprintf(stderr, "Bad icount read\n");
            exit(1);
        }
        icount -= (cpu->icount_decr.u16.low + cpu->icount_extra);
    }
    return icount;
}

/* Return the virtual CPU time, based on the instruction counter.  */
static int64_t cpu_get_icount_locked(void)
{
    int64_t icount = cpu_get_icount_raw();
    return timers_state.qemu_icount_bias + cpu_icount_to_ns(icount);
}

int64_t cpu_get_icount(void)
{
    int64_t icount;
    unsigned start;

    do {
        start = seqlock_read_begin(&timers_state.vm_clock_seqlock);
        icount = cpu_get_icount_locked();
    } while (seqlock_read_retry(&timers_state.vm_clock_seqlock, start));

    return icount;
}

int64_t cpu_icount_to_ns(int64_t icount)
{
    return icount << icount_time_shift;
}

/* return the host CPU cycle counter and handle stop/restart */
/* Caller must hold the BQL */
int64_t cpu_get_ticks(void)
{
    int64_t ticks;

    if (use_icount) {
        return cpu_get_icount();
    }

    ticks = timers_state.cpu_ticks_offset;
    if (timers_state.cpu_ticks_enabled) {
        ticks += cpu_get_host_ticks();
    }

    if (timers_state.cpu_ticks_prev > ticks) {
        /* Note: non increasing ticks may happen if the host uses
           software suspend */
        timers_state.cpu_ticks_offset += timers_state.cpu_ticks_prev - ticks;
        ticks = timers_state.cpu_ticks_prev;
    }

    timers_state.cpu_ticks_prev = ticks;
    return ticks;
}

static int64_t cpu_get_clock_locked(void)
{
    int64_t ticks;

    ticks = timers_state.cpu_clock_offset;
    if (timers_state.cpu_ticks_enabled) {
        ticks += get_clock();
    }

    return ticks;
}

/* return the host CPU monotonic timer and handle stop/restart */
int64_t cpu_get_clock(void)
{
    int64_t ti;
    unsigned start;

    do {
        start = seqlock_read_begin(&timers_state.vm_clock_seqlock);
        ti = cpu_get_clock_locked();
    } while (seqlock_read_retry(&timers_state.vm_clock_seqlock, start));

    return ti;
}

/* enable cpu_get_ticks()
 * Caller must hold BQL which server as mutex for vm_clock_seqlock.
 */
void cpu_enable_ticks(void)
{
    /* Here, the really thing protected by seqlock is cpu_clock_offset. */
    seqlock_write_lock(&timers_state.vm_clock_seqlock);
    if (!timers_state.cpu_ticks_enabled) {
        timers_state.cpu_ticks_offset -= cpu_get_host_ticks();
        timers_state.cpu_clock_offset -= get_clock();
        timers_state.cpu_ticks_enabled = 1;
    }
    seqlock_write_unlock(&timers_state.vm_clock_seqlock);
}

/* disable cpu_get_ticks() : the clock is stopped. You must not call
 * cpu_get_ticks() after that.
 * Caller must hold BQL which server as mutex for vm_clock_seqlock.
 */
void cpu_disable_ticks(void)
{
    /* Here, the really thing protected by seqlock is cpu_clock_offset. */
    seqlock_write_lock(&timers_state.vm_clock_seqlock);
    if (timers_state.cpu_ticks_enabled) {
        timers_state.cpu_ticks_offset += cpu_get_host_ticks();
        timers_state.cpu_clock_offset = cpu_get_clock_locked();
        timers_state.cpu_ticks_enabled = 0;
    }
    seqlock_write_unlock(&timers_state.vm_clock_seqlock);
}

/* Correlation between real and virtual time is always going to be
   fairly approximate, so ignore small variation.
   When the guest is idle real and virtual time will be aligned in
   the IO wait loop.  */
#define ICOUNT_WOBBLE (NANOSECONDS_PER_SECOND / 10)

static void icount_adjust(void)
{
    int64_t cur_time;
    int64_t cur_icount;
    int64_t delta;

    /* Protected by TimersState mutex.  */
    static int64_t last_delta;

    /* If the VM is not running, then do nothing.  */
    if (!runstate_is_running()) {
        return;
    }

    seqlock_write_lock(&timers_state.vm_clock_seqlock);
    cur_time = cpu_get_clock_locked();
    cur_icount = cpu_get_icount_locked();

    delta = cur_icount - cur_time;
    /* FIXME: This is a very crude algorithm, somewhat prone to oscillation.  */
    if (delta > 0
        && last_delta + ICOUNT_WOBBLE < delta * 2
        && icount_time_shift > 0) {
        /* The guest is getting too far ahead.  Slow time down.  */
        icount_time_shift--;
    }
    if (delta < 0
        && last_delta - ICOUNT_WOBBLE > delta * 2
        && icount_time_shift < MAX_ICOUNT_SHIFT) {
        /* The guest is getting too far behind.  Speed time up.  */
        icount_time_shift++;
    }
    last_delta = delta;
    timers_state.qemu_icount_bias = cur_icount
                              - (timers_state.qemu_icount << icount_time_shift);
    seqlock_write_unlock(&timers_state.vm_clock_seqlock);
}

static void icount_adjust_rt(void *opaque)
{
    timer_mod(icount_rt_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL_RT) + 1000);
    icount_adjust();
}

static void icount_adjust_vm(void *opaque)
{
    timer_mod(icount_vm_timer,
                   qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                   NANOSECONDS_PER_SECOND / 10);
    icount_adjust();
}

static int64_t qemu_icount_round(int64_t count)
{
    return (count + (1 << icount_time_shift) - 1) >> icount_time_shift;
}

static void icount_warp_rt(void)
{
    unsigned seq;
    int64_t warp_start;

    /* The icount_warp_timer is rescheduled soon after vm_clock_warp_start
     * changes from -1 to another value, so the race here is okay.
     */
    do {
        seq = seqlock_read_begin(&timers_state.vm_clock_seqlock);
        warp_start = vm_clock_warp_start;
    } while (seqlock_read_retry(&timers_state.vm_clock_seqlock, seq));

    if (warp_start == -1) {
        return;
    }

    seqlock_write_lock(&timers_state.vm_clock_seqlock);
    if (runstate_is_running()) {
        int64_t clock = REPLAY_CLOCK(REPLAY_CLOCK_VIRTUAL_RT,
                                     cpu_get_clock_locked());
        int64_t warp_delta;

        warp_delta = clock - vm_clock_warp_start;
        if (use_icount == 2) {
            /*
             * In adaptive mode, do not let QEMU_CLOCK_VIRTUAL run too
             * far ahead of real time.
             */
            int64_t cur_icount = cpu_get_icount_locked();
            int64_t delta = clock - cur_icount;
            warp_delta = MIN(warp_delta, delta);
        }
        timers_state.qemu_icount_bias += warp_delta;
    }
    vm_clock_warp_start = -1;
    seqlock_write_unlock(&timers_state.vm_clock_seqlock);

    if (qemu_clock_expired(QEMU_CLOCK_VIRTUAL)) {
        qemu_clock_notify(QEMU_CLOCK_VIRTUAL);
    }
}

static void icount_timer_cb(void *opaque)
{
    /* No need for a checkpoint because the timer already synchronizes
     * with CHECKPOINT_CLOCK_VIRTUAL_RT.
     */
    icount_warp_rt();
}

void qtest_clock_warp(int64_t dest)
{
    int64_t clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    AioContext *aio_context;
    assert(qtest_enabled());
    aio_context = qemu_get_aio_context();
    while (clock < dest) {
        int64_t deadline = qemu_clock_deadline_ns_all(QEMU_CLOCK_VIRTUAL);
        int64_t warp = qemu_soonest_timeout(dest - clock, deadline);

        seqlock_write_lock(&timers_state.vm_clock_seqlock);
        timers_state.qemu_icount_bias += warp;
        seqlock_write_unlock(&timers_state.vm_clock_seqlock);

        qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL);
        timerlist_run_timers(aio_context->tlg.tl[QEMU_CLOCK_VIRTUAL]);
        clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    }
    qemu_clock_notify(QEMU_CLOCK_VIRTUAL);
}

void qemu_start_warp_timer(void)
{
    int64_t clock;
    int64_t deadline;

    if (!use_icount) {
        return;
    }

    /* Nothing to do if the VM is stopped: QEMU_CLOCK_VIRTUAL timers
     * do not fire, so computing the deadline does not make sense.
     */
    if (!runstate_is_running()) {
        return;
    }

    /* warp clock deterministically in record/replay mode */
    if (!replay_checkpoint(CHECKPOINT_CLOCK_WARP_START)) {
        return;
    }

    if (!all_cpu_threads_idle()) {
        return;
    }

    if (qtest_enabled()) {
        /* When testing, qtest commands advance icount.  */
        return;
    }

    /* We want to use the earliest deadline from ALL vm_clocks */
    clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_RT);
    deadline = qemu_clock_deadline_ns_all(QEMU_CLOCK_VIRTUAL);
    if (deadline < 0) {
        static bool notified;
        if (!icount_sleep && !notified) {
            error_report("WARNING: icount sleep disabled and no active timers");
            notified = true;
        }
        return;
    }

    if (deadline > 0) {
        /*
         * Ensure QEMU_CLOCK_VIRTUAL proceeds even when the virtual CPU goes to
         * sleep.  Otherwise, the CPU might be waiting for a future timer
         * interrupt to wake it up, but the interrupt never comes because
         * the vCPU isn't running any insns and thus doesn't advance the
         * QEMU_CLOCK_VIRTUAL.
         */
        if (!icount_sleep) {
            /*
             * We never let VCPUs sleep in no sleep icount mode.
             * If there is a pending QEMU_CLOCK_VIRTUAL timer we just advance
             * to the next QEMU_CLOCK_VIRTUAL event and notify it.
             * It is useful when we want a deterministic execution time,
             * isolated from host latencies.
             */
            seqlock_write_lock(&timers_state.vm_clock_seqlock);
            timers_state.qemu_icount_bias += deadline;
            seqlock_write_unlock(&timers_state.vm_clock_seqlock);
            qemu_clock_notify(QEMU_CLOCK_VIRTUAL);
        } else {
            /*
             * We do stop VCPUs and only advance QEMU_CLOCK_VIRTUAL after some
             * "real" time, (related to the time left until the next event) has
             * passed. The QEMU_CLOCK_VIRTUAL_RT clock will do this.
             * This avoids that the warps are visible externally; for example,
             * you will not be sending network packets continuously instead of
             * every 100ms.
             */
            seqlock_write_lock(&timers_state.vm_clock_seqlock);
            if (vm_clock_warp_start == -1 || vm_clock_warp_start > clock) {
                vm_clock_warp_start = clock;
            }
            seqlock_write_unlock(&timers_state.vm_clock_seqlock);
            timer_mod_anticipate(icount_warp_timer, clock + deadline);
        }
    } else if (deadline == 0) {
        qemu_clock_notify(QEMU_CLOCK_VIRTUAL);
    }
}

static void qemu_account_warp_timer(void)
{
    if (!use_icount || !icount_sleep) {
        return;
    }

    /* Nothing to do if the VM is stopped: QEMU_CLOCK_VIRTUAL timers
     * do not fire, so computing the deadline does not make sense.
     */
    if (!runstate_is_running()) {
        return;
    }

    /* warp clock deterministically in record/replay mode */
    if (!replay_checkpoint(CHECKPOINT_CLOCK_WARP_ACCOUNT)) {
        return;
    }

    timer_del(icount_warp_timer);
    icount_warp_rt();
}

static bool icount_state_needed(void *opaque)
{
    return use_icount;
}

/*
 * This is a subsection for icount migration.
 */
static const VMStateDescription icount_vmstate_timers = {
    .name = "timer/icount",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = icount_state_needed,
    .fields = (VMStateField[]) {
        VMSTATE_INT64(qemu_icount_bias, TimersState),
        VMSTATE_INT64(qemu_icount, TimersState),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_timers = {
    .name = "timer",
    .version_id = 2,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_INT64(cpu_ticks_offset, TimersState),
        VMSTATE_INT64(dummy, TimersState),
        VMSTATE_INT64_V(cpu_clock_offset, TimersState, 2),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription*[]) {
        &icount_vmstate_timers,
        NULL
    }
};

static void cpu_throttle_thread(void *opaque)
{
    CPUState *cpu = opaque;
    double pct;
    double throttle_ratio;
    long sleeptime_ns;

    if (!cpu_throttle_get_percentage()) {
        return;
    }

    pct = (double)cpu_throttle_get_percentage()/100;
    throttle_ratio = pct / (1 - pct);
    sleeptime_ns = (long)(throttle_ratio * CPU_THROTTLE_TIMESLICE_NS);

    qemu_mutex_unlock_iothread();
    atomic_set(&cpu->throttle_thread_scheduled, 0);
    g_usleep(sleeptime_ns / 1000); /* Convert ns to us for usleep call */
    qemu_mutex_lock_iothread();
}

static void cpu_throttle_timer_tick(void *opaque)
{
    CPUState *cpu;
    double pct;

    /* Stop the timer if needed */
    if (!cpu_throttle_get_percentage()) {
        return;
    }
    CPU_FOREACH(cpu) {
        if (!atomic_xchg(&cpu->throttle_thread_scheduled, 1)) {
            async_run_on_cpu(cpu, cpu_throttle_thread, cpu);
        }
    }

    pct = (double)cpu_throttle_get_percentage()/100;
    timer_mod(throttle_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_RT) +
                                   CPU_THROTTLE_TIMESLICE_NS / (1-pct));
}

void cpu_throttle_set(int new_throttle_pct)
{
    /* Ensure throttle percentage is within valid range */
    new_throttle_pct = MIN(new_throttle_pct, CPU_THROTTLE_PCT_MAX);
    new_throttle_pct = MAX(new_throttle_pct, CPU_THROTTLE_PCT_MIN);

    atomic_set(&throttle_percentage, new_throttle_pct);

    timer_mod(throttle_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_RT) +
                                       CPU_THROTTLE_TIMESLICE_NS);
}

void cpu_throttle_stop(void)
{
    atomic_set(&throttle_percentage, 0);
}

bool cpu_throttle_active(void)
{
    return (cpu_throttle_get_percentage() != 0);
}

int cpu_throttle_get_percentage(void)
{
    return atomic_read(&throttle_percentage);
}

void cpu_ticks_init(void)
{
    seqlock_init(&timers_state.vm_clock_seqlock, NULL);
    vmstate_register(NULL, 0, &vmstate_timers, &timers_state);
    throttle_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL_RT,
                                           cpu_throttle_timer_tick, NULL);
}

void configure_icount(QemuOpts *opts, Error **errp)
{
    const char *option;
    char *rem_str = NULL;

    option = qemu_opt_get(opts, "shift");
    if (!option) {
        if (qemu_opt_get(opts, "align") != NULL) {
            error_setg(errp, "Please specify shift option when using align");
        }
        return;
    }

    icount_sleep = qemu_opt_get_bool(opts, "sleep", true);
    if (icount_sleep) {
        icount_warp_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL_RT,
                                         icount_timer_cb, NULL);
    }

    icount_align_option = qemu_opt_get_bool(opts, "align", false);

    if (icount_align_option && !icount_sleep) {
        error_setg(errp, "align=on and sleep=off are incompatible");
    }
    if (strcmp(option, "auto") != 0) {
        errno = 0;
        icount_time_shift = strtol(option, &rem_str, 0);
        if (errno != 0 || *rem_str != '\0' || !strlen(option)) {
            error_setg(errp, "icount: Invalid shift value");
        }
        use_icount = 1;
        return;
    } else if (icount_align_option) {
        error_setg(errp, "shift=auto and align=on are incompatible");
    } else if (!icount_sleep) {
        error_setg(errp, "shift=auto and sleep=off are incompatible");
    }

    use_icount = 2;

    /* 125MIPS seems a reasonable initial guess at the guest speed.
       It will be corrected fairly quickly anyway.  */
    icount_time_shift = 3;

    /* Have both realtime and virtual time triggers for speed adjustment.
       The realtime trigger catches emulated time passing too slowly,
       the virtual time trigger catches emulated time passing too fast.
       Realtime triggers occur even when idle, so use them less frequently
       than VM triggers.  */
    icount_rt_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL_RT,
                                   icount_adjust_rt, NULL);
    timer_mod(icount_rt_timer,
                   qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL_RT) + 1000);
    icount_vm_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                        icount_adjust_vm, NULL);
    timer_mod(icount_vm_timer,
                   qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                   NANOSECONDS_PER_SECOND / 10);
}

/***********************************************************/
void hw_error(const char *fmt, ...)
{
    va_list ap;
    CPUState *cpu;

    va_start(ap, fmt);
    fprintf(stderr, "qemu: hardware error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    CPU_FOREACH(cpu) {
        fprintf(stderr, "CPU #%d:\n", cpu->cpu_index);
        cpu_dump_state(cpu, stderr, fprintf, CPU_DUMP_FPU);
    }
    va_end(ap);
    abort();
}

void cpu_synchronize_all_states(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        cpu_synchronize_state(cpu);
    }
}

void cpu_synchronize_all_post_reset(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        cpu_synchronize_post_reset(cpu);
    }
}

void cpu_synchronize_all_post_init(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        cpu_synchronize_post_init(cpu);
    }
}

static int do_vm_stop(RunState state)
{
    int ret = 0;

    if (runstate_is_running()) {
        cpu_disable_ticks();
        pause_all_vcpus();
        runstate_set(state);
        vm_state_notify(0, state);
        qapi_event_send_stop(&error_abort);
    }

    bdrv_drain_all();
    ret = blk_flush_all();

    return ret;
}

static bool cpu_can_run(CPUState *cpu)
{
    if (cpu->stop) {
        return false;
    }
    if (cpu_is_stopped(cpu)) {
        return false;
    }
    return true;
}

static void cpu_handle_guest_debug(CPUState *cpu)
{
    gdb_set_stop_cpu(cpu);
    qemu_system_debug_request();
    cpu->stopped = true;
}

#ifdef CONFIG_LINUX
static void sigbus_reraise(void)
{
    sigset_t set;
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (!sigaction(SIGBUS, &action, NULL)) {
        raise(SIGBUS);
        sigemptyset(&set);
        sigaddset(&set, SIGBUS);
        sigprocmask(SIG_UNBLOCK, &set, NULL);
    }
    perror("Failed to re-raise SIGBUS!\n");
    abort();
}

static void sigbus_handler(int n, struct qemu_signalfd_siginfo *siginfo,
                           void *ctx)
{
    if (kvm_on_sigbus(siginfo->ssi_code,
                      (void *)(intptr_t)siginfo->ssi_addr)) {
        sigbus_reraise();
    }
}

static void qemu_init_sigbus(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = (void (*)(int, siginfo_t*, void*))sigbus_handler;
    sigaction(SIGBUS, &action, NULL);

    prctl(PR_MCE_KILL, PR_MCE_KILL_SET, PR_MCE_KILL_EARLY, 0, 0);
}

static void qemu_kvm_eat_signals(CPUState *cpu)
{
    struct timespec ts = { 0, 0 };
    siginfo_t siginfo;
    sigset_t waitset;
    sigset_t chkset;
    int r;

    sigemptyset(&waitset);
    sigaddset(&waitset, SIG_IPI);
    sigaddset(&waitset, SIGBUS);

    do {
        r = sigtimedwait(&waitset, &siginfo, &ts);
        if (r == -1 && !(errno == EAGAIN || errno == EINTR)) {
            perror("sigtimedwait");
            exit(1);
        }

        switch (r) {
        case SIGBUS:
            if (kvm_on_sigbus_vcpu(cpu, siginfo.si_code, siginfo.si_addr)) {
                sigbus_reraise();
            }
            break;
        default:
            break;
        }

        r = sigpending(&chkset);
        if (r == -1) {
            perror("sigpending");
            exit(1);
        }
    } while (sigismember(&chkset, SIG_IPI) || sigismember(&chkset, SIGBUS));
}

#else /* !CONFIG_LINUX */

static void qemu_init_sigbus(void)
{
}

static void qemu_kvm_eat_signals(CPUState *cpu)
{
}
#endif /* !CONFIG_LINUX */

#ifndef _WIN32
static void dummy_signal(int sig)
{
}

static void qemu_kvm_init_cpu_signals(CPUState *cpu)
{
    int r;
    sigset_t set;
    struct sigaction sigact;

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = dummy_signal;
    sigaction(SIG_IPI, &sigact, NULL);

    pthread_sigmask(SIG_BLOCK, NULL, &set);
    sigdelset(&set, SIG_IPI);
    sigdelset(&set, SIGBUS);
    r = kvm_set_signal_mask(cpu, &set);
    if (r) {
        fprintf(stderr, "kvm_set_signal_mask: %s\n", strerror(-r));
        exit(1);
    }
}

#else /* _WIN32 */
static void qemu_kvm_init_cpu_signals(CPUState *cpu)
{
    abort();
}
#endif /* _WIN32 */

static QemuMutex qemu_global_mutex;
static QemuCond qemu_io_proceeded_cond;
static unsigned iothread_requesting_mutex;

static QemuThread io_thread;

/* cpu creation */
static QemuCond qemu_cpu_cond;
/* system init */
static QemuCond qemu_pause_cond;
static QemuCond qemu_work_cond;

void qemu_init_cpu_loop(void)
{
    qemu_init_sigbus();
    qemu_cond_init(&qemu_cpu_cond);
    qemu_cond_init(&qemu_pause_cond);
    qemu_cond_init(&qemu_work_cond);
    qemu_cond_init(&qemu_io_proceeded_cond);
    qemu_mutex_init(&qemu_global_mutex);

    qemu_thread_get_self(&io_thread);
}

void run_on_cpu(CPUState *cpu, void (*func)(void *data), void *data)
{
    struct qemu_work_item wi;

    if (qemu_cpu_is_self(cpu)) {
        func(data);
        return;
    }

    wi.func = func;
    wi.data = data;
    wi.free = false;

    qemu_mutex_lock(&cpu->work_mutex);
    if (cpu->queued_work_first == NULL) {
        cpu->queued_work_first = &wi;
    } else {
        cpu->queued_work_last->next = &wi;
    }
    cpu->queued_work_last = &wi;
    wi.next = NULL;
    wi.done = false;
    qemu_mutex_unlock(&cpu->work_mutex);

    qemu_cpu_kick(cpu);
    while (!atomic_mb_read(&wi.done)) {
        CPUState *self_cpu = current_cpu;

        qemu_cond_wait(&qemu_work_cond, &qemu_global_mutex);
        current_cpu = self_cpu;
    }
}

void async_run_on_cpu(CPUState *cpu, void (*func)(void *data), void *data)
{
    struct qemu_work_item *wi;

    if (qemu_cpu_is_self(cpu)) {
        func(data);
        return;
    }

    wi = g_malloc0(sizeof(struct qemu_work_item));
    wi->func = func;
    wi->data = data;
    wi->free = true;

    qemu_mutex_lock(&cpu->work_mutex);
    if (cpu->queued_work_first == NULL) {
        cpu->queued_work_first = wi;
    } else {
        cpu->queued_work_last->next = wi;
    }
    cpu->queued_work_last = wi;
    wi->next = NULL;
    wi->done = false;
    qemu_mutex_unlock(&cpu->work_mutex);

    qemu_cpu_kick(cpu);
}

static void flush_queued_work(CPUState *cpu)
{
    struct qemu_work_item *wi;

    if (cpu->queued_work_first == NULL) {
        return;
    }

    qemu_mutex_lock(&cpu->work_mutex);
    while (cpu->queued_work_first != NULL) {
        wi = cpu->queued_work_first;
        cpu->queued_work_first = wi->next;
        if (!cpu->queued_work_first) {
            cpu->queued_work_last = NULL;
        }
        qemu_mutex_unlock(&cpu->work_mutex);
        wi->func(wi->data);
        qemu_mutex_lock(&cpu->work_mutex);
        if (wi->free) {
            g_free(wi);
        } else {
            atomic_mb_set(&wi->done, true);
        }
    }
    qemu_mutex_unlock(&cpu->work_mutex);
    qemu_cond_broadcast(&qemu_work_cond);
}

static void qemu_wait_io_event_common(CPUState *cpu)
{
    if (cpu->stop) {
        cpu->stop = false;
        cpu->stopped = true;
        qemu_cond_broadcast(&qemu_pause_cond);
    }
    flush_queued_work(cpu);
    cpu->thread_kicked = false;
}

static void qemu_tcg_wait_io_event(CPUState *cpu)
{
    while (all_cpu_threads_idle()) {
        qemu_cond_wait(cpu->halt_cond, &qemu_global_mutex);
    }

    while (iothread_requesting_mutex) {
        qemu_cond_wait(&qemu_io_proceeded_cond, &qemu_global_mutex);
    }

    CPU_FOREACH(cpu) {
        qemu_wait_io_event_common(cpu);
    }
}

static void qemu_kvm_wait_io_event(CPUState *cpu)
{
    while (cpu_thread_is_idle(cpu)) {
        qemu_cond_wait(cpu->halt_cond, &qemu_global_mutex);
    }

    qemu_kvm_eat_signals(cpu);
    qemu_wait_io_event_common(cpu);
}

static void *qemu_kvm_cpu_thread_fn(void *arg)
{
    CPUState *cpu = arg;
    int r;

    rcu_register_thread();

    qemu_mutex_lock_iothread();
    qemu_thread_get_self(cpu->thread);
    cpu->thread_id = qemu_get_thread_id();
    cpu->can_do_io = 1;
    current_cpu = cpu;

    r = kvm_init_vcpu(cpu);
    if (r < 0) {
        fprintf(stderr, "kvm_init_vcpu failed: %s\n", strerror(-r));
        exit(1);
    }

    qemu_kvm_init_cpu_signals(cpu);

    /* signal CPU creation */
    cpu->created = true;
    qemu_cond_signal(&qemu_cpu_cond);

    while (1) {
        if (cpu_can_run(cpu)) {
            r = kvm_cpu_exec(cpu);
            if (r == EXCP_DEBUG) {
                cpu_handle_guest_debug(cpu);
            }
        }
        qemu_kvm_wait_io_event(cpu);
    }

    return NULL;
}

static void *qemu_dummy_cpu_thread_fn(void *arg)
{
#ifdef _WIN32
    fprintf(stderr, "qtest is not supported under Windows\n");
    exit(1);
#else
    CPUState *cpu = arg;
    sigset_t waitset;
    int r;

    rcu_register_thread();

    qemu_mutex_lock_iothread();
    qemu_thread_get_self(cpu->thread);
    cpu->thread_id = qemu_get_thread_id();
    cpu->can_do_io = 1;

    sigemptyset(&waitset);
    sigaddset(&waitset, SIG_IPI);

    /* signal CPU creation */
    cpu->created = true;
    qemu_cond_signal(&qemu_cpu_cond);

    current_cpu = cpu;
    while (1) {
        current_cpu = NULL;
        qemu_mutex_unlock_iothread();
        do {
            int sig;
            r = sigwait(&waitset, &sig);
        } while (r == -1 && (errno == EAGAIN || errno == EINTR));
        if (r == -1) {
            perror("sigwait");
            exit(1);
        }
        qemu_mutex_lock_iothread();
        current_cpu = cpu;
        qemu_wait_io_event_common(cpu);
    }

    return NULL;
#endif
}

static void tcg_exec_all(void);

static void *qemu_tcg_cpu_thread_fn(void *arg)
{
    CPUState *cpu = arg;

    rcu_register_thread();

    qemu_mutex_lock_iothread();
    qemu_thread_get_self(cpu->thread);

    CPU_FOREACH(cpu) {
        cpu->thread_id = qemu_get_thread_id();
        cpu->created = true;
        cpu->can_do_io = 1;
    }
    qemu_cond_signal(&qemu_cpu_cond);

    /* wait for initial kick-off after machine start */
    while (first_cpu->stopped) {
        qemu_cond_wait(first_cpu->halt_cond, &qemu_global_mutex);

        /* process any pending work */
        CPU_FOREACH(cpu) {
            qemu_wait_io_event_common(cpu);
        }
    }

    /* process any pending work */
    atomic_mb_set(&exit_request, 1);

    while (1) {
        tcg_exec_all();

        if (use_icount) {
            int64_t deadline = qemu_clock_deadline_ns_all(QEMU_CLOCK_VIRTUAL);

            if (deadline == 0) {
                qemu_clock_notify(QEMU_CLOCK_VIRTUAL);
            }
        }
        qemu_tcg_wait_io_event(QTAILQ_FIRST(&cpus));
    }

    return NULL;
}

static void qemu_cpu_kick_thread(CPUState *cpu)
{
#ifndef _WIN32
    int err;

    if (cpu->thread_kicked) {
        return;
    }
    cpu->thread_kicked = true;
    err = pthread_kill(cpu->thread->thread, SIG_IPI);
    if (err) {
        fprintf(stderr, "qemu:%s: %s", __func__, strerror(err));
        exit(1);
    }
#else /* _WIN32 */
    abort();
#endif
}

static void qemu_cpu_kick_no_halt(void)
{
    CPUState *cpu;
    /* Ensure whatever caused the exit has reached the CPU threads before
     * writing exit_request.
     */
    atomic_mb_set(&exit_request, 1);
    cpu = atomic_mb_read(&tcg_current_cpu);
    if (cpu) {
        cpu_exit(cpu);
    }
}

void qemu_cpu_kick(CPUState *cpu)
{
    qemu_cond_broadcast(cpu->halt_cond);
    if (tcg_enabled()) {
        qemu_cpu_kick_no_halt();
    } else {
        qemu_cpu_kick_thread(cpu);
    }
}

void qemu_cpu_kick_self(void)
{
    assert(current_cpu);
    qemu_cpu_kick_thread(current_cpu);
}

bool qemu_cpu_is_self(CPUState *cpu)
{
    return qemu_thread_is_self(cpu->thread);
}

bool qemu_in_vcpu_thread(void)
{
    return current_cpu && qemu_cpu_is_self(current_cpu);
}

static __thread bool iothread_locked = false;

bool qemu_mutex_iothread_locked(void)
{
    return iothread_locked;
}

void qemu_mutex_lock_iothread(void)
{
    atomic_inc(&iothread_requesting_mutex);
    /* In the simple case there is no need to bump the VCPU thread out of
     * TCG code execution.
     */
    if (!tcg_enabled() || qemu_in_vcpu_thread() ||
        !first_cpu || !first_cpu->created) {
        qemu_mutex_lock(&qemu_global_mutex);
        atomic_dec(&iothread_requesting_mutex);
    } else {
        if (qemu_mutex_trylock(&qemu_global_mutex)) {
            qemu_cpu_kick_no_halt();
            qemu_mutex_lock(&qemu_global_mutex);
        }
        atomic_dec(&iothread_requesting_mutex);
        qemu_cond_broadcast(&qemu_io_proceeded_cond);
    }
    iothread_locked = true;
}

void qemu_mutex_unlock_iothread(void)
{
    iothread_locked = false;
    qemu_mutex_unlock(&qemu_global_mutex);
}

static int all_vcpus_paused(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (!cpu->stopped) {
            return 0;
        }
    }

    return 1;
}

void pause_all_vcpus(void)
{
    CPUState *cpu;

    qemu_clock_enable(QEMU_CLOCK_VIRTUAL, false);
    CPU_FOREACH(cpu) {
        cpu->stop = true;
        qemu_cpu_kick(cpu);
    }

    if (qemu_in_vcpu_thread()) {
        cpu_stop_current();
        if (!kvm_enabled()) {
            CPU_FOREACH(cpu) {
                cpu->stop = false;
                cpu->stopped = true;
            }
            return;
        }
    }

    while (!all_vcpus_paused()) {
        qemu_cond_wait(&qemu_pause_cond, &qemu_global_mutex);
        CPU_FOREACH(cpu) {
            qemu_cpu_kick(cpu);
        }
    }
}

void cpu_resume(CPUState *cpu)
{
    cpu->stop = false;
    cpu->stopped = false;
    qemu_cpu_kick(cpu);
}

void resume_all_vcpus(void)
{
    CPUState *cpu;

    qemu_clock_enable(QEMU_CLOCK_VIRTUAL, true);
    CPU_FOREACH(cpu) {
        cpu_resume(cpu);
    }
}

/* For temporary buffers for forming a name */
#define VCPU_THREAD_NAME_SIZE 16

static void qemu_tcg_init_vcpu(CPUState *cpu)
{
    char thread_name[VCPU_THREAD_NAME_SIZE];
    static QemuCond *tcg_halt_cond;
    static QemuThread *tcg_cpu_thread;

    /* share a single thread for all cpus with TCG */
    if (!tcg_cpu_thread) {
        cpu->thread = g_malloc0(sizeof(QemuThread));
        cpu->halt_cond = g_malloc0(sizeof(QemuCond));
        qemu_cond_init(cpu->halt_cond);
        tcg_halt_cond = cpu->halt_cond;
        snprintf(thread_name, VCPU_THREAD_NAME_SIZE, "CPU %d/TCG",
                 cpu->cpu_index);
        qemu_thread_create(cpu->thread, thread_name, qemu_tcg_cpu_thread_fn,
                           cpu, QEMU_THREAD_JOINABLE);
#ifdef _WIN32
        cpu->hThread = qemu_thread_get_handle(cpu->thread);
#endif
        while (!cpu->created) {
            qemu_cond_wait(&qemu_cpu_cond, &qemu_global_mutex);
        }
        tcg_cpu_thread = cpu->thread;
    } else {
        cpu->thread = tcg_cpu_thread;
        cpu->halt_cond = tcg_halt_cond;
    }
}

static void qemu_kvm_start_vcpu(CPUState *cpu)
{
    char thread_name[VCPU_THREAD_NAME_SIZE];

    cpu->thread = g_malloc0(sizeof(QemuThread));
    cpu->halt_cond = g_malloc0(sizeof(QemuCond));
    qemu_cond_init(cpu->halt_cond);
    snprintf(thread_name, VCPU_THREAD_NAME_SIZE, "CPU %d/KVM",
             cpu->cpu_index);
    qemu_thread_create(cpu->thread, thread_name, qemu_kvm_cpu_thread_fn,
                       cpu, QEMU_THREAD_JOINABLE);
    while (!cpu->created) {
        qemu_cond_wait(&qemu_cpu_cond, &qemu_global_mutex);
    }
}

static void qemu_dummy_start_vcpu(CPUState *cpu)
{
    char thread_name[VCPU_THREAD_NAME_SIZE];

    cpu->thread = g_malloc0(sizeof(QemuThread));
    cpu->halt_cond = g_malloc0(sizeof(QemuCond));
    qemu_cond_init(cpu->halt_cond);
    snprintf(thread_name, VCPU_THREAD_NAME_SIZE, "CPU %d/DUMMY",
             cpu->cpu_index);
    qemu_thread_create(cpu->thread, thread_name, qemu_dummy_cpu_thread_fn, cpu,
                       QEMU_THREAD_JOINABLE);
    while (!cpu->created) {
        qemu_cond_wait(&qemu_cpu_cond, &qemu_global_mutex);
    }
}

void qemu_init_vcpu(CPUState *cpu)
{
    cpu->nr_cores = smp_cores;
    cpu->nr_threads = smp_threads;
    cpu->stopped = true;

    if (!cpu->as) {
        /* If the target cpu hasn't set up any address spaces itself,
         * give it the default one.
         */
        AddressSpace *as = address_space_init_shareable(cpu->memory,
                                                        "cpu-memory");
        cpu->num_ases = 1;
        cpu_address_space_init(cpu, as, 0);
    }

    if (kvm_enabled()) {
        qemu_kvm_start_vcpu(cpu);
    } else if (tcg_enabled()) {
        qemu_tcg_init_vcpu(cpu);
    } else {
        qemu_dummy_start_vcpu(cpu);
    }
}

void cpu_stop_current(void)
{
    if (current_cpu) {
        current_cpu->stop = false;
        current_cpu->stopped = true;
        cpu_exit(current_cpu);
        qemu_cond_broadcast(&qemu_pause_cond);
    }
}

int vm_stop(RunState state)
{
    if (qemu_in_vcpu_thread()) {
        qemu_system_vmstop_request_prepare();
        qemu_system_vmstop_request(state);
        /*
         * FIXME: should not return to device code in case
         * vm_stop() has been requested.
         */
        cpu_stop_current();
        return 0;
    }

    return do_vm_stop(state);
}

/* does a state transition even if the VM is already stopped,
   current state is forgotten forever */
int vm_stop_force_state(RunState state)
{
    if (runstate_is_running()) {
        return vm_stop(state);
    } else {
        runstate_set(state);

        bdrv_drain_all();
        /* Make sure to return an error if the flush in a previous vm_stop()
         * failed. */
        return blk_flush_all();
    }
}

static int64_t tcg_get_icount_limit(void)
{
    int64_t deadline;

    if (replay_mode != REPLAY_MODE_PLAY) {
        deadline = qemu_clock_deadline_ns_all(QEMU_CLOCK_VIRTUAL);

        /* Maintain prior (possibly buggy) behaviour where if no deadline
         * was set (as there is no QEMU_CLOCK_VIRTUAL timer) or it is more than
         * INT32_MAX nanoseconds ahead, we still use INT32_MAX
         * nanoseconds.
         */
        if ((deadline < 0) || (deadline > INT32_MAX)) {
            deadline = INT32_MAX;
        }

        return qemu_icount_round(deadline);
    } else {
        return replay_get_instructions();
    }
}

static int tcg_cpu_exec(CPUState *cpu)
{
    int ret;
#ifdef CONFIG_PROFILER
    int64_t ti;
#endif

#ifdef CONFIG_PROFILER
    ti = profile_getclock();
#endif
    if (use_icount) {
        int64_t count;
        int decr;
        timers_state.qemu_icount -= (cpu->icount_decr.u16.low
                                    + cpu->icount_extra);
        cpu->icount_decr.u16.low = 0;
        cpu->icount_extra = 0;
        count = tcg_get_icount_limit();
        timers_state.qemu_icount += count;
        decr = (count > 0xffff) ? 0xffff : count;
        count -= decr;
        cpu->icount_decr.u16.low = decr;
        cpu->icount_extra = count;
    }
    ret = cpu_exec(cpu);
#ifdef CONFIG_PROFILER
    tcg_time += profile_getclock() - ti;
#endif
    if (use_icount) {
        /* Fold pending instructions back into the
           instruction counter, and clear the interrupt flag.  */
        timers_state.qemu_icount -= (cpu->icount_decr.u16.low
                        + cpu->icount_extra);
        cpu->icount_decr.u32 = 0;
        cpu->icount_extra = 0;
        replay_account_executed_instructions();
    }
    return ret;
}

static void tcg_exec_all(void)
{
    int r;

    /* Account partial waits to QEMU_CLOCK_VIRTUAL.  */
    qemu_account_warp_timer();

    if (next_cpu == NULL) {
        next_cpu = first_cpu;
    }
    for (; next_cpu != NULL && !exit_request; next_cpu = CPU_NEXT(next_cpu)) {
        CPUState *cpu = next_cpu;

        qemu_clock_enable(QEMU_CLOCK_VIRTUAL,
                          (cpu->singlestep_enabled & SSTEP_NOTIMER) == 0);

        if (cpu_can_run(cpu)) {
            r = tcg_cpu_exec(cpu);
            if (r == EXCP_DEBUG) {
                cpu_handle_guest_debug(cpu);
                break;
            }
        } else if (cpu->stop || cpu->stopped) {
            break;
        }
    }

    /* Pairs with smp_wmb in qemu_cpu_kick.  */
    atomic_mb_set(&exit_request, 0);
}

void list_cpus(FILE *f, fprintf_function cpu_fprintf, const char *optarg)
{
    /* XXX: implement xxx_cpu_list for targets that still miss it */
#if defined(cpu_list)
    cpu_list(f, cpu_fprintf);
#endif
}

CpuInfoList *qmp_query_cpus(Error **errp)
{
    CpuInfoList *head = NULL, *cur_item = NULL;
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        CpuInfoList *info;
#if defined(TARGET_I386)
        X86CPU *x86_cpu = X86_CPU(cpu);
        CPUX86State *env = &x86_cpu->env;
#elif defined(TARGET_PPC)
        PowerPCCPU *ppc_cpu = POWERPC_CPU(cpu);
        CPUPPCState *env = &ppc_cpu->env;
#elif defined(TARGET_SPARC)
        SPARCCPU *sparc_cpu = SPARC_CPU(cpu);
        CPUSPARCState *env = &sparc_cpu->env;
#elif defined(TARGET_MIPS)
        MIPSCPU *mips_cpu = MIPS_CPU(cpu);
        CPUMIPSState *env = &mips_cpu->env;
#elif defined(TARGET_TRICORE)
        TriCoreCPU *tricore_cpu = TRICORE_CPU(cpu);
        CPUTriCoreState *env = &tricore_cpu->env;
#endif

        cpu_synchronize_state(cpu);

        info = g_malloc0(sizeof(*info));
        info->value = g_malloc0(sizeof(*info->value));
        info->value->CPU = cpu->cpu_index;
        info->value->current = (cpu == first_cpu);
        info->value->halted = cpu->halted;
        info->value->qom_path = object_get_canonical_path(OBJECT(cpu));
        info->value->thread_id = cpu->thread_id;
#if defined(TARGET_I386)
        info->value->arch = CPU_INFO_ARCH_X86;
        info->value->u.x86.pc = env->eip + env->segs[R_CS].base;
#elif defined(TARGET_PPC)
        info->value->arch = CPU_INFO_ARCH_PPC;
        info->value->u.ppc.nip = env->nip;
#elif defined(TARGET_SPARC)
        info->value->arch = CPU_INFO_ARCH_SPARC;
        info->value->u.q_sparc.pc = env->pc;
        info->value->u.q_sparc.npc = env->npc;
#elif defined(TARGET_MIPS)
        info->value->arch = CPU_INFO_ARCH_MIPS;
        info->value->u.q_mips.PC = env->active_tc.PC;
#elif defined(TARGET_TRICORE)
        info->value->arch = CPU_INFO_ARCH_TRICORE;
        info->value->u.tricore.PC = env->PC;
#else
        info->value->arch = CPU_INFO_ARCH_OTHER;
#endif

        /* XXX: waiting for the qapi to support GSList */
        if (!cur_item) {
            head = cur_item = info;
        } else {
            cur_item->next = info;
            cur_item = info;
        }
    }

    return head;
}

void qmp_memsave(int64_t addr, int64_t size, const char *filename,
                 bool has_cpu, int64_t cpu_index, Error **errp)
{
    FILE *f;
    uint32_t l;
    CPUState *cpu;
    uint8_t buf[1024];
    int64_t orig_addr = addr, orig_size = size;

    if (!has_cpu) {
        cpu_index = 0;
    }

    cpu = qemu_get_cpu(cpu_index);
    if (cpu == NULL) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "cpu-index",
                   "a CPU number");
        return;
    }

    f = fopen(filename, "wb");
    if (!f) {
        error_setg_file_open(errp, errno, filename);
        return;
    }

    while (size != 0) {
        l = sizeof(buf);
        if (l > size)
            l = size;
        if (cpu_memory_rw_debug(cpu, addr, buf, l, 0) != 0) {
            error_setg(errp, "Invalid addr 0x%016" PRIx64 "/size %" PRId64
                             " specified", orig_addr, orig_size);
            goto exit;
        }
        if (fwrite(buf, 1, l, f) != l) {
            error_setg(errp, QERR_IO_ERROR);
            goto exit;
        }
        addr += l;
        size -= l;
    }

exit:
    fclose(f);
}

void qmp_pmemsave(int64_t addr, int64_t size, const char *filename,
                  Error **errp)
{
    FILE *f;
    uint32_t l;
    uint8_t buf[1024];

    f = fopen(filename, "wb");
    if (!f) {
        error_setg_file_open(errp, errno, filename);
        return;
    }

    while (size != 0) {
        l = sizeof(buf);
        if (l > size)
            l = size;
        cpu_physical_memory_read(addr, buf, l);
        if (fwrite(buf, 1, l, f) != l) {
            error_setg(errp, QERR_IO_ERROR);
            goto exit;
        }
        addr += l;
        size -= l;
    }

exit:
    fclose(f);
}

void qmp_inject_nmi(Error **errp)
{
#if defined(TARGET_I386)
    CPUState *cs;

    CPU_FOREACH(cs) {
        X86CPU *cpu = X86_CPU(cs);

        if (!cpu->apic_state) {
            cpu_interrupt(cs, CPU_INTERRUPT_NMI);
        } else {
            apic_deliver_nmi(cpu->apic_state);
        }
    }
#else
    nmi_monitor_handle(monitor_get_cpu_index(), errp);
#endif
}

void dump_drift_info(FILE *f, fprintf_function cpu_fprintf)
{
    if (!use_icount) {
        return;
    }

    cpu_fprintf(f, "Host - Guest clock  %"PRIi64" ms\n",
                (cpu_get_clock() - cpu_get_icount())/SCALE_MS);
    if (icount_align_option) {
        cpu_fprintf(f, "Max guest delay     %"PRIi64" ms\n", -max_delay/SCALE_MS);
        cpu_fprintf(f, "Max guest advance   %"PRIi64" ms\n", max_advance/SCALE_MS);
    } else {
        cpu_fprintf(f, "Max guest delay     NA\n");
        cpu_fprintf(f, "Max guest advance   NA\n");
    }
}
