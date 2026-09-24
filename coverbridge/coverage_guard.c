/* SPDX-License-Identifier: MIT
   Compile WITHOUT coverage instrumentation. GNU/LLD --wrap redirects only
   trace-pc-guard calls to these hooks, avoiding libFuzzer's deprecated stubs. */
#define _GNU_SOURCE
#include "covbridge.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

_Static_assert(__atomic_always_lock_free(sizeof(uint64_t), 0),
               "guard backend requires lock-free 64-bit atomics");
_Static_assert(__atomic_always_lock_free(sizeof(uint32_t), 0),
               "guard backend requires lock-free 32-bit atomics");

typedef struct {
    uint64_t layout_id, run_id;
    _Atomic uint32_t enabled, overflow;
    _Atomic uint64_t counts[];
} shared_map;
static shared_map *map;
static uint32_t nslots;
static pid_t controller;
static int producer_enabled;

static void bad_registration(void) {
    static const char msg[] = "covbridge: too many edges or instrumented module loaded after cb_init\n";
    (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _exit(125);
}
void __wrap___sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *end) {
    if (start == end || *start) return;
    size_t n = (size_t)(end - start);
    if (map || n > CB_MAX_EDGES - nslots) bad_registration();
    for (uint32_t *p = start; p < end; ++p) *p = ++nslots;
}
void __wrap___sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    /* No allocation, lock, socket operation, or callback into libFuzzer. */
    if (!producer_enabled || !map || !*guard ||
        !atomic_load_explicit(&map->enabled, memory_order_acquire))
        return;
    uint64_t old = atomic_fetch_add_explicit(&map->counts[*guard - 1], 1,
                                             memory_order_relaxed);
    if (old == UINT64_MAX)
        atomic_store_explicit(&map->overflow, 1, memory_order_relaxed);
}
uint32_t cb_slots(void) { return nslots; }
void cb_producer_enable(void) { producer_enabled = 1; }
int cb_init(uint64_t layout_id) {
    if (map) { errno = EALREADY; return -1; }
    if (!layout_id || !nslots) { errno = EINVAL; return -1; }
    size_t bytes = sizeof(shared_map) + (size_t)nslots * sizeof(_Atomic uint64_t);
    shared_map *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return -1;
    p->layout_id = layout_id;
    p->run_id = 0;
    atomic_init(&p->enabled, 0);
    atomic_init(&p->overflow, 0);
    for (uint32_t i = 0; i < nslots; ++i) atomic_init(&p->counts[i], 0);
    controller = getpid();
    map = p;  /* Initialize before any target threads or forks. */
    return 0;
}
int cb_begin(uint64_t run_id) {
    if (!map || !run_id) { errno = EINVAL; return -1; }
    if (getpid() != controller) { errno = EPERM; return -1; }
    if (atomic_load_explicit(&map->enabled, memory_order_relaxed)) {
        errno = EBUSY; return -1;
    }
    if (run_id <= map->run_id) { errno = EINVAL; return -1; }
    /* Producer quiescence is a CALLER precondition, not provided by this flag. */
    for (uint32_t i = 0; i < nslots; ++i)
        atomic_store_explicit(&map->counts[i], 0, memory_order_relaxed);
    atomic_store_explicit(&map->overflow, 0, memory_order_relaxed);
    map->run_id = run_id;
    atomic_store_explicit(&map->enabled, 1, memory_order_release);
    return 0;
}
int cb_end(cb_snapshot *out) {
    if (!map || !out) { errno = EINVAL; return -1; }
    if (getpid() != controller) { errno = EPERM; return -1; }
    if (!atomic_exchange_explicit(&map->enabled, 0, memory_order_acq_rel)) {
        errno = EINVAL; return -1;
    }
    /* Disabling collection does NOT wait for an already-running hook.
       The caller must have joined/parked ALL target workers before this call. */
    if (atomic_load_explicit(&map->overflow, memory_order_relaxed)) {
        errno = EOVERFLOW; return -1;
    }
    if (cb_snapshot_reserve(out, nslots)) return -1;
    out->run_id = map->run_id;
    out->layout_id = map->layout_id;
    out->mode = CB_COUNTS64;
    for (uint32_t i = 0; i < nslots; ++i)
        out->counts[i] = atomic_load_explicit(&map->counts[i], memory_order_relaxed);
    return 0;
}
