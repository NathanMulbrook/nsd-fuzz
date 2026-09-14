/* SPDX-License-Identifier: MIT
   Compile WITHOUT coverage. Link this object directly (or reference the API
   from a static archive). This ELF section is consumed by stock libFuzzer. */
#include "covbridge.h"
#include <errno.h>
#include <string.h>

_Static_assert(CB_MAX_EDGES % 64 == 0, "counter capacity must be a multiple of 64");
__attribute__((section("__libfuzzer_extra_counters"), used, aligned(64)))
static uint8_t extra[CB_MAX_EDGES];

void cb_libfuzzer_clear(void) { memset(extra, 0, sizeof(extra)); }
int cb_libfuzzer_import(const cb_snapshot *s, uint32_t offset) {
    if (!s || !s->counts || !s->nslots || offset > CB_MAX_EDGES ||
        s->nslots > CB_MAX_EDGES - offset ||
        (s->mode != CB_COUNTS64 && s->mode != CB_INLINE8)) {
        errno = EINVAL; return -1;
    }
    if (s->mode == CB_INLINE8)
        for (uint32_t i = 0; i < s->nslots; ++i)
            if (s->counts[i] > 255) { errno = EINVAL; return -1; }
    for (uint32_t i = 0; i < s->nslots; ++i) {
        uint32_t old = extra[offset + i];
        uint64_t c = s->counts[i];
        extra[offset + i] = c >= 255u - old ? 255 : (uint8_t)(old + c);
    }
    return 0;
}
