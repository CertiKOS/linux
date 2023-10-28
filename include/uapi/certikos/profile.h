#ifndef _PROFILE_H_
#define _PROFILE_H_

#if (defined(_KERN_))
/* CERTIKOS KERNEL */
#include <arch/arch.h>
#include <arch/benchmark.h>
#include <arch/kstack.h>
#include <lib/common.h>
#include <lib/debug.h>
#include <lib/export/include/app.h>
#include <profile_env.h>

#define output(args...) KERN_INFO(args)

#elif (defined(_USER_))
/* CERTIKOS USERSPACE */
#include <app.h>
#include <arch.h>
#include <proc.h>
#include <profile_env.h>
#include <stdio.h>
#include <stdlib.h>

#define output(args...) printf(args)
#define cpu()           get_cpu()

#else
/* LINUX USERSPACE */
#include "profile_env.h"
#include <certikos/app.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define output(args...) printf(args)
#define cpu()           gettid()

#endif

/**
 * Choose the measurement primitive
 * For ARM  tsc() is timer ticks, cycle() should be cycles,
 */
#if (!defined(PROFILE_TIMER_TICKS) && !defined(PROFILE_CYCLES))
#define PROFILE_TIMER_TICKS 1
#define PROFILE_CYCLES      0
#endif

#if (PROFILE_TIMER_TICKS)
#define time()      tsc()
#define time_unit() "ticks"
#endif /* PROFILE_TIMER_TICKS */

#if (PROFILE_CYCLES)
#define time()      cycle()
#define time_unit() "cycles"
#endif /* PROFILE_CYCLES */

#define WARM (30u)

enum profile_style
{
    prf_style_void = 0,
    prf_style_ret,

    n_prf_styles
};

struct overhead_t
{
    const char*       name;
    volatile uint64_t min;
    volatile uint64_t max;
    volatile uint64_t avg;
    volatile uint64_t n;
};

struct overheads_t
{
    struct overhead_t  overhead[n_tracks];
    int                set[n_tracks];
    enum profile_style style[n_tracks];

    /* calibration */
    uint64_t           cal_style[n_prf_styles];
};

#define overhead_declare() uint64_t start, end, duration;

#define overhead_profile(o, func, args...)                                    \
    start = time();                                                           \
    func(args);                                                               \
    end      = time();                                                        \
    duration = end - start;                                                   \
    _overhead_update(o, duration);

#define overhead_profile_ret(o, func, ret_type, args...)                      \
    ({                                                                        \
        ret_type __ret_val__;                                                 \
        start       = time();                                                 \
        __ret_val__ = func(args);                                             \
        end         = time();                                                 \
        duration    = end - start;                                            \
        _overhead_update(o, duration);                                        \
        __ret_val__;                                                          \
    })

#define overheads_track(os, t, s) _overheads_track(os, t, s, #t)

#define overheads_profile(os, track, func, args...)                           \
    start = time();                                                           \
    func(args);                                                               \
    end      = time();                                                        \
    duration = end >= start ? end - start : UINT64_MAX;                       \
    _overheads_update(os, track, duration);

#define overheads_warm(n, os, track, func, args...)                           \
    for (unsigned int i = 0; i < WARM; i++)                                   \
    {                                                                         \
        overheads_profile(os, track, func, args);                             \
    }                                                                         \
    overheads_reset(os, track);

#define overheads_measure(n, os, track, func, args...)                        \
    output("start to measure " #func "(" #args ") ... ");                     \
    for (unsigned int i = 0; i < n; i++)                                      \
    {                                                                         \
        overheads_profile(os, track, func, args);                             \
    }                                                                         \
    output("done.\n");

#define overheads_warm_measure(n, os, track, func, args...)                   \
    overheads_warm(n, os, track, func, args);                                 \
    overheads_measure(n, os, track, func, args);

#define overheads_profile_ret(os, track, func, ret_type, args...)             \
    ({                                                                        \
        ret_type __ret_val__;                                                 \
        start       = time();                                                 \
        __ret_val__ = func(args);                                             \
        end         = time();                                                 \
        duration    = end >= start ? end - start : UINT64_MAX;                \
        _overheads_update(os, track, duration);                               \
        __ret_val__;                                                          \
    })

#define overheads_measure_ret(n, os, track, func, ret_type, args...)          \
    output("start to measure " #func "(" #args ") ... ");                     \
    for (unsigned int i = 0; i < n; i++)                                      \
    {                                                                         \
        overheads_profile_ret(os, track, func, ret_type, args);               \
    }                                                                         \
    output("done.\n");

#define overheads_warm_measure_ret(n, os, track, func, ret_type, args...)     \
    overheads_warm(n, os, track, func, args);                                 \
    overheads_measure_ret(n, os, track, func, ret_type, args);

static inline void
_overhead_init(struct overhead_t* o, const char* name)
{
    o->n    = 1llu;
    o->min  = UINT64_MAX;
    o->max  = 0llu;
    o->avg  = 0llu;
    o->name = name;
}

static inline void
_overhead_update(struct overhead_t* o, uint64_t value)
{
    if (value == UINT64_MAX)
    {
        /* counter overflow, case not count */
        output("WARNING: case %u: counter overflow!\n", o->n);
        return;
    }
    o->min = (value < o->min) ? value : o->min;
    o->max = (o->max < value) ? value : o->max;
    o->avg = (o->avg < value) ? (o->avg + (value - o->avg) / o->n)
                              : (o->avg - (o->avg - value) / o->n);
    o->n++;
}

static inline void
overheads_reset(struct overheads_t* os, enum overhead_tracking t)
{
    _overhead_init(&os->overhead[t], os->overhead[t].name);
}

static inline void
_overheads_update(struct overheads_t* os, enum overhead_tracking t,
                  uint64_t value)
{
    _overhead_update(&os->overhead[t], value);
}

static inline void
_overheads_track(struct overheads_t* os, enum overhead_tracking t,
                 enum profile_style s, const char* name)
{
    _overhead_init(&os->overhead[t], name);
    os->set[t]   = 1;
    os->style[t] = s;
}

gcc_keep static void
_empty_no_ret_(void)
{
}

gcc_keep static int
_empty_ret_(void)
{
    return (0xf0);
}

static inline void
overhead_dump(struct overhead_t* o, uint64_t framework_overhead)
{
    if (o->min == UINT64_MAX)
    {
        output("%s: Nan, Nan, Nan, Nan, (n=%llu)\n", o->name, o->n - 1);
    }
    else
    {
        output("%s: %llu, %llu, %llu, %llu, (n=%llu)\n", o->name, o->min,
               o->max, o->avg,
               (o->avg < framework_overhead) ? 0 : o->avg - framework_overhead,
               o->n - 1);
    }
}

static inline void
overhead_dump_json(struct overhead_t* o, uint64_t framework_overhead)
{
    output("        \"%s\":\n", o->name);
    output("        {\n");
    output("            \"min\":      %llu,\n", o->min);
    output("            \"max\":      %llu,\n", o->max);
    output("            \"adj_ave\":  %llu,\n",
           (o->avg < framework_overhead) ? 0 : o->avg - framework_overhead);
    output("            \"overhead\": %llu,\n", framework_overhead);
    output("            \"n\":        %llu\n", o->n - 1);
    output("        }");
}

static inline void
overheads_calibrate(struct overheads_t* os)
{
    unsigned int i;
    volatile int v;
    overhead_declare();

    _overhead_init(&os->overhead[track_calibrate], "calibrate");
    for (i = 0; i < WARM; i++)
    {
        overhead_profile(&os->overhead[track_calibrate], _empty_no_ret_);
    }
    os->cal_style[prf_style_void] = os->overhead[track_calibrate].min;

    for (i = 0; i < WARM; i++)
    {
        v = overhead_profile_ret(&os->overhead[track_calibrate], _empty_ret_,
                                 int);
    }
    os->cal_style[prf_style_ret] = os->overhead[track_calibrate].min;
    v                            = v;

    output(
        "calibration: profile framework overhead [void %llu] [return %llu].\n",
        os->cal_style[prf_style_void], os->cal_style[prf_style_ret]);
}

static inline void
overheads_init(struct overheads_t* os)
{
    unsigned int i;

    for (i = 0; i < n_tracks; i++)
    {
        os->set[i] = 0;
    }

    output("===========================================\n");
    overheads_calibrate(os);
}

static inline void
overheads_dump(struct overheads_t* os)
{
    size_t i;
    size_t n_rows = 0;

    output("=== Overhead (%s): min. max. avg. adj.avg. N ===\n", time_unit());
    for (i = 0; i < n_tracks; i++)
    {
        if (os->set[i] == 1)
        {
            overhead_dump(&os->overhead[i], os->cal_style[os->style[i]]);
            n_rows++;
        }
    }

    output("=== Overhead JSON:\n");
    output("{\n");
    output("    \"app_suite\": \"%s\",\n", app_suite_name);
    output("    \"time_unit\": \"%s\",\n", time_unit());
    output("    \"tracks\":\n");
    output("    {\n");
    for (i = 0; i < n_tracks; i++)
    {
        if (os->set[i] == 1)
        {
            overhead_dump_json(&os->overhead[i], os->cal_style[os->style[i]]);
            if (--n_rows > 0)
            {
                output(",");
            }
            output("\n");
        }
    }
    output("    }\n");
    output("}\n");
    output("===========================================\n");
}

#endif /* !_PROFILE_H_ */
