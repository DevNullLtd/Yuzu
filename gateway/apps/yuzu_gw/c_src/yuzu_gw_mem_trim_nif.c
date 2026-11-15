/* yuzu_gw_mem_trim_nif: one function, malloc_trim(0), for yuzu_gw_mem_reclaim.
 *
 * glibc keeps freed heap pages in its arenas; malloc_trim(0) hands the free
 * ones back to the OS. musl has no malloc_trim, so a build against any other
 * libc returns `unsupported'. The rebar3 hook (apps/yuzu_gw/rebar.config)
 * compiles this file only on a glibc Linux target ("-linux-gnu-"); on Alpine,
 * macOS and Windows there is no .so and yuzu_gw_mem_trim reports the NIF as
 * not loaded, so the reclaim pass garbage-collects only.
 *
 * No input (arity 0), no state, no resource type, no allocation. Dirty CPU
 * scheduler: malloc_trim walks and locks every arena. */
#include <erl_nif.h>
#ifdef __GLIBC__
#include <malloc.h>
#endif

static ERL_NIF_TERM nif_malloc_trim(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    (void)argv;
#ifdef __GLIBC__
    return enif_make_int(env, malloc_trim(0));
#else
    return enif_make_atom(env, "unsupported");
#endif
}

static ErlNifFunc funcs[] = {
    {"malloc_trim", 0, nif_malloc_trim, ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

ERL_NIF_INIT(yuzu_gw_mem_trim, funcs, NULL, NULL, NULL, NULL)
