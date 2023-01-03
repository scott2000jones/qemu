#include "qemu/osdep.h"
#include "qemu.h"
#include "native-lib.h"

#include <gmodule.h>

static GHashTable *txln_hooks;
static GArray *shared_libs;
static unsigned int nr_shared_libs;
static int enable_nlib;

static const char *nlib_fname_denylist[] = {
    "__libc_start_main",
    "__gmon_start__",
    "__cxa_atexit",
    
    "fstat",
    // "printf",

    "qsort",
    "signal",
    "OPENSSL_LH_insert",
    "OPENSSL_LH_retrieve",
    "BIO_printf",
    "BIO_free",
    "BIO_new_fp",
    "BIO_free_all",
    "BIO_ctrl",
    "ERR_print_errors",
};

static int nlib_fname_denylist_count = sizeof(nlib_fname_denylist)/sizeof(nlib_fname_denylist[0]);

/**
 * Initialises the Native Library infrastructure
 */
void nlib_init(void)
{
    txln_hooks = g_hash_table_new(NULL, NULL);
    shared_libs = g_array_new(false, true, sizeof(unsigned long));
}

/**
 * Registers a translation hook for catching guest shared-library invocations.
 */
void nlib_register_txln_hook(target_ulong va, const char *fname)
{
    if (!enable_nlib) return;

    for (int i = 0; i < nlib_fname_denylist_count; i++) {
        if (g_strcmp0(nlib_fname_denylist[i], fname) == 0) {
            // fprintf(stderr, "> Did not register nlib function %s: function is on denylist\n", fname);
            return;
        }
    }

    // Allocate storage for the native function descriptor.
    nlib_function *fn = g_malloc(sizeof(nlib_function));

    // Zero out the structure.
    memset(fn, 0, sizeof(*fn));

    // Copy in the function details that we know at this time.
    fn->fname = g_strdup(fname);

    bool found = false;
    for (int i = 0; i < nr_shared_libs; i++) {
        fn->libname = g_strdup(g_array_index(shared_libs, char *, i));

        fn->mdl = g_module_open(fn->libname, 0);
        if (!fn->mdl) {
            fprintf(stderr, "nlib: could not open module '%s'\n", fn->libname);
            return;
        }

        // Attempt to resolve the function symbol from the module.
        if (g_module_symbol((GModule *)fn->mdl, fn->fname, &fn->fnptr)) {
            found = true;
            break;
        }
    }
    if (!found) {
        fprintf(stderr, "nlib: could not resolve function %s\n", fn->fname);
        return;
    }

    // fprintf(stderr, "Successfully registered hook for %s in %s\n", fn->fname, fn->libname);
    // fprintf(stderr, "\"%s\",\n", fn->fname);

    g_hash_table_insert(txln_hooks, (gpointer)va, (gpointer)fn);
}

/**
 * Looks up a corresponding native library function, given the registered
 * guest virtual address.
 */
nlib_function *nlib_get_txln_hook(target_ulong va)
{
    return (nlib_function *)g_hash_table_lookup(txln_hooks, (gconstpointer)va);
}

void nlib_register_shared_lib(const char *name) {
    if (!enable_nlib) return;
    g_array_append_val(shared_libs, name);
    nr_shared_libs++;
}

char *nlib_get_shared_lib(unsigned int index) {
    return g_array_index(shared_libs, char*, index);
}

void set_nlib_enabled(void) {
    enable_nlib = 1;
}
