#include "qemu/osdep.h"
#include "qemu.h"
#include "native-lib.h"

#include <gmodule.h>

static nlib_function **native_functions;
static unsigned int nr_native_functions;
static GHashTable *txln_hooks;
static GArray *shared_libs;
static unsigned int nr_shared_libs;

static const char *nlib_fname_denylist[] = {
    "__libc_start_main", 
    "__gmon_start__",
    "__cxa_atexit",
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
 * Registers a function to be redirected to native code from a guest
 * shared-library invocation.
 */
nlib_function *nlib_add_function(const char *fname, const char *libname)
{
    // Allocate storage for the native function descriptor.
    nlib_function *fn = g_malloc(sizeof(nlib_function));

    // Zero out the structure.
    memset(fn, 0, sizeof(*fn));

    // Copy in the function details that we know at this time.
    fn->fname = g_strdup(fname);
    fn->libname = g_strdup(libname);
    fn->mdl = g_module_open(fn->libname, 0);
    if (!fn->mdl) {
        fprintf(stderr, "nlib: could not open module '%s'\n", libname);
        exit(EXIT_FAILURE);
    }

    // Attempt to resolve the function symbol from the module.
    if (!g_module_symbol((GModule *)fn->mdl, fn->fname, &fn->fnptr)) {
        fprintf(stderr, "nlib: could not resolve function %s\n", fn->fname);
        exit(EXIT_FAILURE);
    }

    // Add the new function to the list.
    nr_native_functions++;
    native_functions = g_realloc(native_functions, sizeof(nlib_function *) * nr_native_functions);
    native_functions[nr_native_functions-1] = fn;

    return fn;
}

/**
 * Looks up a function from the registered function list, given an index.
 */
nlib_function *nlib_lookup_function(unsigned int idx)
{
    if (idx >= nr_native_functions) {
        return NULL;
    }

    return native_functions[idx];
}

/**
 * Sets the metadata for the return type of the function.
 */
void nlib_fn_set_ret(nlib_function *fn, nlib_type_class tc, int width, int cnst)
{
    fn->retty.tc = tc;
    fn->retty.width = width;
    fn->retty.cnst = cnst;
}

/**
 * Adds new argument metadata to the function.
 */
void nlib_fn_add_arg(nlib_function *fn, nlib_type_class tc, int width, int cnst)
{
    fn->nr_args++;
    fn->argty = g_realloc(fn->argty, sizeof(nlib_type) * fn->nr_args);

    nlib_type *t = &fn->argty[fn->nr_args-1];

    t->tc = tc;
    t->width = width;
    t->cnst = cnst;
}

/**
 * Registers a translation hook for catching guest shared-library invocations.
 */
void nlib_register_txln_hook(target_ulong va, const char *fname)
{
    for (int i = 0; i < nlib_fname_denylist_count; i++) {
        if (g_strcmp0(nlib_fname_denylist[i], fname) == 0) {
            printf("Did not register nlib function %s: function is on denylist\n", fname);
            return;
        }
    }

    // printf("> ");
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
            exit(EXIT_FAILURE);
        }

        // Attempt to resolve the function symbol from the module.
        if (g_module_symbol((GModule *)fn->mdl, fn->fname, &fn->fnptr)) {
            found = true;
            break;
        }
    }
    if (!found) {
        fprintf(stderr, "nlib: could not resolve function %s\n", fn->fname);
        exit(EXIT_FAILURE);
    }

    // printf("Successfully registered hook for %s in %s\n", fn->fname, fn->libname);
    printf("%s in %s\n", fn->fname, fn->libname);

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
    g_array_append_val(shared_libs, name);
    nr_shared_libs++;
}

char *nlib_get_shared_lib(unsigned int index) {
    return g_array_index(shared_libs, char*, index);
}
