#ifndef NATIVE_LIB_H
#define NATIVE_LIB_H

typedef enum
{
    NLTC_VOID,
    NLTC_SINT,
    NLTC_UINT,
    NLTC_FLOAT,
    NLTC_STRING,
    NLTC_MEMPTR,
    NLTC_FNPTR,
    NLTC_FD,
    NLTC_CPLX
} nlib_type_class;

typedef struct
{
    nlib_type_class tc;
    int width;
    int cnst;
} nlib_type;

typedef struct
{
    const char *fname;
    const char *libname;

    void *mdl;
    void *fnptr;

    nlib_type retty;
    nlib_type *argty;
    int nr_args;
} nlib_function;

void nlib_init(void);
void nlib_register_txln_hook(unsigned long va, const char *fname);
nlib_function *nlib_get_txln_hook(unsigned long va);
void nlib_register_shared_lib(const char *name);
char *nlib_get_shared_lib(unsigned int index);
void set_nlib_enabled(void);
#endif
