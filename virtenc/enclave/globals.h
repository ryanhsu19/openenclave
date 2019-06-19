// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _VE_ENCLAVE_GLOBALS_H
#define _VE_ENCLAVE_GLOBALS_H

#include <openenclave/bits/types.h>
#include "lock.h"

#define MAX_THREADS 1024

typedef struct _thread_arg
{
    int sock;
    size_t stack_size;
    uint32_t tcs;
    int tid;
} thread_arg_t;

typedef struct _globals
{
    int sock;
    thread_arg_t threads[MAX_THREADS];
    size_t num_threads;
    ve_lock_t threads_lock;
} globals_t;

extern globals_t globals;

#endif /* _VE_ENCLAVE_GLOBALS_H */