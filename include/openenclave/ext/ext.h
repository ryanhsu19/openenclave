// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_EXT_EXT_H
#define _OE_EXT_EXT_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/ext/policy.h>
#include <openenclave/ext/signature.h>

oe_result_t oe_ext_verify_signature(
    const oe_ext_signature_t* signature,
    const oe_ext_policy_t* policy);

#endif /* _OE_EXT_EXT_H */
