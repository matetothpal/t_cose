/*
 * t_cose_test_crypto.h
 *
 * Copyright 2022, Laurence Lundblade
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef t_cose_psa_crypto_h
#define t_cose_psa_crypto_h

#include <psa/crypto.h>

struct t_cose_psa_crypto_context {
    psa_sign_hash_interruptible_operation_t operation;
};

#endif /* t_cose_psa_crypto_h */
