/*
 *  t_cose_crypto_test.h
 *
 * Copyright 2022-2023, Laurence Lundblade
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 * Created by Laurence Lundblade on 12/28/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef t_cose_crypto_test_h
#define t_cose_crypto_test_h

#include <stdint.h>

#if defined(T_COSE_USE_OPENSSL_CRYPTO)
    #define DECLARE_DEFAULT_ALGORITHM_ID(alg_id) \
        int32_t alg_id = 0
    #define DECLARE_RESTARTABLE_CONTEXT(crypto_ctx) \
        int32_t crypto_ctx = 0; \
        /* This crypto adapter doesn't support restartable operations, so */ \
        /* return as test passed */ \
        return 0
#elif defined(T_COSE_USE_PSA_CRYPTO)
    #define DECLARE_DEFAULT_ALGORITHM_ID(alg_id) \
        int32_t alg_id = T_COSE_ALGORITHM_ES256
    #define DECLARE_RESTARTABLE_CONTEXT(crypto_ctx) \
        psa_interruptible_set_max_ops(0); \
        struct t_cose_psa_crypto_context crypto_ctx = {0}
#elif defined(T_COSE_USE_B_CON_SHA256)
    #define DECLARE_DEFAULT_ALGORITHM_ID(alg_id) \
        int32_t alg_id = T_COSE_ALGORITHM_SHORT_CIRCUIT_256
    #define DECLARE_RESTARTABLE_CONTEXT(crypto_ctx) \
        struct t_cose_test_crypto_context crypto_ctx = {0}
#endif

int_fast32_t aead_test(void);

int_fast32_t kw_test(void);

#endif /* t_cose_crypto_test_h */
