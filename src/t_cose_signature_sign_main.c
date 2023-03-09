/*
 * t_cose_signature_sign_main.c
 *
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 * Created by Laurence Lundblade on 5/23/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor_encode.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_signature_sign_main.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"
#include "t_cose_crypto.h"


/** This is an implementation of \ref t_cose_signature_sign_headers_cb */
static void
t_cose_signature_sign_headers_main_cb(struct t_cose_signature_sign   *me_x,
                                      struct t_cose_parameter       **params)
{
    struct t_cose_signature_sign_main *me =
                                    (struct t_cose_signature_sign_main *)me_x;

    me->local_params[0]  = t_cose_make_alg_id_parameter(me->cose_algorithm_id);
    if(!q_useful_buf_c_is_null(me->kid)) {
        me->local_params[1] = t_cose_make_kid_parameter(me->kid);
        me->local_params[0].next = &me->local_params[1];
    }

    *params = me->local_params;
}


/** This is an implementation of \ref t_cose_signature_sign_cb */
static enum t_cose_err_t
t_cose_signature_sign1_main_cb(struct t_cose_signature_sign     *me_x,
                               const struct t_cose_sign_inputs *sign_inputs,
                               QCBOREncodeContext              *qcbor_encoder)
{
    struct t_cose_signature_sign_main *me =
                                     (struct t_cose_signature_sign_main *)me_x;
    enum t_cose_err_t           return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(buffer_for_tbs_hash_stack,
                               T_COSE_CRYPTO_MAX_HASH_SIZE);
    struct q_useful_buf         buffer_for_signature_stack;
    struct q_useful_buf_c       tbs_hash_stack;
    struct q_useful_buf_c      *tbs_hash;
    struct q_useful_buf        *buffer_for_tbs_hash;
    struct q_useful_buf        *buffer_for_signature;
    struct q_useful_buf_c       signature;
    bool                        do_signing_step = true;

    if(me->rst_ctx) {
        tbs_hash = &me->rst_ctx->tbs_hash;
        buffer_for_tbs_hash = &me->rst_ctx->buffer_for_tbs_hash;
        buffer_for_signature = &me->rst_ctx->buffer_for_signature;
    } else {
        tbs_hash = &tbs_hash_stack;
        buffer_for_tbs_hash = &buffer_for_tbs_hash_stack;
        buffer_for_signature = &buffer_for_signature_stack;
    }

    if(!me->rst_ctx || !me->rst_ctx->started) {
        if(me->rst_ctx) {
            me->rst_ctx->buffer_for_tbs_hash.ptr =
                me->rst_ctx->c_buffer_for_tbs_hash;
            me->rst_ctx->buffer_for_tbs_hash.len =
                sizeof(me->rst_ctx->c_buffer_for_tbs_hash);
        }

        /* The signature gets written directly into the output buffer.
         * The matching QCBOREncode_CloseBytes call further down still
         * needs do a memmove to make space for the CBOR header, but
         * at least we avoid the need to allocate an extra buffer.
         */
        QCBOREncode_OpenBytes(qcbor_encoder, buffer_for_signature);

        if(QCBOREncode_IsBufferNULL(qcbor_encoder)) {
            /* Size calculation mode */
            signature.ptr = NULL;
            t_cose_crypto_sig_size(me->cose_algorithm_id,
                                   me->signing_key,
                                   &signature.len);

            return_value = T_COSE_SUCCESS;
            do_signing_step = false;

        } else {
            /* Run the crypto to produce the signature */

            /* Create the hash of the to-be-signed bytes. Inputs to the
             * hash are the protected parameters, the payload that is
             * getting signed, the cose signature alg from which the hash
             * alg is determined. The cose_algorithm_id was checked in
             * t_cose_sign_init() so it doesn't need to be checked here.
             */
            return_value = create_tbs_hash(me->cose_algorithm_id,
                                           sign_inputs,
                                          *buffer_for_tbs_hash,
                                           tbs_hash);
            if(return_value) {
                goto Done;
            }
        }
    }

    if(do_signing_step) {
        return_value = t_cose_crypto_sign(
                    me->cose_algorithm_id,
                    me->signing_key,
                    me->crypto_context,
                    *tbs_hash,
                    *buffer_for_signature,
                    &signature,
                    me->rst_ctx ? &(me->rst_ctx->started) : NULL);
        if(return_value == T_COSE_ERR_SIG_IN_PROGRESS) {
            /* Assuming T_COSE_ERR_SIG_IN_PROGRESS return value is only possible
             * in restartable mode which implies a valid me->rst_ctx pointer
             */
            me->rst_ctx->started = true;
            goto Done;
        } else {
            if(me->rst_ctx) {
                /* Reset the started value to enable reuse of the context */
                me->rst_ctx->started = false;
            }
        }
    }

    QCBOREncode_CloseBytes(qcbor_encoder, signature.len);

Done:
    return return_value;
}


/** This is an implementation of \ref t_cose_signature_sign1_cb */
static enum t_cose_err_t
t_cose_signature_sign_main_cb(struct t_cose_signature_sign  *me_x,
                              struct t_cose_sign_inputs     *sign_inputs,
                              QCBOREncodeContext            *qcbor_encoder)
{
    struct t_cose_signature_sign_main *me =
                                     (struct t_cose_signature_sign_main *)me_x;
    enum t_cose_err_t         return_value;
    struct t_cose_parameter  *parameters;

    if(!me->rst_ctx || !me->rst_ctx->started) {

        /* Array that holds a COSE_Signature */
        QCBOREncode_OpenArray(qcbor_encoder);

        /* -- The headers for a COSE_Sign -- */
        t_cose_signature_sign_headers_main_cb(me_x, &parameters);
        t_cose_parameter_list_append(parameters, me->added_signer_params);
        t_cose_encode_headers(qcbor_encoder,
                              parameters,
                              &sign_inputs->sign_protected);
    }
    /* The actual signature (this runs hash and public key crypto) */
    return_value = t_cose_signature_sign1_main_cb(me_x,
                                                  sign_inputs,
                                                  qcbor_encoder);
    if(return_value != T_COSE_ERR_SIG_IN_PROGRESS) {
        /* Close the array for the COSE_Signature */
        QCBOREncode_CloseArray(qcbor_encoder);
    }

    return return_value;
}


void
t_cose_signature_sign_main_init(struct t_cose_signature_sign_main *me,
                                const int32_t               cose_algorithm_id)
{
    memset(me, 0, sizeof(*me));
    me->s.rs.ident        = RS_IDENT(TYPE_RS_SIGNER, 'M');
    me->s.headers_cb      = t_cose_signature_sign_headers_main_cb;
    me->s.sign_cb         = t_cose_signature_sign_main_cb;
    me->s.sign1_cb        = t_cose_signature_sign1_main_cb;
    me->cose_algorithm_id = cose_algorithm_id;
}

void t_cose_signature_sign_main_set_restartable(
                    struct t_cose_signature_sign_main *me,
                    struct t_cose_signature_sign_main_restart_ctx *rst_context)
{
    me->rst_ctx = rst_context;
}
