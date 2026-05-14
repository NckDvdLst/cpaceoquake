/**
 * \file cpaceoquake.c
 *
 * \brief Hybrid PAKE of combined CPace and OQUAKE.
 */
/*
 *  Copyright Nick Leist
 */

#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>

#include "cpaceoquake.h"
#include "oquake.h"
#include "crypto_cpace.h"
#include "cpaceoquake_crypto_utils.h"

/*
 * J-PAKE is a password-authenticated key exchange that allows deriving a
 * strong shared secret from a (potentially low entropy) pre-shared
 * passphrase, with forward secrecy and mutual authentication.
 * https://en.wikipedia.org/wiki/Password_Authenticated_Key_Exchange_by_Juggling
 *
 * This file implements the Elliptic Curve variant of J-PAKE,
 * as defined in Chapter 7.4 of the Thread v1.0 Specification,
 * available to members of the Thread Group http://threadgroup.org/
 *
 * As the J-PAKE algorithm is inherently symmetric, so is our API.
 * Each party needs to send its first round message, in any order, to the
 * other party, then each sends its second round message, in any order.
 * The payloads are serialized in a way suitable for use in TLS, but could
 * also be use outside TLS.
 */

int lv_encode(const uint8_t *msg, const size_t msg_len, uint8_t **out) {
    uint8_t *out_msg = calloc(1, msg_len + 2);
    if (!out_msg) return -1;
    memcpy(out_msg + 2, msg, msg_len);
    out_msg[0] = (msg_len >> 8) & 0xFF;
    out_msg[1] = msg_len & 0xFF;
    *out = out_msg;
    return 0;
}

size_t lv_decode(uint8_t *msg) {
    const size_t msg_len = (msg[0] << 8) | msg[1];
    memmove(msg, msg + 2, msg_len);
    return msg_len;
}

int cpaceoquake_init(const unsigned char *prs, const size_t prs_len,
                    const uint8_t *sid, const size_t sid_len,
                    const uint8_t u[16], const uint8_t s[16],
                    cpaceoquake_initiator_ctx *ctx, uint8_t **init_msg) {

    // init CPace
    crypto_cpace_init();
    struct crypto_cpace_state_ *cp_ctx = calloc(1, sizeof(struct crypto_cpace_state_));
    if (!cp_ctx) return -1;
    ctx->cp_ctx = cp_ctx;
    const size_t msg1_len = crypto_cpace_PUBLICDATABYTES;
    uint8_t msg1[msg1_len];

    // perform initial step of CPace
    const unsigned char temp = 0;
    const unsigned char *additional_data = &temp;
    if (crypto_cpace_step1(cp_ctx, msg1, (const char *)prs, prs_len,
            (char *)u, 16, (char *)s, 16, additional_data, 0)) goto cleanup;

    // generate random number s1 (if no sid is present) and concat with CPace msg1 to get the init_msg
    uint8_t *s1 = calloc(1, 32);
    if (sid && sid_len >= 32) {
        // if sid is present and long enough use first 32 bit as sid
        memcpy(s1, sid, 32);
    } else {
        if (!s1 || !RAND_bytes(s1, 32)) {
            free(s1);
            goto cleanup;
        }
    }
    ctx->s1 = s1;
    *init_msg = calloc(1, 32 + crypto_cpace_PUBLICDATABYTES + 2);
    memcpy(*init_msg, s1, 32);
    uint8_t *emsg;
    lv_encode(msg1, msg1_len, &emsg);
    memcpy(*init_msg+32, emsg, msg1_len+2);
    free(emsg);

    return 0;

    cleanup:
    // TODO: check cleanup
    free(cp_ctx);
    return -1;

}


int cpaceoquake_respond(unsigned char *prs, size_t prs_len,
                    uint8_t *init_msg,
                    const uint8_t *sid, const size_t sid_len,
                    uint8_t u[16], uint8_t s[16],
                    cpaceoquake_responder_ctx *ctx, uint8_t **resp_msg) {
    // TODO: It MUST abort if the message does not have the correct length

    // deconstruct init_msg to its constituents
    uint8_t *s1 = init_msg;
    size_t msg1len = lv_decode(init_msg + 32);
    uint8_t *msg1 = init_msg + 32; // CPace-implementation-dependant: "public_data"

    // necessary output variables for CPace Step 2
    uint8_t *msg2 = calloc(1, crypto_cpace_RESPONSEBYTES);;
    size_t msg2len = crypto_cpace_RESPONSEBYTES;
    struct crypto_cpace_shared_keys_ shared_keys;

    // perform second step of CPace
    const unsigned char temp = 0;
    const unsigned char *additional_data = &temp;
    if (crypto_cpace_step2(msg2, msg1, &shared_keys, (char *)prs, prs_len,
        (char *)u, 16, (char *)s, 16, additional_data, 0))
        return -1;

    // extract key1A and key1B
    unsigned char key1A[SHA256_DIGEST_LENGTH];
    unsigned char *key1B = calloc(1, SHA256_DIGEST_LENGTH);
    if (cpace_kdf(&shared_keys, key1A, key1B))
        return -1;

    // if no sid is present, create random s2 and extend it to get fullsid
    uint8_t s2[32];
    unsigned char extended_sid[32];
    uint8_t *fullsid;
    size_t fullsid_len;
    if (sid && sid_len >= 32) {
        // if sid is present, it must be the same as the one sent by the peer
        if (memcmp(sid, s1, 32) != 0) goto cleanup;
        // copy 32 byte of sid to s2 for sending it to the peer for checkup
        memcpy(s2, sid, 32);
        // encode sid to get fullsid
        if (encode_sid(sid, sid_len, u, s, &fullsid)) goto cleanup;
        fullsid_len = 3*4 + sid_len + 32; // 3*32bit + sid_len + 2*16byte
        // extend sid for usage in OQUAKE.Init
        extend_sid(sid, sid_len, extended_sid);
    } else {
        if (!RAND_bytes(s2, 32)) {
            goto cleanup;
        }
        if (extend_sid_of_two(s1, s2, extended_sid))
            return -1;
        // encode extended_sid to get fullsid
        if (encode_sid(extended_sid, sizeof extended_sid, u, s, &fullsid)) goto cleanup;
        fullsid_len = 3*4 + 32 + 32; // 3*32bit + extended_sid length + 2*16byte
    }

    // derive second PRS from CPace Result
    unsigned char prs2[CPACEOQUAKE_NKEY];
    if (prs_to_prs2(prs, prs_len, fullsid, fullsid_len, msg1, msg1len, msg2,
        msg2len, key1A, sizeof key1A, prs2))
        return -1;

    // execute OQUAKE.init
    oquake_initiator_ctx *oq_ctx = calloc(1, sizeof(oquake_initiator_ctx));
    init_oq_initiator_ctx(oq_ctx, prs, prs_len);
    uint8_t *oq_init_msg;
    if (oquake_init(prs, prs_len, extended_sid, sizeof extended_sid, u, s,
        oq_ctx, &oq_init_msg)) goto cleanup;
    size_t oq_init_msg_len = 3*NSEC+KEMELEON_EKBYTES;

    // construct resp_msg of CPaceOQUAKE.Respond:
    // resp_msg = s2 || msg2 || msg3 (= oq_init_msg)
    *resp_msg = calloc(1, sizeof(s2) + 2+msg2len + 2+oq_init_msg_len);
    memcpy(*resp_msg, s2, sizeof(s2));
    uint8_t *emsg2;
    lv_encode(msg2, msg2len, &emsg2);
    memcpy(*resp_msg+sizeof(s2), emsg2, 2+msg2len);
    uint8_t *eoq_init_msg;
    lv_encode(oq_init_msg, oq_init_msg_len, &eoq_init_msg);
    memcpy(*resp_msg+sizeof(s2)+msg2len+2,
        eoq_init_msg,
        2+oq_init_msg_len);
    free(emsg2);
    free(eoq_init_msg);

    // fill cpaceoquake_responder_ctx
    ctx->fullsid = fullsid;
    ctx->fullsid_len = fullsid_len;
    ctx->prs = prs;
    ctx->prs_len = prs_len;
    ctx->msg1 = msg1;
    ctx->msg1_len = msg1len;
    ctx->msg2 = msg2;
    ctx->msg2_len = msg2len;
    ctx->msg3 = oq_init_msg;
    ctx->msg3_len = oq_init_msg_len;
    ctx->key1B = key1B;
    ctx->oq_ctx = oq_ctx;

    return 0;

    cleanup:
    // TODO: Add cleanup
    return -1;

}


int cpaceoquake_initiator_finish(const unsigned char *prs, const size_t prs_len,
    const cpaceoquake_initiator_ctx *ctx, uint8_t *resp_msg,
    const uint8_t *sid, const size_t sid_len,
    uint8_t u[16], uint8_t s[16],
    uint8_t **key, size_t *key_len,
    uint8_t **fin_msg, size_t *fin_msg_len) {
    // TODO: The client should abort when the message does not have the correct length

    // deconstruct resp_msg to get s2, msg2 and msg3
    uint8_t *s2 = resp_msg;
    size_t msg2len = lv_decode(resp_msg + 32);
    uint8_t msg2[msg2len];
    memcpy(msg2, resp_msg+32, msg2len);
    size_t msg3len = lv_decode(resp_msg + 32 + 2 + msg2len);
    uint8_t *msg3 = resp_msg + 32 + 2 + msg2len;

    // finish CPace flow and derive key1A and key1B
    struct crypto_cpace_shared_keys_ shared_keys;
    crypto_cpace_step3(ctx->cp_ctx, &shared_keys, msg2);
    unsigned char key1A[SHA256_DIGEST_LENGTH];
    unsigned char key1B[SHA256_DIGEST_LENGTH];
    cpace_kdf(&shared_keys, key1A, key1B);

    // check if sid is present or both s1 and s2
    uint8_t extended_sid[32];
    uint8_t *fullsid;
    size_t fullsid_len;
    if (sid && sid_len >= 32) {
        // if sid is present, it must be the same as the one sent by the peer
        if (memcmp(sid, s2, 32) != 0) goto cleanup;
        // encode sid to get fullsid
        if (encode_sid(sid, sid_len, u, s, &fullsid)) goto cleanup;
        fullsid_len = 3*4 + sid_len + 32; // 3*32bit + sid_len + 2*16byte
        // extend sid for usage in OQUAKE.Respond
        extend_sid(sid, sid_len, extended_sid);
    } else {
        extend_sid_of_two(ctx->s1, s2, extended_sid);
        // encode extended_sid to get fullsid
        if (encode_sid(extended_sid, sizeof extended_sid, u, s, &fullsid)) goto cleanup;
        fullsid_len = 3*4 + 32 + 32; // 3*32bit + extended_sid length + 2*16byte
    }

    // derive prs2 from prs and key1A
    // msg1 was CPace-SID || PK
    uint8_t *msg1 = ctx->cp_ctx->session_id;
    size_t msg1len = crypto_cpace_PUBLICDATABYTES;
    // output buffer for prs2
    uint8_t prs2[CPACEOQUAKE_NKEY];
    prs_to_prs2(prs, prs_len, fullsid, fullsid_len,
        msg1, msg1len, msg2, msg2len, key1A, sizeof(key1A),
        prs2);

    // process OQUAKE.Respond
    uint8_t *key2;
    *fin_msg_len = CRYPTO_CIPHERTEXTBYTES + 64;
    oquake_respond(prs, prs_len, msg3, msg3len, extended_sid, sizeof(extended_sid),
        u, s, &key2, fin_msg);

    // derive final secret
    *key = calloc(1, CPACEOQUAKE_NKEY);
    *key_len = CPACEOQUAKE_NKEY;
    if (cpaceoquake_kdf(prs, prs_len, fullsid, fullsid_len, msg1, msg1len,
        msg2, msg2len, msg3, msg3len, *fin_msg, *fin_msg_len,
        key1B, key2, *key))
        goto cleanup;

    return 0;

    cleanup:
    // TODO: Add cleanup stuff if necessary
    return -1;
}

int cpaceoquake_responder_finish(cpaceoquake_responder_ctx *ctx, uint8_t *fin_msg, 
    size_t fin_msg_len, uint8_t **key, size_t *key_len) {

    // TODO: It should abort when the message does not have the correct length.

    // process OQUAKE.Finish
    uint8_t *key2;
    oquake_finish(ctx->oq_ctx, fin_msg, fin_msg_len, &key2);

    // derive final secret
    *key = calloc(1, CPACEOQUAKE_NKEY);
    *key_len = CPACEOQUAKE_NKEY;
    if (cpaceoquake_kdf(ctx->prs, ctx->prs_len, ctx->fullsid, ctx->fullsid_len,
        ctx->msg1, ctx->msg1_len, ctx->msg2, ctx->msg2_len, ctx->msg3, ctx->msg3_len,
        fin_msg, fin_msg_len, ctx->key1B, key2, *key))
        goto cleanup;

    return 0;

    cleanup:
    // TODO: Add cleanup stuff if necessary
    return -1;

}