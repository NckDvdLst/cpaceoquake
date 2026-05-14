#include "cpaceoquake.h"

#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>


int cpace_kdf(struct crypto_cpace_shared_keys_ *shared_keys,
                     unsigned char key1A[SHA256_DIGEST_LENGTH],
                     unsigned char key1B[SHA256_DIGEST_LENGTH])
{
    EVP_PKEY_CTX *pctx = NULL;
    size_t outlen;

    /* --- Subkey A: "prskey" --- */
    unsigned char tagA[] = CPACEOQUAKE_DST "prskey";

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx,
                                   shared_keys->client_sk,
                                   SHA256_DIGEST_LENGTH) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, tagA, sizeof(tagA) - 1) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    outlen = SHA256_DIGEST_LENGTH;
    if (EVP_PKEY_derive(pctx, key1A, &outlen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);

    /* --- Subkey B: "outputkey" --- */
    unsigned char tagB[] = CPACEOQUAKE_DST "outputkey";

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx,
                                   shared_keys->client_sk,
                                   SHA256_DIGEST_LENGTH) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, tagB, sizeof(tagB) - 1) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    outlen = SHA256_DIGEST_LENGTH;
    if (EVP_PKEY_derive(pctx, key1B, &outlen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);

    return 0;
}


int extend_sid_of_two(const uint8_t s1[32],
                             const uint8_t s2[32],
                             uint8_t extended_sid[32])
{
    uint8_t prk_extended_sid[SHA256_DIGEST_LENGTH];
    uint8_t s_concat[64];
    EVP_PKEY_CTX *pctx = NULL;
    size_t outlen;

    /* s1 || s2 */
    memcpy(s_concat,      s1, 32);
    memcpy(s_concat + 32, s2, 32);

    /* ============================
     * HKDF-Extract
     * PRK = HMAC(salt = CPACEOQUAKE_DST "CPaceOQUAKE", IKM = s_concat)
     * ============================ */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(
            pctx,
            CPACEOQUAKE_DST "CPaceOQUAKE",
            sizeof(CPACEOQUAKE_DST "CPaceOQUAKE") - 1
        ) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(
            pctx,
            s_concat,
            sizeof(s_concat)
        ) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    outlen = SHA256_DIGEST_LENGTH;
    if (EVP_PKEY_derive(pctx, prk_extended_sid, &outlen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);

    /* ============================
     * HKDF-Expand
     * OKM = HKDF-Expand(PRK, info = CPACEOQUAKE_DST "SID")
     * ============================ */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0) <= 0 || /* Expand = kein Salt */
        EVP_PKEY_CTX_set1_hkdf_key(
            pctx,
            prk_extended_sid,
            SHA256_DIGEST_LENGTH
        ) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            pctx,
            CPACEOQUAKE_DST "SID",
            sizeof(CPACEOQUAKE_DST "SID") - 1
        ) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    outlen = 32;
    if (EVP_PKEY_derive(pctx, extended_sid, &outlen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;
}


int extend_sid(const uint8_t *sid, size_t sid_len,
                      uint8_t extended_sid[SHA256_DIGEST_LENGTH])
{
    uint8_t prk_extended_sid[SHA256_DIGEST_LENGTH];
    EVP_PKEY_CTX *pctx = NULL;
    size_t outlen;

    /* ============================
     * HKDF-Extract:
     * PRK = HMAC(salt = CPACEOQUAKE_DST "CPaceOQUAKE", IKM = sid)
     * ============================ */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(
            pctx,
            CPACEOQUAKE_DST "CPaceOQUAKE",
            sizeof(CPACEOQUAKE_DST "CPaceOQUAKE") - 1
        ) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(
            pctx,
            sid,
            sid_len
        ) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    outlen = SHA256_DIGEST_LENGTH;
    if (EVP_PKEY_derive(pctx, prk_extended_sid, &outlen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);

    /* ============================
     * HKDF-Expand:
     * OKM = HKDF-Expand(PRK, info = CPACEOQUAKE_DST "SID")
     * ============================ */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0) <= 0 || /* Expand = kein Salt */
        EVP_PKEY_CTX_set1_hkdf_key(
            pctx,
            prk_extended_sid,
            SHA256_DIGEST_LENGTH
        ) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            pctx,
            CPACEOQUAKE_DST "SID",
            sizeof(CPACEOQUAKE_DST "SID") - 1
        ) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    outlen = SHA256_DIGEST_LENGTH;
    if (EVP_PKEY_derive(pctx, extended_sid, &outlen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;
}


int prs_to_prs2(const unsigned char *prs, const size_t prs_len,
                       const uint8_t *fullsid, const size_t fullsid_len,
                       const uint8_t *msg1, const size_t msg1_len,
                       const uint8_t *msg2, const size_t msg2_len,
                       const unsigned char key1A[SHA256_DIGEST_LENGTH], const size_t key1A_len,
                       unsigned char prs2[CPACEOQUAKE_NKEY])
{
    uint8_t prk_prs2[SHA256_DIGEST_LENGTH];
    unsigned char salt_prs2[CPACEOQUAKE_DST_LEN + sizeof("CPaceOQUAKE") - 1
                            + fullsid_len + msg1_len + msg2_len + key1A_len];
    unsigned char *temp_ptr = salt_prs2;
    EVP_PKEY_CTX *pctx = NULL;
    size_t outlen;

    /* salt = DST || "CPaceOQUAKE" || fullsid || msg1 || msg2 || key1A */
    memcpy(temp_ptr, CPACEOQUAKE_DST, CPACEOQUAKE_DST_LEN);
    temp_ptr += CPACEOQUAKE_DST_LEN;

    memcpy(temp_ptr, "CPaceOQUAKE", sizeof("CPaceOQUAKE") - 1);
    temp_ptr += sizeof("CPaceOQUAKE") - 1;

    memcpy(temp_ptr, fullsid, fullsid_len);
    temp_ptr += fullsid_len;

    memcpy(temp_ptr, msg1, msg1_len);
    temp_ptr += msg1_len;

    memcpy(temp_ptr, msg2, msg2_len);
    temp_ptr += msg2_len;

    memcpy(temp_ptr, key1A, key1A_len);

    /* HKDF-Extract: PRK = HKDF-Extract(salt_prs2, prs) */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt_prs2, sizeof(salt_prs2)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, prs, prs_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    outlen = SHA256_DIGEST_LENGTH;
    if (EVP_PKEY_derive(pctx, prk_prs2, &outlen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);

    /* HKDF-Expand: prs2 = HKDF-Expand(PRK, info = CPACEOQUAKE_DST "PRS2") */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, prk_prs2, SHA256_DIGEST_LENGTH) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            pctx,
            CPACEOQUAKE_DST "PRS2",
            sizeof(CPACEOQUAKE_DST "PRS2") - 1
        ) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    outlen = CPACEOQUAKE_NKEY;
    if (EVP_PKEY_derive(pctx, prs2, &outlen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;
}


int cpaceoquake_kdf(uint8_t *prs, size_t prs_len,
                           uint8_t *fullsid, size_t fullsid_len,
                           uint8_t *msg1, size_t msg1_len,
                           uint8_t *msg2, size_t msg2_len,
                           uint8_t *msg3, size_t msg3_len,
                           uint8_t *msg4, size_t msg4_len,
                           unsigned char key1B[SHA256_DIGEST_LENGTH],
                           unsigned char key2[32],
                           unsigned char secret[CPACEOQUAKE_NKEY])
{
    uint8_t prk_sk[SHA256_DIGEST_LENGTH];
    unsigned char salt_sk[CPACEOQUAKE_DST_LEN + sizeof("CPaceOQUAKE") - 1
                          + fullsid_len + msg1_len + msg2_len + msg3_len + msg4_len
                          + SHA256_DIGEST_LENGTH + 32];
    unsigned char *temp_ptr = salt_sk;
    EVP_PKEY_CTX *pctx = NULL;
    size_t outlen;

    /* salt = DST || "CPaceOQUAKE" || fullsid || msg1 || msg2 || msg3 || msg4 || key1B || key2 */
    memcpy(temp_ptr, CPACEOQUAKE_DST, CPACEOQUAKE_DST_LEN);
    temp_ptr += CPACEOQUAKE_DST_LEN;

    memcpy(temp_ptr, "CPaceOQUAKE", sizeof("CPaceOQUAKE") - 1);
    temp_ptr += sizeof("CPaceOQUAKE") - 1;

    memcpy(temp_ptr, fullsid, fullsid_len);
    temp_ptr += fullsid_len;

    memcpy(temp_ptr, msg1, msg1_len);
    temp_ptr += msg1_len;

    memcpy(temp_ptr, msg2, msg2_len);
    temp_ptr += msg2_len;

    memcpy(temp_ptr, msg3, msg3_len);
    temp_ptr += msg3_len;

    memcpy(temp_ptr, msg4, msg4_len);
    temp_ptr += msg4_len;

    memcpy(temp_ptr, key1B, SHA256_DIGEST_LENGTH);
    temp_ptr += SHA256_DIGEST_LENGTH;

    memcpy(temp_ptr, key2, 32);

    /* HKDF-Extract: PRK = HKDF-Extract(salt_sk, prs) */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt_sk, sizeof(salt_sk)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, prs, prs_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    outlen = SHA256_DIGEST_LENGTH;
    if (EVP_PKEY_derive(pctx, prk_sk, &outlen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);

    /* HKDF-Expand: secret = HKDF-Expand(PRK, info = CPACEOQUAKE_DST "sessionkey") */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, prk_sk, SHA256_DIGEST_LENGTH) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            pctx,
            CPACEOQUAKE_DST "sessionkey",
            sizeof(CPACEOQUAKE_DST "sessionkey") - 1
        ) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    outlen = CPACEOQUAKE_NKEY;
    if (EVP_PKEY_derive(pctx, secret, &outlen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;
}