#include "oquake_utils.h"

/* Public mlkem-native API */
#include <openssl/crypto.h>  /* for CRYPTO_memcmp */
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <stdlib.h>

#include "mlkem_native.h"
#include "src/poly.h"
#include "src/poly_k.h"

int hkdf_extract_custom(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm,  size_t ikm_len,
                        uint8_t        prk[SHA256_LEN])
{
    int ret = -1;

    EVP_KDF       *kdf  = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX   *kctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    if (!kctx) goto cleanup;

    OSSL_PARAM params[6];
    int        idx = 0;

    /* mode = extract-only */
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
    params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);

    /* digest = SHA-256 */
    params[idx++] = OSSL_PARAM_construct_utf8_string(
                        OSSL_KDF_PARAM_DIGEST, "SHA256", 0);

    /* salt */
    params[idx++] = OSSL_PARAM_construct_octet_string(
                        OSSL_KDF_PARAM_SALT,
                        (void *)salt, salt_len);

    /* ikm (called "key" in OpenSSL's HKDF API) */
    params[idx++] = OSSL_PARAM_construct_octet_string(
                        OSSL_KDF_PARAM_KEY,
                        (void *)ikm, ikm_len);

    params[idx]   = OSSL_PARAM_construct_end();

    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) goto cleanup;

    size_t prk_len = SHA256_LEN;
    if (EVP_KDF_derive(kctx, prk, prk_len, NULL) <= 0) goto cleanup;

    ret = 0;

cleanup:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}


int hkdf_expand_custom(const uint8_t *prk,  size_t prk_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t       *okm,  size_t okm_len)
{
    int ret = -1;

    EVP_KDF       *kdf  = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX   *kctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    if (!kctx) goto cleanup;

    OSSL_PARAM params[6];
    int        idx = 0;

    /* mode = expand-only */
    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);

    /* digest = SHA-256 */
    params[idx++] = OSSL_PARAM_construct_utf8_string(
                        OSSL_KDF_PARAM_DIGEST, "SHA256", 0);

    /* prk (passed as "key" in expand-only mode) */
    params[idx++] = OSSL_PARAM_construct_octet_string(
                        OSSL_KDF_PARAM_KEY,
                        (void *)prk, prk_len);

    /* info */
    params[idx++] = OSSL_PARAM_construct_octet_string(
                        OSSL_KDF_PARAM_INFO,
                        (void *)info, info_len);

    params[idx]   = OSSL_PARAM_construct_end();

    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) goto cleanup;

    if (EVP_KDF_derive(kctx, okm, okm_len, NULL) <= 0) goto cleanup;

    ret = 0;

cleanup:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

int kemeleon_encode_ek(const uint8_t pk[CRYPTO_PUBLICKEYBYTES],
                       uint8_t       ek[KEMELEON_EKBYTES])
{
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return -1;
    BN_CTX_start(ctx);

    BIGNUM *r      = BN_CTX_get(ctx);  /* accumulator: sum a[i] * q^i      */
    BIGNUM *qpow   = BN_CTX_get(ctx);  /* q^i, advances per coefficient    */
    BIGNUM *bq     = BN_CTX_get(ctx);  /* constant q = 3329                */
    BIGNUM *tmp    = BN_CTX_get(ctx);  /* scratch                          */
    BIGNUM *qn     = BN_CTX_get(ctx);  /* q^n  (denominator for m)         */
    BIGNUM *bound  = BN_CTX_get(ctx);  /* 2^(b+t)                          */
    BIGNUM *m      = BN_CTX_get(ctx);  /* random m in [0, floor((2^(b+t)-r)/q^n)] */
    if (!r || !qpow || !bq || !tmp || !qn || !bound || !m) {
        BN_CTX_end(ctx); BN_CTX_free(ctx); return -1;
    }

    BN_set_word(bq, 3329u);

    /* Load and reduce polyvec */
    mlk_polyvec a;
    mlk_polyvec_frombytes(&a, pk);
    mlk_polyvec_reduce(&a);   /* ensure coefficients in [0, q-1] */

    for (int poly = 0; poly < MLKEM_K; poly++) {

        /* ----------------------------------------------------------------
         * Accumulate: r = sum_{i=0}^{n-1} a[i] * q^i
         * ---------------------------------------------------------------- */
        BN_zero(r);
        BN_one(qpow);

        for (int i = 0; i < MLKEM_N; i++) {
            uint16_t coeff = (uint16_t)a.vec[poly].coeffs[i]; /* [0, q-1] */
            BN_set_word(tmp, coeff);
            BN_mul(tmp, tmp, qpow, ctx);   /* tmp = a[i] * q^i  */
            BN_add(r, r, tmp);             /* r  += a[i] * q^i  */
            BN_mul(qpow, qpow, bq, ctx);   /* qpow = q^(i+1)    */
        }
        /* qpow == q^n after the loop */
        BN_copy(qn, qpow);

        /* ----------------------------------------------------------------
         * Compute bound = 2^(b+t)
         * b = KEMELEON_B_BITS = 2996, t = KEMELEON_T_BITS = 128
         * ---------------------------------------------------------------- */
        BN_zero(bound);
        BN_set_bit(bound, KEMELEON_B_BITS + KEMELEON_T_BITS);  /* 2^(b+t) */

        /* ----------------------------------------------------------------
         * Sample m uniformly at random from [0, floor((2^(b+t) - r) / q^n)]
         *
         * range = floor((2^(b+t) - r) / q^n)
         * m <--$ [0, range]
         * ---------------------------------------------------------------- */
        BN_sub(tmp, bound, r);             /* tmp   = 2^(b+t) - r           */
        BN_div(tmp, NULL, tmp, qn, ctx);   /* tmp   = floor((2^(b+t)-r)/q^n)*/
        BN_add_word(tmp, 1);               /* tmp   = range + 1 (exclusive)  */
        BN_rand_range(m, tmp);             /* m <--$ [0, range]              */

        /* ----------------------------------------------------------------
         * Output = r + m * q^n
         * ---------------------------------------------------------------- */
        BN_mul(tmp, m, qn, ctx);           /* tmp = m * q^n                 */
        BN_add(r, r, tmp);                 /* r   = r + m * q^n             */

        /* Serialise to exactly KEMELEON_PER_POLY_BYTES big-endian bytes */
        uint8_t *out = ek + poly * KEMELEON_PER_POLY_BYTES;
        if (BN_bn2binpad(r, out, KEMELEON_PER_POLY_BYTES) < 0) {
            BN_CTX_end(ctx); BN_CTX_free(ctx); return -1;
         }
    }

    /* Append rho (seed) */
    memcpy(ek + MLKEM_K * KEMELEON_PER_POLY_BYTES,
           pk + MLKEM_POLYVECBYTES,
           MLKEM_SYMBYTES);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return 1;  /* always succeeds */
}

int kemeleon_decode_ek(const uint8_t ek[KEMELEON_EKBYTES],
                       uint8_t       pk[CRYPTO_PUBLICKEYBYTES])
{
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return -1;
    BN_CTX_start(ctx);

    BIGNUM *r   = BN_CTX_get(ctx);
    BIGNUM *bq  = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    if (!r || !bq || !tmp) {
        BN_CTX_end(ctx); BN_CTX_free(ctx); return -1;
    }

    BN_set_word(bq, 3329u);

    mlk_polyvec a;

    for (int poly = 0; poly < MLKEM_K; poly++) {
        /* Load encoded polynomial */
        const uint8_t *in = ek + poly * KEMELEON_PER_POLY_BYTES;
        BN_bin2bn(in, KEMELEON_PER_POLY_BYTES, r);

        /* VectorDecode: r = r mod q^n, then extract coefficients
         * a[i] = r % q; r = r / q  */
        for (int i = 0; i < MLKEM_N; i++) {
            BN_div(r, tmp, r, bq, ctx);    /* tmp = r % q, r = r / q */
            a.vec[poly].coeffs[i] = (int16_t)BN_get_word(tmp);
        }
    }

    /* Re-encode polyvec to bytes */
    mlk_polyvec_tobytes(pk, &a);

    /* Copy rho */
    memcpy(pk + MLKEM_POLYVECBYTES,
           ek + MLKEM_K * KEMELEON_PER_POLY_BYTES,
           MLKEM_SYMBYTES);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return 1;
}

int compute_t_pad(const uint8_t *PRS,     size_t PRS_len,
              const uint8_t *fullsid, size_t fullsid_len,
              const uint8_t *r,                          /* R_LEN bytes */
              uint8_t        t_pad[KEMELEON_EKBYTES])
{
    int ret = -1;

    /*
     * Build IKM for Extract:
     *   ikm = DST || "OQUAKE" || fullsid || r
     */
    size_t  ikm_len = DST_LEN + LABEL_OQUAKE_LEN + fullsid_len + R_LEN;
    uint8_t *ikm    = calloc(1, ikm_len);
    if (!ikm) return -1;

    {
        uint8_t *p = ikm;
        memcpy(p, DST,          DST_LEN);          p += DST_LEN;
        memcpy(p, LABEL_OQUAKE, LABEL_OQUAKE_LEN); p += LABEL_OQUAKE_LEN;
        memcpy(p, fullsid,      fullsid_len);       p += fullsid_len;
        memcpy(p, r,            R_LEN);
    }

    /*
     * Build info for Expand:
     *   info = DST || "T_pad"
     */
    uint8_t info[DST_LEN + LABEL_TPAD_LEN];
    memcpy(info,           DST,         DST_LEN);
    memcpy(info + DST_LEN, LABEL_TPAD,  LABEL_TPAD_LEN);
    const size_t info_len = sizeof info;

    /*
     * prk_T_pad = HKDF-Extract(salt=PRS, ikm=ikm)
     */
    uint8_t prk[SHA256_LEN];
    if (hkdf_extract_custom(PRS, PRS_len, ikm, ikm_len, prk) != 0)
    //if (hmac_sha256(PRS, PRS_len, ikm, ikm_len, prk) !=0);
        goto cleanup;

    /*
     * T_pad = HKDF-Expand(prk=prk_T_pad, info=info, len=CRYPTO_PUBLICKEYBYTES)
     */
    if (hkdf_expand_custom(prk, SHA256_LEN, info, info_len, t_pad, KEMELEON_EKBYTES) != 0)
    //if (hmac_sha256_kdf(prk,  SHA256_LEN,
                        //NULL,              /* label=NULL → HKDF-Expand  */
                        //info, info_len,    /* seed = info               */
                        //t_pad,  KEMELEON_EKBYTES) != 0);
        goto cleanup;

    ret = 0;

cleanup:
    memset(ikm, 0,  ikm_len);
    memset(prk, 0, sizeof prk);
    free(ikm);
    return ret;
}

int compute_s_pad(const uint8_t *PRS,     size_t PRS_len,
              const uint8_t *fullsid, size_t fullsid_len,
              const uint8_t *T,
              uint8_t s_pad[3*NSEC])                          /* R_LEN bytes */
{
    int ret = -1;

    /*
     */
    size_t  ikm_len = DST_LEN + LABEL_OQUAKE_LEN + fullsid_len + KEMELEON_EKBYTES;
    uint8_t *ikm    = calloc(1, ikm_len);
    if (!ikm) return -1;

    {
        uint8_t *p = ikm;
        memcpy(p, DST,          DST_LEN);          p += DST_LEN;
        memcpy(p, LABEL_OQUAKE, LABEL_OQUAKE_LEN); p += LABEL_OQUAKE_LEN;
        memcpy(p, fullsid,      fullsid_len);       p += fullsid_len;
        memcpy(p, T,            KEMELEON_EKBYTES);
    }

    /*
     * Build info for Expand:
     *   info = DST || "S_pad"
     */
    uint8_t info[DST_LEN + LABEL_SPAD_LEN];
    memcpy(info,           DST,         DST_LEN);
    memcpy(info + DST_LEN, LABEL_SPAD,  LABEL_SPAD_LEN);
    const size_t info_len = sizeof info;

    /*
     * prk_T_pad = HKDF-Extract(salt=PRS, ikm=ikm)
     */
    uint8_t prk[SHA256_LEN];
    /*
     * T_pad = HKDF-Expand(prk=prk_T_pad, info=info, len=CRYPTO_PUBLICKEYBYTES)
     */
    if (hkdf_extract_custom(PRS, PRS_len, ikm, ikm_len, prk) != 0)
        goto cleanup;

    /*
     * T_pad = HKDF-Expand(prk=prk_T_pad, info=info, len=CRYPTO_PUBLICKEYBYTES)
     */
    if (hkdf_expand_custom(prk, SHA256_LEN, info, info_len, s_pad, 3*NSEC) != 0)
        goto cleanup;

    ret = 0;

cleanup:
    OPENSSL_cleanse(ikm,   ikm_len);
    OPENSSL_cleanse(prk,   sizeof prk);
    free(ikm);
    return ret;
}

void xor_inplace(uint8_t *a,
                 const uint8_t *b,
                 size_t len)
{
    for (size_t i = 0; i < len; i++) {
        a[i] ^= b[i];   // same as a[i] = a[i] ^ b[i];
    }
}

int memcmp_const(const void *a, const void *b, size_t len)
{
    const uint8_t *aa = a;
    const uint8_t *bb = b;
    size_t i;
    uint8_t res;

    for (res = 0, i = 0; i < len; i++)
        res |= aa[i] ^ bb[i];

    return res;
}