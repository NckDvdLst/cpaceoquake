#include <string.h>
#include <openssl/rand.h>

#include "oquake.h"
#include "oquake_utils.h"

static void write_u32_be(uint8_t *dst, uint32_t v) {
    dst[0] = (v >> 24) & 0xFF;
    dst[1] = (v >> 16) & 0xFF;
    dst[2] = (v >>  8) & 0xFF;
    dst[3] =  v        & 0xFF;
}

/**
 * Turns sid into fullsid:
 * fullsid = len(sid)<32bit> || sid || len(u)<32bit> || u || len(s)<32bit> || s
 *
 * \param sid           Session ID to convert
 * \param sid_len       Length of session ID in bytes
 * \param u             Client's IPv6 Address
 * \param s             Server's IPv6 Address
 * \param encoded_sid   Output pointer for the byte array containing fullsid (the encoded sid)
 *
 * \return A byte array containing fullsid
 */
int encode_sid(const uint8_t *sid, const size_t sid_len, const uint8_t u[16], const uint8_t s[16],
    uint8_t **encoded_sid) {
    uint8_t *fullsid = calloc(1, 44+sid_len);
    if (!fullsid) return -1;

    write_u32_be(fullsid, sid_len);
    memcpy(&fullsid[4], sid, sid_len);
    write_u32_be(fullsid+4, 16);
    memcpy(&fullsid[8+sid_len], u, 16);
    write_u32_be(fullsid+24, 16);
    memcpy(&fullsid[28+sid_len], s, 16);
    *encoded_sid = fullsid;
    return 0;
}

int oquake_init(unsigned char *prs, const size_t prs_len,
                    const uint8_t *sid, const size_t sid_len,
                    const uint8_t u[16], const uint8_t s[16],
                    oquake_initiator_ctx *ctx, uint8_t **init_msg) {

    // convert sid to fullsid
    uint8_t *fullsid;
    if (encode_sid(sid, sid_len, u, s, &fullsid)) return -1;
    const size_t fullsid_len = 3*4 + sid_len + 32; // 3*32bit + sid_len + 2*16bit
    
    // generate seed and keypair
    uint8_t *seed = calloc(1, 2*MLKEM_SYMBYTES);
    if (!RAND_bytes(seed, 2*MLKEM_SYMBYTES)) return -1;

    // generate keypair and encode public key for indistinguishability
    uint8_t ek[KEMELEON_EKBYTES];
	if (crypto_kem_keypair_derand(ctx->pk, ctx->sk, seed)) return -1;
	kemeleon_encode_ek(ctx->pk, ek);

    // mask encoded public key ek using randomness r
    uint8_t r[3*NSEC];
	if (!RAND_bytes(r, 2*NSEC)) return -1;
	uint8_t T_pad[KEMELEON_EKBYTES];
	compute_t_pad(prs, prs_len, fullsid, fullsid_len, r, T_pad);
	xor_inplace(ek, T_pad, sizeof T_pad);

    // mask randomness r using masked ek
	uint8_t s_pad[3*NSEC];
	compute_s_pad(prs, prs_len, fullsid, fullsid_len, ek, s_pad);
	xor_inplace(r, s_pad, sizeof s_pad);

    // init_msg: r || ek
    uint8_t *message = calloc(1, sizeof(r) + sizeof(ek));
    if(!message) return -1;
    memcpy(message, r, sizeof(r));
    memcpy(message + sizeof(r), ek, sizeof(ek));
    *init_msg = message;
    
    // configure initiator_ctx
    ctx->prs = prs;
    ctx->prs_len = prs_len;
    memcpy(ctx->s, r, sizeof(r));
    memcpy(ctx->T, ek, sizeof(ek));
    ctx->fullsid = fullsid;
    ctx->fullsid_len = fullsid_len;
	return 0;

}

int oquake_respond(const unsigned char *prs, const size_t prs_len,
                    const uint8_t *init_msg, size_t msg_len,
                    const uint8_t *sid, const size_t sid_len,
                    uint8_t u[16], uint8_t s[16],
                    uint8_t **ss, uint8_t **resp_msg) {

    // convert sid to fullsid
    uint8_t *fullsid;
    if (encode_sid(sid, sid_len, u, s, &fullsid)) goto failure_cleanup_fullsid;;
    const size_t fullsid_len = 3*4 + sid_len + 32; // 3*32bit + sid_len + 2*16bit

    // extract masked random and masked ek from init_msg
    uint8_t msg_s[3*NSEC];
    memcpy(msg_s, init_msg, sizeof msg_s);
    uint8_t ek[KEMELEON_EKBYTES];
    memcpy(ek, init_msg+sizeof(msg_s), sizeof ek);

    // reconstruct random and ek from masked values
    uint8_t s_pad[3*NSEC];
    compute_s_pad(prs, prs_len, fullsid, fullsid_len, ek, s_pad);
    xor_inplace(msg_s, s_pad, sizeof s_pad);
    uint8_t T_pad[KEMELEON_EKBYTES];
    compute_t_pad(prs, prs_len, fullsid, fullsid_len, msg_s, T_pad);
    xor_inplace(ek, T_pad, sizeof T_pad);

    // decode encoded pk
    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    kemeleon_decode_ek(ek, pk);

    // use kem to generate and encapsulate key using pk
    uint8_t ciphertext[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key[32];
    if (crypto_kem_enc(ciphertext, key, pk)) goto failure_cleanup_fullsid;;

    // input keying material for KDF Extraction
    const size_t  ikm_len = DST_LEN + LABEL_OQUAKE_LEN + fullsid_len + sizeof(key);
    uint8_t *ikm    = calloc(1, ikm_len);
    if (!ikm) goto failure_cleanup_ikm; ;
    {
        uint8_t *p = ikm;
        memcpy(p, DST,          DST_LEN);          p += DST_LEN;
        memcpy(p, LABEL_OQUAKE, LABEL_OQUAKE_LEN); p += LABEL_OQUAKE_LEN;
        memcpy(p, fullsid,      fullsid_len);              p += fullsid_len;
        memcpy(p, key,            sizeof(key));
    }

    // extract pseudo random key from input keying material
    uint8_t prk[SHA256_LEN];
    uint8_t h[64];
    hkdf_extract_custom(prs, prs_len, ikm, ikm_len, prk);

    // expand prk to get shared secret
    uint8_t sk[DST_LEN + 2];
    memcpy(sk,           DST,         DST_LEN);
    memcpy(sk + DST_LEN, "sk",  2);
    const size_t sk_len = sizeof sk;
    uint8_t *shared_secret = calloc(1, 32);;
    hkdf_expand_custom(prk, SHA256_LEN, sk, sk_len, shared_secret, 32);
    *ss = shared_secret;

    // expand prk again to get confirmation value h
    uint8_t confirm[DST_LEN + 7];
    memcpy(confirm,           DST,         DST_LEN);
    memcpy(confirm + DST_LEN, "confirm",  7);
    const size_t confirm_len = sizeof confirm;
    hkdf_expand_custom(prk, SHA256_LEN, confirm, confirm_len, h, sizeof h);

    // build response message
    uint8_t *message = calloc(1, CRYPTO_CIPHERTEXTBYTES + sizeof(h));
    memcpy(message, ciphertext, CRYPTO_CIPHERTEXTBYTES);
    memcpy(message+CRYPTO_CIPHERTEXTBYTES, h, sizeof h);
    *resp_msg = message;

    free(ikm);
    free(fullsid);
    return 0;

    failure_cleanup_ikm:
    free(ikm);
    failure_cleanup_fullsid:
    free(fullsid);
    return -1;

}

int oquake_finish(const oquake_initiator_ctx *ctx, const uint8_t *resp_msg, size_t resp_msg_len, uint8_t **ss) {

    uint8_t verifier[64];
    size_t hash_len = 64;
    uint8_t key[32];

    // get ciphertext from resp_msg and decapsulate the shared key
    uint8_t ciphertext[CRYPTO_CIPHERTEXTBYTES];
    memcpy(ciphertext, resp_msg, CRYPTO_CIPHERTEXTBYTES);
    if (crypto_kem_dec(key, ciphertext, ctx->sk)) return -1;

    // prepare shared secret computation
    const size_t  ikm_len = DST_LEN + LABEL_OQUAKE_LEN + ctx->fullsid_len + sizeof(key);
    uint8_t *ikm    = calloc(1, ikm_len);
    if (!ikm) return -1;

    {
        uint8_t *p = ikm;
        memcpy(p, DST,          DST_LEN);          p += DST_LEN;
        memcpy(p, LABEL_OQUAKE, LABEL_OQUAKE_LEN); p += LABEL_OQUAKE_LEN;
        memcpy(p, ctx->fullsid,      ctx->fullsid_len);       p += ctx->fullsid_len;
        memcpy(p, key,            sizeof(key));
    }

    uint8_t prk[SHA256_LEN];

    hkdf_extract_custom(ctx->prs, ctx->prs_len, ikm, ikm_len, prk);

    // compute shared secret using KDF
    uint8_t sk[DST_LEN + 2];
    memcpy(sk,           DST,         DST_LEN);
    memcpy(sk + DST_LEN, "sk",  2);
    const size_t sk_len = sizeof sk;
    uint8_t *shared_secret = calloc(1, 32);;
    hkdf_expand_custom(prk, SHA256_LEN, sk, sk_len, shared_secret, 32);
    *ss = shared_secret;

    // compute confirmation value h
    uint8_t confirm[DST_LEN + 7];
    memcpy(confirm,           DST,         DST_LEN);
    memcpy(confirm + DST_LEN, "confirm",  7);
    const size_t confirm_len = sizeof confirm;
    hkdf_expand_custom(prk, SHA256_LEN, confirm, confirm_len, verifier, sizeof verifier);

    if (memcmp_const(verifier, resp_msg + CRYPTO_CIPHERTEXTBYTES, hash_len))
        return -1;

    return 0;

}

int init_oq_initiator_ctx(struct oquake_initiator_ctx *ctx, uint8_t *prs, size_t prs_len) {
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(oquake_initiator_ctx));
    ctx->prs = prs;
    ctx->prs_len = prs_len;
    return 0;
}