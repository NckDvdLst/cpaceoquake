#ifndef PQC_UTIL_H
#define PQC_UTIL_H

#include <openssl/sha.h>

#include <stdlib.h>

#include "mlkem/mlkem_native.h"
#include "mlkem/src/fips202/fips202.h"
#include "mlkem/src/poly.h"

#define UC_PAKE_LABEL      "UC-PAKE-v1"
#define UC_PAKE_LABEL_LEN  10

#define AES_256_GCM_KEY_SIZE  32
#define AES_256_GCM_IV_SIZE   12
#define AES_256_GCM_TAG_SIZE  16


#define KEMELEON_B_BITS     2996
#define KEMELEON_T_BITS     128
#define KEMELEON_PER_POLY_BYTES  391   /* ceil((2996+128)/8) */
#define KEMELEON_EKBYTES   (MLKEM_K * KEMELEON_PER_POLY_BYTES + MLKEM_SYMBYTES)

#define NSEC 32

#define SHA256_LEN  32
#define DST          "OQUAKE-v1"
#define DST_LEN      (sizeof(DST) - 1)   /* exclude NUL terminator    */

/* Fixed label used in the Expand info field */
#define LABEL_OQUAKE     "OQUAKE"
#define LABEL_OQUAKE_LEN (sizeof(LABEL_OQUAKE) - 1)

#define LABEL_TPAD       "T_pad"
#define LABEL_TPAD_LEN   (sizeof(LABEL_TPAD) - 1)
#define LABEL_SPAD       "S_pad"
#define LABEL_SPAD_LEN   (sizeof(LABEL_SPAD) - 1)
#define R_LEN 92


void xor_inplace(uint8_t *a,
                 const uint8_t *b,
                 size_t len);


typedef struct {
    uint8_t *data;
    size_t   size;
} s_buffer;


typedef enum { PQC_ENCRYPTION, PQC_DECRYPTION } PQC_CIPHER_MODE;


/* Allocate a zeroed secure buffer */
s_buffer sb_alloc(size_t size);
/* Deep-copy a slice of src into a new s_buffer */
s_buffer sb_slice(const uint8_t *src, size_t size);
/* Concatenate two buffers into a new one (mimics S += T) */
s_buffer sb_concat(const s_buffer *a, const s_buffer *b);
/* Wipe and free */
void sb_free(s_buffer *sb);

int compute_t_pad(const uint8_t *PRS,     size_t PRS_len,
              const uint8_t *fullsid, size_t fullsid_len,
              const uint8_t *r,                          /* R_LEN bytes */
              uint8_t        t_pad[KEMELEON_EKBYTES]);


int kemeleon_encode_ek(const uint8_t pk[CRYPTO_PUBLICKEYBYTES],
                       uint8_t       ek[KEMELEON_EKBYTES]);

int kemeleon_decode_ek(const uint8_t ek[KEMELEON_EKBYTES],
                       uint8_t       pk[CRYPTO_PUBLICKEYBYTES]);

int compute_s_pad(const uint8_t *PRS,     size_t PRS_len,
              const uint8_t *fullsid, size_t fullsid_len,
              const uint8_t *T,                          /* R_LEN bytes */
              uint8_t s_pad[3*NSEC]);                         /* R_LEN bytes */



int compute_sid(const uint8_t  id_a[6],
                const uint8_t  id_b[6],
                const uint8_t  nonce_a[32],
                const uint8_t  nonce_b[32],
                uint8_t        sid_out[32]);

int hkdf_expand_custom(const uint8_t *prk,  size_t prk_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t       *okm,  size_t okm_len);

int hkdf_extract_custom(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm,  size_t ikm_len,
                        uint8_t        prk[SHA256_LEN]);

int memcmp_const(const void *a, const void *b, size_t len);

#endif