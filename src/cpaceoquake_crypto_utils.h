#ifndef CPACEOQUAKE_CRYPTO_UTILS_H
#define CPACEOQUAKE_CRYPTO_UTILS_H

#include <openssl/sha.h>

#include "cpaceoquake.h"
#include "crypto_cpace.h"

/**
* @brief   Derives two keys, key1A and key1B from CPace-Shared Key key1 as specified in CPaceOQUAKE
 *
 * @param shared_keys   Shared Keys Struct of CPace to derive key1A and key1B from
 * @param[out] key1A    Derived key1A
 * @param[out] key1B    Derived key1B
 * @return 0 if successful
 */
int cpace_kdf(struct crypto_cpace_shared_keys_ *shared_keys,
                     unsigned char key1A[SHA256_DIGEST_LENGTH],
                     unsigned char key1B[SHA256_DIGEST_LENGTH]);

/**
 * @brief Extends two shared random strings to an extended sid
 *
 * @param s1                    Client random value
 * @param s2                    Server random value
 * @param[out] extended_sid     Output buffer for extended sid
 *
 * @return 0 if successful
 */
int extend_sid_of_two(const uint8_t s1[32],
                             const uint8_t s2[32],
                             uint8_t extended_sid[32]);

/**
 * @brief Extends shared sid to extended sid
 *
 * @param sid                   Shared sid
 * @param sid_len               Length of sid
 * @param[out] extended_sid     Output buffer for extended sid
 *
 * @return 0 if successful
 */
int extend_sid(const uint8_t *sid, size_t sid_len,
                      uint8_t extended_sid[SHA256_DIGEST_LENGTH]);

/**
 * @brief Derives PRS2 from PRS and key1A of CPace
 *
 * @param prs           Original PRS used for derivation
 * @param prs_len       Length of prs
 * @param fullsid       fullsid of the connection
 * @param fullsid_len   Length of fullsid
 * @param msg1          CPace.Init Message
 * @param msg1_len      Length of msg1
 * @param msg2          CPace.Respond Message
 * @param msg2_len      Length of msg2
 * @param key1A         key1A derived from key1 from CPace
 * @param key1A_len     Length of key1A
 * @param[out] prs2     Output buffer for derived password related string 2
 *
 * @return 0 if successful
 */
int prs_to_prs2(const unsigned char *prs, const size_t prs_len,
                       const uint8_t *fullsid, const size_t fullsid_len,
                       const uint8_t *msg1, const size_t msg1_len,
                       const uint8_t *msg2, const size_t msg2_len,
                       const unsigned char key1A[SHA256_DIGEST_LENGTH], const size_t key1A_len,
                       unsigned char prs2[CPACEOQUAKE_NKEY]);

/**
 * @brief   Derives final secret from PRS and a full transcript
 *
* @param prs            Original PRS used for derivation
 * @param prs_len       Length of prs
 * @param fullsid       fullsid of the connection
 * @param fullsid_len   Length of fullsid
 * @param msg1          CPace.Init Message
 * @param msg1_len      Length of msg1
 * @param msg2          CPace.Respond Message
 * @param msg2_len      Length of msg2
 * @param msg3          OQUAKE.Init Message
 * @param msg3_len      Length of msg3
 * @param msg4          OQUAKE.Respond Message
 * @param msg4_len      Length of msg4
 * @param key1B         key1B derived from key1 from CPace
 * @param key2          key2 (resulting key from OQUAKE)
 * @param secret        Final shared secret between Client and Server
 *
 * @return 0 if successful
 */
int cpaceoquake_kdf(uint8_t *prs, size_t prs_len,
                           uint8_t *fullsid, size_t fullsid_len,
                           uint8_t *msg1, size_t msg1_len,
                           uint8_t *msg2, size_t msg2_len,
                           uint8_t *msg3, size_t msg3_len,
                           uint8_t *msg4, size_t msg4_len,
                           unsigned char key1B[SHA256_DIGEST_LENGTH],
                           unsigned char key2[32],
                           unsigned char secret[CPACEOQUAKE_NKEY]);

#endif /* CPACEOQUAKE_CRYPTO_UTILS_H */
