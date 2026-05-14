/**
 * \file oquake.h
 *
 * \brief Post-Quantum secure PAKE "OQUAKE".
 */
/*
 *  Copyright Nick Leist
 */

#ifndef OQUAKE_H
#define OQUAKE_H

#define NSEC 32

#include <stdint.h>

#include "oquake_utils.h"
#include "mlkem/mlkem_native.h"

/*
 * OQUAKE is a PAKE built on a BUA-sKEM and KDF. If the BUA-sKEM provides security against
 * quantum-enabled attacks, then so does OQUAKE. It consists of three messages sent between 
 * initiator and responder, produced by the functions Init, Respond, and Finish, described 
 * below. Both parties take as input a password-related string PRS, an optional session 
 * identifier sid, and an optional client identifier U and server identifier S. Upon 
 * completion, both parties obtain matching session keys if their PRS, sid, key length 
 * (specified by N), and client and server identifiers match. Otherwise, they obtain random 
 * session keys.
 * https://www.ietf.org/archive/id/draft-vos-cfrg-pqpake-01.html#name-oquake-specification
 */

/**
 * OQUAKE context structure to be stored by the initiator
 */
typedef struct oquake_initiator_ctx {
    unsigned char *prs;
    size_t prs_len;
    uint8_t sk[MLKEM768_SECRETKEYBYTES];
    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    uint8_t s[3*NSEC];
    uint8_t T[KEMELEON_EKBYTES];
    uint8_t *fullsid;
    size_t fullsid_len;
} oquake_initiator_ctx;

/**
 * \brief           Turns sid into fullsid:
 *                  fullsid = len(sid)<32bit> || sid || len(u)<32bit> || u || len(s)<32bit> || s
 *
 * \param sid       Session ID to convert
 * \param sid_len   Length of session ID in bytes
 * \param u         Client's IPv6 Address
 * \param s         Server's IPv6 Address
 * \param encoded_sid   Output pointer for the byte array containing fullsid (the encoded sid)
 *
 * \return A byte array containing fullsid
 *
 */
int encode_sid(const uint8_t *sid, size_t sid_len, const uint8_t u[16], const uint8_t s[16],
    uint8_t **encoded_sid);

/**
 * \brief           Creates init message of OQUAKE flow 
 *
 * \param prs       Password-related string
 * \param prs_len   Length of the password-related string
 * \param sid       Session ID
 * \param sid_len   Length of session ID
 * \param u         Client identifier
 * \param s         Server identifier
 *
 * \param[out] ctx   Will contain the opaque context to be stored by the initiator
 * \param[out] init_msg   Pointer to the message bytestring output of the function
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int oquake_init(unsigned char *prs, size_t prs_len,
                    const uint8_t *sid, size_t sid_len,
                    const uint8_t u[16], const uint8_t s[16],
                    oquake_initiator_ctx *ctx, uint8_t **init_msg);


/**
 * \brief           Processes init message and creates response message of OQUAKE flow. 
 *                  Computes also the shared secret.
 *
 * \param prs       Password-related string
 * \param prs_len   Length of the password-related string
 * \param init_msg  Init message received from initiator
 * \param msg_len   Length of init message
 * \param sid       Session ID
 * \param sid_len   Length of Session ID
 * \param u         Client identifier
 * \param s         Server identifier
 *
 * \param[out] ss       Shared secret, byte string of 32 bytes
 * \param[out] resp_msg Pointer to the message bytestring output of the function
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int oquake_respond(const unsigned char *prs, size_t prs_len,
                    const uint8_t *init_msg, size_t msg_len,
                    const uint8_t *sid, size_t sid_len,
                    uint8_t u[16], uint8_t s[16],
                    uint8_t **ss, uint8_t **resp_msg);


/**
 * \brief           Processes response message and computes the shared secret
 *
 * \param ctx           OQUAKE initiator context
 * \param resp_msg      Response message received from responder
 * \param resp_msg_len  Length of resp_msg in bytes
 *
 * \param[out] ss       Shared secret, byte string of 32 bytes
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int oquake_finish(const oquake_initiator_ctx *ctx, const uint8_t *resp_msg, size_t resp_msg_len, uint8_t **ss);


/**
 * \brief           Initialises \c struct \c oquake_init_ctx with the prs
 *
 * \param ctx           OQUAKE initiator context to initialise
 * \param prs           Password Related String (aka password)
 * \param prs_len       Length of prs
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int init_oq_initiator_ctx(struct oquake_initiator_ctx *ctx, uint8_t *prs, size_t prs_len);

#endif /* OQUAKE_H */