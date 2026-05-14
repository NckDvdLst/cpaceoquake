#include <stdio.h>
#include <openssl/rand.h>
#include "cpaceoquake.h"

void DumpHex(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

int main(void) {
    // Setze Passwort und Benutzerkennungen
    unsigned char *prs = (unsigned char *)"Paßwort";
    const unsigned char prs_len = sizeof("Paßwort")-1;
    unsigned char u[16];
    unsigned char s[16];
    RAND_bytes(u, 16);
    RAND_bytes(s, 16);

    // IO declaration for cpaceoquake_init
    cpaceoquake_initiator_ctx init_ctx;
    crypto_cpace_state cp_ctx;
    init_ctx.cp_ctx = &cp_ctx;
    unsigned char *init_msg;

    // perform Client.Init step
    cpaceoquake_init(prs, prs_len, NULL, 0, u, s,
                    &init_ctx, &init_msg);

    // IO declaration for cpaceoquake_respond
    unsigned char *resp_msg;
    cpaceoquake_responder_ctx resp_ctx;

    //perform Server.Respond step
    cpaceoquake_respond(prs, prs_len, init_msg, NULL, 0, u, s,
                    &resp_ctx, &resp_msg);

    // IO declaration for cpaceoquake_initiator_finish
    unsigned char *key_c;
    size_t key_c_len;
    unsigned char *fin_msg;
    size_t fin_msg_len;

    // perform Client.Finish step
    cpaceoquake_initiator_finish(prs, prs_len, &init_ctx, resp_msg, NULL, 0, u, s,
    &key_c, &key_c_len, &fin_msg, &fin_msg_len);

    // IO declaration for cpaceoquake_responder_finish
    unsigned char *key_s;
    size_t key_s_len;

    //perform Server.Finish step
    cpaceoquake_responder_finish(&resp_ctx, fin_msg, fin_msg_len, &key_s, &key_s_len);

    if (key_s_len != key_c_len) {
        printf("Die Schlüssellängen sind ungleich. Client: %llu ; Server: %llu", key_c_len, key_s_len);
    } else {
        for (int i = 0; i < key_s_len; i++) {
            if (*(key_c+i) != *(key_s+i)) {
                printf("Schlüssel sind ungleich!");
            }
        }
    }

    printf("Key Client:");
    DumpHex(key_c, key_c_len);
    printf("Key Server:");
    DumpHex(key_s, key_s_len);
}
