#ifndef SH_PIR_H_
#define SH_PIR_H_

#include "../util/typedefs.h"
#include "../util/connection.h"
#include "../util/crypto/crypto.h"
#include "../util/crypto/pk-crypto.h"
#include <glib.h>
#include "../util/helpers.h"
#include <iomanip>

typedef struct sudo_pir_hw_ctx_st SUDO_PIR_HW_CTX;

SUDO_PIR_HW_CTX * teepir_init(role_type role, uint8_t * nego_data, uint32_t * nego_data_len, uint32_t ntasks = 1, bool enable_dev = true);
int teeppir_negotiate(SUDO_PIR_HW_CTX * ctx, const uint8_t * nego_data, uint32_t nego_data_len);

int server_preprocess(SUDO_PIR_HW_CTX * ctx, 
    uint8_t ** p_key, uint32_t * k_size, 
    uint8_t ** p_value, uint32_t * v_size,
    uint32_t db_size);

int server_gen_table(SUDO_PIR_HW_CTX * ctx);
int server_reshuffle_table(SUDO_PIR_HW_CTX * ctx);
int server_response(SUDO_PIR_HW_CTX * ctx, uint8_t * enc_key, uint32_t enc_klen, uint8_t ** enc_value, uint32_t * enc_vlen);

int client_gen_query(SUDO_PIR_HW_CTX * ctx, uint8_t * key, uint32_t klen, uint8_t * enc_key, uint32_t * enc_klen);
int client_getv(SUDO_PIR_HW_CTX * ctx, uint8_t * key, uint32_t klen, uint8_t * enc_value, uint32_t enc_vlen, uint8_t ** value, uint32_t * vlen);

int teepsi_done(SUDO_PIR_HW_CTX * ctx);


#endif
