#ifndef SHW_PRIVATE_H_
#define SHW_PRIVATE_H_

#include "../util/typedefs.h"
#include "../util/connection.h"
#include "../util/crypto/crypto.h"
#include "../util/crypto/pk-crypto.h"
#include <glib.h>
#include "../util/helpers.h"
#include <iomanip>

typedef struct sudo_shw_pri_ctx_st SUDO_SHW_PRI_CTX;

SUDO_SHW_PRI_CTX * shw_init(role_type role, uint8_t * nego_data, uint32_t * nego_data_len, uint32_t ntasks = 1, bool enable_dev = true);
int shw_negotiate(SUDO_SHW_PRI_CTX * ctx, const uint8_t * nego_data, uint32_t nego_data_len);

//--------------------------------------------------------------------
int shw_pir_preprocess(SUDO_SHW_PRI_CTX * ctx);

int shw_pir_server_gen_table(
    SUDO_SHW_PRI_CTX * ctx, 
    uint8_t ** ptr_keyw, uint32_t * kw_size, 
    uint8_t ** ptr_val, uint32_t * val_size,
    uint32_t db_size
);

int shw_pir_client_gen_query(
    SUDO_SHW_PRI_CTX * ctx, 
    uint8_t * keyw, uint32_t kwlen, 
    uint8_t ** ptr_enc_keyw, uint32_t * enc_kwlen
);

int shw_pir_server_response(
    SUDO_SHW_PRI_CTX * ctx, 
    uint8_t * ptr_enc_keyw, uint32_t enc_kwlen, 
    uint8_t ** ptr_enc_value, uint32_t * enc_vlen
);

int shw_pir_client_getv(
    SUDO_SHW_PRI_CTX * ctx, 
    uint8_t * ptr_keyw, uint32_t kwlen, 
    uint8_t * ptr_enc_value, uint32_t enc_vlen, 
    uint8_t ** ptr_value, uint32_t * vlen
);

int shw_pir_done(SUDO_SHW_PRI_CTX * ctx);

//--------------------------------------------------------------------
int shw_psi_preprocess(SUDO_SHW_PRI_CTX * ctx);

int shw_psi_calc(
    SUDO_SHW_PRI_CTX * ctx, 
    uint32_t neles, uint32_t pneles, 
    uint32_t * elebytelens, uint8_t ** elements, 
    uint8_t * result, uint32_t result_len
);

int shw_psi_find_intersection(
    SUDO_SHW_PRI_CTX * ctx, 
    const uint8_t* hashes, uint32_t neles, 
    const uint8_t* phashes, uint32_t pneles, 
    const uint32_t * elebytelens, const uint8_t ** elements, 
    uint8_t*** result, uint32_t** resbytelens
);

int shw_psi_find_intersection_index(
    SUDO_SHW_PRI_CTX * ctx, 
    const uint8_t* hashes, uint32_t neles, 
    const uint8_t* phashes, uint32_t pneles, 
    uint32_t* matches_index
);

int shw_psi_done(SUDO_SHW_PRI_CTX * ctx);

#endif
