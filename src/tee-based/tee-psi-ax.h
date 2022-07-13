#ifndef TEE_PSI_AX_H_
#define TEE_PSI_AX_H_


#include "../util/typedefs.h"
#include "../util/connection.h"
#include "../util/crypto/crypto.h"
#include "../util/crypto/pk-crypto.h"
#include <glib.h>
#include "../util/helpers.h"
#include <iomanip>

typedef struct sudo_psi_hw_ctx_st SUDO_PSI_HW_CTX;

SUDO_PSI_HW_CTX * teepsi_init(role_type role, uint32_t ntasks = 1, uint8_t * nego_data, uint32_t * nego_data_len, bool enable_dev = true);
int teepsi_negotiate(SUDO_PSI_HW_CTX * ctx, uint8_t * nego_data, uint32_t nego_data_len);
int teepsi_calc(SUDO_PSI_HW_CTX * ctx, uint32_t neles, uint32_t pneles, uint32_t * elebytelens, uint8_t ** elements, uint8_t * result, uint32_t result_len);

int teepsi_find_intersection(SUDO_PSI_HW_CTX * ctx, uint8_t* hashes, uint32_t neles, uint8_t* phashes, uint32_t pneles, 
    uint32_t * elebytelens, uint8_t ** elements, uint8_t*** result, uint32_t** resbytelens);

int teepsi_done(SUDO_PSI_HW_CTX * ctx);


#endif
