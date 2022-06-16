#ifndef TEE_PSI_H_
#define TEE_PSI_H_


#include "../util/typedefs.h"
#include "../util/connection.h"
#include "../util/crypto/crypto.h"
#include "../util/crypto/pk-crypto.h"
#include <glib.h>
#include "../util/helpers.h"


uint32_t teepsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** resbytelens, crypto* crypt_env, CSocket* sock, uint32_t ntasks);

uint32_t teepsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks);

uint32_t teepsi(role_type role, uint32_t neles, uint32_t pneles, task_ctx ectx,
		crypto* crypt_env, CSocket* sock, uint32_t ntasks, uint32_t* matches);


#endif /* NAIVE_PSI_H_ */
