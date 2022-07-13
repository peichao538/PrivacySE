#include "tee-psi-ax.h"


typedef struct sudo_psi_hw_ctx_st
{
    role_type role;

    crypto * crypt_env;

    task_ctx * ectx;

    void * data;

    uint8_t entr[64];

    uint32_t maskbytelen;

    //
    uint32_t * perm;

    //
    int ntasks;

}SUDO_PSI_HW_CTX;

static const uint8_t const_rng_seed[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};


SUDO_PSI_HW_CTX * teepsi_init(role_type role, uint32_t ntasks, uint8_t * nego_data, uint32_t * nego_data_len, bool enable_dev) 
{
    int ret = 0;

    if ( !nego_data || !nego_data_len || (*nego_data_len < sizeof(cap_ecc_pubkey_t)) )
    {
        return NULL;
    }

    //
    SUDO_PSI_HW_CTX * psi_ctx = (SUDO_PSI_HW_CTX *)malloc(sizeof(SUDO_PSI_HW_CTX));
    if (psi_ctx == NULL)
    {
        return NULL;
    }

    //
    memset(psi_ctx, 0, sizeof(SUDO_PSI_HW_CTX));

    //
    psi_ctx->data = (void *)malloc(1024);
    if (psi_ctx->data == NULL)
    {
        free(psi_ctx);
        return NULL;
    }

    // default use 128 as security level
    uint32_t symsecbits = 128;
    psi_ctx->crypt_env = new crypto(symsecbits, (uint8_t*) const_rng_seed);

    psi_ctx->ntasks = ntasks;

    //
    if (enable_dev)
    {
        ret = psi_ctx->crypt_env->open_device(1, 128);
        //ret = psi_ctx->crypt_env->open_device(1, 1);
        if (0 == ret)
        {
            psi_ctx->crypt_env->close_device();
            free(psi_ctx);
            return NULL;
        }
    }
    
    //
    psi_ctx->role = role;

    //
  	cap_ecc_keypair_t * spkey = (cap_ecc_keypair_t *) psi_ctx->data;

	psi_ctx->crypt_env->sm2_gen_key(psi_ctx->crypt_env->dev_mngt.hdev[0], (uint8_t *)spkey);
    
    memcpy(nego_data, &(spkey->pubkey), sizeof(cap_ecc_pubkey_t));
    *nego_data_len = sizeof(cap_ecc_pubkey_t);

    return psi_ctx;

}

int teepsi_negotiate(SUDO_PSI_HW_CTX * ctx, uint8_t * nego_data, uint32_t nego_data_len)
{
    //
    if (!ctx || !nego_data)
    {
        return 0;
    }

    //
    crypto * crypt_env = ctx->crypt_env;

    cap_ecc_keypair_t * spkey = (cap_ecc_keypair_t *) ctx->data;
    cap_ecc_pubkey_t * rpubkey = (cap_ecc_pubkey_t *) nego_data;
    crypt_env->sm2_set_pow(crypt_env->dev_mngt.hdev[0], &(spkey->prikey), rpubkey, &(spkey->pubkey));

    //
    memcpy(ctx->entr, spkey->pubkey.x, 64);

    //
	free(ctx->data);
    ctx->data = NULL;

    return 1;
}

int teepsi_calc(SUDO_PSI_HW_CTX * ctx, uint32_t neles, uint32_t pneles, uint32_t * elebytelens, uint8_t ** elements, uint8_t * result, uint32_t result_len)
{
    if (!ctx || !elebytelens || !elebytelens || (!result && result_len != 0))
    {
        return 0;
    }

    crypto * crypt_env = ctx->crypt_env;

	// check hw is enabled
	if (1 != crypt_env->hw_on)
	{
		return 0;
	}

    //
    uint32_t maskbytelen_t = ceil_divide(crypt_env->get_seclvl().statbits + ceil_log2(neles) + ceil_log2(pneles), 8);
    ctx->maskbytelen = maskbytelen_t;

    if (!result)
    {
        return neles * maskbytelen_t;
    }

    //
	ctx->perm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
    uint8_t * hashes = result;

	/* Generate the random permutation the elements */
	crypt_env->gen_rnd_perm(ctx->perm, neles);

    //
    ctx->ectx = (task_ctx *)malloc(sizeof(task_ctx));

    //
	ctx->ectx->eles.input2d = elements;
	ctx->ectx->eles.varbytelens = elebytelens;
	ctx->ectx->eles.hasvarbytelen = true;

	//ctx->ectx->eles.input = permeles;
	//ctx->ectx->eles.inbytelen = elebytelen;
	ctx->ectx->eles.outbytelen = maskbytelen_t,
	ctx->ectx->eles.nelements = neles;
	ctx->ectx->eles.output = hashes;
	ctx->ectx->eles.perm = ctx->perm;
	ctx->ectx->sctx.symcrypt = crypt_env;
	ctx->ectx->entropy = ctx->entr;
	ctx->ectx->entropylen = 64;

	run_task(ctx->ntasks, *(ctx->ectx), psi_hashing_use_tee_function);

    return 1;
}

int teepsi_find_intersection(SUDO_PSI_HW_CTX * ctx, uint8_t* hashes, uint32_t neles, uint8_t* phashes, uint32_t pneles, 
    uint32_t * elebytelens, uint8_t ** elements, uint8_t*** result, uint32_t** resbytelens)
{
    uint32_t intersect_size;
    uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * min(neles, pneles));

    intersect_size = find_intersection(hashes, neles, phashes, pneles, ctx->maskbytelen, ctx->perm, matches);

	if(ctx->role == CLIENT) 
	{
		create_result_from_matches_var_bitlen(result, resbytelens, elebytelens, elements, matches, intersect_size);
	}

    //
	free(matches);
    matches = NULL;
    
    //
    free(ctx->perm);
    ctx->perm = NULL;

    //
    return intersect_size;
}

int teepsi_done(SUDO_PSI_HW_CTX * ctx)
{
    if (!ctx) return 1;

    if (ctx->data != NULL)
    {
        free(ctx->data);
    }

    //
    if (ctx->perm != NULL)
    {
        free(ctx->perm);
    }

    //
    if (ctx->ectx != NULL)
    {
        free(ctx->ectx);
    }

    //
    if (ctx->crypt_env != NULL)
    {
        ctx->crypt_env->close_device();
        
        delete ctx->crypt_env;
        ctx->crypt_env = NULL;
    }

    //
    free(ctx);

    return 1;
}

