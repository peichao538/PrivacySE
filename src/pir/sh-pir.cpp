#include "sh-pir.h"


typedef struct pir_task_ctx
{
    uint8_t ** p_key;
    uint32_t * p_ksize;

    uint8_t ** p_value;
    uint32_t * p_vsize;

    uint32_t dbsize;

    //uint8_t ** p_enckey;
    uint8_t * p_enckey;
    uint8_t ** p_encvalue;
    uint32_t * p_encvalue_len;

    uint32_t nelements;
    uint32_t startelements;
    uint32_t endelements;

}pir_task_ctx_t;


typedef struct sudo_pir_hw_ctx_st
{
    role_type role;

    crypto * crypt_env;

    task_ctx * ectx;

    pir_task_ctx_t * e2ctx;

    void * data;

    uint8_t entr[64];

    uint8_t slt[64];
    uint32_t slt_len;

    uint8_t kek[64];
    uint32_t kek_len;

    uint32_t maskbytelen;

    //
    uint32_t * perm;
    uint32_t * invperm;

    //
    int ntasks;

    uint32_t hblkid;

    GHashTable * map;

}SUDO_PIR_HW_CTX;

static const uint8_t const_rng_seed[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

int derive_key(SUDO_PIR_HW_CTX * ctx);


SUDO_PIR_HW_CTX * teepir_init(role_type role, uint8_t * nego_data, uint32_t * nego_data_len, uint32_t ntasks, bool enable_dev) 
{
    int ret = 0;

    if ( !nego_data || !nego_data_len || (*nego_data_len < sizeof(cap_ecc_pubkey_t)) )
    {
        return NULL;
    }

    //
    SUDO_PIR_HW_CTX * pir_ctx = (SUDO_PIR_HW_CTX *)malloc(sizeof(SUDO_PIR_HW_CTX));
    if (pir_ctx == NULL)
    {
        return NULL;
    }

    //
    memset(pir_ctx, 0, sizeof(SUDO_PIR_HW_CTX));

    //
    pir_ctx->data = (void *)malloc(1024);
    if (pir_ctx->data == NULL)
    {
        free(pir_ctx);
        return NULL;
    }

    // default use 128 as security level
    uint32_t symsecbits = 128;
    pir_ctx->crypt_env = new crypto(symsecbits, (uint8_t*) const_rng_seed);

    pir_ctx->ntasks = ntasks;
    pir_ctx->maskbytelen = 8; // 64 bit default

    //
    if (enable_dev)
    {
        //ret = pir_ctx->crypt_env->open_device(1, 128);
        //ret = pir_ctx->crypt_env->open_device(1, 64);
        ret = pir_ctx->crypt_env->open_device(1, 1);
        if (0 == ret)
        {
            pir_ctx->crypt_env->close_device();
            free(pir_ctx);
            return NULL;
        }
    }
    
    //
    pir_ctx->role = role;

    //
  	cap_ecc_keypair_t * spkey = (cap_ecc_keypair_t *) pir_ctx->data;

	pir_ctx->crypt_env->sm2_gen_key(pir_ctx->crypt_env->dev_mngt.hdev[0], (uint8_t *)spkey);
    
    memcpy(nego_data, &(spkey->pubkey), sizeof(cap_ecc_pubkey_t));
    *nego_data_len = sizeof(cap_ecc_pubkey_t);

    return pir_ctx;

}

int teepir_negotiate(SUDO_PIR_HW_CTX * ctx, const uint8_t * nego_data, uint32_t nego_data_len)
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

    //
    derive_key(ctx);

    return 1;
}

int derive_key(SUDO_PIR_HW_CTX * ctx)
{
    int ret;

    if (!ctx)
    {
        return 0;
    }

    crypto * crypt_env = ctx->crypt_env;

    crypt_env->kdf(ctx->crypt_env->dev_mngt.hdev[0], ctx->entr, 16, (uint8_t *)"salt", strlen("salt"), ctx->slt, &ctx->slt_len);
    crypt_env->kdf(ctx->crypt_env->dev_mngt.hdev[0], ctx->entr, 16, (uint8_t *)"kek", strlen("kek"), ctx->kek, &ctx->kek_len);

    return 1;
}

void * pir_preprocess_function(void* context) 
{
#ifdef DEBUG
	cout << "PIR preprocess thread started" << endl;
#endif
    SUDO_PIR_HW_CTX * pir_ctx = (SUDO_PIR_HW_CTX *)context;
    crypto* crypt_env = pir_ctx->crypt_env;
    pir_task_ctx_t * electx = pir_ctx->e2ctx;

	uint8_t * salt = pir_ctx->slt;
	uint32_t saltlen = pir_ctx->slt_len;

    uint8_t * key = pir_ctx->kek;
    uint32_t keylen = pir_ctx->kek_len;

	if (1 != crypt_env->hw_on)
	{
		return NULL;
	}

	uint32_t* perm = pir_ctx->perm;
	uint32_t i;
	uint8_t* tmphashbuf = (uint8_t*) malloc(crypt_env->get_hash_bytes());

	{
        uint8_t **inptr = electx->p_key;
        uint8_t kdk[16] = {0};
        uint32_t kdk_len = 0;

        for(i = electx->startelements; i < electx->endelements; i++) 
        {
            
            // encrypt payload
            {
                crypt_env->kdf(crypt_env->dev_mngt.hdev[pir_ctx->hblkid], pir_ctx->kek, pir_ctx->kek_len, inptr[i], electx->p_ksize[i], kdk, &kdk_len);
                electx->p_encvalue_len[i] = crypt_env->encrypt_hw(crypt_env->dev_mngt.hdev[pir_ctx->hblkid], kdk, \
                        &electx->p_encvalue[i], electx->p_value[i], electx->p_vsize[i]);
            }

            // hash key
            {
                // todo: need randomized
                crypt_env->hash_with_salt_hw(crypt_env->dev_mngt.hdev[pir_ctx->hblkid], electx->p_enckey+perm[i]*pir_ctx->maskbytelen, pir_ctx->maskbytelen, 
                    salt, saltlen, inptr[i], electx->p_ksize[i], tmphashbuf);

                // crypt_env->hash_with_salt_hw(crypt_env->dev_mngt.hdev[pir_ctx->hblkid], electx->p_enckey+perm[i]*pir_ctx->maskbytelen, pir_ctx->maskbytelen, 
                //     salt, saltlen, inptr[i], electx->p_ksize[i], tmphashbuf);
            }
        }
	}

	//
	free(tmphashbuf);
	return 0;
}

// temperory function
void pir_run_task(uint32_t nthreads, SUDO_PIR_HW_CTX context, void* (*func)(void*) ) 
{

	crypto * crypt = context.crypt_env;

	if (crypt->hw_on)
	{
		nthreads = crypt->dev_mngt.thread_num;
	}
	
	SUDO_PIR_HW_CTX* contexts = (SUDO_PIR_HW_CTX*) malloc(sizeof(SUDO_PIR_HW_CTX) * nthreads);
	pthread_t* threads = (pthread_t*) malloc(sizeof(pthread_t) * nthreads);
	uint32_t i, neles_thread, electr, neles_cur;
	bool created, joined;

	neles_thread = ceil_divide(context.e2ctx->dbsize, nthreads);

	for(i = 0, electr = 0; i < nthreads; i++) {

		neles_cur = min(context.e2ctx->dbsize - electr, neles_thread);
		memcpy(contexts + i, &context, sizeof(SUDO_PIR_HW_CTX));

		contexts[i].hblkid = i;

		contexts[i].e2ctx->nelements = neles_cur;
		contexts[i].e2ctx->startelements = electr;
		contexts[i].e2ctx->endelements = electr + neles_cur;

		electr += neles_cur;
	}

	for(i = 0; i < nthreads; i++) {
		created = !pthread_create(threads + i, NULL, func, (void*) &(contexts[i]));
	}

	assert(created);

	for(i = 0; i < nthreads; i++) {
		joined = !pthread_join(threads[i], NULL);
	}

	assert(joined);

	free(threads);
	free(contexts);
}


int server_preprocess(SUDO_PIR_HW_CTX * ctx, 
    uint8_t ** p_key, uint32_t * k_size, 
    uint8_t ** p_value, uint32_t * v_size,
    uint32_t db_size)
{
    if (!ctx || !p_key || !p_value || !k_size || !v_size)
    {
        return 0;
    }

    crypto * crypt_env = ctx->crypt_env;

    ctx->perm = (uint32_t*) malloc(sizeof(uint32_t) * db_size);
    crypt_env->gen_rnd_perm(ctx->perm, db_size);

    //
    uint8_t * tp_key = (uint8_t *)malloc(db_size * ctx->maskbytelen);;
    uint8_t ** tp_encv = (uint8_t **)malloc(db_size * sizeof(uint8_t *));
    uint32_t * tp_encv_len = (uint32_t *)malloc(db_size * sizeof(uint32_t));

    //
    ctx->e2ctx = (pir_task_ctx_t *)malloc(sizeof(pir_task_ctx_t));
    ctx->e2ctx->dbsize = db_size;
    ctx->e2ctx->p_key = p_key;
    ctx->e2ctx->p_ksize = k_size;
    ctx->e2ctx->p_value = p_value;
    ctx->e2ctx->p_vsize = v_size;
    ctx->e2ctx->p_enckey = tp_key;
    ctx->e2ctx->p_encvalue = tp_encv;
    ctx->e2ctx->p_encvalue_len = tp_encv_len;

    pir_run_task(ctx->ntasks, *ctx, pir_preprocess_function);

    // *p_enckey = tp_key;
    // *p_encvalue = tp_value;
    // *p_encvalue_len = tp_encv_len;

    return 1;
}

int server_gen_table(SUDO_PIR_HW_CTX * ctx)
{
    uint32_t neles = ctx->e2ctx->dbsize;
    uint8_t * hashes = ctx->e2ctx->p_enckey;
    uint32_t hashbytelen = ctx->maskbytelen;

	ctx->invperm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint64_t *tmpval, tmpkey = 0;
	//uint64_t *tmpval, *tmpkey;
	uint32_t mapbytelen = min((uint32_t)ctx->maskbytelen, (uint32_t) sizeof(uint64_t));
	uint32_t size_intersect, i, intersect_ctr;

	for(i = 0; i < neles; i++) {
		ctx->invperm[ctx->perm[i]] = i;
	}

	// g_direct_hash 
	//GHashTable *map= g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
	GHashTable *map= g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

	for(i = 0; i < neles; i++) {
		memcpy(&tmpkey, hashes + i*hashbytelen, mapbytelen);
		//tmpkey = (uint64_t *)(hashes + i*hashbytelen);
		//g_hash_table_insert(map,(void*) &tmpkey, &(invperm[i]));
		g_hash_table_insert(map, GINT_TO_POINTER(tmpkey), &(ctx->invperm[i]));
        //g_hash_table_insert(map, GINT_TO_POINTER(tmpkey), &(ctx->perm[i]));
	}

    ctx->map = map;

	return 1;
}

int server_reshuffle_table(SUDO_PIR_HW_CTX * ctx)
{
    return 0;
}

int client_gen_query(SUDO_PIR_HW_CTX * ctx, uint8_t * key, uint32_t klen, uint8_t ** enc_key, uint32_t * enc_klen)
{

    crypto * crypto_env = ctx->crypt_env;
    pir_task_ctx_t * electx = ctx->e2ctx;

    uint8_t tmphashbuf[32] = {0};

	uint8_t * salt = ctx->slt;
	uint32_t saltlen = ctx->slt_len;

    uint8_t * tenc_key = (uint8_t *)malloc(ctx->maskbytelen);

    crypto_env->hash_with_salt_hw(crypto_env->dev_mngt.hdev[0], tenc_key, ctx->maskbytelen, 
        salt, saltlen, key, klen, tmphashbuf);

    *enc_key = tenc_key;
    *enc_klen = ctx->maskbytelen;

    return 1;
}

int server_response(SUDO_PIR_HW_CTX * ctx, uint8_t * enc_key, uint32_t enc_klen, uint8_t ** enc_value, uint32_t * enc_vlen)
{
    uint32_t neles = ctx->e2ctx->dbsize;
    uint8_t * hashes = ctx->e2ctx->p_enckey;
    uint32_t hashbytelen = ctx->maskbytelen;

	uint64_t *tmpval, tmpkey = 0;
	//uint64_t *tmpval, *tmpkey;
	uint32_t mapbytelen = min((uint32_t)ctx->maskbytelen, (uint32_t) sizeof(uint64_t));
	uint32_t size_intersect, i, intersect_ctr;

    uint32_t pos = -1;

	// g_direct_hash 
	//GHashTable *map= g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
	GHashTable *map = ctx->map;

	//for(i = 0, intersect_ctr = 0; i < pneles; i++) 
    {
		memcpy(&tmpkey, enc_key, mapbytelen);

		if(g_hash_table_lookup_extended(map, GINT_TO_POINTER(tmpkey), NULL, (void**) &tmpval)) {
			pos = tmpval[0];
		}
        else{
            pos = -1;
        }
	}

    //
    if (-1 == pos)
    {
        *enc_value = NULL;
        *enc_vlen = 0;
    }
    else
    {
        uint8_t * tenc_val = (uint8_t *)malloc(ctx->e2ctx->p_encvalue_len[pos]);
        memcpy(tenc_val, ctx->e2ctx->p_encvalue[pos], ctx->e2ctx->p_encvalue_len[pos]);

        *enc_value = tenc_val;
        *enc_vlen = ctx->e2ctx->p_encvalue_len[pos];
    }

	return 1;
}

int client_getv(SUDO_PIR_HW_CTX * ctx, uint8_t * key, uint32_t klen, uint8_t * enc_value, uint32_t enc_vlen, uint8_t ** value, uint32_t * vlen)
{
    crypto * crypt_env = ctx->crypt_env;

    if (!enc_value)
    {
        return 0;
    }

    uint8_t kdk[16] = {0};
    uint32_t kdk_len = 0;
    uint8_t * dec_val = NULL;
    uint32_t val_len = 0;

    {
        crypt_env->kdf(crypt_env->dev_mngt.hdev[0], ctx->kek, ctx->kek_len, key, klen, kdk, &kdk_len);
        val_len = crypt_env->decrypt_hw(crypt_env->dev_mngt.hdev[0], kdk, &dec_val, enc_value, enc_vlen);
    }

    *value = dec_val;
    *vlen = val_len;

    return 0;
}

int teepir_done(SUDO_PIR_HW_CTX * ctx)
{
    if (!ctx) return 0;

    if (ctx->data != NULL)
    {
        free(ctx->data);
        ctx->data = NULL;
    }

    //
    if (ctx->perm != NULL)
    {
        free(ctx->perm);
        ctx->perm = NULL;
    }

    if (ctx->invperm != NULL)
    {
        free(ctx->invperm);
        ctx->invperm = NULL;
    }

    //
    if (ctx->ectx != NULL)
    {
        free(ctx->ectx);
        ctx->ectx = NULL;
    }

    if (ctx->e2ctx != NULL)
    {
        int i = 0;

        for (i = 0; i < ctx->e2ctx->dbsize; i++)
        {
            free(ctx->e2ctx->p_encvalue[i]);
        }

        free(ctx->e2ctx->p_enckey);
        free(ctx->e2ctx->p_encvalue);
        free(ctx->e2ctx->p_encvalue_len);

        free(ctx->ectx);
        ctx->ectx = NULL;
    }

    //
    if (ctx->crypt_env != NULL)
    {
        ctx->crypt_env->close_device();
        
        delete ctx->crypt_env;
        ctx->crypt_env = NULL;
    }

    if (ctx->map)
	{
		g_hash_table_remove_all(ctx->map);
		g_hash_table_destroy(ctx->map);
		ctx->map = NULL;
	}

    //
    free(ctx);
    ctx = NULL;

    return 1;
}
