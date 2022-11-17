#include "shw-pri.h"

struct sudo_shw_pri_ctx_st 
{
    role_type role;
    crypto * crypt_env;

    union {
        task_ctx * ectx;
        task_ctx2 * ectx2;
    };

    void * data;

    uint8_t entr[64];
    uint32_t maskbytelen;

    uint8_t slt[64];
    uint32_t slt_len;

    uint8_t kek[64];
    uint32_t kek_len;

    uint32_t * perm;
    uint32_t * invperm;

    int ntasks;

    //
    uint32_t intersect_size;
    uint32_t * mathches;

    //
    GHashTable * map;
};

static const uint8_t const_rng_seed[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

SUDO_SHW_PRI_CTX * shw_init(role_type role, uint8_t * nego_data, uint32_t * nego_data_len, uint32_t ntasks, bool enable_dev)
{
    int ret = 0;

    if ( !nego_data || !nego_data_len || (*nego_data_len < sizeof(cap_ecc_pubkey_t)) )
    {
        return NULL;
    }

    //
    SUDO_SHW_PRI_CTX * spri_ctx = (SUDO_SHW_PRI_CTX *)malloc(sizeof(SUDO_SHW_PRI_CTX));
    if (spri_ctx == NULL)
    {
        return NULL;
    }

    //
    memset(spri_ctx, 0, sizeof(SUDO_SHW_PRI_CTX));

    //
    spri_ctx->data = (void *)malloc(1024);
    if (spri_ctx->data == NULL)
    {
        free(spri_ctx);
        return NULL;
    }

    // default use 128 as security level
    uint32_t symsecbits = 128;
    spri_ctx->crypt_env = new crypto(symsecbits, (uint8_t*) const_rng_seed);

    spri_ctx->ntasks = ntasks;

    //
    if (enable_dev)
    {
        //ret = spri_ctx->crypt_env->open_device(1, 128);
        ret = spri_ctx->crypt_env->open_device(1, 64);
        //ret = spri_ctx->crypt_env->open_device(1, 1);
        if (0 == ret)
        {
            spri_ctx->crypt_env->close_device();
            free(spri_ctx);
            return NULL;
        }
    }
    
    //
    spri_ctx->role = role;

    //
  	cap_ecc_keypair_t * spkey = (cap_ecc_keypair_t *) spri_ctx->data;

	spri_ctx->crypt_env->sm2_gen_key(spri_ctx->crypt_env->dev_mngt.hdev[0], (uint8_t *)spkey);
    
    memcpy(nego_data, &(spkey->pubkey), sizeof(cap_ecc_pubkey_t));
    *nego_data_len = sizeof(cap_ecc_pubkey_t);

    return spri_ctx;

}

int shw_negotiate(SUDO_SHW_PRI_CTX * ctx, const uint8_t * nego_data, uint32_t nego_data_len)
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
    //derive_key(ctx);

    return 1;
}

int shw_pir_preprocess(SUDO_SHW_PRI_CTX * ctx)
{
    int ret;
    if (!ctx || !ctx->crypt_env)
    {
        return 0;
    }

    //
    //pir_derive_key(ctx);
    crypto * crypt_env = ctx->crypt_env;

    ret = crypt_env->kdf(ctx->crypt_env->dev_mngt.hdev[0], ctx->entr, 16, (uint8_t *)"pir-salt", strlen("pir-salt"), ctx->slt, &ctx->slt_len);
    if (0 == ret)
    {
        printf("error kdf salt: %08x \n", ret);
        return 0;
    }

    ret = crypt_env->kdf(ctx->crypt_env->dev_mngt.hdev[0], ctx->entr, 16, (uint8_t *)"pir-kek", strlen("pir-kek"), ctx->kek, &ctx->kek_len);
    if (0 == ret)
    {
        printf("error kdf kek: %08x \n", ret);
        return 0;
    }

    // default use
    ctx->maskbytelen = 8;

    return 1;
}

static void * shw_pir_sever_process_func(void * context) 
{
#ifdef DEBUG
	cout << "PIR preprocess thread started" << endl;
#endif
    task_ctx2 * pir_ctx = (task_ctx2 *)context;
    crypto * crypt_env = pir_ctx->sctx.symcrypt;
    element_ctx2 electx = pir_ctx->subdbase;

    uint32_t* perm = electx.perm;
	uint8_t * salt = pir_ctx->slt;
	uint32_t saltlen = pir_ctx->sltlen;

    uint8_t * key = pir_ctx->kek;
    uint32_t keylen = pir_ctx->keklen;

	if (1 != crypt_env->hw_on)
	{
		return NULL;
	}

	uint32_t i, ret;
	uint8_t* tmphashbuf = (uint8_t*) malloc(crypt_env->get_hash_bytes());

    uint8_t kdk[16] = {0};
    uint32_t kdk_len = 0;

    if(electx.keyw.hasvarbytelen_i) 
    {
        uint8_t **inptr_kw = electx.keyw.input2d;
        uint32_t *inptr_kw_len = electx.keyw.varbytelens_i;

        uint8_t *outptr_kw = electx.keyw.output1d;
        uint32_t out_kw_len = electx.keyw.fixedbytelen_o;

        for (i = electx.startelement; i < electx.endelement; i++)
        {
            
            // encrypt payload
            {
                ret = crypt_env->kdf(crypt_env->dev_mngt.hdev[pir_ctx->hblkid], key, keylen, \
                        inptr_kw[i], inptr_kw_len[i], kdk, &kdk_len);
                if (ret == 0)
                {
                    // Todo: log error
                    continue;
                }

                if (electx.value.hasvarbytelen_i)
                {
                    uint8_t **inptr_val = electx.value.input2d;
                    uint32_t *inptr_val_len = electx.value.varbytelens_i;

                    uint8_t **outptr_val = electx.value.output2d;
                    uint32_t *outptr_val_len = electx.value.varbytelens_o;

                    outptr_val_len[perm[i]] = crypt_env->encrypt_hw(crypt_env->dev_mngt.hdev[pir_ctx->hblkid], kdk, \
                            &outptr_val[perm[i]], inptr_val[i], inptr_val_len[i]);
                }
                else
                {
                    uint8_t *inptr_val = electx.value.input1d + i*electx.value.fixedbytelen_i;
                    uint32_t in_val_len = electx.value.fixedbytelen_i;

                    uint8_t *outptr_val = electx.value.output1d + perm[i]*electx.value.fixedbytelen_o;
                    uint32_t out_val_len = electx.value.fixedbytelen_o;

                    out_val_len = crypt_env->encrypt_hw(crypt_env->dev_mngt.hdev[pir_ctx->hblkid], kdk, \
                            &outptr_val, inptr_val, in_val_len);
                }

            }

            // hash key
            {
                // todo: need randomized
                crypt_env->hash_with_salt_hw(crypt_env->dev_mngt.hdev[pir_ctx->hblkid], outptr_kw+perm[i]*out_kw_len, out_kw_len, 
                    salt, saltlen, inptr_kw[i], inptr_kw_len[i], tmphashbuf);
            }
        }
    }
    else     
	{
        uint8_t *inptr_kw = electx.keyw.input1d;
        uint32_t in_kw_len = electx.keyw.fixedbytelen_i;

        uint8_t *outptr_kw = electx.keyw.output1d;
        uint32_t out_kw_len = electx.keyw.fixedbytelen_o;

        for (i = electx.startelement; i < electx.endelement; i++)
        {
            
            // encrypt payload
            {
                ret = crypt_env->kdf(crypt_env->dev_mngt.hdev[pir_ctx->hblkid], pir_ctx->kek, pir_ctx->keklen, \
                        inptr_kw + i*in_kw_len, in_kw_len, kdk, &kdk_len);
                if (ret == 0)
                {
                    // Todo: log error
                    continue;
                }

                if (electx.value.hasvarbytelen_i)
                {
                    uint8_t **inptr_val = electx.value.input2d;
                    uint32_t *inptr_val_len = electx.value.varbytelens_i;

                    uint8_t **outptr_val = electx.value.output2d;
                    uint32_t *outptr_val_len = electx.value.varbytelens_o;

                    outptr_val_len[perm[i]] = crypt_env->encrypt_hw(crypt_env->dev_mngt.hdev[pir_ctx->hblkid], kdk, \
                            &outptr_val[perm[i]], inptr_val[i], inptr_val_len[i]);
                }
                else
                {
                    uint8_t *inptr_val = electx.value.input1d + i*electx.value.fixedbytelen_i;
                    uint32_t in_val_len = electx.value.fixedbytelen_i;

                    uint8_t *outptr_val = electx.value.output1d + perm[i]*electx.value.fixedbytelen_o;
                    uint32_t out_val_len = electx.value.fixedbytelen_o;

                    out_val_len = crypt_env->encrypt_hw(crypt_env->dev_mngt.hdev[pir_ctx->hblkid], kdk, \
                            &outptr_val, inptr_val, in_val_len);
                }

            }

            // hash key
            {
                // todo: need randomized
                crypt_env->hash_with_salt_hw(crypt_env->dev_mngt.hdev[pir_ctx->hblkid], outptr_kw+perm[i]*out_kw_len, out_kw_len, 
                    salt, saltlen, inptr_kw + i*in_kw_len, in_kw_len, tmphashbuf);
            }
        }
	}

	//
	free(tmphashbuf);
	return 0;
}

// temperory function
static void shw_pir_server_run_task(uint32_t nthreads, task_ctx2 context, void* (*func)(void*) ) 
{
    crypto * crypt = context.sctx.symcrypt;
	if (crypt->hw_on)
	{
		nthreads = crypt->dev_mngt.thread_num;
	}
	
	task_ctx2* contexts = (task_ctx2*) malloc(sizeof(task_ctx2) * nthreads);
	pthread_t* threads = (pthread_t*) malloc(sizeof(pthread_t) * nthreads);
	uint32_t i, neles_thread, electr, neles_cur;
	bool created, joined;

	neles_thread = ceil_divide(context.subdbase.nelements, nthreads);

	for(i = 0, electr = 0; i < nthreads; i++) {

        neles_cur = min(context.subdbase.nelements - electr, neles_thread);
		memcpy(contexts + i, &context, sizeof(task_ctx2));

		contexts[i].hblkid = i;

        contexts[i].subdbase.nelements = neles_cur;
        contexts[i].subdbase.startelement = electr;
        contexts[i].subdbase.endelement = electr + neles_cur;

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

static int shw_pir_server_gen_hashmap(SUDO_SHW_PRI_CTX * ctx)
{
    int i;
    task_ctx2 * ectx = ctx->ectx2;

    uint32_t neles = ectx->subdbase.nelements;
    uint8_t * hashes = ectx->subdbase.keyw.output1d;
    uint32_t hashbytelen = ectx->subdbase.keyw.fixedbytelen_o;

	ctx->invperm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
    if (ctx->invperm == NULL)
    {
        return 0;
    }

	uint64_t *tmpval, tmpkey = 0;
	uint32_t mapbytelen = min((uint32_t)ctx->maskbytelen, (uint32_t) sizeof(uint64_t));

	for(i = 0; i < neles; i++) 
    {
		ctx->invperm[i] = i;
	}

	// g_direct_hash 
	GHashTable * map= g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

	for(i = 0; i < neles; i++) 
    {
		memcpy(&tmpkey, hashes + i*hashbytelen, mapbytelen);
        g_hash_table_insert(map, GINT_TO_POINTER(tmpkey), &(ctx->invperm[i]));
	}

    //
    ctx->map = map;

	return 1;
}

int shw_pir_server_reshuffle_table(SUDO_SHW_PRI_CTX * ctx)
{
    return 0;
}

int shw_pir_server_gen_table(
    SUDO_SHW_PRI_CTX * ctx, 
    uint8_t ** ptr_keyw, uint32_t * kw_size, 
    uint8_t ** ptr_val, uint32_t * val_size,
    uint32_t db_size
){
    int ret;
    if (!ctx || !ptr_keyw || !ptr_val || !kw_size || !val_size)
    {
        return 0;
    }

    crypto * crypt_env = ctx->crypt_env;

    ctx->perm = (uint32_t*) malloc(sizeof(uint32_t) * db_size);
    crypt_env->gen_rnd_perm(ctx->perm, db_size);

    // default use
    ctx->maskbytelen = 8;

    //
    uint8_t * tp_enckeyw = (uint8_t *)malloc(db_size * ctx->maskbytelen);;    
    uint8_t ** tp_encval = (uint8_t **)malloc(db_size * sizeof(uint8_t *));
    uint32_t * tp_encval_len = (uint32_t *)malloc(db_size * sizeof(uint32_t));

    memset(tp_enckeyw, 0, db_size * ctx->maskbytelen);
    memset(tp_encval, 0, db_size * sizeof(uint8_t *));
    memset(tp_encval_len, 0, db_size * sizeof(uint32_t));

    //
    task_ctx2 * ectx = (task_ctx2 *)malloc(sizeof(task_ctx2));
    if (!ectx)
    {
        return 0;
    }

    //
    ectx->sctx.symcrypt = crypt_env;
    ectx->subdbase.nelements = db_size;

    ectx->subdbase.keyw.hasvarbytelen_i = true;
    ectx->subdbase.keyw.input2d = ptr_keyw;
    ectx->subdbase.keyw.varbytelens_i = kw_size;
    ectx->subdbase.keyw.getvarbytelen_o = false;
    ectx->subdbase.keyw.output1d = tp_enckeyw;
    ectx->subdbase.keyw.fixedbytelen_o = ctx->maskbytelen;

    ectx->subdbase.value.hasvarbytelen_i = true;
    ectx->subdbase.value.input2d = ptr_val;
    ectx->subdbase.value.varbytelens_i = val_size;
    ectx->subdbase.value.getvarbytelen_o = true;
    ectx->subdbase.value.output2d = tp_encval;
    ectx->subdbase.value.varbytelens_o = tp_encval_len;

    ectx->subdbase.perm = ctx->perm;
    ectx->slt = ctx->slt;
    ectx->sltlen = ctx->slt_len;
    ectx->kek = ctx->kek;
    ectx->keklen = ctx->kek_len;
    
    ctx->ectx2 = ectx;

    shw_pir_server_run_task(ctx->ntasks, *ectx, shw_pir_sever_process_func);

    //
    memset(ctx->perm, 0, db_size * sizeof(uint32_t));
    free(ctx->perm);
    ctx->perm = NULL;

    //
    ret = shw_pir_server_gen_hashmap(ctx);

    //
    return 1;
}

int shw_pir_client_gen_query(
    SUDO_SHW_PRI_CTX * ctx, 
    uint8_t * keyw, uint32_t kwlen, 
    uint8_t ** ptr_enc_keyw, uint32_t * enc_kwlen
){
    int ret;
    crypto * crypto_env = ctx->crypt_env;

    uint8_t * tmphashbuf = (uint8_t *)malloc(crypto_env->get_hash_bytes() * sizeof(uint8_t));
    if (!tmphashbuf)
    {
        return 0;
    }

	uint8_t * salt = ctx->slt;
	uint32_t saltlen = ctx->slt_len;

    uint8_t * tenc_keyw = (uint8_t *)malloc(ctx->maskbytelen);

    ret = crypto_env->hash_with_salt_hw(crypto_env->dev_mngt.hdev[0], tenc_keyw, ctx->maskbytelen, 
        salt, saltlen, keyw, kwlen, tmphashbuf);

    *ptr_enc_keyw = tenc_keyw;
    *enc_kwlen = ctx->maskbytelen;

    free(tmphashbuf);

    return 1;
}

int shw_pir_server_response(
    SUDO_SHW_PRI_CTX * ctx, 
    uint8_t * ptr_enc_keyw, uint32_t enc_kwlen, 
    uint8_t ** ptr_enc_value, uint32_t * enc_vlen
){
    task_ctx2 * ectx = ctx->ectx2;
    uint32_t neles = ectx->subdbase.nelements;
    uint8_t * hashes = ectx->subdbase.keyw.output1d;
    uint32_t hashbytelen = ectx->subdbase.keyw.fixedbytelen_o;

	uint64_t *tmpval, tmpkey = 0;
	uint32_t mapbytelen = min((uint32_t)ctx->maskbytelen, (uint32_t) sizeof(uint64_t));

    //
    uint32_t pos = -1;

	// g_direct_hash 
	GHashTable * map = ctx->map;

	//
    {
		memcpy(&tmpkey, ptr_enc_keyw, mapbytelen);

		if(g_hash_table_lookup_extended(map, GINT_TO_POINTER(tmpkey), NULL, (void**)&tmpval)) {
			pos = tmpval[0];
		}
        else{
            pos = -1;
        }
	}

    //
    if (-1 == pos)
    {
        *ptr_enc_value = NULL;
        *enc_vlen = 0;
    }
    else
    {
        uint32_t vlen = ectx->subdbase.value.varbytelens_o[pos];
        uint8_t * ptr_v = ectx->subdbase.value.output2d[pos];

        uint8_t * tenc_val = (uint8_t *)malloc(vlen * sizeof(uint8_t));
        memcpy(tenc_val, ptr_v, vlen);

        *ptr_enc_value = tenc_val;
        *enc_vlen = vlen;
    }

	return 1;
}

int shw_pir_client_getv(
    SUDO_SHW_PRI_CTX * ctx, 
    uint8_t * ptr_keyw, uint32_t kwlen, 
    uint8_t * ptr_enc_value, uint32_t enc_vlen, 
    uint8_t ** ptr_value, uint32_t * vlen
){
    int ret;
    crypto * crypt_env = ctx->crypt_env;

    if (!ptr_keyw || !ptr_enc_value)
    {
        return 0;
    }

    uint8_t kdk[16] = {0};
    uint32_t kdk_len = 0;
    uint8_t * dec_val = NULL;
    uint32_t val_len = 0;

    {
        ret = crypt_env->kdf(crypt_env->dev_mngt.hdev[0], ctx->kek, ctx->kek_len, ptr_keyw, kwlen, kdk, &kdk_len);
        val_len = crypt_env->decrypt_hw(crypt_env->dev_mngt.hdev[0], kdk, &dec_val, ptr_enc_value, enc_vlen);
    }

    *ptr_value = dec_val;
    *vlen = val_len;

    return 0;
}

int shw_pir_done(SUDO_SHW_PRI_CTX * ctx)
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
    if (ctx->ectx2 != NULL)
    {
        int i = 0;
        uint32_t dbsize = ctx->ectx2->subdbase.nelements;

        for (i = 0; i < dbsize; i++)
        {
            free(ctx->ectx2->subdbase.value.output2d[i]);
        }

        free(ctx->ectx2->subdbase.keyw.output1d);
        free(ctx->ectx2->subdbase.value.output2d);
        free(ctx->ectx2->subdbase.value.varbytelens_o);

        free(ctx->ectx2);
        ctx->ectx2 = NULL;
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

//--------------------------------------------------------------------

int shw_psi_preprocess(SUDO_SHW_PRI_CTX * ctx)
{
    int ret;
    if (!ctx || !ctx->crypt_env)
    {
        return 0;
    }

    //
    crypto * crypt_env = ctx->crypt_env;

    ret = crypt_env->kdf(ctx->crypt_env->dev_mngt.hdev[0], ctx->entr, 16, (uint8_t *)"psi-salt", strlen("psi-salt"), ctx->slt, &ctx->slt_len);
    if (0 == ret)
    {
        return 0;
    }

    // default use
    ctx->maskbytelen = 8;

    return 1;
}

static void *shw_psi_hashing_process_func(void* context) {
#ifdef DEBUG
	cout << "Hashing thread started" << endl;
#endif
    task_ctx2 * psi_ctx = (task_ctx2 *)context;
    crypto * crypt_env = psi_ctx->sctx.symcrypt;
    element_ctx electx = psi_ctx->eles;

	uint8_t * salt = psi_ctx->slt;
	uint32_t saltlen = psi_ctx->sltlen;

	if (1 != crypt_env->hw_on)
	{
		return NULL;
	}

	uint32_t i;
	uint32_t* perm = electx.perm;
	uint8_t* tmphashbuf = (uint8_t*) malloc(crypt_env->get_hash_bytes());

	{
		if(electx.hasvarbytelen) {
			uint8_t **inptr = electx.input2d;
			for(i = electx.startelement; i < electx.endelement; i++) {
				crypt_env->hash_with_salt_hw(crypt_env->dev_mngt.hdev[psi_ctx->hblkid], electx.output+perm[i]*electx.outbytelen, electx.outbytelen, 
					salt, saltlen, inptr[i], electx.varbytelens[i], tmphashbuf);
			}
		} else {
			uint8_t *inptr = electx.input1d;
			for(i = electx.startelement; i < electx.endelement; i++, inptr+=electx.fixedbytelen) {
				crypt_env->hash_with_salt_hw(crypt_env->dev_mngt.hdev[psi_ctx->hblkid], electx.output+perm[i]*electx.outbytelen, electx.outbytelen, 
					salt, saltlen, inptr, electx.fixedbytelen, tmphashbuf);
			}
		}
	}

	//
	free(tmphashbuf);
	return 0;
}

// temperory function
static void shw_psi_run_task(uint32_t nthreads, task_ctx2 context, void* (*func)(void*) ) 
{
    crypto * crypt = context.sctx.symcrypt;
	if (crypt->hw_on)
	{
		nthreads = crypt->dev_mngt.thread_num;
	}
	
	task_ctx2* contexts = (task_ctx2*) malloc(sizeof(task_ctx2) * nthreads);
	pthread_t* threads = (pthread_t*) malloc(sizeof(pthread_t) * nthreads);
	uint32_t i, neles_thread, electr, neles_cur;
	bool created, joined;

	neles_thread = ceil_divide(context.eles.nelements, nthreads);

	for(i = 0, electr = 0; i < nthreads; i++) {

        neles_cur = min(context.eles.nelements - electr, neles_thread);
		memcpy(contexts + i, &context, sizeof(task_ctx2));

		contexts[i].hblkid = i;

        contexts[i].eles.nelements = neles_cur;
        contexts[i].eles.startelement = electr;
        contexts[i].eles.endelement = electr + neles_cur;

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

int shw_psi_calc(
    SUDO_SHW_PRI_CTX * ctx, 
    uint32_t neles, uint32_t pneles, 
    uint32_t * elebytelens, uint8_t ** elements, 
    uint8_t * result, uint32_t result_len
){
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
    task_ctx2 * ectx = (task_ctx2 *)malloc(sizeof(task_ctx2));
    if (!ectx)
    {
        return 0;
    }

    //
	ectx->eles.nelements = neles;
	ectx->eles.hasvarbytelen = true;
	ectx->eles.input2d = elements;
	ectx->eles.varbytelens = elebytelens;
	ectx->eles.output = hashes;
	ectx->eles.outbytelen = maskbytelen_t,

	ectx->eles.perm = ctx->perm;
	ectx->sctx.symcrypt = crypt_env;
    ectx->slt = ctx->slt;
    ectx->sltlen = ctx->slt_len;

    ctx->ectx2 = ectx;

    //
    shw_psi_run_task(ctx->ntasks, *ectx, shw_psi_hashing_process_func);

    return 1;
}

int shw_psi_find_intersection(
    SUDO_SHW_PRI_CTX * ctx, 
    const uint8_t* hashes, uint32_t neles, 
    const uint8_t* phashes, uint32_t pneles, 
    const uint32_t * elebytelens, const uint8_t ** elements, 
    uint8_t*** result, uint32_t** resbytelens
){
    uint32_t intersect_size;
    uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * min(neles, pneles));

    intersect_size = find_intersection((uint8_t *)hashes, neles, (uint8_t *)phashes, pneles, ctx->maskbytelen, ctx->perm, matches);

	if(ctx->role == CLIENT) 
	{
		create_result_from_matches_var_bitlen(result, resbytelens, (uint32_t *)elebytelens, (uint8_t **)elements, matches, intersect_size);
	}

    //
	free(matches);
    matches = NULL;
    
    //
    return intersect_size;
}

int shw_psi_find_intersection_index(
    SUDO_SHW_PRI_CTX * ctx, 
    const uint8_t* hashes, uint32_t neles, 
    const uint8_t* phashes, uint32_t pneles, 
    uint32_t* matches_index
){
    uint32_t intersect_size;

    intersect_size = find_intersection((uint8_t *)hashes, neles, (uint8_t *)phashes, pneles, ctx->maskbytelen, ctx->perm, matches_index);

    //
    return intersect_size;
}

int shw_psi_done(SUDO_SHW_PRI_CTX * ctx)
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


