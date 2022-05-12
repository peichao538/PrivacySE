#include "hashing_util.h"

typedef struct hash_entry_gen_ctx
{

    uint8_t **eleptr;
    uint32_t *elebytelens;

    uint32_t resultbytelen;
    uint8_t *resultptr;

    uint32_t startpos;
    uint32_t endpos;

    crypto *crypt;

} heg_ctx;

void domain_hashing(uint32_t nelements, uint8_t **elements, uint32_t *elebytelens, uint8_t *result,
                    uint32_t resultbytelen, crypto *crypt, uint32_t nhash_tasks)
{
    uint8_t *resultptr = NULL;
    uint32_t i, j;
    heg_ctx *ctx = NULL;
    pthread_t *entry_gen_hash_tasks = NULL;

    resultptr = result;
#ifndef BATCH
    cout << "Hashing " << nelements << " elements with arbitrary length into into " << resultbytelen << " bytes" << endl;
#endif

    entry_gen_hash_tasks = (pthread_t *)malloc(sizeof(pthread_t) * nhash_tasks);
    ctx = (heg_ctx *)malloc(sizeof(heg_ctx) * nhash_tasks);

    for (i = 0; i < nhash_tasks; i++)
    {
        ctx[i].eleptr = elements;
        ctx[i].elebytelens = elebytelens;
        ctx[i].resultbytelen = resultbytelen;
        ctx[i].resultptr = resultptr;
        ctx[i].startpos = i * ceil_divide(nelements, nhash_tasks);
        ctx[i].endpos = min(ctx[i].startpos + ceil_divide(nelements, nhash_tasks), nelements);
        ctx[i].crypt = crypt;

        // cout << "Thread " << i << " starting from " << ctx[i].startpos << " going to " << ctx[i].endpos << " for " << neles << " elements" << endl;
        if (pthread_create(entry_gen_hash_tasks + i, NULL, gen_hash_routine, (void *)(ctx + i)))
        {
            cerr << "Error in creating new pthread at simple hashing!" << endl;
            exit(0);
        }
    }

    for (i = 0; i < nhash_tasks; i++)
    {
        if (pthread_join(entry_gen_hash_tasks[i], NULL))
        {
            cerr << "Error in joining pthread at elements hashing!" << endl;
            exit(0);
        }
    }

    free(ctx);
    free(entry_gen_hash_tasks);
}

void *gen_hash_routine(void * ctx_tmp)
{
    uint32_t i, j, resultbytelen;

    uint8_t ** elements = NULL, * resultptr = NULL;
    uint32_t * elebytelens = NULL;
    heg_ctx* ctx = (heg_ctx*) ctx_tmp;

    //
    elements = ctx->eleptr;
    elebytelens = ctx->elebytelens;
    resultbytelen = ctx->resultbytelen;
    resultptr = ctx->resultptr + ctx->resultbytelen * ctx->startpos;
    // hash_buf = (uint8_t*) calloc(crypt->get_hash_bytes(), sizeof(uint8_t));
    for (i = ctx->startpos; i < ctx->endpos; i++, resultptr += ctx->resultbytelen)
    {

        ctx->crypt->hash(resultptr, ctx->resultbytelen, elements[i], elebytelens[i]);

#define PRINT_DOMAIN_HASHING
#ifdef PRINT_DOMAIN_HASHING
        cout << "Hash for element " << i << " ";
        for (j = 0; j < elebytelens[i]; j++)
        {
            cout << elements[i][j];
        }
        cout << ": ";
        for (j = 0; j < resultbytelen; j++)
        {
            cout << (hex) << (uint32_t)resultptr[j] << (dec);
        }
        cout << endl;
#endif
#undef PRINT_DOMAIN_HASHING
    }

    return NULL;
}
