/*
 * crypto.cpp
 *
 *  Created on: Jul 9, 2014
 *      Author: mzohner
 */


#include "crypto.h"

crypto::crypto(uint32_t symsecbits, uint8_t* seed) {
	init(symsecbits, seed);
}

crypto::crypto(uint32_t symsecbits) {
	uint8_t* seed = (uint8_t*) malloc(sizeof(uint8_t) * AES_BYTES);
	gen_secure_random(seed, AES_BYTES);

	init(symsecbits, seed);
	free(seed);
}

crypto::~crypto() {
	free_prf_state(&global_prf_state);
	free(aes_hash_in_buf);
	free(aes_hash_out_buf);
	free(sha_hash_buf);
	free(aes_hash_buf_y1);
	free(aes_hash_buf_y2);

#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	clean_aes_key(&aes_hash_key);
	clean_aes_key(&aes_enc_key);
	clean_aes_key(&aes_dec_key);
#endif
}


void crypto::init(uint32_t symsecbits, uint8_t* seed) {
	secparam = get_sec_lvl(symsecbits);

#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	aes_hash_key = EVP_CIPHER_CTX_new();
	aes_enc_key = EVP_CIPHER_CTX_new();
	aes_dec_key = EVP_CIPHER_CTX_new();
#endif

	init_prf_state(&global_prf_state, seed);

	aes_hash_in_buf = (uint8_t*) malloc(AES_BYTES);
	aes_hash_out_buf = (uint8_t*) malloc(AES_BYTES);
	aes_hash_buf_y1 = (uint8_t*) malloc(AES_BYTES);
	aes_hash_buf_y2 = (uint8_t*) malloc(AES_BYTES);

	if (secparam.symbits == ST.symbits) {
		hash_routine = &sha1_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA1_OUT_BYTES);
	} else if (secparam.symbits == MT.symbits) {
		hash_routine = &sha256_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA256_OUT_BYTES);
	} else if (secparam.symbits == LT.symbits) {
		hash_routine = &sha256_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA256_OUT_BYTES);
	} else if (secparam.symbits == XLT.symbits) {
		hash_routine = &sha512_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA512_OUT_BYTES);
	} else if (secparam.symbits == XXLT.symbits) {
		hash_routine = &sha512_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA512_OUT_BYTES);
	} else {
		hash_routine = &sha256_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA256_OUT_BYTES);
	}
}

pk_crypto* crypto::gen_field(field_type ftype) {
	uint8_t* pkseed = (uint8_t*) malloc(sizeof(uint8_t) * (secparam.symbits >> 3));
	gen_rnd(pkseed, secparam.symbits>>3);
	pk_crypto* ret;
	if (ftype == P_FIELD)
		ret = new prime_field(secparam, pkseed);
	else
		ret = new ecc_field(secparam, pkseed);
	free(pkseed);
	return ret;
}

void gen_rnd_bytes(prf_state_ctx* prf_state, uint8_t* resbuf, uint32_t nbytes) {
	AES_KEY_CTX* aes_key;
	uint64_t* rndctr;
	uint8_t* tmpbuf;
	uint32_t i, size;
	int32_t dummy;

	aes_key = &(prf_state->aes_key);
	rndctr = prf_state->ctr;
	size = ceil_divide(nbytes, AES_BYTES);
	tmpbuf = (uint8_t*) malloc(sizeof(uint8_t) * size * AES_BYTES);

	//TODO it might be better to store the result directly in resbuf but this would require the invoking routine to pad it to a multiple of AES_BYTES
	for(i = 0; i < size; i++, rndctr[0]++)	{
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
		EVP_EncryptUpdate(*aes_key, tmpbuf + i * AES_BYTES, &dummy, (uint8_t*) rndctr, AES_BYTES);
#else
		EVP_EncryptUpdate(aes_key, tmpbuf + i * AES_BYTES, &dummy, (uint8_t*) rndctr, AES_BYTES);
#endif
	}

	memcpy(resbuf, tmpbuf, nbytes);

	free(tmpbuf);
}

void crypto::gen_rnd(uint8_t* resbuf, uint32_t nbytes) {
	std::lock_guard<std::mutex> lock(global_prf_state_mutex);
	gen_rnd_bytes(&global_prf_state, resbuf, nbytes);
}

#ifdef AES256_HASH
void gen_rnd_bytes_pipelined(prf_state_ctx* prf_state, uint8_t* resbuf, uint32_t nbytes) {
	//Do as many pipelined iterations as fit into the AES buffer
	uint64_t aes_iters_pipe = nbytes/AES_BYTES;
	intrin_sequential_gen_rnd8_ks1(*(prf_state->ctr), resbuf, aes_iters_pipe, &(prf_state->aes_pipe_key));
	*(prf_state->ctr) += aes_iters_pipe;

	//Use the standard method for the remaining bytes
	uint32_t resnbytes = nbytes - (aes_iters_pipe * AES_BYTES);
	if(resnbytes > 0) {
		gen_rnd_bytes(prf_state, resbuf+(aes_iters_pipe * AES_BYTES), resnbytes);
	}
}

void crypto::gen_rnd_pipelined(uint8_t* resbuf, uint32_t numbytes) {
	gen_rnd_bytes_pipelined(&global_prf_state, resbuf, numbytes);
}
#endif

void crypto::gen_rnd_uniform(uint8_t* res, uint64_t mod) {
	//pad to multiple of 4 bytes for uint32_t length
	uint32_t nrndbytes = pad_to_multiple(ceil_divide(secparam.symbits, 8) + ceil_log2(mod), sizeof(uint32_t));
	uint64_t bitsint = (8*sizeof(uint32_t));
	uint32_t rnditers = ceil_divide(nrndbytes * 8, bitsint);

	uint32_t* rndbuf = (uint32_t*) malloc(nrndbytes);
	gen_rnd((uint8_t*) rndbuf, nrndbytes);

	uint64_t tmpval = 0, tmpmod = mod;

	for(uint32_t i = 0; i < rnditers; i++) {
		tmpval = (((uint64_t) (tmpval << bitsint)) | ((uint64_t)rndbuf[i]));
		tmpval %= tmpmod;
	}
	*res = (uint32_t) tmpval;
	free(rndbuf);
}

void crypto::encrypt(AES_KEY_CTX* enc_key, uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes) {
	int32_t dummy;
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	EVP_EncryptUpdate(*enc_key, resbuf, &dummy, inbuf, ninbytes);
	EVP_EncryptFinal_ex(*enc_key, resbuf, &dummy);
#else
	EVP_EncryptUpdate(enc_key, resbuf, &dummy, inbuf, ninbytes);
	EVP_EncryptFinal_ex(enc_key, resbuf, &dummy);
#endif
}
void crypto::decrypt(AES_KEY_CTX* dec_key, uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes) {
	int32_t dummy;
	//cout << "inbuf = " << (hex) << ((uint64_t*) inbuf)[0] << ((uint64_t*) inbuf)[1] << (dec) << endl;
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	EVP_DecryptUpdate(*dec_key, resbuf, &dummy, inbuf, ninbytes);
	EVP_DecryptFinal_ex(*dec_key, resbuf, &dummy);
#else
	EVP_DecryptUpdate(dec_key, resbuf, &dummy, inbuf, ninbytes);
	EVP_DecryptFinal_ex(dec_key, resbuf, &dummy);
#endif
	//cout << "outbuf = " << (hex) << ((uint64_t*) resbuf)[0] << ((uint64_t*) resbuf)[1] << (dec) << " (" << dummy << ")" << endl;
}

void crypto::encrypt(uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes) {
	encrypt(&aes_enc_key, resbuf, inbuf, ninbytes);
}


void crypto::decrypt(uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes) {
	decrypt(&aes_dec_key, resbuf, inbuf, ninbytes);
}

void crypto::seed_aes_hash(uint8_t* seed, bc_mode mode, const uint8_t* iv) {
	seed_aes_key(&aes_hash_key, seed, mode, iv);
}

void crypto::seed_aes_enc(uint8_t* seed, bc_mode mode, const uint8_t* iv) {
	seed_aes_key(&aes_enc_key, seed, mode, iv, true);
	seed_aes_key(&aes_dec_key, seed, mode, iv, false);
}

void crypto::init_aes_key(AES_KEY_CTX* aes_key, uint8_t* seed, bc_mode mode, const uint8_t* iv) {
	seed_aes_key(aes_key, seed, mode, iv);
}

void crypto::init_aes_key(AES_KEY_CTX* aes_key, uint32_t symbits, uint8_t* seed, bc_mode mode, const uint8_t* iv) {
	seed_aes_key(aes_key, symbits, seed, mode, iv);
}

void crypto::clean_aes_key(AES_KEY_CTX* aeskey) {
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	EVP_CIPHER_CTX_free(*aeskey);
#else
	EVP_CIPHER_CTX_cleanup(aeskey);
#endif
}


void crypto::seed_aes_key(AES_KEY_CTX* aeskey, uint8_t* seed, bc_mode mode, const uint8_t* iv, bool encrypt) {
	seed_aes_key(aeskey, secparam.symbits, seed, mode, iv, encrypt);
}


void crypto::seed_aes_key(AES_KEY_CTX* aeskey, uint32_t symbits, uint8_t* seed, bc_mode mode, const uint8_t* iv, bool encrypt) {
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	*aeskey = EVP_CIPHER_CTX_new();
	AES_KEY_CTX aes_key_tmp = *aeskey;
#else
	EVP_CIPHER_CTX_init(aeskey);
	AES_KEY_CTX* aes_key_tmp = aeskey;
#endif

	int (*initfct)(EVP_CIPHER_CTX*,const EVP_CIPHER*, ENGINE*,
			const unsigned char*, const unsigned char*);

	if(encrypt)
		initfct = EVP_EncryptInit_ex;
	else
		initfct = EVP_DecryptInit_ex;

	switch (mode) {
	case ECB:
		if(symbits <= 128) {
			initfct(aes_key_tmp, EVP_aes_128_ecb(), NULL, seed, iv);
		} else {
			initfct(aes_key_tmp, EVP_aes_256_ecb(), NULL, seed, iv);
		}
		break;
	case CBC: //ECB_ENC
		if(symbits <= 128) {
			initfct(aes_key_tmp, EVP_aes_128_cbc(), NULL, seed, iv);
		} else {
			initfct(aes_key_tmp, EVP_aes_256_cbc(), NULL, seed, iv);
		}
		break;
	default:
		if(symbits <= 128) {
			initfct(aes_key_tmp, EVP_aes_128_ecb(), NULL, seed, iv);
		} else {
			initfct(aes_key_tmp, EVP_aes_256_ecb(), NULL, seed, iv);
		}
		break;
	}
}



void crypto::hash_ctr(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint64_t ctr) {
	uint8_t* tmpbuf = (uint8_t*) malloc(ninbytes + sizeof(uint64_t));
	memcpy(tmpbuf, &ctr, sizeof(uint64_t));
	memcpy(tmpbuf + sizeof(uint64_t), inbuf, ninbytes);
	hash_routine(resbuf, noutbytes, tmpbuf, ninbytes+sizeof(uint64_t), sha_hash_buf);
	free(tmpbuf);
}


void crypto::hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes) {
	hash_routine(resbuf, noutbytes, inbuf, ninbytes, sha_hash_buf);
}

void crypto::hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint8_t* tmpbuf) {
	hash_routine(resbuf, noutbytes, inbuf, ninbytes, tmpbuf);
}

void crypto::hash_hw(void * hdev, uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes) {

	cap_hash_ctx_t cap_hash_ctx;
	uint32_t hash_len;

	cap_hash_ctx.hdev = hdev;
	cap_hash_ctx.sess.mode = CAP_SYNC_MODE;

	cap_hash_onetime(&cap_hash_ctx, CAP_MD_SM3, NULL, NULL, 0, inbuf, ninbytes, sha_hash_buf, &hash_len);
    memcpy(resbuf, sha_hash_buf, noutbytes);
}

//A fixed-key hashing scheme that uses AES, should not be used for real hashing, hashes to AES_BYTES bytes
void crypto::fixed_key_aes_hash(AES_KEY_CTX* aes_key, uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes) {
	uint32_t i;
	int32_t dummy;

	//assert(aes_hash_key != NULL);

	memset(aes_hash_in_buf, 0, AES_BYTES);
	memcpy(aes_hash_in_buf, inbuf, ninbytes);

	//two encryption iterations TODO: not secure since both blocks are treated independently, implement DM or MMO
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	EVP_EncryptUpdate(*aes_key, aes_hash_out_buf, &dummy, aes_hash_in_buf, AES_BYTES);
#else
	EVP_EncryptUpdate(aes_key, aes_hash_out_buf, &dummy, aes_hash_in_buf, AES_BYTES);
#endif
	((uint64_t*) aes_hash_out_buf)[0] ^= ((uint64_t*) aes_hash_in_buf)[0];
	((uint64_t*) aes_hash_out_buf)[1] ^= ((uint64_t*) aes_hash_in_buf)[1];

	memcpy(resbuf, aes_hash_out_buf, noutbytes);
}

//An aes hashing scheme that takes as input a counter and an aes-key-struct, should not be used for real hashing
void crypto::aes_cbc_hash(AES_KEY_CTX* aes_key, uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes) {
	uint32_t i;
	int32_t dummy;

#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	EVP_EncryptUpdate(*aes_key, resbuf, &dummy, inbuf, ninbytes);
#else
	EVP_EncryptUpdate(aes_key, resbuf, &dummy, inbuf, ninbytes);
#endif

	//TODO: optimized for faster PSI, input is always size of 32-bytes
	for(i = 0; i < ninbytes/AES_BYTES; i++) {
		((uint64_t*) resbuf)[0] ^= ((uint64_t*) inbuf)[2*i];
		((uint64_t*) resbuf)[1] ^= ((uint64_t*) inbuf)[2*i+1];
	}
	//for(i = 0; i < ninbytes; i++) {
	//	resbuf[i] ^= inbuf[i];
	//}
}

//Generate a random permutation of neles elements using Knuths algorithm
void crypto::gen_rnd_perm(uint32_t* perm, uint32_t neles) {
	uint32_t* rndbuf = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint32_t i, j;
	//TODO Generate random numbers (CAREFUL: NOT UNIFORM)
	gen_rnd((uint8_t*) rndbuf, sizeof(uint32_t) * neles);
	for(i = 0; i < neles; i++) {
		perm[i] = i;
	}
	for(i = 0; i < neles; i++) {
		j = rndbuf[i] % neles; //NOT UNIFORM
		swap(perm[i], perm[j]);
	}
	free(rndbuf);
}

uint32_t crypto::get_aes_key_bytes() {
	if(secparam.symbits == ST.symbits) return 16;
	else if(secparam.symbits == MT.symbits) return 16;
	else if(secparam.symbits == LT.symbits) return 16;
	else if(secparam.symbits == XLT.symbits) return 24;
	else if(secparam.symbits == XXLT.symbits) return 32;
	else return 64;
}

uint32_t crypto::get_hash_bytes() {
	if(secparam.symbits == ST.symbits) return 20;
	else if(secparam.symbits == MT.symbits) return 32;
	else if(secparam.symbits == LT.symbits) return 32;
	else if(secparam.symbits == XLT.symbits) return 64;
	else if(secparam.symbits == XXLT.symbits) return 64;
	else return 64;
}

//Generate a common seed, is only secure in the semi-honest model
void crypto::gen_common_seed(prf_state_ctx* prf_state, CSocket& sock) {
	uint8_t *seed_buf, *seed_rcv_buf;
	uint32_t seed_bytes, i;

	seed_bytes = get_aes_key_bytes();
	seed_buf = (uint8_t*) malloc(seed_bytes);
	seed_rcv_buf = (uint8_t*) malloc(seed_bytes);

	//randomly generate and exchange seed bytes:
	gen_rnd(seed_buf, seed_bytes);
	sock.Send(seed_buf, seed_bytes);
	sock.Receive(seed_rcv_buf, seed_bytes);

	//xor both seeds
	for(i = 0; i < seed_bytes; i++) {
		seed_buf[i] ^= seed_rcv_buf[i];
	}

	init_prf_state(prf_state, seed_buf);

	free(seed_buf);
	free(seed_rcv_buf);
}

void crypto::init_prf_state(prf_state_ctx* prf_state, uint8_t* seed) {
	seed_aes_key(&(prf_state->aes_key), seed);
#ifdef AES256_HASH
	intrin_sequential_ks4(&(prf_state->aes_pipe_key), seed, 1);
#endif
	prf_state->ctr = (uint64_t*) calloc(ceil_divide(secparam.symbits, 8*sizeof(uint64_t)), sizeof(uint64_t));
}

void crypto::free_prf_state(prf_state_ctx* prf_state) {
	free(prf_state->ctr);
	clean_aes_key(&(prf_state->aes_key));
}


#define MAX_DEV_NUM 66
char *cap_dev_name[MAX_DEV_NUM] = 
{
    "rsp_dev_01", "rsp_dev_02", "rsp_dev_03", "rsp_dev_04", "rsp_dev_05", "rsp_dev_06", "rsp_dev_07", "rsp_dev_08",
    "rsp_dev_09", "rsp_dev_10", "rsp_dev_11", "rsp_dev_12", "rsp_dev_13", "rsp_dev_14", "rsp_dev_15", "rsp_dev_16",
    "rsp_dev_17", "rsp_dev_18", "rsp_dev_19", "rsp_dev_20", "rsp_dev_21", "rsp_dev_22", "rsp_dev_23", "rsp_dev_24",
    "rsp_dev_25", "rsp_dev_26", "rsp_dev_27", "rsp_dev_28", "rsp_dev_29", "rsp_dev_30", "rsp_dev_31", "rsp_dev_32",
    "rsp_dev_33", "rsp_dev_34", "rsp_dev_35", "rsp_dev_36", "rsp_dev_37", "rsp_dev_38", "rsp_dev_39", "rsp_dev_40", 
    "rsp_dev_41", "rsp_dev_42", "rsp_dev_43", "rsp_dev_44", "rsp_dev_45", "rsp_dev_46", "rsp_dev_47", "rsp_dev_48", 
    "rsp_dev_49", "rsp_dev_50", "rsp_dev_51", "rsp_dev_52", "rsp_dev_53", "rsp_dev_54", "rsp_dev_55", "rsp_dev_56", 
    "rsp_dev_57", "rsp_dev_58", "rsp_dev_59", "rsp_dev_60", "rsp_dev_61", "rsp_dev_62", "rsp_dev_63", "rsp_dev_64",
    "rsp_dev_65", "rsp_dev_66" 
};

#define POLL_WAIT_US                    1
#define SEND_PKG_WAIT_US                10


int crypto::open_device(int devno, int ndevtd)
{
	int ret = 0;

	memset(&dev_mngt, 0, sizeof(dev_mngt));

	for (int i = 0; i < ndevtd; ++i)
	{
		ret = cap_open_device(cap_dev_name[devno-1], &dev_mngt.hdev[i], POLL_WAIT_US);
		if (ret != CAP_RET_SUCCESS)
		{
			printf("Device Open Filed.\n");
			exit(0);
		}

		dev_mngt.handle_cnt = i+1;
		dev_mngt.thread_num = i+1;
	}

	hw_on = 1;

	return;
}

int crypto::close_device()
{
	int ret = 0;

	for (int i = 0; i < dev_mngt.handle_cnt; ++i)
	{
		ret = cap_close_device(dev_mngt.hdev[i]);

		if (ret != CAP_RET_SUCCESS)
		{
			printf("Device Close Filed.\n");
			exit(0);
		}
	}

	hw_on = 0;

	return;
}

void sha1_hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint8_t* hash_buf) {
	SHA_CTX sha;
	SHA1_Init(&sha);
	SHA1_Update(&sha, inbuf, ninbytes);
	SHA1_Final(hash_buf, &sha);
	memcpy(resbuf, hash_buf, noutbytes);
}

void sha256_hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint8_t* hash_buf) {
	SHA256_CTX sha;
	SHA256_Init(&sha);
	SHA256_Update(&sha, inbuf, ninbytes);
	SHA256_Final(hash_buf, &sha);
	memcpy(resbuf, hash_buf, noutbytes);
}

void sha512_hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint8_t* hash_buf) {
	SHA512_CTX sha;
	SHA512_Init(&sha);
	SHA512_Update(&sha, inbuf, ninbytes);
	SHA512_Final(hash_buf, &sha);
	memcpy(resbuf, hash_buf, noutbytes);
}

//Read random bytes from /dev/random
void gen_secure_random(uint8_t* dest, uint32_t nbytes) {
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
	{
		std::cerr << "Unable to open /dev/urandom, exiting" << std::endl;
		exit(0);
	}
	size_t bytectr = 0;
	while (bytectr < nbytes) {
		ssize_t result = read(fd, dest + bytectr, nbytes - bytectr);
		if (result < 0) {
			std::cerr << "Unable to read from /dev/urandom, exiting" << std::endl;
			exit(0);
		}
		bytectr += static_cast<size_t>(result);
	}
	if (close(fd) < 0)
	{
		std::cerr << "Unable to close /dev/urandom" << std::endl;
	}
}

seclvl get_sec_lvl(uint32_t symsecbits) {
	if(symsecbits == ST.symbits) return ST;
	else if(symsecbits == MT.symbits) return MT;
	else if(symsecbits == LT.symbits) return LT;
	else if(symsecbits == XLT.symbits) return XLT;
	else if(symsecbits == XXLT.symbits) return XXLT;
	else return LT;
}

void crypto::aes_compression_hash(AES_KEY_CTX* aes_key, uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes) {
	int32_t dummy;

	((uint64_t*) aes_hash_in_buf)[0] = ((uint64_t*) inbuf)[0] ^ ((uint64_t*) inbuf)[2];
	((uint64_t*) aes_hash_in_buf)[1] = ((uint64_t*) inbuf)[1] ^ ((uint64_t*) inbuf)[3];

#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	EVP_EncryptUpdate(*aes_key, aes_hash_buf_y1, &dummy, aes_hash_in_buf, AES_BYTES);
#else
	EVP_EncryptUpdate(aes_key, aes_hash_buf_y1, &dummy, aes_hash_in_buf, AES_BYTES);
#endif

	//cout << (hex) << ((uint64_t*) aes_hash_buf_y1)[0] << ((uint64_t*) aes_hash_buf_y1)[1] << (dec) << endl;

	((uint64_t*) aes_hash_in_buf)[0] = ((uint64_t*) inbuf)[0] ^ ((uint64_t*) inbuf)[2] ^ ((uint64_t*) aes_hash_buf_y1)[0];
	((uint64_t*) aes_hash_in_buf)[1] = ((uint64_t*) inbuf)[1] ^ ((uint64_t*) inbuf)[3] ^ ((uint64_t*) aes_hash_buf_y1)[1];

#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
		EVP_EncryptUpdate(*aes_key, aes_hash_buf_y2, &dummy, aes_hash_in_buf, AES_BYTES);
#else
		EVP_EncryptUpdate(aes_key, aes_hash_buf_y2, &dummy, aes_hash_in_buf, AES_BYTES);
#endif

	//cout << (hex) << ((uint64_t*) aes_hash_buf_y2)[0] << ((uint64_t*) aes_hash_buf_y2)[1] << (dec) << endl;

	((uint64_t*) aes_hash_in_buf)[0] = ((uint64_t*) inbuf)[0] ^ ((uint64_t*) inbuf)[2] ^ ((uint64_t*) aes_hash_buf_y2)[0];
	((uint64_t*) aes_hash_in_buf)[1] = ((uint64_t*) inbuf)[1] ^ ((uint64_t*) inbuf)[3] ^ ((uint64_t*) aes_hash_buf_y2)[1];

#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	EVP_EncryptUpdate(*aes_key, resbuf, &dummy, aes_hash_in_buf, AES_BYTES);
#else
	EVP_EncryptUpdate(aes_key, resbuf, &dummy, aes_hash_in_buf, AES_BYTES);
#endif

	//cout << (hex) << ((uint64_t*) resbuf)[0] << ((uint64_t*) resbuf)[1] << (dec) << endl;

	((uint64_t*) resbuf)[0] = ((uint64_t*) inbuf)[0] ^ ((uint64_t*) aes_hash_buf_y1)[0] ^ ((uint64_t*) aes_hash_buf_y2)[0] ^ ((uint64_t*) resbuf)[0];
	((uint64_t*) resbuf)[1] = ((uint64_t*) inbuf)[1] ^ ((uint64_t*) aes_hash_buf_y1)[1] ^ ((uint64_t*) aes_hash_buf_y2)[1] ^ ((uint64_t*) resbuf)[1];
}




/*static void InitAndReadCodeWord(REGISTER_SIZE*** codewords) {
	uint32_t ncodewords = m_nCodeWordBits;
	uint32_t ncwintlen = 8;
	*codewords = (REGISTER_SIZE**) malloc(sizeof(REGISTER_SIZE*) * ncodewords);
	for(uint32_t i = 0; i < m_nCodewords; i++) {
		(*codewords)[i] = (REGISTER_SIZE*) malloc(sizeof(REGISTER_SIZE) * ((ncwintlen * sizeof(uint32_t)) / sizeof(REGISTER_SIZE)));
	}
	readCodeWords(*codewords);
}*/
