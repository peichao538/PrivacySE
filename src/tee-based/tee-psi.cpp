#include "tee-psi.h"

//routine for 2dimensional array with variable bit-length elements
uint32_t teepsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** resbytelens, crypto* crypt_env, CSocket* sock, uint32_t ntasks) {
	task_ctx ectx;
	ectx.eles.input2d = elements;
	ectx.eles.varbytelens = elebytelens;
	ectx.eles.hasvarbytelen = true;
	uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * min(neles, pneles));

	uint32_t intersect_size = teepsi(role, neles, pneles, ectx, crypt_env, sock, ntasks, matches);

	if(role == CLIENT) 
	{
		create_result_from_matches_var_bitlen(result, resbytelens, elebytelens, elements, matches, intersect_size);
	}

	free(matches);

	return intersect_size;
}

//routine for 1dimensional array with fixed bit-length elements
uint32_t teepsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks) {
	task_ctx ectx;
	ectx.eles.input1d = elements;
	ectx.eles.fixedbytelen = elebytelen;
	ectx.eles.hasvarbytelen = false;

	uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * min(neles, pneles));

	uint32_t intersect_size = teepsi(role, neles, pneles, ectx, crypt_env, sock, ntasks, matches);

	create_result_from_matches_fixed_bitlen(result, elebytelen, elements, matches, intersect_size);

	free(matches);

	return intersect_size;
}

uint32_t teepsi(role_type role, uint32_t neles, uint32_t pneles, task_ctx ectx,
		crypto* crypt_env, CSocket* sock, uint32_t ntasks, uint32_t* matches) {

	uint32_t i, intersect_size, maskbytelen;
	//task_ctx_naive ectx;
	CSocket* tmpsock = sock;

	uint32_t* perm;
	uint8_t *hashes, *phashes;

	maskbytelen = ceil_divide(crypt_env->get_seclvl().statbits + ceil_log2(neles) + ceil_log2(pneles), 8);

	// check hw is enabled
	if (1 != crypt_env->hw_on)
	{
		return 0;
	}
	
	//
	hashes = (uint8_t*) malloc(sizeof(uint8_t) * neles * maskbytelen);
	perm  = (uint32_t*) malloc(sizeof(uint32_t) * neles);

	/* Generate the random permutation the elements */
	crypt_env->gen_rnd_perm(perm, neles);

    /* negotiate */
	/* Todo: use tee to protect */
	cap_ecc_keypair_t * spkey = (cap_ecc_keypair_t *) malloc(sizeof(cap_ecc_keypair_t));
	cap_ecc_pubkey_t * rpubkey = (cap_ecc_pubkey_t *) malloc(sizeof(cap_ecc_pubkey_t));

	crypt_env->sm2_gen_key(crypt_env->dev_mngt.hdev[0], (uint8_t *)spkey);

	snd_and_rcv((uint8_t *)(&(spkey->pubkey)), sizeof(cap_ecc_pubkey_t), (uint8_t *)rpubkey, sizeof(cap_ecc_pubkey_t), tmpsock);

	crypt_env->sm2_set_pow(crypt_env->dev_mngt.hdev[0], &(spkey->prikey), rpubkey, rpubkey);

	memset(spkey, 0, sizeof(cap_ecc_keypair_t));
	free(spkey);

	uint8_t * psalt = (uint8_t *) malloc(sizeof(uint8_t) * 32 * 2);
	memcpy(psalt, rpubkey->x, 64);
	//memcpy(psalt + 32, rpubkey->y, 32);

//#define DEBUG
#ifdef DEBUG
	cout << "negotiate key" << endl;
	for(uint8_t * tptr = (uint8_t *)rpubkey, i = 0; i < sizeof(cap_ecc_pubkey_t); i++) {
		cout << std::setw(2) << setfill('0') << (hex) << (uint32_t)tptr[i];// << (dec);
	}
	cout << endl;
#endif

	free(rpubkey);

	/* Hash and permute elements */
#ifdef DEBUG
	cout << "Hashing my elements" << endl;
#endif

	//ectx.eles.input = permeles;
	//ectx.eles.inbytelen = elebytelen;
	ectx.eles.outbytelen = maskbytelen,
	ectx.eles.nelements = neles;
	ectx.eles.output = hashes;
	ectx.eles.perm = perm;
	ectx.sctx.symcrypt = crypt_env;
	ectx.entropy = psalt;
	ectx.entropylen = 64;

	run_task(ntasks, ectx, psi_hashing_use_tee_function);

	phashes = (uint8_t*) malloc(sizeof(uint8_t) * pneles * maskbytelen);


#ifdef DEBUG
	cout << "Exchanging hashes" << endl;
#endif
	snd_and_rcv(hashes, neles * maskbytelen, phashes, pneles * maskbytelen, tmpsock);

#ifdef DEBUG
	//
	std::ofstream ofs;

	if (SERVER == role)
	{
		/* code */
		ofs.open ("server.txt", std::ofstream::out | std::ofstream::trunc);
	}
	else
	{
		//
		ofs.open ("client.txt", std::ofstream::out | std::ofstream::trunc);
	}


	cout << "Hashes of my elements: " << endl;
	for(i = 0; i < neles; i++) {
		for(uint32_t j = 0; j < maskbytelen; j++) {
			//cout << std::setw(2) << setfill('0') << (hex) << (uint32_t) hashes[i * maskbytelen + j] << (dec);
			ofs << std::setw(2) << setfill('0') << (hex) << (uint32_t) hashes[i * maskbytelen + j] << (dec);
		}
		//cout << endl;
		ofs << endl;
	}
	ofs.close();
#endif

	// cout << "Hashes of partner elements: " << endl;
	// for(i = 0; i < pneles; i++) {
	// 	for(uint32_t j = 0; j < maskbytelen; j++) {
	// 		cout << std::setw(2) << setfill('0') << (hex) << (uint32_t) phashes[i * maskbytelen + j] << (dec);
	// 	}
	// 	cout << endl;
	// }

#ifdef DEBUG
	cout << "Finding intersection" << endl;
#endif
	intersect_size = find_intersection(hashes, neles, phashes, pneles, maskbytelen,
			perm, matches);


#ifdef DEBUG
	cout << "Free-ing allocated memory" << endl;
#endif
#undef DEBUG

	free(perm);
	free(hashes);
	//free(permeles);
	free(phashes);

	free(psalt);

	return intersect_size;
}


