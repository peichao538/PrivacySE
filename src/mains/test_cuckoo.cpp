#include <unistd.h>
#include <string>
#include <algorithm>
#include <math.h>
#include "../util/typedefs.h"
#include "../util/crypto/crypto.h"
//#include "../util/helpers.h"
#include "../hashing/cuckoo.h"
#include "../hashing/simple_hashing.h"

static const uint8_t test_seed[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};


static void read_elements(uint8_t*** elements, uint32_t** elebytelens, uint32_t* nelements, string filename) {
	uint32_t i, j;
	ifstream infile(filename.c_str());
	if(!infile.good()) {
		cerr << "Input file " << filename << " does not exist, program exiting!" << endl;
		exit(0);
	}
	string line;
	if(*nelements == 0) {
		while (std::getline(infile, line)) {
			++*nelements;
		}
	}
	*elements=(uint8_t**) malloc(sizeof(uint8_t*)*(*nelements));
	*elebytelens = (uint32_t*) malloc(sizeof(uint32_t) * (*nelements));

	infile.clear();
	infile.seekg(ios::beg);
	for(i = 0; i < *nelements; i++) {
		assert(std::getline(infile, line));
		(*elebytelens)[i] = line.length();
		(*elements)[i] = (uint8_t*) malloc((*elebytelens)[i]);
		memcpy((*elements)[i], (uint8_t*) line.c_str(), (*elebytelens)[i]);

#ifdef PRINT_INPUT_ELEMENTS
		cout << "Element " << i << ": ";
		for(j = 0; j < (*elebytelens)[i]; j++)
			cout << (*elements)[i][j];
		cout << endl;
#endif
	}
}


int32_t main(int32_t argc, char **argv)
{

    uint32_t symsecbits = 128;
    uint8_t **elements;
    uint32_t neles = 0, nbins = 0, ntasks=1, pneles = 0, *elebytelens, *res_bytelens, nclients = 2;
    uint32_t maskbytelen, maskbitlen;
    prf_state_ctx prf_state;
    double epsilon = 1.2;

    string filename = "./sample_sets/emails_alice.txt";

	uint8_t *hash_table, *masks;

    crypto crypt_env(symsecbits, (uint8_t *)test_seed);

 
    //
    read_elements(&elements, &elebytelens, &neles, filename);
    pneles = 1024;

    //
  	maskbitlen = pad_to_multiple(crypt_env.get_seclvl().statbits + ceil_log2(neles) + ceil_log2(pneles), 8);
	maskbytelen = ceil_divide(maskbitlen, 8);

    uint8_t* eleptr = (uint8_t*) malloc(maskbytelen * neles);

    domain_hashing(neles, elements, elebytelens, eleptr, maskbytelen, &crypt_env);

    //
    crypt_env.init_prf_state(&prf_state, (uint8_t *)test_seed);

    //
    nbins = ceil(epsilon * neles);

  	uint32_t* perm = (uint32_t*) calloc(neles, sizeof(uint32_t));

    uint32_t internal_bitlen = maskbitlen;
    uint32_t outbitlen;

    uint32_t* nelesinbin = (uint32_t*) calloc(nbins, sizeof(uint32_t));

	hash_table = cuckoo_hashing(eleptr, neles, nbins, internal_bitlen, &outbitlen,
			nelesinbin, perm, ntasks, &prf_state);

    //
    crypt_env.free_prf_state(&prf_state);
    free(nelesinbin);
    free(perm);

    free(hash_table);
    free(eleptr);

	for(int i = 0; i < neles; i++)
		free(elements[i]);

	free(elements);
	free(elebytelens);

}