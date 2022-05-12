#include <unistd.h>
#include <string>
#include <algorithm>
#include <iomanip>
#include <math.h>
#include "../util/typedefs.h"
#include "../util/crypto/crypto.h"
//#include "../util/helpers.h"
#include "../hashing/cuckoo.h"
#include "../hashing/simple_hashing.h"
#include "../hashing/hashing_util.h"

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

	timeval t_start, t_end;

    string filename = "./sample_sets/emails_alice.txt";

    crypto crypt_env(symsecbits, (uint8_t *)test_seed);

 
    //
    read_elements(&elements, &elebytelens, &neles, filename);
    pneles = 1024;

    //
  	maskbitlen = pad_to_multiple(crypt_env.get_seclvl().statbits + ceil_log2(neles) + ceil_log2(pneles), 8);
	maskbytelen = ceil_divide(maskbitlen, 8);

    uint8_t* eleptr_1 = (uint8_t*) malloc(maskbytelen * neles);

    gettimeofday(&t_start, NULL);
    domain_hashing(neles, elements, elebytelens, eleptr_1, maskbytelen, &crypt_env);
    gettimeofday(&t_end, NULL);

    cout << "Time for hash elements(single thread):\t" << fixed << std::setprecision(2) << getMillies(t_start, t_end)/1000 << " s" << endl;

    cout << "---------------------------------------" << endl;

    uint8_t* eleptr_2 = (uint8_t*) malloc(maskbytelen * neles);

    gettimeofday(&t_start, NULL);
    domain_hashing(neles, elements, elebytelens, eleptr_2, maskbytelen, &crypt_env, 10);
    gettimeofday(&t_end, NULL);

    cout << "Time for hash elements(mult thread):\t" << fixed << std::setprecision(2) << getMillies(t_start, t_end)/1000 << " s" << endl;

    int ret = memcmp(eleptr_1, eleptr_2, maskbytelen * neles); 
    assert(ret == 0);

    free(eleptr_1);
    free(eleptr_2);

	for(int i = 0; i < neles; i++)
		free(elements[i]);

	free(elements);
	free(elebytelens);

}