#include <fstream>
#include <iostream>
#include <string>
#include <iomanip>
#include "../util/parse_options.h"
#include "../util/helpers.h"

using namespace std;


static int32_t read_psi_demo_options(int32_t* argcp, char*** argvp, string* filename)
{
	uint32_t int_role, int_protocol = 0;
	parsing_ctx options[] = {
		{(void*) filename, T_STR, 'f', "Input file", true, false},
	};

	if(!parse_options(argcp, argvp, options, sizeof(options)/sizeof(parsing_ctx))) {
		print_usage(argvp[0][0], options, sizeof(options)/sizeof(parsing_ctx));
		exit(0);
	}

	return 1;
}

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



int main(int32_t argc, char** argv)
{
    int i;
    timeval t_start, t_end;
    string filename;
    uint32_t nelements = 0, ntasks = 128;

    uint8_t **elements;
    uint32_t *elebytelens;

    //
    read_psi_demo_options(&argc, &argv, &filename);
    read_elements(&elements, &elebytelens, &nelements, filename);

    //
    uint32_t maskbytelen = 32;
    uint8_t * hashes_soft = (uint8_t*) malloc(sizeof(uint8_t) * nelements * maskbytelen);
    uint8_t * hashes_hard = (uint8_t*) malloc(sizeof(uint8_t) * nelements * maskbytelen);

	uint32_t * perm  = (uint32_t*) malloc(sizeof(uint32_t) * nelements);

    //
    crypto crypto(128, (uint8_t*) const_seed);

	/* Generate the random permutation the elements */
	crypto.gen_rnd_perm(perm, nelements);

    // soft -------------------------------------------------------------------
	task_ctx ectx;
	ectx.eles.input2d = elements;
	ectx.eles.varbytelens = elebytelens;
	ectx.eles.hasvarbytelen = true;
    ectx.eles.outbytelen = maskbytelen,
	ectx.eles.nelements = nelements;
	ectx.eles.output = hashes_soft;
	ectx.eles.perm = perm;
	ectx.sctx.symcrypt = &crypto;

    //
    gettimeofday(&t_start, NULL);

    //run_task(ntasks, ectx, psi_hashing_function);
	run_task(8, ectx, psi_hashing_function);

    gettimeofday(&t_end, NULL);

    cout << "Soft time:\t" << fixed << std::setprecision(1) << getMillies(t_start, t_end)/1000 << " s" << endl;

    // hard -------------------------------------------------------------------
    crypto.open_device(1);

	ectx.eles.input2d = elements;
	ectx.eles.varbytelens = elebytelens;
	ectx.eles.hasvarbytelen = true;
    ectx.eles.outbytelen = maskbytelen,
	ectx.eles.nelements = nelements;
	ectx.eles.output = hashes_hard;
	ectx.eles.perm = perm;
	ectx.sctx.symcrypt = &crypto;

    //
    gettimeofday(&t_start, NULL);

    run_task(ntasks, ectx, psi_hashing_function);

    gettimeofday(&t_end, NULL);

    cout << "Hard time:\t" << fixed << std::setprecision(1) << getMillies(t_start, t_end)/1000 << " s" << endl;


    crypto.close_device();

    if (0 != memcmp(hashes_soft, hashes_hard, nelements * maskbytelen))
    {
        cout << "Error!!!!" << endl;
    }
    else
    {
        cout << "OK!" << endl;
    }

    //
    free(hashes_soft);
    free(hashes_hard);

    //
	for(i = 0; i < nelements; i++)
		free(elements[i]);

	free(elements);
	free(elebytelens);

    return 0;
}


//* Environment
//* Intel(R) Core(TM) i7-10700KF CPU @ 3.80GHz
// File Size    File Name
//   1698153    emails_alice_2p16.txt
//  27158596    emails_alice_2p20.txt
// 562142337    emails_alice_2p24.txt
// Soft: OpenSSL
// Hard: CryptoCard
// --------------------------------------------------------------------
// ubuntu@ubuntu:~/gitrepo/PrivacySE$ ./test-cmp-hash.exe -f sample_sets/emails_alice_2p16.txt
// Soft time:	0.0 s
// Hard time:	0.1 s
// OK!
// ubuntu@ubuntu:~/gitrepo/PrivacySE$ ./test-cmp-hash.exe -f sample_sets/emails_alice_2p20.txt
// Soft time:	0.0 s
// Hard time:	0.7 s
// OK!
// ubuntu@ubuntu:~/gitrepo/PrivacySE$ ./test-cmp-hash.exe -f sample_sets/emails_alice_2p24.txt
// Soft time:	0.3 s
// Hard time:	14.4 s
// OK!
