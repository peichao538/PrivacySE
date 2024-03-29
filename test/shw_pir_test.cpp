#include "../src/tee-based/shw-pri.h"
#include <fstream>
#include <iostream>
#include <string>
#include <iomanip>

using namespace std;

void read_database_elements(uint8_t*** kelements, uint32_t** kelebytelens, uint8_t*** velements, uint32_t** velebytelens, uint32_t* nelements, string filename) {
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

	*kelements=(uint8_t**) malloc(sizeof(uint8_t*)*(*nelements));
	*kelebytelens = (uint32_t*) malloc(sizeof(uint32_t) * (*nelements));
	*velements=(uint8_t**) malloc(sizeof(uint8_t*)*(*nelements));
	*velebytelens = (uint32_t*) malloc(sizeof(uint32_t) * (*nelements));

	infile.clear();
	infile.seekg(ios::beg);
	for(i = 0; i < *nelements; i++) {
		assert(std::getline(infile, line));
        int sepos = line.find(",");

        string tk, tv;
        tk = line.substr(0, sepos);
        tv = line.substr(sepos+1, line.length() - sepos);

		(*kelebytelens)[i] = tk.length();
		(*kelements)[i] = (uint8_t*) malloc((*kelebytelens)[i]);
		memcpy((*kelements)[i], (uint8_t*) tk.c_str(), (*kelebytelens)[i]);

		(*velebytelens)[i] = tv.length();
		(*velements)[i] = (uint8_t*) malloc((*velebytelens)[i]);
		memcpy((*velements)[i], (uint8_t*) tv.c_str(), (*velebytelens)[i]);

#ifdef PRINT_INPUT_ELEMENTS
		cout << "Element " << i << ": ";
		for(j = 0; j < (*kelebytelens)[i]; j++)
			cout << (*kelements)[i][j];
		cout << endl;
#endif
	}
}


int shw_pir_test(int32_t argc, char** argv)
{
    int ret = 0;

    //
    SUDO_SHW_PRI_CTX * pir_server = NULL;
    SUDO_SHW_PRI_CTX * pir_client = NULL;

    //
    uint8_t nego_data_server[128];
    uint32_t nego_data_len_server = 128;

    uint8_t nego_data_client[128];
    uint32_t nego_data_len_client = 128;

    uint32_t server_nelements = 0, client_nelements = 0;
    uint8_t ** server_kelements = NULL, ** server_velements = NULL;
    uint32_t * server_kelebytelens = NULL, * server_velebytelens = NULL;

    //char * client_query_str = (char *)"Aziz.Ecker@wanadoo.co.uk";    
    char * client_query_str = (char *)"Willibald.Sieben@live.com.mx";
    uint32_t client_query_str_len = strlen(client_query_str);


    //
    string sever_filename = "../sample_sets/account_info_test.txt";

    //
    read_database_elements(&server_kelements, &server_kelebytelens, &server_velements, &server_velebytelens, 
            &server_nelements, sever_filename);

    // Init
    pir_server = shw_init(SERVER, nego_data_server, &nego_data_len_server);
    if (!pir_server)
    {
        printf("Server init fail!\n");
    }

    pir_client = shw_init(CLIENT, nego_data_client, &nego_data_len_client);
    if (!pir_client)
    {
        printf("Client init fail!\n");
    }

    // 1st time
    // Server <--> Client


    // negotiate
    ret = shw_negotiate(pir_server, nego_data_client, nego_data_len_client);
    if (ret != 1)
    {
        printf("Server negotiate fail!\n");
    }

    ret = shw_negotiate(pir_client, nego_data_server, nego_data_len_server);
    if (ret != 1)
    {
        printf("Client negotiate fail!\n");
    }

    // server preprocess
    ret = shw_pir_preprocess(pir_server);

    // client preprocess
    ret = shw_pir_preprocess(pir_client);

    // server
    shw_pir_server_gen_table(pir_server, server_kelements, server_kelebytelens, server_velements, server_velebytelens, server_nelements);

    // client
    uint8_t * client_enckey = NULL;
    uint32_t client_enckey_len;
    shw_pir_client_gen_query(pir_client, (uint8_t *)client_query_str, client_query_str_len, &client_enckey, &client_enckey_len);

    // server - query
    uint8_t * server_encval = NULL;
    uint32_t server_encval_len;
    shw_pir_server_response(pir_server, client_enckey, client_enckey_len, &server_encval, &server_encval_len);

    // client - get value
    uint8_t * client_val = NULL;
    uint32_t client_val_len;
    shw_pir_client_getv(pir_client, (uint8_t *)client_query_str, client_query_str_len, 
        server_encval, server_encval_len, &client_val, &client_val_len);

    //
    shw_pir_done(pir_server);
    shw_pir_done(pir_client);

    //
    int i = 0, j = 0;

	{
		cout << "PIR results:" << endl;
		if(1) {
			for(i = 0; i < 1; i++) {
				//cout << i << ": \t";
                cout<< "keyword : ";
                for(j = 0; j < client_query_str_len; j++) {
					cout << client_query_str[j];
				}

                cout << endl << "Value : ";

				for(j = 0; j < client_val_len; j++) {
					cout << client_val[j];
				}
				cout << endl;
			}
		}
    }

    //
    free(client_enckey);
    free(server_encval);
    free(client_val);

    //
	for(i = 0; i < server_nelements; i++)
    {
		free(server_kelements[i]);
        free(server_velements[i]);
    }
	free(server_kelements);
	free(server_velements);

	free(server_kelebytelens);
	free(server_velebytelens);

    return 1;
}

int32_t main(int32_t argc, char** argv) {
	shw_pir_test(argc, argv);
}
