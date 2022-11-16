#include "../src/tee-based/shw-pri.h"
#include <fstream>
#include <iostream>
#include <string>
#include <iomanip>

using namespace std;


void read_elements(uint8_t*** elements, uint32_t** elebytelens, uint32_t* nelements, string filename) {
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


int psi_test(int32_t argc, char** argv)
{
    int ret = 0;

    //
    SUDO_SHW_PRI_CTX * psi_server = NULL;
    SUDO_SHW_PRI_CTX * psi_client = NULL;

    //
    uint8_t nego_data_server[128];
    uint32_t nego_data_len_server = 128;

    uint8_t nego_data_client[128];
    uint32_t nego_data_len_client = 128;

    uint32_t server_nelements = 0, client_nelements = 0;
    uint8_t ** server_elements = NULL, ** client_elements = NULL;
    uint32_t * server_elebytelens = NULL, * client_elebytelens = NULL;

    uint8_t ** server_intersection = NULL, ** client_intersection = NULL;
    uint32_t * server_res_bytelens = NULL, * client_res_bytelens = NULL;

    //
    string sever_filename = "../sample_sets/emails_alice.txt";
    string client_filename = "../sample_sets/emails_bob.txt";

    //
    read_elements(&server_elements, &server_elebytelens, &server_nelements, sever_filename);
    read_elements(&client_elements, &client_elebytelens, &client_nelements, client_filename);

    // Init
    psi_server = shw_init(SERVER, nego_data_server, &nego_data_len_server);
    if (!psi_server)
    {
        printf("Server init fail!\n");
    }

    psi_client = shw_init(CLIENT, nego_data_client, &nego_data_len_client);
    if (!psi_client)
    {
        printf("Client init fail!\n");
    }

    // 1st time
    // Server <--> Client


    // negotiate
    ret = shw_negotiate(psi_server, nego_data_client, nego_data_len_client);
    if (ret != 1)
    {
        printf("Server negotiate fail!\n");
    }

    ret = shw_negotiate(psi_client, nego_data_server, nego_data_len_server);
    if (ret != 1)
    {
        printf("Client negotiate fail!\n");
    }

    //
    shw_psi_preprocess(psi_server);

    shw_psi_preprocess(psi_client);

    // server calculate
    //shw_psi_preprocess(psi_server);

    int server_len = shw_psi_calc(psi_server, server_nelements, client_nelements, server_elebytelens, server_elements, NULL, 0);
    uint8_t * server_result = (uint8_t *)malloc(server_len);    
    shw_psi_calc(psi_server, server_nelements, client_nelements, server_elebytelens, server_elements, server_result, server_len);
    
    // client calculate
    //shw_psi_preprocess(psi_client);

    int client_len = shw_psi_calc(psi_client, client_nelements, server_nelements, client_elebytelens, client_elements, NULL, 0);
    uint8_t * client_result = (uint8_t *)malloc(client_len);    
    shw_psi_calc(psi_client, client_nelements, server_nelements, client_elebytelens, client_elements, client_result, client_len);

    // 2nd time
    // Server --> Client

    // read result
    // int intsect_size_server = shw_psi_find_intersection(psi_server, server_result, server_nelements, client_result, client_nelements, 
    //             server_elebytelens, server_elements, &server_intersection, &server_res_bytelens);

    int intsect_size_client = shw_psi_find_intersection(psi_client, client_result, client_nelements, server_result, server_nelements, 
                client_elebytelens, (const uint8_t **)client_elements, &client_intersection, &client_res_bytelens);

    //
    shw_psi_done(psi_server);
    shw_psi_done(psi_client);

    //
    free(server_result);
    free(client_result);

    //
    int i = 0, j = 0;

	{
		cout << "Computation finished. Found " << intsect_size_client << " intersecting elements:" << endl;
		if(1) {
			for(i = 0; i < intsect_size_client; i++) {
				//cout << i << ": \t";
				for(j = 0; j < client_res_bytelens[i]; j++) {
					cout << client_intersection[i][j];
				}
				cout << endl;
			}
		}

		for(i = 0; i < intsect_size_client; i++) {
			free(client_intersection[i]);
		}
		
		if(intsect_size_client > 0)
			free(client_intersection);
			free(client_res_bytelens);
	}

    //
	for(i = 0; i < server_nelements; i++)
		free(server_elements[i]);
	free(server_elements);
	free(server_elebytelens);

	for(i = 0; i < client_nelements; i++)
		free(client_elements[i]);
	free(client_elements);
	free(client_elebytelens);

    return 1;
}

int psi_test_2(int32_t argc, char** argv)
{
    int ret = 0;

    //
    SUDO_SHW_PRI_CTX * psi_server = NULL;
    SUDO_SHW_PRI_CTX * psi_client = NULL;
    SUDO_SHW_PRI_CTX * psi_client_t = NULL;

    //
    uint8_t nego_data_server[128];
    uint32_t nego_data_len_server = 128;

    uint8_t nego_data_client[128];
    uint32_t nego_data_len_client = 128;

    uint8_t nego_data_client_t[128];
    uint32_t nego_data_len_client_t = 128;

    uint32_t server_nelements = 0, client_nelements = 0;
    uint8_t ** server_elements = NULL, ** client_elements = NULL;
    uint32_t * server_elebytelens = NULL, * client_elebytelens = NULL;

    uint8_t ** server_intersection = NULL, ** client_intersection = NULL;
    uint32_t * server_res_bytelens = NULL, * client_res_bytelens = NULL;

    timeval t_start, t_end;

    //
    string sever_filename = "../sample_sets/emails_alice_2p20.txt";
    string client_filename = "../sample_sets/emails_bob_2p20.txt";

    //
    read_elements(&server_elements, &server_elebytelens, &server_nelements, sever_filename);
    read_elements(&client_elements, &client_elebytelens, &client_nelements, client_filename);

    // Init
    psi_server = shw_init(SERVER, nego_data_server, &nego_data_len_server);
    if (!psi_server)
    {
        printf("Server init fail!\n");
    }

    psi_client = shw_init(CLIENT, nego_data_client, &nego_data_len_client);
    if (!psi_client)
    {
        printf("Client init fail!\n");
    }

    // 1st time
    // Server <--> Client


    // negotiate
    ret = shw_negotiate(psi_server, nego_data_client, nego_data_len_client);
    if (ret != 1)
    {
        printf("Server negotiate fail!\n");
    }

    ret = shw_negotiate(psi_client, nego_data_server, nego_data_len_server);
    if (ret != 1)
    {
        printf("Client negotiate fail!\n");
    }

    //
    shw_psi_preprocess(psi_server);

    shw_psi_preprocess(psi_client);


    // calculate
    gettimeofday(&t_start, NULL);

    // server calculate
    int server_len = shw_psi_calc(psi_server, server_nelements, client_nelements, server_elebytelens, server_elements, NULL, 0);
    uint8_t * server_result = (uint8_t *)malloc(server_len);    
    shw_psi_calc(psi_server, server_nelements, client_nelements, server_elebytelens, server_elements, server_result, server_len);

    gettimeofday(&t_end, NULL);

    cout << "Server(teepsi_calc) time:\t" << fixed << std::setprecision(1) << getMillies(t_start, t_end) << " ms" << endl;

    //
    gettimeofday(&t_start, NULL);

    // client calculate
    int client_len = shw_psi_calc(psi_client, client_nelements, server_nelements, client_elebytelens, client_elements, NULL, 0);
    uint8_t * client_result = (uint8_t *)malloc(client_len);    
    shw_psi_calc(psi_client, client_nelements, server_nelements, client_elebytelens, client_elements, client_result, client_len);

    gettimeofday(&t_end, NULL);

    cout << "Client(teepsi_calc) time:\t" << fixed << std::setprecision(1) << getMillies(t_start, t_end) << " ms" << endl;

    // 2nd time
    // Server --> Client

    // read result
    // only get count of intersect set
    uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * min(client_nelements, server_nelements));

    gettimeofday(&t_start, NULL);

    int intersect_size = shw_psi_find_intersection_index(psi_client, client_result, client_nelements, server_result, server_nelements, matches);

    gettimeofday(&t_end, NULL);

    cout << "Get intersect index time:\t" << fixed << std::setprecision(1) << getMillies(t_start, t_end) << " ms" << endl;

    cout << "intersec size is " << intersect_size << endl;
    // cout << "index is {";

    // for (int t = 0; t < intersect_size; t++)
    // {
    //     cout << " " << matches[t] << ",";
    // }
    // cout << "}" << endl;

    free(matches);

    //
    shw_psi_done(psi_server);
    shw_psi_done(psi_client);

    //
    free(server_result);
    free(client_result);

    //
    int i;

	for(i = 0; i < server_nelements; i++)
		free(server_elements[i]);
	free(server_elements);
	free(server_elebytelens);

	for(i = 0; i < client_nelements; i++)
		free(client_elements[i]);
	free(client_elements);
	free(client_elebytelens);

    return 1;
}

int32_t main(int32_t argc, char** argv) {

    // get result
	psi_test(argc, argv);

    // get index
	psi_test_2(argc, argv);

}

