#include "../src/tee-based/tee-psi-ax.h"
#include <fstream>
#include <iostream>
#include <string>
#include "../src/util/helpers.h"


int32_t main(int32_t argc, char** argv) {
	psi_test(argc, argv);
}


int psi_test()
{
    int ret = 0;

    //
    SUDO_PSI_HW_CTX * psi_server = NULL;
    SUDO_PSI_HW_CTX * psi_client = NULL;

    //
    uint8_t nego_data_server[128];
    uint32_t nego_data_len_server = 128;

    uint8_t nego_data_client[128];
    uint32_t nego_data_len_client = 128;

    uint32_t server_nelements, client_nelements;
    uint8_t ** server_elements, ** client_elements;
    uint32_t * server_elebytelens, * client_elebytelens;

    uint32_t ** server_intersection, ** client_intersection;
    uint32_t * server_res_bytelens, * client_res_bytelens;

    //
    string sever_filename = "../sample_sets/emails_alice.txt";
    string client_filename = "../sample_sets/emails_bob.txt";

    //
    read_elements(&server_elements, &server_elebytelens, &server_nelements, sever_filename);
    read_elements(&client_elements, &client_elebytelens, &client_nelements, sever_filename);

    // Init
    psi_server = teepsi_init(SERVER, 1, nego_data_server, &nego_data_len_server);
    if (!psi_server)
    {
        printf("Server init fail!\n");
    }

    psi_client = teepsi_init(SERVER, 1, nego_data_client, &nego_data_len_client);
    if (!psi_client)
    {
        printf("Client init fail!\n");
    }

    // negotiate
    ret = teepsi_negotiate(psi_server, nego_data_client, nego_data_len_client);
    if (ret != !)
    {
        printf("Server negotiate fail!\n");
    }

    ret = teepsi_negotiate(psi_client, nego_data_server, nego_data_len_server);
    if (ret != !)
    {
        printf("Client negotiate fail!\n");
    }

    // calculate
    int server_len = teepsi_calc(psi_server, server_nelements, client_nelements, server_elebytelens, server_elements, NULL, 0);
    uint8_t * server_result = (uint8_t *)malloc(len);    
    teepsi_calc(psi_server, server_nelements, client_nelements, server_elebytelens, server_elements, server_result, server_len);

    int client_len = teepsi_calc(psi_client, client_nelements, server_nelements, client_elebytelens, client_elements, NULL, 0);
    uint8_t * client_result = (uint8_t *)malloc(len);    
    teepsi_calc(psi_client, client_nelements, server_nelements, client_elebytelens, client_elements, client_result, client_len);

    //
    int intsect_size_server = teepsi_find_intersection(psi_server, server_result, server_nelements, client_result, client_nelements, &server_result, &server_res_bytelens);

    int intsect_size_client = teepsi_find_intersection(psi_client, client_result, client_nelements, server_result, server_nelements, &client_result, &client_res_bytelens);

    //
    teepsi_done(psi_server);
    teepsi_done(psi_client);

    //
	if(role == CLIENT) {
		cout << "Computation finished. Found " << intersect_size << " intersecting elements:" << endl;
		if(1) {
			for(i = 0; i < intsect_size_client; i++) {
				//cout << i << ": \t";
				for(j = 0; j < client_res_bytelens[i]; j++) {
					cout << client_result[i][j];
				}
				cout << endl;
			}
		}

		for(i = 0; i < intsect_size_client; i++) {
			free(client_result[i]);
		}
		
		if(intersect_size > 0)
			free(client_result);
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
