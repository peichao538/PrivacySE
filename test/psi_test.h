/*
 * psi_test.h
 *
 *  Created on: May 20, 2020
 *      Author: peic
 */

#ifndef DEMONSTRATOR_H_
#define DEMONSTRATOR_H_

#include "../src/pk-based/dh-psi.h"
#include "../src/ot-based/ot-psi.h"
#include "../src/server-aided/sapsi.h"
#include "../src/naive-hashing/naive-psi.h"
#include "../src/tee-based/tee-psi.h"
#include <fstream>
#include <iostream>
#include <string>
#include "../src/util/parse_options.h"
#include "../src/util/helpers.h"


using namespace std;

//#define PRINT_INPUT_ELEMENTS

int32_t psi_demonstrator(int32_t argc, char** argv);

void read_elements(uint8_t*** elements, uint32_t** elebytelens, uint32_t* nelements, string filename);

int32_t read_psi_demo_options(int32_t* argcp, char*** argvp, role_type* role, psi_prot* protocol, string* filename, string* address,
		uint32_t* nelements, bool* detailed_timings);

int32_t read_psi_demo_options(int32_t* argcp, char*** argvp, role_type* role, psi_prot* protocol, string* filename, string* address,
		uint32_t* nelements, bool* detailed_timings, bool* enable_dev);


#endif /* DEMONSTRATOR_H_ */
