/*
 * ecc-pk-crypto.h
 *
 *  Created on: Jul 11, 2014
 *      Author: mzohner
 */

#ifndef ECC_PK_CRYPTO_H_
#define ECC_PK_CRYPTO_H_

#include "pk-crypto.h"
#include <memory>

// forward declarations
class Big;
class EC2;


#define fe2ec2(fieldele) (((ecc_fe*) (fieldele))->get_val())
#define num2Big(number) (((ecc_num*) (number))->get_val())

//how many repetitions of random point samplings should be performed
#define MAXMSGSAMPLE 256


struct ecc_fparams {
	Big* BA;
	Big* BB;
	Big* X;
	Big* Y;
	Big* BP;
	int32_t m;
	int32_t a;
	int32_t b;
	int32_t c;
	uint32_t secparam;
};

class ecc_num;
class ecc_fe;
class ecc_brickexp;

class ecc_field : public pk_crypto {
public:
	ecc_field(seclvl sp, uint8_t* seed) : pk_crypto(sp, seed) {init(sp, seed);};
	~ecc_field();

	num* get_num();
	num* get_rnd_num(uint32_t bitlen=0);
	fe* get_fe();
	fe* get_rnd_fe(uint32_t bitlen);
	fe* get_generator();
	fe* get_rnd_generator();
	uint32_t get_size();
	//fe* sample_fe_from_bytes(uint8_t* buf, uint32_t bytelen);
	uint32_t num_byte_size() {return ceil_divide(secparam.ecckcbits, 8);}
	uint32_t get_field_size() {return secparam.ecckcbits;};

	brickexp* get_brick(fe* gen);
	ecc_fparams* get_params() {return fparams;};

	//#define SampleFieldElementFromBytes(ele, buf, bytelen) ByteToFieldElement(ele, bytelen, buf)
	//#define FieldSampleRandomGenerator(g, div, params) SampleRandomGenerator(g, div, (&params))
protected:
	void init(seclvl sp, uint8_t* seed);
private:
	fe* sample_random_point();
	/*Big* BA;
	Big* BB;
	Big* X;
	Big* Y;
	Big* BP;
	int32_t m;
	int32_t a;
	int32_t b;
	int32_t c;*/
	ecc_fparams* fparams;
};



class ecc_num : public num {
	//This is a Big
public:
	ecc_num(ecc_field* fld);
	ecc_num(ecc_field* fld, Big* src);
	~ecc_num();
	void set(num* src);
	void set_si(int32_t src);
	void set_add(num* a, num* b);
	void set_mul(num* a, num* b);

	Big* get_val();

	void export_to_bytes(uint8_t* buf, uint32_t field_size_bytes);
	void import_from_bytes(uint8_t* buf, uint32_t field_size_bytes);
	void set_rnd(uint32_t bits);
	void print();

	//
	void addone();

private:
	Big* val;
	ecc_field* field;
};


class ecc_fe : public fe {
public:
	ecc_fe(ecc_field* fld);
	ecc_fe(ecc_field* fld, EC2* src);
	~ecc_fe();
	void set(fe* src);
	EC2* get_val();
	void set_mul(fe* a, fe* b);

	void set_pow(fe* b, num* e);
	void set_div(fe* a, fe* b);
	void set_double_pow_mul(fe* b1, num* e1, fe* b2, num* e2);
	void export_to_bytes(uint8_t* buf);
	void import_from_bytes(uint8_t* buf);
	void sample_fe_from_bytes(uint8_t* buf, uint32_t bytelen);

	void print();

	//
	int iszero();


private:
	void init();
	EC2* val;
	ecc_field* field;
};

class ecc_brickexp : public brickexp {
public:
	ecc_brickexp(fe* point, ecc_fparams* fparams);
	~ecc_brickexp();

	void pow(fe* res, num* e);
private:
	struct ecc_brickexp_impl;	// used to hide MIRACL's ebrick2 type in the implementation
	std::unique_ptr<ecc_brickexp_impl> impl;
};

void point_to_byte(uint8_t* pBufIdx, uint32_t field_size_bytes, EC2* to_export);
void byte_to_point(EC2* to_export, uint32_t field_size_bytes, uint8_t* pBufIdx);

#endif /* ECC_PK_CRYPTO_H_ */
