#include "ecc-sm-crypto.h"

#include "../../externals/miracl_lib/ecn.h"
#include "../../externals/miracl_lib/big.h"


char sm2_p[] = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
char sm2_a[] = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
char sm2_b[] = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
char sm2_Gx[] = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
char sm2_Gy[] = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
char sm2_n[] = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";



void ecc_sm_field::init(seclvl sp, uint8_t* seed) {

	miracl *mip = mirsys(sp.eccpfbits, 2);
	fparams = (ecc_sm_fparams*) malloc(sizeof(ecc_sm_fparams));

    if (sp.eccpfbits != LT.eccpfbits)
    {
        sp = LT;
    }

	secparam = sp;

	//miracl *mip=mirsys(MR_ROUNDUP(abs(163),4),16);
	fparams->P = new Big();
	fparams->A = new Big();
	fparams->B = new Big();

    fparams->secparam = LT.eccpfbits;

	//Change the base to read in the parameters
	mip->IOBASE = 16;

    *fparams->P = sm2_p;
    *fparams->A = sm2_a;
    *fparams->B = sm2_b;


	//seed the miracl rnd generator
	irand((long)(*seed));


    //
    ecurve_init(fparams->A->getbig(), fparams->B->getbig(), fparams->P->getbig(), MR_BEST);

	fparams->X = new Big();
	fparams->Y = new Big();
	*fparams->X = sm2_Gx;
	*fparams->Y = sm2_Gy;

	//For ECC, a coordinate is transferred as well as a 1/-1
	fe_bytelen = ceil_divide(secparam.eccpfbits,8) + 1;

	mip->IOBASE = 16;
}

ecc_sm_field::~ecc_sm_field(){
	delete fparams->Y;
	delete fparams->X;
	delete fparams->A;
	delete fparams->B;
	delete fparams->P;

	free(fparams);

	mirexit();
}


num* ecc_sm_field::get_num() {
	return new ecc_sm_num(this);
}

num* ecc_sm_field::get_rnd_num(uint32_t bitlen) {
	Big ele;
	if(bitlen == 0)
		bitlen = secparam.eccpfbits;
	ele = rand(bitlen, 2);
	return new ecc_sm_num(this, &ele);
}

fe* ecc_sm_field::get_fe() {
	return new ecc_sm_fe(this);
}

fe* ecc_sm_field::get_rnd_fe(uint32_t bitlen) {
	return sample_random_point();
}

fe* ecc_sm_field::get_generator() {
	ECn g = ECn(*fparams->X, *fparams->Y);
	return new ecc_sm_fe(this, &g);
}

fe* ecc_sm_field::get_rnd_generator() {
	return sample_random_point();
}

brickexp* ecc_sm_field::get_brick(fe* gen) {
	return new ecc_sm_brickexp(gen, fparams);
}

uint32_t ecc_sm_field::get_size() {
	return secparam.eccpfbits;
}

fe* ecc_sm_field::sample_random_point() {
	Big bigtmp;
	ECn point;
	uint32_t itmp = rand()%2;
	do
	{
		bigtmp = rand(secparam.symbits, 2);
		point = ECn(bigtmp, itmp);
	}
	while (point_at_infinity(point.get_point()));
	return new ecc_sm_fe(this, &point);
}




ecc_sm_fe::ecc_sm_fe(ecc_sm_field* fld) {
	field = fld;
	init();
}

ecc_sm_fe::ecc_sm_fe(ecc_sm_field* fld, ECn* src) {
	field = fld;
	init();
	*val = *src;
}
ecc_sm_fe::~ecc_sm_fe() {
	delete val;
}

void ecc_sm_fe::set(fe* src) {
	*val = *fe2ecn(src);
}

ECn* ecc_sm_fe::get_val() {
	return val;
}

void ecc_sm_fe::set_mul(fe* a, fe* b) {
	set(a);
	(*val)+=(*fe2ecn(b));
}

void ecc_sm_fe::set_pow(fe* b, num* e) {
	set(b);
	(*val)*=(*sm_num2Big(e));
}

void ecc_sm_fe::set_div(fe* a, fe* b) {
	set(a);
	(*val)-=(*fe2ecn(b));
}

void ecc_sm_fe::set_double_pow_mul(fe* b1, num* e1, fe* b2, num* e2) {
    ecurve_mult2(sm_num2Big(e1)->getbig(), fe2ecn(b1)->get_point(), sm_num2Big(e2)->getbig(), fe2ecn(b2)->get_point(), val->get_point());
}

void ecc_sm_fe::import_from_bytes(uint8_t* buf) {
	byte_to_point(val, field->fe_byte_size(), buf);

}
//export and pad all leading zeros
void ecc_sm_fe::export_to_bytes(uint8_t* buf) {
	point_to_byte(buf, field->fe_byte_size(), val);
}

void ecc_sm_fe::sample_fe_from_bytes(uint8_t* buf, uint32_t bytelen) {
	ECn point;
	Big bigtmp;

    bytes_to_big (bytelen, (const char*) buf, bigtmp.getbig());

	premult(bigtmp.getbig(), MAXMSGSAMPLE, bigtmp.getbig());
	for(int i = 0; i < MAXMSGSAMPLE; i++)
	{
		point = ECn(bigtmp, 0);
		if(!point_at_infinity(point.get_point())) {
			*val = point;
			return;
		}
		point = ECn(bigtmp, 1);
		if(!point_at_infinity(point.get_point())) {
			*val = point;
			return;
		}
		incr(bigtmp.getbig(), 1, bigtmp.getbig());
	}
	cerr << "Error while sampling point, exiting!" << endl;
	exit(0);
}


void ecc_sm_fe::print() {
	cout << (*val) << endl;
}

int ecc_sm_fe::iszero() {
	if (val->iszero())
		return 1;
	else
		return 0;
}

void ecc_sm_fe::init() {
	val = new ECn();
}


ecc_sm_num::ecc_sm_num(ecc_sm_field* fld) {
	field = fld;
	val = new Big();
}
ecc_sm_num::ecc_sm_num(ecc_sm_field* fld, Big* src) {
	field = fld;
	val = new Big();
	copy(src->getbig(), val->getbig());
}

ecc_sm_num::~ecc_sm_num() {
	delete val;
}

Big* ecc_sm_num::get_val() {
	return val;
}

void ecc_sm_num::set(num* src) {
	copy(((ecc_sm_num*) src)->get_val()->getbig(), val->getbig());
}
void ecc_sm_num::set_si(int32_t src) {
	convert(src, val->getbig());
}
void ecc_sm_num::set_add(num* a, num* b) {
	add(((ecc_sm_num*) a)->get_val()->getbig(), ((ecc_sm_num*) b)->get_val()->getbig(), val->getbig());
}
void ecc_sm_num::set_mul(num* a, num* b) {
	multiply(((ecc_sm_num*) a)->get_val()->getbig(), ((ecc_sm_num*) b)->get_val()->getbig(), val->getbig());
}

void ecc_sm_num::import_from_bytes(uint8_t* buf, uint32_t field_size_bytes) {
	bytes_to_big (field_size_bytes, (const char*) buf, val->getbig());
}

//export and pad all leading zeros
void ecc_sm_num::export_to_bytes(uint8_t* buf, uint32_t field_size_bytes) {
	big_to_bytes ((int32_t) field_size_bytes, val->getbig(), (char*) buf, true);
}

void ecc_sm_num::print() {
	cout << (*val) << endl;
}

void ecc_sm_num::addone() {
	*val += 1;
}


// ecc_sm_brickexp methods
struct ecc_sm_brickexp::ecc_sm_brickexp_impl {
    ebrick br;
};

ecc_sm_brickexp::ecc_sm_brickexp(fe* point, ecc_sm_fparams* fparams) {
	Big x, y;
	fe2ecn(point)->getxy(x, y);
	impl = std::make_unique<ecc_sm_brickexp_impl>();

    ebrick_init(&impl->br, x.getbig(), y.getbig(), fparams->A->getbig(),
	 		fparams->B->getbig(), fparams->P->getbig(), 8, fparams->secparam);
}

ecc_sm_brickexp::~ecc_sm_brickexp() {
    ebrick_end(&impl->br);
}

void ecc_sm_brickexp::pow(fe* result, num* e)
{
	Big xtmp, ytmp;

	mul_brick(&impl->br, sm_num2Big(e)->getbig(), xtmp.getbig(), ytmp.getbig());
	*fe2ecn(result) = ECn(xtmp, ytmp);
}


// general methods

void byte_to_point(ECn *point, uint32_t field_size_bytes, uint8_t* pBufIdx) {
	uint32_t itmp;
	Big bigtmp;
	itmp = (uint32_t) (pBufIdx[0]);

	bytes_to_big(field_size_bytes-1, (const char*) (pBufIdx + 1), bigtmp.getbig());
	*point = ECn(bigtmp, itmp);
}

void point_to_byte(uint8_t* pBufIdx, uint32_t field_size_bytes, ECn* point) {
	uint32_t itmp;
	Big bigtmp;
	//compress to x-point and y-bit and convert to byte array
	itmp = point->get(bigtmp);

	//first store the y-bit
	pBufIdx[0] = (uint8_t) (itmp & 0x01);

	//then store the x-coordinate (sec-param/8 byte size)
	big_to_bytes(field_size_bytes-1, bigtmp.getbig(), (char*) pBufIdx+1, true);

}

