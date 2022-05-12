#include "ecc.h"

ECC::ECC() {
  Init();
}

ECC::~ECC() {
  Free();
}

void ECC::Init() 
{
  ecc_ctrl = (void *)init_bch(CONFIG_BCH_CONST_M, CONFIG_BCH_CONST_T, 0);
}

void ECC::Free()
{
  free_bch((bch_control *)ecc_ctrl);
}

void ECC::PrintCodeParams() {

  bch_control * bch_ctrl = (bch_control *)ecc_ctrl;

  if (NULL == bch_ctrl)
  {
    std::cout << "ECC Error to print code params!" << std::endl;  
  }

  std::cout << "Code parameters: " << std::endl;
  std::cout << "m = " << bch_ctrl->m << std::endl;
  std::cout << "n = " << bch_ctrl->n << std::endl;
  std::cout << "t = " << bch_ctrl->t << std::endl;
  std::cout << "ecc_bits = " << bch_ctrl->ecc_bits << std::endl;
  std::cout << "ecc_bytes = " << bch_ctrl->ecc_bytes << std::endl;
}

//checkbits should be BCH_BYTES long and initialized to 0!
void ECC::Encode(uint8_t data[], uint32_t len, uint8_t checkbits[]) {
  encode_bch((bch_control *)ecc_ctrl, data, len, checkbits);
}
