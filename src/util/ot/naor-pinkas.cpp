#include "naor-pinkas.h"

//#include "../../externals/miracl_lib/ecn.h"
//#include "../../externals/miracl_lib/big.h"
//#include "../../externals/miracl_lib/ec2.h"

typedef std::unique_ptr<num> uptr_num;
typedef std::unique_ptr<fe> uptr_fe;
typedef std::unique_ptr<brickexp> uptr_brickexp;

void NaorPinkas::Receiver(uint32_t nSndVals, uint32_t nOTs, CBitVector &choices,
						  CSocket *socket, uint8_t *ret)
{
	uptr_fe PK0 = uptr_fe(m_cPKCrypto->get_fe());	   // fe* PK0 = m_cPKCrypto->get_fe();
	std::vector<uptr_fe> PK_sigma(nOTs);			   // fe** PK_sigma = (fe**) malloc(sizeof(fe*) * nOTs);
	std::vector<uptr_fe> pDec(nOTs);				   // fe** pDec = (fe**) malloc(sizeof(fe*) * nOTs);
	std::vector<uptr_fe> pC(nSndVals);				   // fe** pC = (fe**) malloc(sizeof(fe*) * nSndVals);
	uptr_fe g = uptr_fe(m_cPKCrypto->get_generator()); // fe* g = m_cPKCrypto->get_generator();

	std::vector<uptr_num> pK(nOTs); // num** pK = (num**) malloc(sizeof(num*) * nOTs);

	uint8_t *retPtr;
	uint32_t u, k, choice, hash_bytes, fe_bytes;
	hash_bytes = m_cCrypto->get_hash_bytes();
	fe_bytes = m_cPKCrypto->fe_byte_size();

	uptr_brickexp bg, bc;								 // brickexp *bg, *bc;
	bg = uptr_brickexp(m_cPKCrypto->get_brick(g.get())); // bg = m_cPKCrypto->get_brick(g);	//BrickInit(&bg, g, m_fParams);

	// calculate the generator of the group
	for (k = 0; k < nOTs; k++)
	{
		PK_sigma[k] = uptr_fe(m_cPKCrypto->get_fe()); // PK_sigma[k] = m_cPKCrypto->get_fe();//	FieldElementInit(PK_sigma[k]);
		pK[k] = uptr_num(m_cPKCrypto->get_rnd_num()); // pK[k] = m_cPKCrypto->get_rnd_num(); //FieldElementInit(pK[k]);

		// pK[k]->//GetRandomNumber(pK[k], m_fParams.secparam, m_fParams);/
		bg->pow(PK_sigma[k].get(), pK[k].get()); // BrickPowerMod(&bg, PK_sigma[k], pK[k]);
	}

	uint8_t *pBuf = (uint8_t *)malloc(sizeof(uint8_t) * nSndVals * fe_bytes);
	uint32_t nBufSize = nSndVals * fe_bytes;

	socket->Receive(pBuf, nBufSize);
	uint8_t *pBufIdx = pBuf;

	for (u = 0; u < nSndVals; u++)
	{
		pC[u] = uptr_fe(m_cPKCrypto->get_fe()); // pC[u] = m_cPKCrypto->get_fe();//FieldElementInit(pC[u]);
		pC[u]->import_from_bytes(pBufIdx);		// ByteToFieldElement(pC + u, m_fParams.elebytelen, pBufIdx);
		pBufIdx += fe_bytes;
	}

	free(pBuf);

	//
	bc = uptr_brickexp(m_cPKCrypto->get_brick(pC[0].get())); // bc = m_cPKCrypto->get_brick(pC[0]);//BrickInit(&bc, pC[0], m_fParams);

	//====================================================
	// N-P receiver: send pk0
	pBuf = (uint8_t *)malloc(sizeof(uint8_t) * nOTs * fe_bytes);

	pBufIdx = pBuf;
	for (k = 0; k < nOTs; k++)
	{
		choice = choices.GetBit((int32_t)k);
		if (choice != 0)
		{
			PK0->set_div(pC[choice].get(), PK_sigma[k].get()); // FieldElementDiv(PK0, pC[choice], PK_sigma[k], m_fParams);//PK0 = pC[choice];

			if (PK0->iszero())
			{
				//cout << "Invalid data happen, renew!" << endl;

				do
				{
					pK[k]->addone();
					bg->pow(PK_sigma[k].get(), pK[k].get());
					PK0->set_div(pC[choice].get(), PK_sigma[k].get());
				} while (PK0->iszero());
			}
		}
		else
		{
			PK0->set(PK_sigma[k].get()); // FieldElementSet(PK0, PK_sigma[k]);//PK0 = PK_sigma[k];
		}
		// cout << "PK0: " << PK0 << ", PK_sigma: " << PK_sigma[k] << ", choice: " << choice << ", pC[choice: " << pC[choice] << endl;
		PK0->export_to_bytes(pBufIdx); // FieldElementToByte(pBufIdx, m_fParams.elebytelen, PK0);
		pBufIdx += fe_bytes;		   // m_fParams.elebytelen;
	}

	// -->debug by peic
	//cout << __FILE__ << __LINE__ << endl;
	//cout << "[Receiver to send] print pk0 start------------------------------" << endl;
	//for (int ttt = 0; ttt <  nOTs * fe_bytes; ttt++)
	//{
	//	cout << setw(2) << setfill('0') << (hex) << (int)pBuf[ttt];
	//}
	//cout << endl;
	//cout << "[Receiver to send] end print pk0" << endl;
	// <--

	socket->Send(pBuf, nOTs * m_cPKCrypto->fe_byte_size());

	free(pBuf);
	pBuf = (uint8_t *)malloc(sizeof(uint8_t) * fe_bytes); // new uint8_t[m_fParams.elebytelen];
	retPtr = ret;

	for (k = 0; k < nOTs; k++)
	{
		pDec[k] = uptr_fe(m_cPKCrypto->get_fe()); // pDec[k] = m_cPKCrypto->get_fe();//FieldElementInit(pDec[k]);
		bc->pow(pDec[k].get(), pK[k].get());	  // bc->pow(pDec[k], pK[k]);//BrickPowerMod(&bc, pDec[k], pK[k]);
		pDec[k]->export_to_bytes(pBuf);			  // FieldElementToByte(pBuf, m_fParams.elebytelen, pDec[k]);

		hashReturn(retPtr, hash_bytes, pBuf, fe_bytes, k);
		retPtr += hash_bytes; // SHA1_BYTES;
	}

	// delete bc;//BrickDelete(&bc);
	// delete bg;//BrickDelete(&bg);

	free(pBuf);
	// free(PK_sigma);
	// free(pDec);
	// free(pC);
	// free(pK);
}

void NaorPinkas::Sender(uint32_t nSndVals, uint32_t nOTs, CSocket *socket, uint8_t *ret)
{
	uptr_num alpha, PKr, tmp;
	uptr_fe fetmp, PK0r, g;
	std::vector<uptr_fe> pCr(nSndVals), pC(nSndVals), pPK0(nOTs);
	uint8_t *pBuf, *pBufIdx;
	uint32_t hash_bytes, fe_bytes, nBufSize, u, k;

	hash_bytes = m_cCrypto->get_hash_bytes();
	fe_bytes = m_cPKCrypto->fe_byte_size();

	alpha = uptr_num(m_cPKCrypto->get_rnd_num());
	PKr = uptr_num(m_cPKCrypto->get_num());

	// pCr = (fe**) malloc(sizeof(fe*) * nSndVals);
	// pC = (fe**) malloc(sizeof(fe*) * nSndVals);

	fetmp = uptr_fe(m_cPKCrypto->get_fe());
	PK0r = uptr_fe(m_cPKCrypto->get_fe());

	pC[0] = uptr_fe(m_cPKCrypto->get_fe()); // pC[0] = m_cPKCrypto->get_fe();

	g = uptr_fe(m_cPKCrypto->get_generator());

	pC[0]->set_pow(g.get(), alpha.get()); // FieldElementPow(pC[0], g, alpha, m_fParams);

	// random C(i+1)
	for (u = 1; u < nSndVals; u++)
	{
		pC[u] = uptr_fe(m_cPKCrypto->get_fe());		// pC[u] = m_cPKCrypto->get_fe();//FieldElementInit(pC[u]);
		tmp = uptr_num(m_cPKCrypto->get_rnd_num()); // tmp = m_cPKCrypto->get_rnd_num();
		pC[u]->set_pow(g.get(), tmp.get());			// FieldElementPow(pC[u], g, tmp, m_fParams);
	}

	//====================================================
	// Export the generated C_1-C_nSndVals to a uint8_t vector and send them to the receiver
	nBufSize = nSndVals * fe_bytes;
	pBuf = (uint8_t *)malloc(nBufSize);
	pBufIdx = pBuf;
	for (u = 0; u < nSndVals; u++)
	{
		pC[u]->export_to_bytes(pBufIdx); // FieldElementToByte(pBufIdx, m_fParams.elebytelen, pC[u]);
		pBufIdx += fe_bytes;			 // m_fParams.elebytelen;
	}
	socket->Send(pBuf, nBufSize);

	free(pBuf);

	//====================================================
	// compute C^R
	for (u = 1; u < nSndVals; u++)
	{
		pCr[u] = uptr_fe(m_cPKCrypto->get_fe());   // pCr[u] = m_cPKCrypto->get_fe();//FieldElementInit(pCr[u]);
		pCr[u]->set_pow(pC[u].get(), alpha.get()); // pCr[u]->set_pow(pC[u], alpha);//FieldElementPow(pCr[u], pC[u], alpha, m_fParams);
	}
	//====================================================

	// N-P sender: receive pk0
	nBufSize = fe_bytes * nOTs;
	pBuf = (uint8_t *)malloc(nBufSize);
	socket->Receive(pBuf, nBufSize);
	// -->debug by peic
	//cout << "[Sender]print pk0 start------------------------------" << endl;
	//for (int ttt = 0; ttt < nBufSize; ttt++)
	//{
	//	cout << setw(2) << setfill('0') << (hex) << (int)pBuf[ttt];
	//}
	//cout << endl;
	//cout << "[Sender]end print pk0" << endl;
	// <--

	pBufIdx = pBuf;

	// pPK0 = (fe**) malloc(sizeof(fe*) * nOTs);
	for (k = 0; k < nOTs; k++)
	{
		pPK0[k] = uptr_fe(m_cPKCrypto->get_fe()); // pPK0[k] = m_cPKCrypto->get_fe();
		// FieldElementInit(pPK0[k]);
		pPK0[k]->import_from_bytes(pBufIdx);
		// ByteToFieldElement(pPK0 + k, m_fParams.elebytelen, pBufIdx);
		// --> debug by peic
		if (pPK0[k]->iszero())
		{
			cout << "import a invalid data" << endl;
		//	for (int ttt = 0; ttt < fe_bytes; ttt++)
		//	{
		//		cout << setw(2) << setfill('0') << (hex) << (int)pBufIdx[ttt];
		//	}
		//	cout << endl;
		}
		// <--
		pBufIdx += fe_bytes;
	}

	//====================================================
	// Write all nOTs * nSndVals possible values to ret
	// free(pBuf); TODO fix and uncomment
	free(pBuf);

	pBuf = (uint8_t *)malloc(sizeof(uint8_t) * fe_bytes * nSndVals);
	uint8_t *retPtr = ret;
	fetmp = uptr_fe(m_cPKCrypto->get_fe());

	// --> start debug by peic
	//cout << "**** " << __FILE__ << " : " << __LINE__ << endl;
	// <--
	for (k = 0; k < nOTs; k++)
	{
		pBufIdx = pBuf;
		for (u = 0; u < nSndVals; u++)
		{

			if (u == 0)
			{
				// pk0^r
				PK0r->set_pow(pPK0[k].get(), alpha.get()); // FieldElementPow(PK0r, pPK0[k], alpha, m_fParams);
				PK0r->export_to_bytes(pBufIdx);			   // FieldElementToByte(pBufIdx, m_fParams.elebytelen, PK0r);
			}
			else
			{
				// pk^r
				fetmp->set_div(pCr[u].get(), PK0r.get()); // FieldElementDiv(fetmp, pCr[u], PK0r, m_fParams);
				fetmp->export_to_bytes(pBufIdx);		  // FieldElementToByte(pBufIdx, m_fParams.elebytelen, fetmp);
			}
			hashReturn(retPtr, hash_bytes, pBufIdx, fe_bytes, k);
			pBufIdx += fe_bytes;
			retPtr += hash_bytes;
		}
	}

	free(pBuf);
	// free(pCr);
	// free(pC);
}
