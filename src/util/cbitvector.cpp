/*
 * BitVector.cpp
 *
 *  Created on: May 6, 2013
 *      Author: mzohner
 */

#include "cbitvector.h"

/* Fill the bitvector with random values and pre-initialize the key to the seed-key*/
void CBitVector::FillRand(int bits, crypto *crypt)
{
	InitRand(crypt);
	FillRand(bits);
}

/* Fill random values using the pre-defined AES key */
void CBitVector::FillRand(int bits)
{
	if (bits > m_nByteSize << 3)
		Create(bits);

	/*uint8_t buf[AES_BYTES];
	memset(buf, 0, AES_BYTES);

	for(int i = 0; i < (int) sizeof(int); i++) {
		buf[i] = (cnt>>(8*i)) & 0xFF;
	}*/

	if (m_cCrypto == NULL)
	{
		cerr << "FillRand called without initializing AES key" << endl;
		return;
	}

	// int size = ceil_divide(bits, AES_BITS);
	// unsigned long long* counter = (unsigned long long*) buf;

	m_cCrypto->gen_rnd(m_pBits, (bits >> 3));

	/*for(int i = 0; i < size; i++, counter[0]++, cnt++)
	{
		MPC_AES_ENCRYPT(m_nKey, m_pBits + i*AES_BYTES, buf);
	}*/
	// cnt = (int) counter[0];
}

void CBitVector::Create(int numelements, int elementlength, crypto *crypt)
{
	CreateRand(numelements * elementlength, crypt);
	m_nElementLength = elementlength;
	m_nNumElements = numelements;
	m_nNumElementsDimB = 1;
}

void CBitVector::CreateRand(int bits, crypto *crypt)
{
	FillRand(bits, crypt);
}

void CBitVector::Create(int bits)
{
	if (bits == 0)
		bits = DEFAULT_BITSIZE;
	// cout << "creating " << bits << " sized vector" << endl;
	if (m_nByteSize > 0)
		free(m_pBits);
	m_nByteSize = ceil_divide(bits, 8);
	m_pBits = (uint8_t *)calloc(m_nByteSize, sizeof(uint8_t)); // * m_nSize);
	// m_pBits = (uint8_t*) malloc(m_nSize *  sizeof(uint8_t));// * m_nSize);
	if (m_pBits == NULL)
	{
		cerr << "CBitVector: memory allocation not successful, requested " << m_nByteSize << " bytes" << endl;
		exit(0);
	}
	m_nElementLength = 1;
	m_nNumElements = m_nByteSize;
	m_nNumElementsDimB = 1;
}

void CBitVector::Create(int numelements, int elementlength)
{
	Create(numelements * elementlength);
	m_nElementLength = elementlength;
	m_nNumElements = numelements;
	m_nNumElementsDimB = 1;
}

void CBitVector::Create(int numelementsDimA, int numelementsDimB, int elementlength)
{
	Create(numelementsDimA * numelementsDimB * elementlength);
	m_nElementLength = elementlength;
	m_nNumElements = numelementsDimA;
	m_nNumElementsDimB = numelementsDimB;
}
void CBitVector::Create(int numelementsDimA, int numelementsDimB, int elementlength, crypto *crypt)
{
	CreateRand(numelementsDimA * numelementsDimB * elementlength, crypt);
	m_nElementLength = elementlength;
	m_nNumElements = numelementsDimA;
	m_nNumElementsDimB = numelementsDimB;
}

void CBitVector::ResizeinBytes(int newSizeBytes)
{
	uint8_t *tBits = m_pBits;
	int tSize = m_nByteSize;

	m_nByteSize = newSizeBytes;
	m_pBits = (uint8_t *)calloc(m_nByteSize, sizeof(uint8_t));

	memcpy(m_pBits, tBits, tSize);

	free(tBits);
}

void CBitVector::Copy(uint8_t *p, int pos, int len)
{
	//#ifdef ASSERT
	if (pos + len > m_nByteSize)
	{
		if (m_pBits)
			ResizeinBytes(pos + len);
		else
		{
			CreateBytes(pos + len);
		}
	}
	//#endif
	memcpy(m_pBits + pos, p, len);
}

// pos and len in bits
void CBitVector::SetBits(uint8_t *p, int pos, int len)
{

	if (len < 1 || (pos + len) > (m_nByteSize << 3))
		return;

	if (len == 1)
	{
		SetBitNoMask(pos, *p);
		return;
	}
	if (!((pos & 0x07) || (len & 0x07)))
	{

		SetBytes(p, pos >> 3, len >> 3);
		return;
	}
	int posctr = pos >> 3;
	int lowermask = pos & 7;
	int uppermask = 8 - lowermask;

	int i;
	uint8_t temp;
	for (i = 0; i < len / (sizeof(uint8_t) * 8); i++, posctr++)
	{
		temp = p[i];
		m_pBits[posctr] = (m_pBits[posctr] & RESET_BIT_POSITIONS[lowermask]) | ((temp << lowermask) & 0xFF);
		m_pBits[posctr + 1] = (m_pBits[posctr + 1] & RESET_BIT_POSITIONS_INV[uppermask]) | (temp >> uppermask);
		// cout << "Iteration for whole byte done" << endl;
	}
	int remlen = len & 0x07;
	if (remlen)
	{
		temp = p[i] & RESET_BIT_POSITIONS[remlen];
		// cout << "temp = " << (unsigned int) temp << endl;
		if (remlen <= uppermask)
		{
			// cout << "Setting " << remlen  << " lower bits with lowermask = " << lowermask << ", and temp " << (unsigned int) temp << endl;
			m_pBits[posctr] = (m_pBits[posctr] & (~(((1 << remlen) - 1) << lowermask))) | ((temp << lowermask) & 0xFF);
		}
		else
		{
			// cout << "Setting " << remlen  << " bits with lowermask = " << lowermask << ", uppermask = " << uppermask << ", and temp = " << (unsigned int) temp << endl;
			m_pBits[posctr] = (m_pBits[posctr] & RESET_BIT_POSITIONS[lowermask]) | ((temp << lowermask) & 0xFF);
			m_pBits[posctr + 1] = (m_pBits[posctr + 1] & (~(((1 << (remlen - uppermask)) - 1)))) | (temp >> uppermask);
		}
	}
}

void CBitVector::SetBitsToZero(int bitpos, int bitlen)
{
	int firstlim = ceil_divide(bitpos, 8);
	int firstlen = ceil_divide(bitlen - (bitpos % 8), 8);
	for (int i = bitpos; i < firstlim; i++)
	{
		SetBitNoMask(i, 0);
	}
	if (bitlen > 7)
	{
		memset(m_pBits + firstlim, 0, firstlen);
	}
	for (int i = (firstlim + firstlen) << 8; i < bitpos + bitlen; i++)
	{
		SetBitNoMask(i, 0);
	}
}

void CBitVector::GetBits(uint8_t *p, uint64_t pos, uint64_t len)
{
	if (len < 1 || (pos + len) > (uint64_t)m_nByteSize << 3)
		return;
	if (len == 1)
	{
		*p = GetBitNoMask(pos);
		return;
	}
	if (!((pos & 0x07) || (len & 0x07)))
	{
		GetBytes(p, pos >> 3, len >> 3);
		return;
	}
	int posctr = pos >> 3;
	int lowermask = pos & 7;
	int uppermask = 8 - lowermask;

	int i;
	uint8_t temp;
	for (i = 0; i < len / (sizeof(uint8_t) * 8); i++, posctr++)
	{
		p[i] = ((m_pBits[posctr] & GET_BIT_POSITIONS[lowermask]) >> lowermask) & 0xFF;
		p[i] |= (m_pBits[posctr + 1] & GET_BIT_POSITIONS_INV[uppermask]) << uppermask;
	}
	int remlen = len & 0x07;
	if (remlen)
	{
		// temp = p[i] & GET_BIT_POSITIONS[remlen];
		if (remlen <= uppermask)
		{
			// cout << "Getting " << remlen  << " lower bits with lowermask = " << lowermask << ", " << (unsigned int) m_pBits[posctr] << endl;
			p[i] = ((m_pBits[posctr] & (((1 << remlen) - 1 << lowermask))) >> lowermask) & 0xFF;
			// cout << "p[i] = " << (unsigned int) p[i] << endl;
		}
		else
		{
			// cout << "Getting upper" << endl;
			// cout << "Getting " << remlen  << " upper bits with lowermask = " << lowermask << ", " << (unsigned int) m_pBits[posctr] << ", and uppermask = "
			//		<< uppermask << ", " << (unsigned int) m_pBits[posctr+1] << endl;
			p[i] = ((m_pBits[posctr] & GET_BIT_POSITIONS[lowermask]) >> lowermask) & 0xFF;
			p[i] |= (m_pBits[posctr + 1] & (((1 << (remlen - uppermask)) - 1))) << uppermask;
			// cout << "p[i] = " << (unsigned int) p[i] << endl;
		}
	}
}

void CBitVector::XORBytesReverse(uint8_t *p, int pos, int len)
{
	uint8_t *src = p;
	uint8_t *dst = m_pBits + pos;
	uint8_t *lim = dst + len;
	while (dst != lim)
	{
		*dst++ ^= REVERSE_BYTE_ORDER[*src++];
	}
}

// XOR bits given an offset on the bits for p which is not necessarily divisible by 8
void CBitVector::XORBitsPosOffset(uint8_t *p, int ppos, int pos, int len)
{
	for (int i = pos, j = ppos; j < ppos + len; i++, j++)
	{
		m_pBits[i / 8] ^= (((p[j / 8] & (1 << (j % 8))) >> j % 8) << i % 8);
	}
}

void CBitVector::XORBits(uint8_t *p, int pos, int len)
{
	XORBits(p, (uint64_t)pos, (uint64_t)len);
}

void CBitVector::XORBits(uint8_t *p, uint64_t pos, uint64_t len)
{
	if (len < 1 || (pos + len) > ((uint64_t)m_nByteSize) << 3)
	{
		// cout << "m_nSize = " << m_nSize << ", pos+len = " << (pos + len)/8 << endl;
		return;
	}
	if (len == 1)
	{
		XORBitNoMask(pos, *p);
		return;
	}
	if (!((pos & 0x07) || (len & 0x07)))
	{
		XORBytes(p, pos >> 3, len >> 3);
		return;
	}
	uint64_t posctr = pos >> 3;
	uint64_t lowermask = pos & 7;
	uint64_t uppermask = 8 - lowermask;

	uint64_t i;
	uint8_t temp;
	for (i = 0; i < len / (sizeof(uint8_t) * 8); i++, posctr++)
	{
		temp = p[i];
		m_pBits[posctr] ^= ((temp << lowermask) & 0xFF);
		m_pBits[posctr + 1] ^= (temp >> uppermask);
		// cout << "Iteration for whole byte done" << endl;
	}
	uint64_t remlen = len & 0x07;
	if (remlen)
	{
		temp = p[i] & RESET_BIT_POSITIONS[remlen];
		// cout << "temp = " << (unsigned int) temp << endl;
		if (remlen <= uppermask)
		{
			// cout << "Setting " << remlen  << " lower bits with lowermask = " << lowermask << ", and temp " << (unsigned int) temp << endl;
			m_pBits[posctr] ^= ((temp << lowermask) & 0xFF);
		}
		else
		{
			// cout << "Setting " << remlen  << " bits with lowermask = " << lowermask << ", uppermask = " << uppermask << ", and temp = " << (unsigned int) temp << endl;
			m_pBits[posctr] ^= ((temp << lowermask) & 0xFF);
			m_pBits[posctr + 1] ^= (temp >> uppermask);
		}
	}
}

void CBitVector::ORByte(int pos, uint8_t p)
{
	m_pBits[pos] |= p;
}

// optimized bytewise for set operation
void CBitVector::GetBytes(uint8_t *p, uint64_t pos, uint64_t len)
{

	uint8_t *src = m_pBits + pos;
	uint8_t *dst = p;
	// Do many operations on REGSIZE types first and then (if necessary) use bytewise operations
	GetBytes((REGSIZE *)dst, (REGSIZE *)src, ((REGSIZE *)dst) + (len >> SHIFTVAL));
	dst += ((len >> SHIFTVAL) << SHIFTVAL);
	src += ((len >> SHIFTVAL) << SHIFTVAL);
	GetBytes(dst, src, dst + (len & ((1 << SHIFTVAL) - 1)));
}

template <class T>
void CBitVector::GetBytes(T *dst, T *src, T *lim)
{
	while (dst != lim)
	{
		*dst++ = *src++;
	}
}

void CBitVector::XORBytes(uint8_t *p, uint64_t pos, uint64_t len)
{
	if ((pos + len) > (uint64_t)m_nByteSize)
	{
		cerr << "Error Trying to xor at byte position: " << pos << " with len = " << len << " with m_nSize = " << m_nByteSize << endl;
		exit(0);
	}

	uint8_t *dst = m_pBits + pos;
	uint8_t *src = p;
	// Do many operations on REGSIZE types first and then (if necessary) use bytewise operations
	XORBytes((REGSIZE *)dst, (REGSIZE *)src, ((REGSIZE *)dst) + (len >> SHIFTVAL));
	dst += ((len >> SHIFTVAL) << SHIFTVAL);
	src += ((len >> SHIFTVAL) << SHIFTVAL);
	XORBytes(dst, src, dst + (len & ((1 << SHIFTVAL) - 1)));
}

// Generic bytewise XOR operation
template <class T>
void CBitVector::XORBytes(T *dst, T *src, T *lim)
{
	while (dst != lim)
	{
		*dst++ ^= *src++;
	}
}

void CBitVector::XORRepeat(uint8_t *p, int pos, int len, int num)
{
	unsigned short *dst = (unsigned short *)(m_pBits + pos);
	unsigned short *src = (unsigned short *)p;
	unsigned short *lim = (unsigned short *)(m_pBits + pos + len);
	for (int i = num; dst != lim;)
	{
		*dst++ ^= *src++;
		if (!(--i))
		{
			src = (unsigned short *)p;
			i = num;
		}
	}
}

// optimized bytewise for set operation
void CBitVector::SetBytes(uint8_t *p, int pos, int len)
{

	uint8_t *dst = m_pBits + pos;
	uint8_t *src = p;
	// REGSIZE rem = SHIFTVAL-1;
	// Do many operations on REGSIZE types first and then (if necessary) use bytewise operations
	SetBytes((REGSIZE *)dst, (REGSIZE *)src, ((REGSIZE *)dst) + (len >> SHIFTVAL));
	dst += ((len >> SHIFTVAL) << SHIFTVAL);
	src += ((len >> SHIFTVAL) << SHIFTVAL);
	SetBytes(dst, src, dst + (len & ((1 << SHIFTVAL) - 1)));
}

template <class T>
void CBitVector::SetBytes(T *dst, T *src, T *lim)
{
	while (dst != lim)
	{
		*dst++ = *src++;
	}
}

// optimized bytewise for AND operation
void CBitVector::ANDBytes(uint8_t *p, int pos, int len)
{

	uint8_t *dst = m_pBits + pos;
	uint8_t *src = p;
	// Do many operations on REGSIZE types first and then (if necessary) use bytewise operations
	ANDBytes((REGSIZE *)dst, (REGSIZE *)src, ((REGSIZE *)dst) + (len >> SHIFTVAL));
	dst += ((len >> SHIFTVAL) << SHIFTVAL);
	src += ((len >> SHIFTVAL) << SHIFTVAL);
	ANDBytes(dst, src, dst + (len & ((1 << SHIFTVAL) - 1)));
}
template <class T>
void CBitVector::ANDBytes(T *dst, T *src, T *lim)
{
	while (dst != lim)
	{
		*dst++ &= *src++;
	}
}

void CBitVector::SetXOR(uint8_t *p, uint8_t *q, int pos, int len)
{
	Copy(p, pos, len);
	XORBytes(q, pos, len);
}

void CBitVector::SetAND(uint8_t *p, uint8_t *q, int pos, int len)
{
	Copy(p, pos, len);
	ANDBytes(q, pos, len);
}

void CBitVector::Print(int fromBit, int toBit)
{
	int to = toBit > (m_nByteSize << 3) ? (m_nByteSize << 3) : toBit;
	for (int i = fromBit; i < to; i++)
	{
		cout << (unsigned int)GetBitNoMask(i);
	}
	cout << endl;
}

void CBitVector::PrintHex(int fromByte, int toByte)
{
	for (int i = fromByte; i < toByte; i++)
	{
		cout << setw(2) << setfill('0') << (hex) << ((unsigned int)m_pBits[i]);
	}
	cout << (dec) << endl;
}

void CBitVector::PrintHex()
{
	for (int i = 0; i < m_nByteSize; i++)
	{
		cout << setw(2) << setfill('0') << (hex) << ((unsigned int)m_pBits[i]);
	}
	cout << (dec) << endl;
}

void CBitVector::PrintBinaryMasked(int from, int to)
{
	for (int i = from; i < to; i++)
	{
		cout << (unsigned int)GetBit(i);
	}
	cout << endl;
}

void CBitVector::PrintContent()
{
	if (m_nElementLength == 1)
	{
		PrintHex();
		return;
	}
	if (m_nNumElementsDimB == 1)
	{
		for (int i = 0; i < m_nNumElements; i++)
		{
			cout << Get<int>(i) << ", ";
		}
		cout << endl;
	}
	else
	{
		for (int i = 0; i < m_nNumElements; i++)
		{
			cout << "(";
			for (int j = 0; j < m_nNumElementsDimB - 1; j++)
			{
				cout << Get2D<int>(i, j) << ", ";
			}
			cout << Get2D<int>(i, m_nNumElementsDimB - 1);
			cout << "), ";
		}
		cout << endl;
	}
}

BOOL CBitVector::IsEqual(CBitVector &vec)
{
	if (vec.GetSize() != m_nByteSize)
		return false;

	uint8_t *ptr = vec.GetArr();
	for (int i = 0; i < m_nByteSize; i++)
	{
		if (ptr[i] != m_pBits[i])
			return false;
	}
	return true;
}

BOOL CBitVector::IsEqual(CBitVector &vec, int from, int to)
{
	if (vec.GetSize() * 8 < to || m_nByteSize * 8 < to || from > to)
		return false;

	for (int i = from; i < to; i++)
	{
		if (vec.GetBit(i) != GetBit(i))
			return false;
	}
	return true;
}

void CBitVector::XOR_no_mask(int p, int bitPos, int bitLen)
{
	if (!bitLen)
		return;

	int i = bitPos >> 3, j = 8 - (bitPos & 0x7), k;

	m_pBits[i++] ^= (GetIntBitsFromLen(p, 0, min(j, bitLen)) << (8 - j)) & 0xFF;

	for (k = bitLen - j; k > 0; k -= 8, i++, j += 8)
	{
		m_pBits[i] ^= GetIntBitsFromLen(p, j, min(8, k));
	}
}

unsigned int CBitVector::GetInt(int bitPos, int bitLen)
{
	int ret = 0, i = bitPos >> 3, j = (bitPos & 0x7), k;
	ret = (m_pBits[i++] >> (j)) & (GetMask(min(8, bitLen)));
	if (bitLen == 1)
		return ret;
	// cout << "MpBits: " << (unsigned int) m_pBits[i-1] << ", ret: " << ret << endl;
	j = 8 - j;
	for (k = bitLen - j; i < (bitPos + bitLen + 7) / 8 - 1; i++, j += 8, k -= 8)
	{
		// ret |= REVERSE_BYTE_ORDER[m_pBits[i+pos]] << (i*8);
		ret |= m_pBits[i] << j;
		// cout << "MpBits: " <<(unsigned int) m_pBits[i] << ", ret: " << ret << ", j: " << j << endl;
		// m_pBits[i+pos] = ( ((REVERSE_NIBBLE_ORDER[(p>>((2*i)*4))&0xF] << 4) | REVERSE_NIBBLE_ORDER[(p>>((2*i+1)*4))&0xF])  & 0xFF);//((p>>((2*i+1)*4))&0xF) | ((p>>((2*i)*4))&0xF) & 0xFF;
	}
	ret |= (m_pBits[i] & SELECT_BIT_POSITIONS[k]) << j; // for the last execution 0<=k<=8
	// cout << "MpBits: " <<(unsigned int) m_pBits[i] << ", ret: " << ret << ", k = " << k <<  ", selects: " << (unsigned int) SELECT_BIT_POSITIONS[k] << ", j: " << j << endl;
	return ret;
}

void CBitVector::SimpleTranspose(int rows, int columns)
{
	CBitVector temp(rows * columns);
	temp.Copy(m_pBits, 0, rows * columns / 8);
	for (int i = 0; i < rows; i++)
	{
		for (int j = 0; j < columns; j++)
		{
			SetBit(j * rows + i, temp.GetBit(i * columns + j));
		}
	}
}

// A transposition algorithm for bit-matrices of size 2^i x 2^j
void CBitVector::EklundhBitTranspose(int rows, int columns)
{
	REGISTER_SIZE *rowaptr; // ptr;
	REGISTER_SIZE *rowbptr;
	REGISTER_SIZE temp_row;
	REGISTER_SIZE mask;
	REGISTER_SIZE invmask;
	REGISTER_SIZE *lim = NULL;

	// lim = (REGISTER_SIZE*) m_pBits + ceil_divide(rows * columns, 8);

	int offset = (columns >> 3) / sizeof(REGISTER_SIZE);
	int numiters = ceil_log2(rows);
	int srcidx = 1, destidx;
	int rounds;
	int p;

	// If swapping is performed on bit-level
	for (int i = 0, j; i < LOG2_REGISTER_SIZE; i++, srcidx *= 2)
	{
		destidx = offset * srcidx;
		rowaptr = (REGISTER_SIZE *)m_pBits;
		rowbptr = rowaptr + destidx; // ptr = temp_mat;

		// cout << "numrounds = " << numrounds << " iterations: " << LOG2_REGISTER_SIZE << ", offset = " << offset << ", srcidx = " << srcidx << ", destidx = " << destidx << endl;
		// Preset the masks that are required for bit-level swapping operations
		mask = TRANSPOSITION_MASKS[i];
		invmask = ~mask;

		// If swapping is performed on byte-level reverse operations due to little-endian format.
		rounds = rows / (srcidx * 2);
		if (i > 2)
		{
			for (int j = 0; j < rounds; j++)
			{
				for (lim = rowbptr + destidx; rowbptr < lim; rowaptr++, rowbptr++)
				{
					temp_row = *rowaptr;
					*rowaptr = ((*rowaptr & mask) ^ ((*rowbptr & mask) << srcidx));
					*rowbptr = ((*rowbptr & invmask) ^ ((temp_row & invmask) >> srcidx));
				}
				rowaptr += destidx;
				rowbptr += destidx;
			}
		}
		else
		{
			for (int j = 0; j < rounds; j++)
			{
				for (lim = rowbptr + destidx; rowbptr < lim; rowaptr++, rowbptr++)
				{
					temp_row = *rowaptr;
					*rowaptr = ((*rowaptr & invmask) ^ ((*rowbptr & invmask) >> srcidx));
					*rowbptr = ((*rowbptr & mask) ^ ((temp_row & mask) << srcidx));
				}
				rowaptr += destidx;
				rowbptr += destidx;
			}
		}
	}

	for (int i = LOG2_REGISTER_SIZE, j, swapoffset = 1, dswapoffset; i < numiters; i++, srcidx *= 2, swapoffset = swapoffset << 1)
	{
		destidx = offset * srcidx;
		dswapoffset = swapoffset << 1;
		rowaptr = (REGISTER_SIZE *)m_pBits;
		rowbptr = rowaptr + destidx - swapoffset; // ptr = temp_mat;

		rounds = rows / (srcidx * 2);
		for (int j = 0; j < rows / (srcidx * 2); j++)
		{
			for (p = 0, lim = rowbptr + destidx; p < destidx && rowbptr < lim; p++, rowaptr++, rowbptr++)
			{
				if ((p % dswapoffset >= swapoffset))
				{
					temp_row = *rowaptr;
					*rowaptr = *rowbptr;
					*rowbptr = temp_row;
				}
			}
			rowaptr += destidx;
			rowbptr += destidx;
		}
	}

	if (columns > rows)
	{
		uint8_t *tempvec = (uint8_t *)malloc((rows * columns) / 8);
		memcpy(tempvec, m_pBits, ((rows / 8) * columns));

		rowaptr = (REGISTER_SIZE *)m_pBits;
		int rowbytesize = rows / 8;
		int rowregsize = rows / (sizeof(REGISTER_SIZE) * 8);
		for (int i = 0; i < columns / rows; i++)
		{
			rowbptr = (REGISTER_SIZE *)tempvec;
			rowbptr += (i * rowregsize);
			for (int j = 0; j < rows; j++, rowaptr += rowregsize, rowbptr += offset)
			{
				memcpy(rowaptr, rowbptr, rowbytesize);
			}
		}
		free(tempvec);
	}

	if (rows > columns)
	{
		uint8_t *tempvec = (uint8_t *)malloc((rows * columns) / 8);
		memcpy(tempvec, m_pBits, ((rows / 8) * columns));

		REGISTER_SIZE *rowaptr = (REGISTER_SIZE *)m_pBits;
		std::size_t colbytesize = columns / 8;
		std::size_t colregsize = columns / (sizeof(REGISTER_SIZE) * 8);
		std::size_t offset_cols = (columns * columns) / (sizeof(REGISTER_SIZE) * 8);

		for (std::size_t i = 0; i < columns; i++)
		{
			rowbptr = (REGISTER_SIZE *)tempvec;
			rowbptr += (i * colregsize);
			for (std::size_t j = 0; j < rows / columns; j++, rowaptr += colregsize, rowbptr += offset_cols)
			{
				memcpy(rowaptr, rowbptr, colbytesize);
			}
		}
		free(tempvec);
	}
}
