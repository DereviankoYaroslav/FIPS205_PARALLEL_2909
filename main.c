#include <stdio.h>
#include <intrin.h>

#include "FIPS_205_Params.h"
#include "FIPS_205_Adr.h"
#include "FIPS_205_Test.h"
#include "AVXconst.h"
//#include "AVXconst.h";
//#include "SHA512.h"
//#include "AVX256.h"
//#if FIPS205_N > 16
//#include "AVX512.h"
//#include "FIPS_205_Hashs.h"
//#endif

// _mm256_i32gather_epi64(src, idx, 8)
//int test__mm256_i32gather_epi64()
//{
//	int res = 0;
//	__declspec (align (64))
//		uint64_t in[4][16];
//	uint64_t* in64 = (uint64_t*)in;
//	__m256i out[16];
//	
//
//	for (int i = 0; i < 4; ++i)
//	{
//		for (int j = 0; j < 16; ++j)
//			in[i][j] = i;
//	}
//
//#ifndef _DEBUG
//	uint64_t tacts, min_tacts = 0xFFFFFFFFFFFFFFFF;
//	for (int j = 0; j < 1024; ++j)
//	{
//		tacts = __rdtsc();
//#endif
//		__m128i ind = _mm_setr_epi32(0, 16, 32, 48);
//		__m128i step = _mm_set1_epi32(1);
//		for (int i = 0; i < 16; ++i)
//		{
//			out[i] = _mm256_i32gather_epi64(in64, ind, 8);
//			ind = _mm_add_epi32(ind, step);
//		}
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts; 
//		if (tacts < min_tacts)
//			min_tacts = tacts;
//	}
//	printf("right convert time = %I64d\n", min_tacts);
//#endif
//	uint64_t out1[16][4];
//#ifndef _DEBUG
//	min_tacts = 0xFFFFFFFFFFFFFFFF;
//	for (int j = 0; j < 1024; ++j)
//	{
//		tacts = __rdtsc();
//#endif
//		for (int i = 0; i < 4; ++i)
//			for (int k = 0; k < 16; ++k)
//			{
//				out1[k][i] = in[i][k];
//			}
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < min_tacts)
//			min_tacts = tacts;
//	}
//	printf("hand convert time = %I64d\n", min_tacts);
//#endif
//	if (memcmp((uint8_t*)out, (uint8_t*)out1, sizeof(out)))
//			res = 1;
//	printf("convert and hand convert: %s\n", res == 0 ? "OK" : "ERROR");
//	__m256i back_out[4];
//#ifndef _DEBUG
//	min_tacts = 0xFFFFFFFFFFFFFFFF;
//	for (int j = 0; j < 1024; ++j)
//	{
//		tacts = __rdtsc();
//#endif
//
//	// back
//	
//	
//		__m128i step1 = _mm_set1_epi32(4);
//		__m128i step2 = _mm_set1_epi32(1);
//		__m128i ind1, ind2;
//	
//		ind1 = _mm_setr_epi32(0, 4, 8, 12);
//
//	
//		back_out[0]= _mm256_i32gather_epi64((uint64_t*)out, ind1, 8);
//		ind1 = _mm_add_epi32(ind1, step2);
//		back_out[1] = _mm256_i32gather_epi64((uint64_t*)out, ind1, 8);
//		ind1 = _mm_add_epi32(ind1, step2);
//		back_out[2] = _mm256_i32gather_epi64((uint64_t*)out, ind1, 8);
//		ind1 = _mm_add_epi32(ind1, step2);
//		back_out[3] = _mm256_i32gather_epi64((uint64_t*)out, ind1, 8);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < min_tacts)
//			min_tacts = tacts;
//	}
//	printf("back convert time = %I64d\n", min_tacts);
//#endif
//	uint64_t back_out1[16][4];
//#ifndef _DEBUG
//	
//	min_tacts = 0xFFFFFFFFFFFFFFFF;
//	for (int j = 0; j < 1024; ++j)
//	{
//		tacts = __rdtsc();
//#endif
//		for (int i = 0; i < 4; ++i)
//		{
//			for (int j = 0; j < 16; ++j)
//			{
//				back_out1[j][i] = out1[i][j];
//			}
//
//		}
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < min_tacts)
//			min_tacts = tacts;
//	}
//	printf("hand back convert time = %I64d\n", min_tacts);
//#endif
//	
//	res = memcmp((const void*)back_out1, (const void*)back_out, 32);
//	printf ("back_out and hand back convert %s\n", res == 0 ? "OK" : "ERROR");
//
//	return res;
//
//}

/*
__m128i low_half = _mm256_extracti128_si256(a, 0);
__m128i high_half = _mm256_extracti128_si256(a, 1);
__m128i high_half = _mm_add_epi32 (high_half, low_half);
high_half = _mm_slli_si128(high_half, 4);
low_half = _mm_zero ();

*/

//void replace_key(__m256i* dest, __m256i key)
//{
//	
//
//	__m256i maska1 = _mm256_setr_epi32(0xFF, 0, 0x0, 0x0, 0x0, 0, 0, 0); // low
//	__m256i maska2 = _mm256_setr_epi32(0xFF00, 0, 0x0, 0x0, 0x0, 0, 0, 0); //  high
//	//__m256i maska3 = _mm256_setr_epi32(0x80, 0, 0, 0, 0, 0, 0, 0);    // for 0x80
//	__m256i maska_for_dest_0 = _mm256_setr_epi32(
//		0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF0000, 0, 0);
//
//#if FIPS205_N == 16
//	__m256i maska3 = _mm256_setr_epi32(0, 0, 0, 0x00800000, 0, 0, 0, (22 + (2 * FIPS205_N)) * 8);
//	__m256i maska_for_dest1 = _mm256_setr_epi32(0xffffffff, 0xFFFFFFFF, 0, 0, 0, 0, 0, 0 );
//
//#elif FIPS205_N == 24
//	__m256i maska3 = _mm256_setr_epi32(0, 0, 0, 0, 0, 0x00800000, 0, (22 + (2 * FIPS205_N)) * 8);
//	__m256i maska_for_dest1 = _mm256_setr_epi32(0xffffffff, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0);
//#else
//	__m256i maska3 = _mm256_setr_epi32(0, 0, 0, 0, 0, 0, 0, 0x00800000+ (22 + (2 * FIPS205_N)) * 8);
//	__m256i maska_for_dest1 = _mm256_setr_epi32(0xffffffff, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0);
//#endif
//	
//	
//	__m128i maska4 = _mm_setr_epi32(0x0000FFFF, 0, 0, 0);
//	
//
//	dest[0] = _mm256_and_si256(dest[0], maska_for_dest_0);
//	
//	__m256i zero = _mm256_setzero_si256();
//	__m256i temp5 = _mm256_bslli_epi128(_mm256_and_si256(key, maska1), 1);	//low * 256
//	__m256i temp6 = _mm256_bsrli_epi128(_mm256_and_si256(key, maska2), 1);	//hig / 256
//	temp5 = _mm256_add_epi32(temp5, temp6); //2 bytes;
//	//__m128i  temp128_0 = _mm256_extracti128_si256(temp5, 0);
//	//__m128i  temp128_1 = _mm256_extracti128_si256(temp5, 1);
//	temp5 = _mm256_permute2x128_si256(temp5, temp5, 1);
//	temp5 = _mm256_bslli_epi128(temp5, 4);	//low * 256
//
//	//temp128_0 = _mm_slli_si128(temp128_0, 4);
//	
//	//temp5 = _mm256_inserti128_si256(temp5, temp128_1, 0);
//	//temp5 = _mm256_inserti128_si256(temp5, temp128_0, 1);
//	dest[0] = _mm256_add_epi32(dest[0], temp5);
//	temp5 = _mm256_alignr_epi8(zero, key, 1);
//	temp5 = _mm256_alignr_epi8(zero, temp5, 1);
//	
//	
//
//	//temp128_0 = _mm256_extracti128_si256(key, 0);
//	//temp128_1 = _mm256_extracti128_si256(key, 1);
//	//__m128i temp128;
//	//// shift key (2 bytes)
//	//temp128 = _mm_slli_si128(_mm_and_si128(temp128_1, maska4), 14);
//	//temp128_0 = _mm_srli_si128(temp128_0, 2);
//	//temp128_1 = _mm_srli_si128(temp128_1, 2);
//	//temp128_0 = _mm_add_epi32(temp128_0, temp128);
//	//temp5 = _mm256_inserti128_si256(temp5, temp128_0, 0);
//	//temp5 =_mm256_inserti128_si256(temp5, temp128_1, 1);
//	//temp5 = _mm256_add_epi32(temp5, maska3);
//
//	__m256i maska = _mm256_load_si256((const __m256i*)u8_maska);
//	
//	__m256i maska6 = _mm256_setr_epi32(0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 0, 0);
//	temp6 = _mm256_and_si256(temp5, maska6);
//	temp6 = _mm256_shuffle_epi8(temp6, maska);	// key after shuffle
//		
//	//temp6 = _mm256_alignr_epi8(zero, temp5, 24);
//	temp6 = _mm256_permute2f128_si256(temp6, temp6, 0x08);
//	temp6 = _mm256_bslli_epi128(temp6, 8);	//low * 256
//
//	dest[0] = _mm256_add_epi32(dest[0], temp6);
//
//	
//	temp5 = _mm256_alignr_epi8(zero, temp5, 8);
//	temp5 = _mm256_add_epi8(temp5, maska3);
//	temp5 = _mm256_shuffle_epi8(temp5, maska);	// key after shuffle
//
//
//	////temp128_0 = _mm256_extracti128_si256(temp5, 0);
//	////temp128_1 = _mm256_extracti128_si256(temp5, 1);
//	////__m128i maska6_128 = _mm256_extracti128_si256(maska6, 0);
//	////temp128 = _mm_slli_si128(_mm_and_si128(temp128_1, maska6_128), 8);
//	////
//	////temp128_0 = _mm_srli_si128(temp128_0, 8);
//	////temp128_1 = _mm_srli_si128(temp128_1, 8);
//	////temp128_0 = _mm_add_epi32(temp128_0, temp128);
//	////temp5 = _mm256_inserti128_si256(temp5, temp128_0, 0);
//	////temp5 = _mm256_inserti128_si256(temp5, temp128_1, 1);
//	//
//	//dest[1] = _mm256_andnot_si256(maska_for_dest1, dest[1]);
//	//dest[1] = _mm256_add_epi32(dest[1], temp5);
//	dest[1] = temp5;
//
//
//
//}
//
////void simple_replace_key(uint8_t adr[22], __m256i key256, __m256i dest[2])
////{
////	uint8_t* dest8 = (uint8_t*)&dest[0];
////	uint8_t* key = (uint8_t*)&key256;
////	memcpy(dest8, adr, 22);
////	memcpy(dest8 + ADR_SIZE, key, FIPS205_N);
////	*(dest8 + ADR_SIZE + FIPS205_N) = 0x80;
////	memset(dest8 + ADR_SIZE + FIPS205_N + 1, 0, 62 - (ADR_SIZE + FIPS205_N + 1));
////	int length = (22 + (2 * FIPS205_N)) * 8;
////	uint32_t* p = (uint32_t*)(dest8 + 60);
////	*p = length;
////	__m256i maska = _mm256_load_si256((const __m256i*)u8_maska);
////	
////	dest[0] = _mm256_shuffle_epi8(dest[0], maska);	// key after shuffle
////	dest[1] = _mm256_shuffle_epi8(dest[1], maska);	// key after shuffle
////
////}
////
////void simple_replace_key8(uint8_t adr[8][22], __m256i key256[8], __m256i dest[8][2])
////{
////	int length = (22 + (2 * FIPS205_N)) * 8;
////	for (int i = 0; i < 8; ++i)
////	{
////		uint8_t *dest8 = (uint8_t*)&dest[i][0];
////		uint8_t* key = (uint8_t*)key256;
////		memcpy(dest8, adr, 22);
////		memcpy(dest8 + ADR_SIZE, key, FIPS205_N);
////		*(dest8 + ADR_SIZE + FIPS205_N) = 0x80;
////		memset(dest8 + ADR_SIZE + FIPS205_N + 1, 0, 62 - (ADR_SIZE + FIPS205_N + 1));
////		
////		uint32_t* p = (uint32_t*)(dest8 + 60);
////		*p = length;
////		__m256i maska = _mm256_load_si256((const __m256i*)u8_maska);
////
////		dest[i][0] = _mm256_shuffle_epi8(dest[i][0], maska);	// key after shuffle
////		dest[i][1] = _mm256_shuffle_epi8(dest[i][1], maska);	// key after shuffle
////	}
////
////}

int main()
{

//	SetAVXConst();
//	
//	uint8_t testadr[32] = {0};
//	setChainAddress(testadr, 1);
//	__m256i* testadr_256 = (__m256i*)testadr;
//	__m256i test_maska = _mm256_setr_epi8 (3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
//		19, 18, 17, 16, 23, 22, 21, 20, 27, 26, 25, 24, 31, 30, 29, 28);
//	testadr_256[0] = _mm256_shuffle_epi8(testadr_256[0], test_maska);
//
//	/*uint8_t info[49];
//	__m256i dest_etalon[2];
//	__m256i dest[2];
//	SUCCESS res = 0;
//	__m256i key;
//
//	uint8_t adr[22];
//	for (int i = 0; i < ADR_SIZE; ++i)
//		adr[i] = i;
//	
//	for (int i = 0; i < FIPS205_N; ++i)
//		key.m256i_u8[i] = 0xA0 + i;
//
//#ifndef _DEBUG
//	uint64_t min_tacts, tacts;
//	min_tacts = 0xFFFFFFFFFFFFFFFF;
//	for (int i = 0; i < 256; ++i)
//	{
//		tacts = __rdtsc();
//#endif
//
//		simple_replace_key(adr, key, dest_etalon);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < min_tacts)
//			min_tacts = tacts;
//
//	}
//	printf("simple_replace_key: time = %I64d\n", min_tacts);
//#endif
//	for (int i = 0; i < 8; ++i)
//		printf("%x ", dest_etalon[0].m256i_u32[i]);
//	printf("\n");
//
//	for (int i = 0; i < 8; ++i)
//		printf("%x ", dest_etalon[1].m256i_u32[i]);
//	printf("\n");
//	printf("\n");
//
//
//
//	
//	
//	memcpy(dest, dest_etalon, sizeof(dest_etalon));
//#ifndef _DEBUG
//	
//	min_tacts = 0xFFFFFFFFFFFFFFFF;
//	for (int i = 0; i < 256; ++i)
//	{
//		memcpy(dest, dest_etalon, sizeof(dest_etalon));
//		tacts = __rdtsc();
//#endif
//	
//		
//		replace_key(dest, key);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < min_tacts)
//			min_tacts = tacts;
//
//	}
//	printf("replace_key: time = %I64d\n", min_tacts);
//#endif
//	for (int i = 0; i < 8; ++i)
//		printf("%x ", dest[0].m256i_u32[i]);
//	printf("\n");
//
//	for (int i = 0; i < 8; ++i)
//		printf("%x ", dest[1].m256i_u32[i]);
//	printf("\n");
//	printf("\n");
//
//
//
//
//	if (memcmp(dest_etalon, dest, sizeof(dest_etalon)) != 0)
//		printf("replace_key ERROR\n");
//	else
//		printf("replace_key OK\n");*/

	print_params();
	int res = 0;


	SetAVXConst();
#ifdef _JSON_FILE
	res = TestJSon();
	printf("%s:\tTestJSon - %s\n", smodes[FIPS_205_MODE], res == OK ? "OK" : "ERROR"); 
#endif

	/*res = test_AVX_const();
	printf("test_AVX_const? %s\n", res == 0 ? "OK" : "ERROR");*/

//	res = test_AVX_sha256_WITH_PREDCALC8();
	//test_AVX_sha256_WITH_PREDCALC8
//	printf("test_AVX_sha256_WITH_PREDCALC8? %s\n", res == 0 ? "OK" : "ERROR");
	res = test_2_b();
	printf("test_2_b? %s\n", res == 0 ? "OK" : "ERROR");

	/*{
		__m256i dest[2];
		__m256i key_ = { 0 };
		for (int i = 0; i < FIPS205_N; ++i)
			key_.m256i_i8[i] = 0x20 + i;

		replace_key(dest, key_, 2);
	}*/

	/*res = test__mm256_i32gather_epi64();
	printf("test_fun_256 %s\n", res == OK ? "OK" : "ERROR");*/
#if FIPS205_N > 16
	/*res = test_fun_256();
	printf("test_fun_256 %s\n", res == OK ? "OK" : "ERROR");*/

	res = test_AVX_sha512();
	printf("test_AVX_sha512 %s\n", res == OK ? "OK" : "ERROR");

	res = test_AVX_sha512_compress4();
	printf("test_AVX_sha512_compress4 %s\n", res == OK ? "OK" : "ERROR");

	/*res = test_sha512();
	printf("test_sha512 %s\n", res == OK ? "OK" : "ERROR");*/
	


	/*res = test_sha512_with_predcalc();
	printf("test_sha512_with_predcalc %s\n", res == OK ? "OK" : "ERROR");*/
#endif
	/*uint32_t arr[64];
	for (int i = 0; i < 64; ++i)
		arr[i] = i;
	__m256i idx = _mm256_setr_epi32(0, 4, 8, 12, 16, 20, 24, 28 );
	__m256i _1_256 = _mm256_set1_epi32(1);
	__m256i r[8];
	for (int i = 0; i < 8; ++i)
	{
		r[i] = _mm256_i32gather_epi32(arr, idx, 4);
		idx = _mm256_add_epi32(idx, _1_256);
	}*/
	
	

	// int test_fun_128()
	//res = test_fun_128();
	//printf("test_fun_128 %s\n", res == OK ? "OK" : "ERROR");

	//res = test_AVX_sha256_WITH_PREDCALC4();
	//printf("test_AVX_sha256_WITH_PREDCALC4 %s\n", res == OK ? "OK" : "ERROR");

	//// test_AVX_sha256_compress4
	//res = test_AVX_sha256_compress4();
	//printf("test_AVX_sha256_compress4 %s\n", res == OK ? "OK" : "ERROR");


	res = test_addr();
	printf("test_addr %s\n", res == OK ? "OK" : "ERROR");
	res = test_AVX_sha256();
	printf("test_AVX_sha256 %s\n", res == OK ? "OK" : "ERROR");
	// int test_MGF1_AVX_SHA256()
	res = test_MGF1_AVX_sha256 ();
	printf("test_MGF1_AVX_sha256 %s\n", res == OK ? "OK" : "ERROR");
#if FIPS205_N == 16
	res = test_AVX_HMAC();
	printf("test_AVX_HMAC %s\n", res == OK ? "OK" : "ERROR");
#endif
//#if FIPS205_N > 16
//	res = test_AVX_sha512();
//	
//	printf("test_AVX_sha512 %s\n", res == OK ? "OK" : "ERROR");
//	//res = test_HMAC512();
//	//printf("test_HMAC512 %s\n", res == OK ? "OK" : "ERROR");
//	//res = test_AVX_HMAC512();
//	//printf("test_AVX__HMAC512 %s\n", res == OK ? "OK" : "ERROR");
//	res = test_AVX_MGF1_sha512();
//	printf("test_AVX_MGF1_sha512 %s\n", res == OK ? "OK" : "ERROR");
//
//	//int test_AVX_sha512_compress4()
//	res = test_AVX_sha512_compress4();
//	printf("test_AVX_sha512_compress4 %s\n", res == OK ? "OK" : "ERROR");
//
//	res = test_AVX_MGF1_sha512();
//	printf("test_AVX_MGF1_sha512 %s\n", res == OK ? "OK" : "ERROR");
//
//	/*res = test_PRF();
//	printf("test_PRF %s\n", res == OK ? "OK" : "ERROR");*/
//	res = test_AVX_sha512_WITH_PREDCALC4();
//	printf("test_AVX_sha512_WITH_PREDCALC4 %s\n", res == OK ? "OK" : "ERROR");
//#endif
	//res = test_AVX_sha256_WITH_PREDCALC8();
	//printf("test_AVX_sha256_WITH_PREDCALC8 %s\n", res == OK ? "OK" : "ERROR");

	//
	//res = test_AVX_F();
	//printf("test_AVX_F (PRF) %s\n", res == OK ? "OK" : "ERROR");
	///*res = test_AVX_F4();
	//printf("test_AVX_F4 %s\n", res == OK ? "OK" : "ERROR");*/

	//res = test_AVX_HASH();
	//printf("test_AVX_HASH %s\n", res == OK ? "OK" : "ERROR");

	//res = test_AVX_HMsg();
	//printf("test_AVX_HMsg %s\n", res == OK ? "OK" : "ERROR");

	//res = test_AVX_PRFmsg();
	//printf("test_AVX_PRFmsg %s\n", res == OK ? "OK" : "ERROR");

	////uint64_t state[8];
	//// 
	//res = test_Tl();
	//printf("test_Tl %s\n", res == OK ? "OK" : "ERROR");
	//
	//res = test_AVX_PREDCALC_W_sha();
	//printf("test_AVX_PREDCALC_W_sha %s\n", res == OK ? "OK" : "ERROR");
	// test_wots_gensk_and_pk
	res = test_wots_gensk_and_pk();
	printf("test_wots_gensk_and_pk %s\n", res == OK ? "OK" : "ERROR");

	res = test_base_2b();
	printf("test_base_2b %s\n", res == OK ? "OK" : "ERROR");

	res = test_replace_key();
	printf("test_replace_key %s\n", res == OK ? "OK" : "ERROR");
	
	/*res = test_wots_chain();
	printf("test_wots_chain %s\n", res == OK ? "OK" : "ERROR");*/

	res = test_FIPS205_wots();
	printf("test_FIPS205_wots_gen_sign %s\n", res == OK ? "OK" : "ERROR");

	res = test_FIPS205_xmss();
	printf("test_FIPS205_xmss %s\n", res == OK ? "OK" : "ERROR");

	//res = test_FIPS205_HT();
	//printf("test_FIPS205_HT %s\n", res == OK ? "OK" : "ERROR");

	//res = test_FIPS205_fors();
	//printf("test_FIPS205_fors %s\n", res == OK ? "OK" : "ERROR");

	res = test_FIPS205_fors_and_HT();
	printf("test_FIPS205_fors_and_HT %s\n", res == OK ? "OK" : "ERROR");

	res = test_internal_function();
	printf("test_internal_function %s\n", res == OK ? "OK" : "ERROR");
	return res;
}
