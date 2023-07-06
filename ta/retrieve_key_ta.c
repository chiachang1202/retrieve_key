/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <inttypes.h>
#include <retrieve_key_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "mbedtls/config.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pem.h"

#define RSA_KEY_SIZE 512

static TEE_Result initialize_rsa_keypair(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_storage = TEE_HANDLE_NULL;
	// TEE_ObjectInfo object_info;
	TEE_Result res = TEE_SUCCESS;
	uint32_t key_obj_flag;
	char *key_id;
	size_t key_id_sz;

	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	
	DMSG("\n========== Param check successfully. ==========\n");

	key_id_sz = params[0].memref.size;
	key_id = TEE_Malloc(key_id_sz, 0);
	if (!key_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(key_id, params[0].memref.buffer, key_id_sz);

	// const uint8_t rsa1024_modulus[] = {
	// 	0xd3, 0x30, 0x5a, 0x17, 0x71, 0x5c, 0xdc, 0x72, 0x83, 0x12, 0xb6, 0x7d, 0xc8, 0x73, 0x0a, 
	// 	0x1d, 0x29, 0x1e, 0x88, 0x8b, 0xba, 0x72, 0xe8, 0x16, 0x80, 0xb1, 0xbb, 0xfa, 0x83, 0x41,
	// 	0xcb, 0xee, 0x5c, 0x0b, 0x05, 0xc6, 0x4e, 0x21, 0x7e, 0x43, 0xb8, 0x2f, 0x3f, 0xbe, 0x42, 
	// 	0x2d, 0xf0, 0xb5, 0x55, 0xdb, 0xeb, 0x8f, 0x55, 0xf5, 0x16, 0xdd, 0xf1, 0x6c, 0x9a, 0x36, 
	// 	0x82, 0x3e, 0xcc, 0x74, 0xfc, 0xcc, 0x54, 0x30, 0xc6, 0x79, 0x67, 0x3e, 0xe9, 0xed, 0x30, 
	// 	0x56, 0x1b, 0x21, 0xed, 0x40, 0x79, 0xb9, 0xf6, 0x7a, 0x6f, 0x9e, 0x1d, 0x8e, 0xa3, 0xe2, 
	// 	0xee, 0x58, 0xe6, 0x03, 0x34, 0xce, 0xa9, 0x00, 0x99, 0xca, 0xe0, 0x91, 0x13, 0xee, 0x73, 
	// 	0x62, 0xf7, 0x84, 0x68, 0x3a, 0xf1, 0xc9, 0x0d, 0xdc, 0xb7, 0x36, 0x05, 0x56, 0x53, 0xbf, 
	// 	0x18, 0x05, 0x4a, 0xe7, 0xeb, 0xff, 0xdb, 0x79 };
	// const uint8_t rsa1024_pub_exp[] = { 0x01, 0x00, 0x01 };
	// const uint8_t rsa1024_priv_exp[] = {
	// 	0xa6, 0xa1, 0x06, 0xe4, 0x6a, 0x48, 0x87, 0x93, 0x3e, 0x81, 0xfc, 0x45, 0x20, 0x6c, 0x4c,
	// 	0x35, 0x97, 0xe5, 0x04, 0x7d, 0xa2, 0xfd, 0xd8, 0xcb, 0x30, 0x7d, 0x8b, 0xc0, 0xeb, 0xe1, 
	// 	0x75, 0x43, 0x3b, 0x92, 0x62, 0xdb, 0x05, 0x78, 0x7d, 0xc4, 0x76, 0xc5, 0xa8, 0xf8, 0xb8,
	// 	0x04, 0xc1, 0x60, 0x82, 0x3f, 0x04, 0x0c, 0x53, 0x19, 0x0f, 0x12, 0xcc, 0xd3, 0x10, 0x96,
	// 	0x23, 0x8b, 0xe3, 0x0a, 0x98, 0x1b, 0x6f, 0xb1, 0x5b, 0x0b, 0x36, 0x57, 0x1c, 0xac, 0x29, 
	// 	0x15, 0x3a, 0x61, 0xe2, 0xd0, 0xd4, 0x71, 0xd3, 0x7d, 0x5a, 0xa6, 0xa3, 0xc2, 0x88, 0xdc, 
	// 	0xc1, 0xed, 0x1d, 0x02, 0x9f, 0xfc, 0x6a, 0x71, 0x6f, 0x76, 0xfe, 0xf2, 0x5c, 0xe3, 0x03, 
	// 	0xeb, 0x49, 0xd0, 0xa7, 0xac, 0xdb, 0x7e, 0xa8, 0x8b, 0xb2, 0x08, 0xde, 0xf1, 0xc5, 0x6d, 
	// 	0xfa, 0x7e, 0x2b, 0xb0, 0x06, 0x6a, 0x7c, 0xa5 };
	
	// const uint8_t ciphertext[] = {
	// 	0xb0, 0x67, 0xf2, 0x22, 0x3d, 0x1a, 0xc2, 0x62, 0x2e, 0xf2, 0xd3, 0xf4, 0x13, 0x62, 0x22, 0x5f,
	// 	0xf3, 0xd6, 0xeb, 0xb6, 0x1e, 0x17, 0x5b, 0xf3, 0x98, 0xbd, 0xff, 0x5e, 0x9c, 0x85, 0x8c, 0x48,
	// 	0x64, 0x17, 0x39, 0x79, 0x89, 0x30, 0xfd, 0x4e, 0x12, 0xff, 0x9e, 0x74, 0x68, 0x8f, 0xbb, 0xbb,
	// 	0x54, 0x6b, 0x93, 0xd1, 0xe0, 0xe9, 0x4e, 0x74, 0x89, 0x26, 0x1e, 0x69, 0x6f, 0x34, 0x25, 0x38,
	// 	0x15, 0x8c, 0x6d, 0x64, 0x3f, 0xc2, 0x9b, 0xe7, 0xf9, 0x5e, 0xe8, 0xac, 0x62, 0xfa, 0x91, 0x8d,
	// 	0x62, 0xb3, 0x30, 0x6e, 0xcb, 0x9c, 0xcd, 0x56, 0x88, 0x0f, 0x1b, 0x9d, 0xc4, 0x44, 0x33, 0x35,
	// 	0x52, 0xbb, 0x25, 0x9a, 0x54, 0x38, 0x45, 0xa8, 0x96, 0xd7, 0xf8, 0xff, 0x10, 0xab, 0x69, 0x58,
	// 	0x2b, 0xb6, 0x0a, 0x7a, 0xf5, 0x2b, 0x57, 0xfb, 0xcb, 0xfe, 0xe1, 0xd9, 0x43, 0xf8, 0x1e, 0xfb };

	// const uint8_t plaintext[] = { 
	// 	0xa9, 0x5f, 0x90, 0xe1,  0xea, 0x98, 0xd3, 0xd9, 0x00, 0xa2, 0xdd, 0xcf, 0x1b, 0x4b, 0x81, 0xe1,
	// 	0x28, 0xd9, 0x64, 0x33,  0x4e, 0xc3, 0x7b, 0x7e, 0xd0, 0x85, 0x24, 0xcc, 0xb0, 0x3b, 0xfd, 0x45 };
	
	// DMSG("\n========== Key Attribute init successfully. ==========\n");

	// TEE_Attribute attrs[3];

	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, RSA_KEY_SIZE, &key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("\nFailed to allocate transient object: 0x%x\n", res);
		goto exit;
	}
	DMSG("\n========== TEE_AllocateTransientObject successfully. ==========\n");

	// res = TEE_GetObjectInfo1(key_handle, &object_info);
	// if (res != TEE_SUCCESS) {
	// 	EMSG("\nFailed to get object info: 0x%x\n", res);
	// 	goto exit;
	// }
	// DMSG("\n========== TEE_GetObjectInfo1 successfully. ==========\n");

	res = TEE_GenerateKey(key_handle, RSA_KEY_SIZE, NULL, 0);
	if(TEE_SUCCESS != res){
		EMSG("Fail to generate key ret[0x%x]", res);
		goto exit;
	}
	DMSG("\n========== TEE_GenerateKey successfully. ==========\n");

	char *keypair_modulus, *keypair_pub_expo, *keypair_pri_expo;
	size_t keypair_modulus_len, keypair_pub_expo_len, keypair_pri_expo_len;

	keypair_modulus = TEE_Malloc(RSA_KEY_SIZE * sizeof(char), TEE_MALLOC_FILL_ZERO);
	if (!keypair_modulus)
		return TEE_ERROR_OUT_OF_MEMORY;
	
	keypair_pub_expo = TEE_Malloc(RSA_KEY_SIZE * sizeof(char), TEE_MALLOC_FILL_ZERO);
	if (!keypair_pub_expo)
		return TEE_ERROR_OUT_OF_MEMORY;
	
	// keypair_pri_expo = TEE_Malloc(RSA_KEY_SIZE * sizeof(char), TEE_MALLOC_FILL_ZERO);
	// if (!keypair_pri_expo)
	// 	return TEE_ERROR_OUT_OF_MEMORY;

	TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_RSA_MODULUS, keypair_modulus, &keypair_modulus_len);
	TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_RSA_PUBLIC_EXPONENT, keypair_pub_expo, &keypair_pub_expo_len);
	// TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_RSA_PRIVATE_EXPONENT, keypair_pri_expo, &keypair_pri_expo_len);

	// DHEXDUMP(keypair_modulus, keypair_modulus_len);
	// DHEXDUMP(keypair_pub_expo, keypair_pub_expo_len);
	// DHEXDUMP(keypair_pri_expo, keypair_pri_expo_len);

	key_obj_flag = TEE_DATA_FLAG_ACCESS_READ |		/* we can later read the oject */
			TEE_DATA_FLAG_ACCESS_WRITE |		/* we can later write into the object */
			TEE_DATA_FLAG_ACCESS_WRITE_META |	/* we can later destroy or rename the object */
			TEE_DATA_FLAG_OVERWRITE;		/* destroy existing object of same ID */

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					key_id, key_id_sz,
					key_obj_flag,
					key_handle,
					NULL, 0,		/* we may not fill it right now */
					&key_storage);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
		TEE_Free(key_id);
		return res;
	}

	DMSG("\n========== TEE_CreatePersistentObject successfully. ==========\n");

	// TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS,          rsa1024_modulus,  sizeof(rsa1024_modulus));
	// TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT,  rsa1024_pub_exp,  sizeof(rsa1024_pub_exp));
	// TEE_InitRefAttribute(&attrs[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, rsa1024_priv_exp, sizeof(rsa1024_priv_exp));

	// res = TEE_PopulateTransientObject(key_handle, attrs, 3);
	// if(TEE_SUCCESS != res){
	// 	EMSG("Fail to populate transient object ret[0x%x]", res);
	// 	goto exit;
	// }
	// DMSG("\n========== TEE_PopulateTransientObject successfully. ==========\n");

	// res = TEE_AllocateOperation(&enc_handle, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, RSA_KEY_SIZE);
	// if(TEE_SUCCESS != res){
	// 	EMSG("Fail to allocate operation object ret[0x%x]", res);
	// 	goto exit;
	// }
	// DMSG("\n========== TEE_AllocateOperation successfully. ==========\n");

	// res = TEE_AllocateOperation(&dec_handle, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT, RSA_KEY_SIZE);
	// if(TEE_SUCCESS != res){
	// 	EMSG("Fail to allocate operation object ret[0x%x]", res);
	// 	goto exit;
	// }
	// DMSG("\n========== TEE_AllocateOperation successfully. ==========\n");

	// res = TEE_SetOperationKey(enc_handle, key_handle);
	// if (TEE_SUCCESS != res) {
	// 	EMSG("Fail to set operation key ret[0x%x]", res);
	// 	goto exit;
	// }
	// DMSG("\n========== TEE_SetOperationKey successfully. ==========\n");

	// res = TEE_SetOperationKey(dec_handle, key_handle);
	// if (TEE_SUCCESS != res) {
	// 	EMSG("Fail to set operation key ret[0x%x]", res);
	// 	goto exit;
	// }
	// DMSG("\n========== TEE_SetOperationKey successfully. ==========\n");

	// char *plain_data, *cipher_data, *re_plain_data;
	// size_t plain_data_len, cipher_data_len, re_plain_data_len;

	// plain_data_len = 32;
	// plain_data = TEE_Malloc(plain_data_len, TEE_MALLOC_FILL_ZERO);
	// if (!plain_data)
	// 	return TEE_ERROR_OUT_OF_MEMORY;
	
	// TEE_MemFill(plain_data, 2, plain_data_len);

	// DHEXDUMP(plain_data, plain_data_len);
	
	// cipher_data_len = 128;
	// cipher_data = TEE_Malloc(cipher_data_len, TEE_MALLOC_FILL_ZERO);
	// if (!cipher_data)
	// 	return TEE_ERROR_OUT_OF_MEMORY;
	
	// re_plain_data_len = 32;
	// re_plain_data = TEE_Malloc(re_plain_data_len, TEE_MALLOC_FILL_ZERO);
	// if (!re_plain_data)
	// 	return TEE_ERROR_OUT_OF_MEMORY;

	// res = TEE_AsymmetricEncrypt(enc_handle, (TEE_Attribute *)NULL, 0, plain_data, plain_data_len, cipher_data, &cipher_data_len);
	// if (TEE_SUCCESS != res) {
	// 	EMSG("Fail to encrypt data ret[0x%x], cipher_data_len[%zu]", res, cipher_data_len);
	// 	goto exit;
	// }
	// DMSG("\n========== TEE_AsymmetricEncrypt successfully. ==========\n");

	// DHEXDUMP(cipher_data, cipher_data_len);

	// res = TEE_AsymmetricDecrypt(dec_handle, (TEE_Attribute *)NULL, 0, cipher_data, cipher_data_len, re_plain_data, &re_plain_data_len);
	// if (TEE_SUCCESS != res) {
	// 	EMSG("Fail to decrypt data ret[0x%x], re_plain_data_len[%zu]", res, re_plain_data_len);
	// 	goto exit;
	// }
	// DMSG("\n========== TEE_AsymmetricDecrypt successfully. ==========\n");

	// DHEXDUMP(re_plain_data, re_plain_data_len);

	// DHEXDUMP(plaintext, sizeof(plaintext));
	
	// cipher_data_len = 128;
	// cipher_data = TEE_Malloc(cipher_data_len, TEE_MALLOC_FILL_ZERO);
	// if (!cipher_data)
	// 	return TEE_ERROR_OUT_OF_MEMORY;
	
	// re_plain_data_len = 32;
	// re_plain_data = TEE_Malloc(re_plain_data_len, TEE_MALLOC_FILL_ZERO);
	// if (!re_plain_data)
	// 	return TEE_ERROR_OUT_OF_MEMORY;

	// res = TEE_AsymmetricEncrypt(enc_handle, (TEE_Attribute *)NULL, 0, plaintext, sizeof(plaintext), cipher_data, &cipher_data_len);
	// if (TEE_SUCCESS != res) {
	// 	EMSG("Fail to encrypt data ret[0x%x], cipher_data_len[%zu]", res, cipher_data_len);
	// 	goto exit;
	// }
	// DMSG("\n========== TEE_AsymmetricEncrypt successfully. ==========\n");

	// DHEXDUMP(cipher_data, cipher_data_len);

	// res = TEE_AsymmetricDecrypt(dec_handle, (TEE_Attribute *)NULL, 0, cipher_data, cipher_data_len, re_plain_data, &re_plain_data_len);
	// if (TEE_SUCCESS != res) {
	// 	EMSG("Fail to decrypt data ret[0x%x], re_plain_data_len[%zu]", res, re_plain_data_len);
	// 	goto exit;
	// }
	// DMSG("\n========== TEE_AsymmetricDecrypt successfully. ==========\n");

	// DHEXDUMP(re_plain_data, re_plain_data_len);
	
	// if (!TEE_MemCompare(plaintext, re_plain_data, re_plain_data_len)) {
	// 	DMSG("Match");
	// } else {
	// 	DMSG("Not Match");
	// }


exit:
	if (key_handle != NULL)
		TEE_FreeTransientObject(key_handle);
	// TEE_Free(plain_data);
	// TEE_Free(cipher_data);
	// TEE_Free(re_plain_data);
	TEE_CloseObject(key_storage);
	TEE_Free(keypair_modulus);
	TEE_Free(keypair_pub_expo);
	TEE_Free(keypair_pri_expo);
	return res;
}

static TEE_Result fetch_public_key(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE);

	uint8_t  buffer[RSA_KEY_SIZE] =  {0};
	uint8_t  mod[RSA_KEY_SIZE] = {0};
	size_t bufferlen;
	size_t modlen;
	TEE_BigInt *bigIntMod, *bigIntExp;
	size_t bigInt_len;
	TEE_ObjectHandle key_storage = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;
	uint32_t key_obj_flag;
	char *key_id;
	size_t key_id_sz;

	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	
	key_id_sz = params[0].memref.size;
	key_id = TEE_Malloc(key_id_sz, 0);
	if (!key_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(key_id, params[0].memref.buffer, key_id_sz);


	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					key_id, key_id_sz,
					TEE_DATA_FLAG_ACCESS_READ,
					&key_storage);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open persistent object, res=0x%08x", res);
		TEE_Free(key_id);
		return res;
	}
	DMSG("\n========== TEE_OpenPersistentObject successfully. ==========\n");

	bigInt_len =  (size_t) TEE_BigIntSizeInU32(RSA_KEY_SIZE);
	bigIntExp =(TEE_BigInt *)TEE_Malloc(bigInt_len * sizeof(TEE_BigInt), TEE_MALLOC_FILL_ZERO);
	if (!bigIntExp)
		return TEE_ERROR_OUT_OF_MEMORY;
	
	TEE_BigIntInit(bigIntExp, bigInt_len);

	bigIntMod =(TEE_BigInt *)TEE_Malloc(bigInt_len * sizeof(TEE_BigInt), TEE_MALLOC_FILL_ZERO);
	if (!bigIntMod)
		return TEE_ERROR_OUT_OF_MEMORY;
	
	TEE_BigIntInit(bigIntMod, bigInt_len);

	DMSG("\n========== Init array successfully. ==========\n");

	bufferlen = sizeof(buffer);
	res = TEE_GetObjectBufferAttribute(key_storage, TEE_ATTR_RSA_PUBLIC_EXPONENT, buffer, &bufferlen);
	if (res != TEE_SUCCESS) {
		DMSG("TEE_GetObjectBufferAttribute failed! res: 0x%x", res);
	}
	modlen = sizeof(mod);
	res = TEE_GetObjectBufferAttribute(key_storage, TEE_ATTR_RSA_MODULUS, mod, &modlen);
	if (res != TEE_SUCCESS) {
		DMSG("TEE_GetObjectBufferAttribute (Modulus) failed! res: 0x%x", res);
	}

	DMSG("\n========== TEE_GetObjectBufferAttribute successfully. ==========\n");

	DHEXDUMP(mod, modlen);
	DHEXDUMP(buffer, bufferlen);

	res = TEE_BigIntConvertFromOctetString(bigIntMod, mod, modlen, 0);
	if (res != TEE_SUCCESS) {
		DMSG("TEE_BigIntConvertFromOctetString failed! res: 0x%x", res);
	}
	
	res = TEE_BigIntConvertFromOctetString(bigIntExp, buffer, bufferlen, 0);
	if (res != TEE_SUCCESS) {
		DMSG("TEE_BigIntConvertFromOctetString failed! res: 0x%x", res);
	}

	DMSG("\n========== TEE_BigIntConvertFromOctetString successfully. ==========\n");

	// int32_t *modulus, *exponent;
	// res = TEE_BigIntConvertToS32(modulus, bigIntMod);
	// if (res != TEE_SUCCESS) {
	// 	DMSG("TEE_BigIntConvertToS32 failed!TEE_BigIntConvertToS32 res: 0x%x", res);
	// }
	
	// res = TEE_BigIntConvertToS32(exponent, bigIntExp);
	// if (res != TEE_SUCCESS) {
	// 	DMSG("TEE_BigIntConvertToS32 failed!TEE_BigIntConvertToS32 res: 0x%x", res);
	// }
	// DMSG("Public Exponent: %" PRId32, *exponent);
	// DMSG("\n========== TEE_BigIntConvertToS32 successfully. ==========\n");

	TEE_MemMove(params[1].memref.buffer, mod, modlen);
	params[1].memref.size = modlen;
	TEE_MemMove(params[2].memref.buffer, buffer, bufferlen);
	params[2].memref.size = bufferlen;

	// DHEXDUMP(bigIntMod, bigInt_len * sizeof(TEE_BigInt));
	// DHEXDUMP(bigIntExp, bigInt_len * sizeof(TEE_BigInt));

	// TEE_MemMove(params[1].memref.buffer, bigIntMod, bigInt_len);
	// params[1].memref.size = bigInt_len;
	// TEE_MemMove(params[2].memref.buffer, bigIntExp, bigInt_len);
	// params[2].memref.size = bigInt_len;

exit:
	TEE_CloseObject(key_storage);
	TEE_Free(key_id);
	TEE_Free(bigIntMod);
	TEE_Free(bigIntExp);
	return res;
}

static TEE_Result encrypt_message(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
                TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                TEE_PARAM_TYPE_MEMREF_INPUT,
                                TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
                return TEE_ERROR_BAD_PARAMETERS;

        TEE_ObjectHandle key_storage = TEE_HANDLE_NULL;
	TEE_OperationHandle enc_handle = TEE_HANDLE_NULL;
        TEE_Result res = TEE_SUCCESS;
        char *key_id;
        size_t key_id_sz;

	key_id_sz = params[0].memref.size;
        key_id = TEE_Malloc(key_id_sz, 0);
        if (!key_id)
                return TEE_ERROR_OUT_OF_MEMORY;

        TEE_MemMove(key_id, params[0].memref.buffer, key_id_sz);


        res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                        key_id, key_id_sz,
                                        TEE_DATA_FLAG_ACCESS_READ,
                                        &key_storage);
        if (res != TEE_SUCCESS) {
                EMSG("Failed to open persistent object, res=0x%08x", res);
                TEE_Free(key_id);
                return res;
        }
        DMSG("\n========== TEE_OpenPersistentObject successfully. ==========\n");

	res = TEE_AllocateOperation(&enc_handle, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, RSA_KEY_SIZE);
        if(TEE_SUCCESS != res){
             EMSG("Fail to allocate operation object ret[0x%x]", res);
             goto exit;
        }
        DMSG("\n========== TEE_AllocateOperation successfully. ==========\n");

	res = TEE_SetOperationKey(enc_handle, key_storage);
        if (TEE_SUCCESS != res) {
             EMSG("Fail to set operation key ret[0x%x]", res);
             goto exit;
        }
        DMSG("\n========== TEE_SetOperationKey successfully. ==========\n");

	size_t cipher_data_len = RSA_KEY_SIZE;
        char *cipher_data = TEE_Malloc(cipher_data_len, TEE_MALLOC_FILL_ZERO);
        if (!cipher_data)
             return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_AsymmetricEncrypt(enc_handle, (TEE_Attribute *)NULL, 0, params[1].memref.buffer, params[1].memref.size, cipher_data, &cipher_data_len);
        if (TEE_SUCCESS != res) {
             EMSG("Fail to encrypt data ret[0x%x], cipher_data_len[%zu]", res, cipher_data_len);
             goto exit;
        }
        DMSG("\n========== TEE_AsymmetricEncrypt successfully. ==========\n");

        DHEXDUMP(cipher_data, cipher_data_len);

	TEE_MemMove(params[2].memref.buffer, cipher_data, cipher_data_len);
	params[2].memref.size = cipher_data_len;
exit:
	TEE_CloseObject(key_storage);
	TEE_Free(key_id);
	TEE_Free(cipher_data);
	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void __unused **session)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *session)
{
	/* Nothing to do */
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session,
				      uint32_t command,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	switch (command) {
	case TA_RETRIEVE_KEY_CMD_INIT:
		return initialize_rsa_keypair(param_types, params);
	case TA_RETRIEVE_KEY_CMD_FETCH_PUB:
		return fetch_public_key(param_types, params);
	case TA_RETRIEVE_KEY_CMD_ENCRYPT:
		return encrypt_message(param_types, params);
	// case TA_RETRIEVE_KEY_CMD_DECRYPT:
	//	return decrypt_message(param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", command);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
