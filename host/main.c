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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* TA API: UUID and command IDs */
#include <retrieve_key_ta.h>

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_RETRIEVE_KEY_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

TEEC_Result initialize_keypair(struct test_ctx *ctx, char *id, size_t id_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_RETRIEVE_KEY_CMD_INIT,
				 &op, &origin);
	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_SHORT_BUFFER:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command RETRIEVE failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

TEEC_Result fetch_public_key(struct test_ctx *ctx, char *id, size_t id_len, uint8_t *modulus, size_t modulus_len, uint8_t *exponent, size_t exponent_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;
	op.params[1].tmpref.buffer = modulus;
	// op.params[1].tmpref.size = modulus_len;
	op.params[2].tmpref.buffer = exponent;
	// op.params[2].tmpref.size = exponent_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_RETRIEVE_KEY_CMD_FETCH_PUB,
				 &op, &origin);
	switch (res) {
	case TEEC_SUCCESS:
		// printf("%zu, %zu", op.params[1].tmpref.size, op.params[2].tmpref.size);
		printf("Modulus: ");
		for (size_t i = 0; i < op.params[1].tmpref.size; i++) {
			printf("%" PRIu8, modulus[i]);
			printf(" ");
		}
		printf("\n");

		printf("Exponent: ");
		for (size_t i = 0; i < op.params[2].tmpref.size; i++) {
			printf("%" PRIu8, exponent[i]);
			printf(" ");
		}
		printf("\n");
		break;
	case TEEC_ERROR_SHORT_BUFFER:
		break;
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command FETCH_PUB failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

TEEC_Result encrypt_message(struct test_ctx *ctx, char *id, size_t id_len, char *message, size_t message_len, char* ciphertext)
{
        TEEC_Operation op;
        uint32_t origin;
        TEEC_Result res;

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

        op.params[0].tmpref.buffer = id;
        op.params[0].tmpref.size = id_len;
        op.params[1].tmpref.buffer = message;
        op.params[1].tmpref.size = message_len;
        op.params[2].tmpref.buffer = ciphertext;

        res = TEEC_InvokeCommand(&ctx->sess,
                                 TA_RETRIEVE_KEY_CMD_ENCRYPT,
                                 &op, &origin);
        switch (res) {
        case TEEC_SUCCESS:
		printf("Ciphertext: ");
                for (size_t i = 0; i < op.params[2].tmpref.size; i++) {
                        printf("%c", ciphertext[i]);
                }
                printf("\n");
                break;
        case TEEC_ERROR_SHORT_BUFFER:
                break;
        case TEEC_ERROR_ITEM_NOT_FOUND:
                break;
        default:
                printf("Command ENCRYPT failed: 0x%x / %u\n", res, origin);
        }

        return res;
}


#define KEY_SIZE	512

int main(int argc, char *argv[])
{

	struct test_ctx ctx;
	char key_id[] = "#key";
	char message[] = "secret";
	char ciphertext[KEY_SIZE] = {0};
	TEEC_Result res = TEEC_SUCCESS;
	uint8_t modulus[KEY_SIZE] = {0};
	uint8_t exponent[KEY_SIZE] = {0};
	size_t modulus_sz, exponent_sz;

	printf("Prepare session with the TA\n");
	prepare_tee_session(&ctx);

	res = initialize_keypair(&ctx, key_id, strlen(key_id));
	if (res != TEEC_SUCCESS)
		exit(1);

	res = fetch_public_key(&ctx, key_id, strlen(key_id), modulus, modulus_sz, exponent, exponent_sz);
	if (res != TEEC_SUCCESS)
		exit(1);

	res = encrypt_message(&ctx, key_id, strlen(key_id), message, strlen(message), ciphertext);
	if (res != TEEC_SUCCESS)
                exit(1);

	printf("\nWe're done, close and release TEE resources\n");
	terminate_tee_session(&ctx);
	
	return 0;
}
