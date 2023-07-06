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
#ifndef __RETRIEVE_KEY_H__
#define __RETRIEVE_KEY_H__

/* UUID of the trusted application */
#define TA_RETRIEVE_KEY_UUID \
		{ 0xa4ad7620, 0xfdff, 0x4676, \
			{ 0xb7, 0xbb, 0x50, 0xd8, 0xc9, 0xe8, 0xa0, 0x88 } }
/*
 * TA_RETRIEVE_KEY_CMD_INIT - Initialize RSA keypair
 * param[0] (memref) key object handler
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_RETRIEVE_KEY_CMD_INIT		0

/*
 * TA_RETRIEVE_KEY_CMD_INIT - Initialize RSA keypair
 * param[0] (memref) key object handler
 * param[1] (memref) key modulus
 * param[2] (memref) key public exponent
 * param[3] unused
 */
#define TA_RETRIEVE_KEY_CMD_FETCH_PUB		1

/*
 * TA_RETRIEVE_KEY_CMD_INIT - Initialize RSA keypair
 * param[0] (memref) key object handler
 * param[1] (memref) plaintext
 * param[2] (memref) ciphertext
 * param[3] unused
 */
#define TA_RETRIEVE_KEY_CMD_ENCRYPT             2

/*
 * TA_RETRIEVE_KEY_CMD_INIT - Initialize RSA keypair
 * param[0] (memref) key object handler
 * param[1] (memref) ciphertext
 * param[2] (memref) plaintext
 * param[3] unused
 */
#define TA_RETRIEVE_KEY_CMD_DECRYPT             3

#endif /* __RETRIEVE_KEY_H__ */
