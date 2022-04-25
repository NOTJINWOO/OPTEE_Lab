/*
 * Copyright (c) 2016, Linaro Limited
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
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

TEEC_Result res;
TEEC_Context ctx;
TEEC_Session sess;
TEEC_Operation op;
TEEC_UUID uuid = TA_TEEencrypt_UUID;
uint32_t err_origin;

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

char plaintext[RSA_MAX_PLAIN_LEN_1024];// = {0,};
char ciphertext[RSA_CIPHER_LEN_1024];// = {0,};
int len=64;

void prepare_op(TEEC_Operation *op, char *in, size_t in_sz, char *out, size_t out_sz) {
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
	op->params[0].tmpref.buffer = in;
	op->params[0].tmpref.size = in_sz;
	op->params[1].tmpref.buffer = out;
	op->params[1].tmpref.size = out_sz;
}

void rsa_gen_keys() {

	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_GENKEYS, NULL, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_CMD_RSA_GENKEYS) failed %#x\n", res);
	printf("\n=========== Keys already generated. ==========\n");
}

void rsa_encrypt(char textFile[])
{
	printf("\n============ RSA ENCRYPT CA SIDE ============\n");
	prepare_op(&op, plaintext, RSA_MAX_PLAIN_LEN_1024, ciphertext, RSA_CIPHER_LEN_1024);
	FILE* fp;

	fp = fopen(textFile, "r");
	if(fp == NULL)
	{
		printf("File Read Fail\n");
	}
	while(fgets(plaintext, sizeof(plaintext), fp) != NULL);
	printf("plaintext : %s", plaintext);
	fclose(fp);

	//memcpy(op.params[0].tmpref.buffer, plaintext, RSA_MAX_PLAIN_LEN_1024);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_ENCRYPT,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n",
			res, err_origin);

	//memcpy(ciphertext, op.params[1].tmpref.buffer, RSA_CIPHER_LEN_1024);
	printf("Ciphertext : %s\n", ciphertext);
	//save encryptedText as file
	fp = fopen("encryptedRSAText.txt", "w");
	fputs(ciphertext, fp);
	fclose(fp);
	printf("=====Encryption Complete. please check your directory=====\n");
}

void rsa_decrypt(char textFile[])
{
	printf("\n============ RSA DECRYPT CA SIDE ============\n");
	prepare_op(&op, ciphertext, RSA_CIPHER_LEN_1024, plaintext, RSA_MAX_PLAIN_LEN_1024);
	//open file which is encryptedText written
	FILE* fp;

	fp = fopen(textFile, "r");
	if(fp == NULL)
	{
		printf("File Read Fail\n");
	}
	//get content in file
	while(fgets(ciphertext, sizeof(ciphertext), fp) != NULL);
	printf("Ciphertext : %s", ciphertext);
	fclose(fp);
	//memcpy(op.params[1].tmpref.buffer, ciphertext, RSA_CIPHER_LEN_1024);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_DECRYPT, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_DECRYPT) failed 0x%x origin 0x%x\n",
			res, err_origin);
	//memcpy(plaintext, op.params[1].tmpref.buffer, RSA_MAX_PLAIN_LEN_1024);
	printf("plaintext : %s\n", plaintext);
	//save Ciphertext as file
	fp = fopen("decryptedText.txt", "w");
	fputs(plaintext, fp);
	fclose(fp);
	printf("=====Decryption Complete. please check your directory=====\n");
}

void Encrypt(char textFile[])
{
	printf("========================Encryption========================\n");

	FILE *fp;

	fp = fopen(textFile, "r");
	if(fp == NULL)
	{
		printf("File Read Fail\n");
	}
	while(fgets(plaintext, sizeof(plaintext), fp) != NULL);
	printf("plaintext : %s", plaintext);
	fclose(fp);

	memcpy(op.params[0].tmpref.buffer, plaintext, len);
	//call TA function (ENC_VALUE)
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);
	memcpy(ciphertext, op.params[0].tmpref.buffer, len);
	printf("Ciphertext : %s\n", ciphertext);
	//save encryptedText as file
	fp = fopen("encryptedText.txt", "w");
	fputs(ciphertext, fp);
	fclose(fp);
	printf("key : %d\n", op.params[1].value.a);
	//save key as file
	char sKey[5];
	sprintf(sKey, "%d", op.params[1].value.a);
	fp = fopen("encryptedKey.txt", "w");
	fputs(sKey, fp);
	fclose(fp);
	printf("=====Encryption Complete. please check your directory=====\n");

}

void Decrypt(char textFile[], char keyFile[])
{
	printf("========================Decryption========================\n");
	memset(ciphertext, 0, sizeof(ciphertext));
	memset(plaintext, 0, sizeof(plaintext));
	op.params[1].value.a = 0;
	//open file which is encryptedText written
	FILE* fp;

	fp = fopen(textFile, "r");
	if(fp == NULL)
	{
		printf("File Read Fail\n");
	}
	//get content in file
	while(fgets(ciphertext, sizeof(ciphertext), fp) != NULL);
	printf("Ciphertext : %s", ciphertext);
	fclose(fp);
	//open file which is encryptedKey written
	int eKey[5];
	fp = fopen(keyFile, "r");
	while(fgets(eKey, sizeof(eKey), fp) != NULL);
	fclose(fp);
	op.params[1].value.a = atoi(eKey);
	//printf("%d\n", op.params[1].value.a);
	if(op.params[1].value.a <= 0 || op.params[1].value.a > 27)
	{
		printf("\nIt's Not a KeyFile. please check filename and try again\n");
		return;
	}
	memcpy(op.params[0].tmpref.buffer, ciphertext, len);
	//call TA function(DEC_VALUE)
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
	memcpy(plaintext, op.params[0].tmpref.buffer, len);
	printf("plaintext : %s\n", plaintext);
	//save Ciphertext as file
	fp = fopen("decryptedText.txt", "w");
	fputs(plaintext, fp);
	fclose(fp);
	printf("=====Decryption Complete. please check your directory=====\n");
}

int main(int argc, char* argv[])
{
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	op.params[1].value.a = 0;

	// Check Command
	if(strcmp(argv[1], "-e") == 0)
	{
		if(strcmp(argv[3], "Ceaser") == 0)
		{
			Encrypt(argv[2]);
		}
		else if(strcmp(argv[3], "RSA") == 0)
		{
			rsa_gen_keys();
			rsa_encrypt(argv[2]);
		}
		else
		{
			printf("Wrong Command! Please Check the manual\n");
			return;
		}
	}
	else if(strcmp(argv[1], "-d") == 0)
	{
		if(strcmp(argv[3], "RSA") == 0)
		{
			printf("Not Implemented yet! try other commands\n");
			//rsa_gen_keys();
			//rsa_decrypt(argv[2]);
		}
		else if(argc > 4)
		{
			if(strcmp(argv[4], "Ceaser") == 0)
			{
				Decrypt(argv[2], argv[3]);	
			}
			else
			{
				printf("Wrong Command! Please Check the manual\n");
				return;
			}
		}
		else
		{
			printf("Wrong Command! Please Check the manual\n");
			return;
		}
	}
	else
	{
		printf("Wrong Command! Please Check the manual\n");
		return;
	} 
	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
