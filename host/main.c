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
char plaintext[64] = {0,};
char ciphertext[64] = {0,};
int len=64;


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
		Encrypt(argv[2]);
	}
	else if(strcmp(argv[1], "-d") == 0)
	{
		Decrypt(argv[2], argv[3]);
	}
	else
	{
		printf("Wrong Command! Please Check the manual\n");
		return;
	} 
	/*
	 * TA_HELLO_WORLD_CMD_INC_VALUE is the actual function in the TA to be
	 * called.
	 */
/*
	printf("========================Encryption========================\n");

	FILE *fp;

	fp = fopen("plaintext.txt", "r");
	if(fp == NULL)
	{
		printf("File Read Fail\n");
	}
	while(fgets(plaintext, sizeof(plaintext), fp) != NULL);
	printf("plaintext : %s", plaintext);
	fclose(fp);

	//printf("Please Input Plaintext : ");
	//scanf("%[^\n]s",plaintext);
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

	printf("========================Decryption========================\n");
	memset(ciphertext, 0, sizeof(ciphertext));
	memset(plaintext, 0, sizeof(plaintext));
	op.params[1].value.a = 0;
	//open file which is encryptedText written
	fp = fopen("encryptedText.txt", "r");
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
	fp = fopen("encryptedKey.txt", "r");
	while(fgets(eKey, sizeof(eKey), fp) != NULL);
	fclose(fp);
	op.params[1].value.a = atoi(eKey);
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
*/
/*	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
				 &err_origin);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op,
				 &err_origin);
*/
	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
