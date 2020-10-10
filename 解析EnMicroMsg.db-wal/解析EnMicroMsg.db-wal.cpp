// 解析EnMicroMsg.db-wal.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
using namespace std;
#define DEFAULT_PAGESIZE 1024
#define DEFAULT_ITER 4000
#define IV_SIZE 16
#define KEY_SIZE 32
int Decryptdb();
//这是解析微信主库的7位密码，我这里是5107579
unsigned char pass[] = { 0x35,0x31,0x30,0x037,0x035,0x037,0x039 };
int main()
{
	int ret=Decryptdb();
	return ret;
}
//数组翻转，因为大端存储，数组读取顺序是相反的
void Reverse(unsigned char *p, int size)
{
	int i, tmp;
	for (i = 0; i < size / 2; i++)
	{
		tmp = p[i];
		p[i] = p[size - 1 - i];
		p[size - 1 - i] = tmp;
	}
}
int Decryptdb()
{
	const char*  dbfilename = "EnMicroMsg.db";
	const char*  walfilename = "EnMicroMsg.db-wal";
	FILE* fpdb;
	FILE* fwal;
	fopen_s(&fpdb, dbfilename, "rb+");
	fopen_s(&fwal, walfilename, "rb+");
	if (!fpdb)
	{
		printf("打开文件出错!");
		getchar();
		return -1;
	}
	if (!fwal)
	{
		printf("打开EnMicroMsg.db-wal文件出错!");
		getchar();
		return -1;
	}
	fseek(fpdb, 0, SEEK_END);
	long nFileSize = ftell(fpdb);
	fseek(fpdb, 0, SEEK_SET);
	unsigned char* pDbBuffer = new unsigned char[nFileSize];
	fread(pDbBuffer, 1, nFileSize, fpdb);
	fclose(fpdb);
	unsigned char salt[16] = { 0 };
	memcpy(salt, pDbBuffer, 16);
	fseek(fwal, 0, SEEK_END);
	long walFileSize = ftell(fwal);
	fseek(fwal, 0, SEEK_SET);
	unsigned char* pWALBuffer = new unsigned char[walFileSize];
	fread(pWALBuffer, 1, walFileSize, fwal);
	fclose(fwal);
	/*预写式日志包括一个头和0到多个框，每个框记录一个页修改的内容
	  WAL头有32个字节。跟在WAL头后的式0到多个框，每个框由一个24字节的
	  框头和一个页大小的页数据组成。我这里没有把每个框的校验和WAL头进行比对
	*/
	unsigned char WALHead[32] = { 0 };
	memcpy(WALHead, pWALBuffer, 32);
	//从WAL头中获取页的大小
	unsigned char PageSize[4] = { 0 };
	memcpy(PageSize, pWALBuffer + 8, 4);
	Reverse(PageSize, 4);
	//从WAL头中获取salt-1,salt-2
	unsigned char salt_1[4] = { 0 };
	memcpy(salt_1, WALHead + 16, 4);
	unsigned char salt_2[4] = { 0 };
	memcpy(salt_2, WALHead + 20, 4);
	//将WAL文件头写入
	fopen_s(&fwal, "dec_EnMicroMsg.db-wal", "ab+");
	{
		fwrite(WALHead, 1, 32, fwal);
		fclose(fwal);
	}

	int reserve = IV_SIZE;
	reserve = ((reserve % AES_BLOCK_SIZE) == 0) ? reserve : ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

	unsigned char key[KEY_SIZE] = { 0 };
	unsigned char mac_key[KEY_SIZE] = { 0 };

	OpenSSL_add_all_algorithms();
	PKCS5_PBKDF2_HMAC_SHA1((const char*)pass, sizeof(pass), salt, sizeof(salt), DEFAULT_ITER, sizeof(key), key);

	unsigned char* pTemp = pWALBuffer;

	int _pagesize = *(int*)PageSize;
	unsigned char pDecryptPerPageBuffer[DEFAULT_PAGESIZE];
	unsigned char frameHeader[24] = { 0 };
	int nPage = 1;
	int offset = 32;
	while (pTemp < pWALBuffer + walFileSize)
	{
		if (nPage == 1)
		{
			memcpy(frameHeader, pTemp + offset, 24);
		}
		else
		{
			memcpy(frameHeader, pTemp, 24);
		}
		fopen_s(&fwal, "dec_EnMicroMsg.db-wal", "ab+");
		{
			fwrite(frameHeader, 1, 24, fwal);
			fclose(fwal);
		}

		EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
		EVP_CipherInit_ex(ectx, EVP_get_cipherbyname("aes-256-cbc"), NULL, NULL, NULL, 0);
		EVP_CIPHER_CTX_set_padding(ectx, 0);
		EVP_CipherInit_ex(ectx, NULL, NULL, key, pTemp + offset + 24 + (_pagesize - reserve), 0);
		int nDecryptLen = 0;
		int nTotal = 0;
		EVP_CipherUpdate(ectx, pDecryptPerPageBuffer, &nDecryptLen, pTemp + offset + 24, _pagesize - reserve);
		nTotal = nDecryptLen;
		EVP_CipherFinal_ex(ectx, pDecryptPerPageBuffer + nDecryptLen, &nDecryptLen);
		nTotal += nDecryptLen;
		EVP_CIPHER_CTX_free(ectx);

		memcpy(pDecryptPerPageBuffer + _pagesize - reserve, pTemp + offset+ _pagesize + 24 - reserve, reserve);
		char decFile[1024] = { 0 };
		sprintf_s(decFile, "dec_%s", walfilename);
		FILE * fp;
		fopen_s(&fp, decFile, "ab+");
		//fopen_s(&fwal, "dec_EnMicroMsg.db-wal", "ab+");
		{
			fwrite(pDecryptPerPageBuffer, 1, _pagesize, fp);
			fclose(fp);
		}
		pTemp += _pagesize + offset + 24;
		nPage++;
		offset = 0;
	/*	pTemp += _pagesize + 24;*/
	}
	printf("\n 解密成功! \n");
	system("pause");
	return 0;
}
