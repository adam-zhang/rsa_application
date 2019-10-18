#include "RSAWrapper.h"
#include <cassert>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "base64.h"

using namespace std;

RSAWrapper::RSAWrapper()
{
}

RSAWrapper::~RSAWrapper()
{
}

static std::vector<unsigned char> DecodeRSAKeyFile( const std::string& strPemFileName, const std::vector<unsigned char>& strData )
{
	if (strPemFileName.empty() || strData.empty())
	{
		assert(false);
		return vector<unsigned char>(); 
	}
	FILE* hPriKeyFile = fopen(strPemFileName.c_str(),"rb");
	if( hPriKeyFile == NULL )
	{
		assert(false);
		return vector<unsigned char>(); 
	}

	std::string strRet;
	RSA* pRSAPriKey = RSA_new();
	if(PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
	{
		assert(false);
		return vector<unsigned char>(); 
	}
	int nLen = RSA_size(pRSAPriKey);
	vector<unsigned char> decode(nLen);
 
	int ret = RSA_private_decrypt(strData.size(), strData.data(), decode.data(), pRSAPriKey, RSA_PKCS1_PADDING);
	assert(ret >= 0);
	RSA_free(pRSAPriKey);
	fclose(hPriKeyFile);
	CRYPTO_cleanup_all_ex_data(); 
	return decode;
}



static std::vector<unsigned char> EncodeRSAKeyFile( const std::string& strPemFileName, const std::vector<unsigned char>& strData )
{
	if (strPemFileName.empty() || strData.empty())
	{
		assert(false);
		return vector<unsigned char>(); 
	}
	FILE* hPubKeyFile = fopen(strPemFileName.c_str(), "rb");
	if( hPubKeyFile == NULL )
	{
		assert(false);
		return vector<unsigned char>();
	}
	std::string strRet;
	RSA* pRSAPublicKey = RSA_new();
	if(PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
	{
		assert(false);
		return vector<unsigned char>();
	}
 
	int nLen = RSA_size(pRSAPublicKey);
	vector<unsigned char> encode(nLen);
	int ret = RSA_public_encrypt(strData.size(), strData.data(), encode.data(), pRSAPublicKey, RSA_PKCS1_PADDING);
	assert(ret >=0 );
	RSA_free(pRSAPublicKey);
	fclose(hPubKeyFile);
	CRYPTO_cleanup_all_ex_data(); 
	return encode;
}


std::string  RSAWrapper::encrypt(const std::string& fileName, const std::vector<unsigned char>& data)
{
	auto encoded = EncodeRSAKeyFile(fileName, data);
	return base64_encode(encoded);
}

std::vector<unsigned char> RSAWrapper::decrypt(const std::string& fileName, const std::string& data)
{
	auto decoded = base64_decode(data);
	return DecodeRSAKeyFile(fileName, decoded);
}
