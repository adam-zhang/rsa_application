//demo.cpp
// g++ demo.cpp -o demo -lcrypto
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
 
#include <iostream>
#include <string>
#include <cstring>
#include <cassert>
#include <sstream>
#include <iomanip>
#include "RSAWrapper.h"

using namespace std;
 
 

string to_hex(const string& data)
{
	stringstream ss;
	for(auto c : data)
		ss << hex << setw(2) << setfill('0') << static_cast<unsigned int>(static_cast<unsigned char>(c)) << " ";
	return ss.str();
}

string to_hex(const vector<unsigned char>& data)
{
	string s(data.begin(), data.end());
	return to_hex(s);
}
 
int main()
{
	//原文
	//const string one = "skl;dfhas;lkdfhslk;dfhsidfhoiehrfoishfsidf";
	const string one = "Hello world.";
	cout << "one: " << one << endl;
 
	//密文（二进制数据）
	//string two = EncodeRSAKeyFile("publickey.pem", one);
	vector<unsigned char> data;
	copy(one.begin(), one.end(), back_inserter(data));
	auto two = RSAWrapper::encrypt("publickey.pem", data);
	cout << "two: " << to_hex(two) << endl;
 
	//顺利的话，解密后的文字和原文是一致的
	auto three = RSAWrapper::decrypt("privatekey.pem", two);
	cout << "three: " << three.data() << endl;
	return 0;
}
