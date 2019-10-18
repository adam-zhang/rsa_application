#ifndef __RSAWRAPPER__H
#define __RSAWRAPPER__H

#include <vector>
#include <string>

class RSAWrapper
{
private:
	RSAWrapper();
	~RSAWrapper();
public:
	static std::string encrypt(const std::string& fileName, const std::vector<unsigned char>& data);
	static std::vector<unsigned char> decrypt(const std::string& fileName, const std::string& data);
};
#endif//__RSAWRAPPER__H
