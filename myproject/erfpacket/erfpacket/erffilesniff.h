#pragma once
#include <string>
#include <tins/packet.h>
#include <fstream>

using namespace Tins;
using namespace std;

#define TYPE_ETH 2

#pragma pack(push,1)
struct ERF_HEAD
{
	unsigned long nanoseconds;
	unsigned long seconds;
	char type;
	char flag;
	short rlen;
	short lctr;
	short wlen;

	void ntoh()
	{
		wlen = ntohs(wlen);
		rlen = ntohs(rlen);	

		double tmp1 = nanoseconds;
		double tmp2 = 1000000000.0 / (65536.0 * 65536.0);
		nanoseconds = (unsigned long)(tmp1 * tmp2 + 0.5);
	}

	bool IsValid()
	{	
		if (wlen >= rlen) return false;
		return true;
	}

	int GetType()
	{
		return type & 0x7f;
	}
};

struct ETH_HEAD
{
	char offset;
	char reserved;
};

#pragma pack(pop)

class ErfFileSniff
{
public:
	ErfFileSniff(const std::string &file_name);
	~ErfFileSniff();

	PtrPacket next_packet();



private:
	ifstream infile;
};

