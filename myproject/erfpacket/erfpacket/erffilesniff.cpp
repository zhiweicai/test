#include "erffilesniff.h"
#include "tins\ethernetII.h"

using namespace Tins;


ErfFileSniff::ErfFileSniff(const std::string& file_name)
{
	infile.open(file_name, ios::binary | ios::in);
}


ErfFileSniff::~ErfFileSniff()
{
	infile.close();
}

PtrPacket ErfFileSniff::next_packet()
{
	struct timeval tv;
	PDU *pdu;	
	ERF_HEAD hd;
	
	infile.read(reinterpret_cast <char*>(&hd), sizeof(hd));

	if (infile)
	{
		hd.ntoh();
		if (!hd.IsValid()) throw "Invalid ERF header";
		if (hd.GetType() != TYPE_ETH) throw unknown_link_type();

		tv.tv_sec = hd.seconds;
		tv.tv_usec = hd.nanoseconds;

		char buffer[19200];

		infile.read(buffer, (hd.rlen - sizeof(hd)));
		pdu = new EthernetII(reinterpret_cast <const uint8_t*>(buffer + sizeof(ETH_HEAD)), hd.wlen);
		return PtrPacket(pdu, tv);			
	}
	else
		return PtrPacket(nullptr, tv);
}