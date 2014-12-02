#include <tins/tins.h>
#include <map>
#include <iostream>
#include <functional>
#include "erffilesniff.h"

using namespace Tins;


bool process_packet(const Packet& pkt)
{
	std::cout << pkt.timestamp ().seconds() << "." << pkt.timestamp().microseconds() << std::endl;
	const IP &ip = pkt.pdu()->rfind_pdu<IP>(); // Find the IP layer
	const TCP &tcp = pkt.pdu()->rfind_pdu<TCP>(); // Find the TCP layer
	std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
		<< ip.dst_addr() << ':' << tcp.dport() << std::endl;
	return true;
}

int main(int argc, char *argv[]) 
{
    if(argc != 2) 
	{
        std::cout << "Usage: " << *argv << " <filename>\n";
        return 1;
    }
	try
	{		
		ErfFileSniff sniffer(argv[1]);
	
		// auto cleanup, no need to use pointers!
		Packet packet = sniffer.next_packet();
		// If there was some kind of error, packet.pdu() == nullptr,
		// so we need to check that.
		while (packet)
		{
			process_packet(packet);
			packet = sniffer.next_packet();
		}

		return 1;
		
	}
	catch (std::exception error)
	{
		std::cout << error.what() << std::endl;
	}
}
