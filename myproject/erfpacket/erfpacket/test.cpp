/*
 * Copyright (c) 2014, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
 
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