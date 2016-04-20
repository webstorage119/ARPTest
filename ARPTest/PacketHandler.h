#pragma once
#include <pcap.h>

class PacketHandler
{
public:
	virtual ~PacketHandler() { }

	// return false to stop forwarding
	virtual bool OnTargetPacket(const pcap_pkthdr* header, const BYTE* pkt_data)
	{
		return true;
	}

	// return false to stop forwarding
	virtual bool OnGatewayPacket(const pcap_pkthdr* header, const BYTE* pkt_data)
	{
		return true;
	}
};
