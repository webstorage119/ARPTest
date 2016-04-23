#pragma once
#include "MITM.h"
#include <pcap.h>
#include <memory>


class PacketHandler
{
public:
	PacketHandler()
	{
		g_mitm.AddPacketHandler(this);
	}

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

	// modify the packet from target
	virtual void OnTargetForward(std::unique_ptr<BYTE[]>& data, UINT& len) { }
	// modify the packet from gateway
	virtual void OnGatewayForward(std::unique_ptr<BYTE[]>& data, UINT& len) { }
};
