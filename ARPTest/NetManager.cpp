#include "stdafx.h"
#include "NetManager.h"
#include "ARPTest.h"
#include "ThreadPool.h"
#include "Helper.h"
#include "Packet.h"


NetManager& g_netManager = NetManager::GetInstance();


bool NetManager::Init(char* errBuf)
{
	return pcap_findalldevs(&m_deviceList, errBuf) != -1;
}

void NetManager::Uninit()
{
	pcap_freealldevs(m_deviceList);
}

bool NetManager::SelectAdapter(int index)
{
	// get adapter
	m_adapter = m_deviceList;
	for (int i = 0; i < index; i++)
	{
		m_adapter = m_adapter->next;
		if (m_adapter == nullptr)
			return false;
	}

	// get adapter infomation
	CString ip, gateway;
	MacAddress mac;

	IP_ADAPTER_INFO adapterInfo[16];
	DWORD bufSize = sizeof(adapterInfo);
	DWORD status = GetAdaptersInfo(adapterInfo, &bufSize);
	if (status != ERROR_SUCCESS)
		return false;

	CString name = m_adapter->name;
	for (PIP_ADAPTER_INFO pInfo = adapterInfo; pInfo != nullptr; pInfo = pInfo->Next)
	{
		if (name.Find(pInfo->AdapterName) != -1)
		{
			ip = pInfo->IpAddressList.IpAddress.String;
			mac = *(MacAddress*)pInfo->Address;
			gateway = pInfo->GatewayList.IpAddress.String;
			break;
		}
	}
	if (ip == "")
		return false;

	// fill variables
	m_selfIp = ip;
	m_selfMac = mac;
	m_selfGateway = gateway;

	return true;
}

void NetManager::StartScanHost(std::function<void(IpAddress, MacAddress)> onNewHost)
{
	g_threadPool.AddTask([=]{
		AdapterHandle adapter(GetAdapterHandle());
		if (adapter == nullptr)
			return;

		ARPPacket packet(TRUE);
		memset(&packet.destinationMac, 0xFF, sizeof(packet.destinationMac)); // broadcast
		packet.SetSender(m_selfIp, m_selfMac);

		// get IP range
		DWORD rSelfIp = ntohl(m_selfIp);
		DWORD startIp = rSelfIp & 0xFFFFFF00 | 0x01;
		DWORD stopIp = rSelfIp & 0xFFFFFF00 | 0xFE;

		// scan
		packet.targetIp = m_selfGateway;
		pcap_sendpacket(adapter.get(), (u_char*)&packet, sizeof(packet));
		Sleep(10);
		for (DWORD ip = startIp; ip <= stopIp; ip++)
		{
			DWORD rIp = htonl(ip);
			if (rIp != m_selfIp && rIp != m_selfGateway)
			{
				packet.targetIp = rIp;
				pcap_sendpacket(adapter.get(), (u_char*)&packet, sizeof(packet));
				Sleep(10);
			}
		}

		// get reply
		SetFilter(adapter.get(), "ether proto arp");
		pcap_pkthdr* header;
		const BYTE* pkt_data;
		int res;
		while (theApp.m_isRunning && (res = pcap_next_ex(adapter.get(), &header, &pkt_data)) >= 0)
		{
			if (res == 0) // timeout
				continue;
			const ARPPacket* pak = (const ARPPacket*)pkt_data;
			if (pak->type != PROTOCOL_ARP
				|| (pak->opcode != ARP_OPCODE_REPLY && pak->opcode != ARP_OPCODE_REQUEST)
				|| pak->senderIp == 0) // not ARP
				continue;
			if (m_host.find(pak->senderIp) != m_host.end()) // in m_host
				continue;

			// add to m_host
			m_host[pak->senderIp] = pak->senderMac;

			if (pak->senderIp == m_selfGateway)
				m_gatewayMac = pak->senderMac;

			// callback
			onNewHost(pak->senderIp, pak->senderMac);
		}
		TRACE("scan end\n");
	});
}
