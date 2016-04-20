#pragma once
#include <pcap.h>
#include "SyncMap.h"
#include "TypeHelper.h"
#include <functional>

class NetManager
{
private:
	NetManager() = default;

public:
	static NetManager& GetInstance()
	{
		static NetManager instance;
		return instance;
	}

	pcap_if_t* m_deviceList; // adapter list
	pcap_if_t* m_adapter; // current adapter
	IpAddress m_selfIp;
	MacAddress m_selfMac;
	IpAddress m_selfGateway;
	MacAddress m_gatewayMac;

	// IpAddress -> MacAddress, all hosts in the local network
	SyncMap<IpAddress, MacAddress> m_host;

	bool Init(char* errBuf);
	void Uninit();

	// called when user selects an adapter. get information and fill variables
	bool SelectAdapter(int index);
	// start a thread to scan hosts
	void StartScanHost(std::function<void(IpAddress, MacAddress)> onNewHost);
};

extern NetManager& g_netManager;
