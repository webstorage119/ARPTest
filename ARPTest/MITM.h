#pragma once
#include "SyncMap.h"
#include <memory>
#include <functional>
#include "TypeHelper.h"
#include "ARPCheat.h"
#include <vector>
#include "PacketHandler.h"


class MITM
{
private:
	MITM() = default;

public:
	static MITM& GetInstance()
	{
		static MITM instance;
		return instance;
	}

	std::unique_ptr<ARPCheat> m_arpCheat = std::unique_ptr<ARPCheat>(new ARPCheat());

	struct Config
	{
		bool forward = true;
		UINT send = 0;
		UINT receive = 0;
	};
	Config& GetConfig(IpAddress ip);
	void SetConfig(IpAddress ip, bool forward);

	bool IsAttacking()
	{
		return m_isAttacking;
	}
	void StartAttack(std::function<void()> onThreadStart, std::function<void()> onThreadEnd);
	void StopAttack();

	void AddPacketHandler(PacketHandler* packetHandler);

protected:
	volatile bool m_isAttacking = false;

	SyncMap<IpAddress, std::shared_ptr<Config> > m_attackList; // IP -> Config
	SyncMap<MacAddress, std::shared_ptr<Config> > m_attackListMac; // MAC -> Config

	std::vector<PacketHandler*> m_packetHandlers;
	
	void PacketHandleThread();
};

extern MITM& g_mitm;
