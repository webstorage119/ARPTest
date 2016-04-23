#pragma once
#include "SyncMap.h"
#include "TypeHelper.h"
#include <thread>


class ARPCheat
{
public:
	void init();

	struct Config
	{
		bool attack = true;
		bool cheatTarget = true;
		bool cheatGateway = true;
	};
	Config& GetConfig(IpAddress ip);
	void SetConfig(IpAddress ip, bool attack, bool cheatTarget, bool cheatGateway);

	void StartAttack();
	// will block current thread
	void StopAttack();

protected:
	volatile bool m_isAttacking = false;

	SyncMap<IpAddress, Config> m_attackList; // IP -> Config

	std::thread m_cheatThread;
};
