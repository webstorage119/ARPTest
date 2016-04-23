#pragma once
#include <atomic>
#include "SyncMap.h"
#include "TypeHelper.h"
#include <thread>


class ARPCheat
{
public:
	ARPCheat()
	{
		m_isAttacking = false;
	}

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
	std::atomic_bool m_isAttacking;

	SyncMap<IpAddress, Config> m_attackList; // IP -> Config

	std::thread m_cheatThread;
};
