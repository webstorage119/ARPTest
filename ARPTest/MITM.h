#pragma once
#include <map>
#include <memory>
#include <mutex>
#include <pcap.h>
#include "TypeHelper.h"
#include "ThreadPool.h"


extern volatile BOOL g_programRunning;
extern volatile BOOL g_attacking;

extern pcap_if_t* g_deviceList;
extern pcap_if_t* g_adapter;
extern DWORD g_selfIp;
extern MacAddress g_selfMac;
extern DWORD g_selfGateway;
extern MacAddress g_gatewayMac;

extern std::map<DWORD, HostInfoSetting> g_host; // IP -> HostInfoSetting
extern std::map<DWORD, HostInfoSetting*> g_attackList; // IP -> HostInfoSetting
extern std::map<MacAddress, HostInfoSetting*> g_attackListMac; // MAC -> HostInfoSetting
extern std::mutex g_hostAttackListLock; // for g_host g_attackList g_attackListMac

extern ThreadPool g_threadPool;


void PacketHandleThread();
