#pragma once
#include <pcap.h>
#include <map>
#include <memory>

#include "Packet.h"


struct HostInfoSetting
{
	// information
	DWORD ip;
	MacAddress mac;
	DWORD send, receive;

	// image infomation
	struct HttpImageLink
	{
		WORD sourcePort;
		std::unique_ptr<BYTE[]> initPacket;
		DWORD initPacketLen;
	};
	std::map<WORD, HttpImageLink> httpImageLink; // port -> HttpImageLink
	CCriticalSection httpImageLinkLock;

	// setting
	BOOL cheatTarget, cheatGateway;
	BOOL forward;
	BOOL replaceImages;
	CString imagePath;
	DWORD imageDataLen;
	std::unique_ptr<BYTE[]> imageData;
	CCriticalSection imageDataLock;

	HostInfoSetting()
	{
		ip = 0;
		cheatTarget = cheatGateway = TRUE;
		forward = TRUE;
		send = receive = 0;
		replaceImages = FALSE;
		imageDataLen = 0;
	}

	~HostInfoSetting()
	{
		if (imageData != nullptr)
		{
			imageDataLock.Lock();
			imageData.reset();
			imageDataLock.Unlock();
		}
	}
};


extern volatile BOOL g_programRunning;
extern volatile BOOL g_attacking;

extern pcap_if_t* g_deviceList;
extern pcap_if_t* g_adapter;
extern DWORD g_selfIp;
extern MacAddress g_selfMac;
extern DWORD g_selfGateway;
extern MacAddress g_gatewayMac;

extern std::map<DWORD, HostInfoSetting> g_host; // IP -> HostInfoSetting
extern std::map<DWORD, std::unique_ptr<HostInfoSetting> > g_attackList; // IP -> HostInfoSetting
extern std::map<MacAddress, std::unique_ptr<HostInfoSetting> > g_attackListMac; // MAC -> HostInfoSetting
extern CCriticalSection g_hostAttackListLock; // for g_host g_attackList g_attackListMac


BOOL inputIp(LPCSTR src, DWORD& dest);
// remember pcap_close()
BOOL GetAdapterHandle(pcap_t*& adapter);
void SetFilter(pcap_t* adapter, LPCSTR exp);

UINT AFX_CDECL PacketHandleThread(LPVOID _adapter);
