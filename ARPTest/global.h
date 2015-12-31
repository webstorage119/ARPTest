#pragma once
#include <pcap.h>
#include <map>
using std::map;

#include "Packet.h"


struct HostInfoSetting
{
	DWORD ip;
	MacAddress mac;
	DWORD send, receive;

	struct HttpImageLink
	{
		WORD sourcePort;
		BYTE* initPacket;
		DWORD initPacketLen;

		~HttpImageLink()
		{
			if (initPacket != NULL)
				delete initPacket;
		}
	};
	map<WORD, HttpImageLink> httpImageLink; // port -> HttpImageLink
	CCriticalSection httpImageLinkLock;

	BOOL cheatTarget, cheatGateway;
	BOOL forward;
	BOOL replaceImages;
	CString imagePath;
	DWORD imageDataLen;
	BYTE* imageData;
	CCriticalSection imageDataLock;

	HostInfoSetting()
	{
		ip = 0;
		cheatTarget = cheatGateway = TRUE;
		forward = TRUE;
		send = receive = 0;
		replaceImages = FALSE;
		imageData = NULL;
	}

	~HostInfoSetting()
	{
		if (imageData != NULL)
		{
			imageDataLock.Lock();
			delete imageData;
			imageData = NULL;
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

extern map<DWORD, HostInfoSetting> g_host; // IP -> HostInfoSetting
extern map<DWORD, HostInfoSetting*> g_attackList; // IP -> HostInfoSetting
extern map<MacAddress, HostInfoSetting*> g_attackListMac; // MAC -> HostInfoSetting
extern CCriticalSection g_hostAttackListLock; // for g_host g_attackList g_attackListMac


BOOL inputIp(LPCSTR src, DWORD& dest);
// remember pcap_close()
BOOL GetAdapterHandle(pcap_t*& adapter);
void SetFilter(pcap_t* adapter, LPCSTR exp);

UINT AFX_CDECL PacketHandleThread(LPVOID _adapter);
