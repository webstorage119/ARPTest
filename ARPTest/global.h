#pragma once
#include <pcap.h>
#include <map>
using std::map;


#pragma pack(push)
#pragma pack(1)
struct ARPPacket
{
	BYTE destinationMac[6];
	BYTE sourceMac[6];
	short type;					// 0x0608 ARP

	short hardwareType;			// 0x0100 Ethernet
	short protocolType;			// 0x0008 IP
	BYTE hardwareSize;		// 6 MAC
	BYTE protocolSize;		// 4 IP
	short opcode;				// 0x0100 request, 0x0200 reply
	BYTE senderMac[6];
	int senderIp;
	BYTE targetMac[6];
	int targetIp;

	ARPPacket(short op)
	{
		ZeroMemory(destinationMac, 6);
		ZeroMemory(sourceMac, 6);
		type = 0x0608;
		hardwareType = 0x0100;
		protocolType = 0x0008;
		hardwareSize = 6;
		protocolSize = 4;
		opcode = op;
		ZeroMemory(senderMac, 6);
		senderIp = 0;
		ZeroMemory(targetMac, 6);
		targetIp = 0;
	}
};
#pragma pack(pop)


extern pcap_if_t* g_deviceList;
extern pcap_if_t* g_adapter;
extern int g_selfIp;
extern BYTE g_selfMac[6];
extern int g_selfGateway;
extern BYTE g_gatewayMac[6];

extern map<int, BYTE[6]> g_host;


BOOL inputIp(LPCSTR src, int& dest);

// remember pcap_close()
BOOL GetAdapterHandle(pcap_t*& adapter);

UINT AFX_CDECL PacketHandleThread(LPVOID _adapter);
