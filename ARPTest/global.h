#pragma once
#include <pcap.h>
#include <map>
using std::map;


const DWORD ETH_LENGTH = 14;
const WORD ARP_OPCODE_REQUEST = 0x0100;
const WORD ARP_OPCODE_REPLY = 0x0200;
const WORD PROTOCOL_ARP = 0x0608;
const WORD PROTOCOL_IP = 0x0008;
const BYTE PROTOCOL_TCP = 0x06;


#pragma pack(push)
#pragma pack(1)
struct ARPPacket
{
	BYTE destinationMac[6];
	BYTE sourceMac[6];
	WORD type;					// 0x0608 ARP

	WORD hardwareType;			// 0x0100 Ethernet
	WORD protocolType;			// 0x0008 IP
	BYTE hardwareSize;			// 6 MAC
	BYTE protocolSize;			// 4 IP
	WORD opcode;				// 0x0100 request, 0x0200 reply
	BYTE senderMac[6];
	DWORD senderIp;
	BYTE targetMac[6];
	DWORD targetIp;

	ARPPacket(BOOL request)
	{
		ZeroMemory(destinationMac, 6);
		ZeroMemory(sourceMac, 6);
		type = PROTOCOL_ARP;
		hardwareType = 0x0100;
		protocolType = PROTOCOL_IP;
		hardwareSize = 6;
		protocolSize = 4;
		opcode = request ? ARP_OPCODE_REQUEST : ARP_OPCODE_REPLY;
		ZeroMemory(senderMac, 6);
		senderIp = 0;
		ZeroMemory(targetMac, 6);
		targetIp = 0;
	}

	void SetSender(DWORD ip, BYTE* mac)
	{
		senderIp = ip;
		MoveMemory(sourceMac, mac, 6);
		MoveMemory(senderMac, mac, 6);
	}

	void SetTarget(DWORD ip, BYTE* mac)
	{
		targetIp = ip;
		MoveMemory(destinationMac, mac, 6);
		MoveMemory(targetMac, mac, 6);
	}
};

struct IPPacket
{
	BYTE headerLen : 4;
	BYTE version : 4;
	BYTE typeOfService;
	WORD totalLen;
	WORD identification;
	WORD fragmentOffset : 13;
	WORD flag : 3;
	BYTE timeToLive;
	BYTE protocol;				// 6 TCP
	WORD checkSum;
	DWORD sourceIp;
	DWORD destinationIp;
	//BYTE options[1];

	void CalcCheckSum()
	{
		BYTE* ptr = (BYTE*)this;
		int size = headerLen * 4;

		checkSum = 0;
		DWORD cksum = 0;
		for (int index = 0; index < size; index += 2)
		{
			cksum += ptr[index] << 8;
			cksum += ptr[index + 1];
		}
		while (cksum > 0xFFFF)
			cksum = (cksum >> 16) + (cksum & 0xFFFF);

		checkSum = htons(~(u_short)cksum);
	}
};

struct TCPPacket
{
	WORD sourcePort;
	WORD destinationPort;
	DWORD seq;
	DWORD ack;
	BYTE reserved : 4;
	BYTE headerLen : 4;
	BYTE fin : 1;
	BYTE syn : 1;
	BYTE rst : 1;
	BYTE psh : 1;
	BYTE ackFlag : 1;
	BYTE urg : 1;
	BYTE reserved2 : 2;
	WORD windowSize;
	WORD checkSum;
	WORD urgentPointer;
	//BYTE options[1];

	void CalcCheckSum(DWORD sourceIp, DWORD destinationIp, WORD tcpTotalLen)
	{
		checkSum = 0;
		struct {
			DWORD sourceIP;
			DWORD destinationIP;
			BYTE reserve;
			BYTE protocol;
			WORD tcpLength;
		} pseudo_header = { sourceIp, destinationIp, 0, PROTOCOL_TCP, htons(tcpTotalLen) };

		DWORD cksum = 0;
		BYTE* ptr = (BYTE*)&pseudo_header;
		for (DWORD index = 0; index < sizeof(pseudo_header); index += 2)
		{
			cksum += ptr[index] << 8;
			cksum += ptr[index + 1];
		}

		ptr = (BYTE*)this;
		DWORD size = (tcpTotalLen % 2 == 0) ? tcpTotalLen : tcpTotalLen - 1;
		for (DWORD index = 0; index < size; index += 2)
		{
			cksum += ptr[index] << 8;
			cksum += ptr[index + 1];
			while (cksum > 0xFFFF)
				cksum = (cksum >> 16) + (cksum & 0xFFFF);
		}
		if (tcpTotalLen % 2 != 0)
		{
			cksum += ptr[tcpTotalLen - 1] << 8;
			while (cksum > 0xFFFF)
				cksum = (cksum >> 16) + (cksum & 0xFFFF);
		}

		checkSum = htons(~(u_short)cksum);
	}
};
#pragma pack(pop)

struct HostInfoSetting
{
	DWORD ip;
	BYTE mac[6];
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
		ZeroMemory(mac, sizeof(mac));
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
extern BYTE g_selfMac[6];
extern DWORD g_selfGateway;
extern BYTE g_gatewayMac[6];

extern map<DWORD, HostInfoSetting> g_host; // IP -> HostInfoSetting
extern map<DWORD, HostInfoSetting*> g_attackList; // IP -> HostInfoSetting
extern map<DWORD64, HostInfoSetting*> g_attackListMac; // MAC -> HostInfoSetting
extern CCriticalSection g_hostAttackListLock; // for g_host g_attackList g_attackListMac


BOOL inputIp(LPCSTR src, DWORD& dest);
// remember pcap_close()
BOOL GetAdapterHandle(pcap_t*& adapter);
void SetFilter(pcap_t* adapter, LPCSTR exp);
DWORD64 BMacToDw64(const BYTE* mac);

UINT AFX_CDECL PacketHandleThread(LPVOID _adapter);
