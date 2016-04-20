#pragma once
#include "TypeHelper.h"


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
	MacAddress destinationMac;
	MacAddress sourceMac;
	WORD type;					// 0x0608 ARP

	WORD hardwareType;			// 0x0100 Ethernet
	WORD protocolType;			// 0x0008 IP
	BYTE hardwareSize;			// 6 MAC
	BYTE protocolSize;			// 4 IP
	WORD opcode;				// 0x0100 request, 0x0200 reply
	MacAddress senderMac;
	IpAddress senderIp;
	MacAddress targetMac;
	IpAddress targetIp;

	ARPPacket(bool request)
	{
		type = PROTOCOL_ARP;
		hardwareType = 0x0100;
		protocolType = PROTOCOL_IP;
		hardwareSize = 6;
		protocolSize = 4;
		opcode = request ? ARP_OPCODE_REQUEST : ARP_OPCODE_REPLY;
	}

	void SetSender(DWORD ip, const MacAddress& mac)
	{
		senderIp = ip;
		sourceMac = senderMac = mac;
	}

	void SetTarget(DWORD ip, const MacAddress& mac)
	{
		targetIp = ip;
		destinationMac = targetMac = mac;
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
	IpAddress sourceIp;
	IpAddress destinationIp;
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
