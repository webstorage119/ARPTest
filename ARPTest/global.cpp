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


UINT AFX_CDECL PacketHandleThread(LPVOID _adapter)
{
	pcap_t* adapter = (pcap_t*)_adapter;
	CARPTestDlg* thiz = (CARPTestDlg*)AfxGetApp()->m_pMainWnd;

	int targetIp = (int)thiz->m_hostList.GetItemDataPtr(thiz->m_hostList.GetCurSel());
	BYTE targetMac[6], gatewayMac[6];
	MoveMemory(targetMac, g_host[targetIp], 6);
	MoveMemory(gatewayMac, g_gatewayMac, 6);

	pcap_pkthdr* header;
	const BYTE* pkt_data;
	int res;
	try{
	while ((res = pcap_next_ex(adapter, &header, &pkt_data)) >= 0)
	{
		if (res == 0) // timeout
			continue;
		if (memcmp(&pkt_data[6], targetMac, 6) == 0 && memcmp(pkt_data, g_selfMac, 6) == 0) // is target packet
		{
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
			&& *(short*)&pkt_data[12] == 0x0008 && *(int*)&pkt_data[30] == targetIp) // to target
		{
			if (pkt_data[23] == 6) // TCP
			{
				int ipLength = (pkt_data[14] & 0x0F) * 4;
				int tcpLength = (pkt_data[14 + ipLength + 12] >> 4) * 4;
				if (strncmp((LPCSTR)&pkt_data[14 + ipLength + tcpLength], "HTTP/1.", 7) == 0) // HTTP
				{
					CString http = (LPCSTR)&pkt_data[14 + ipLength + tcpLength];
				}
			}
			
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
	}catch (...){}

	return 0;
}
