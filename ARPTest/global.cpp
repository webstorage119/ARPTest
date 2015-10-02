#include "stdafx.h"
#include "ARPTestDlg.h"
#include "global.h"


pcap_if_t* g_deviceList = NULL;
pcap_if_t* g_adapter = NULL;
int g_selfIp = 0;
BYTE g_selfMac[6] = {};
int g_selfGetway = 0;

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

int reverseInt(int n)
{
	int n2;
	BYTE *bn = (BYTE*)&n, *bn2 = (BYTE*)&n2;
	bn2[0] = bn[3];
	bn2[1] = bn[2];
	bn2[2] = bn[1];
	bn2[3] = bn[0];
	return n2;
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
