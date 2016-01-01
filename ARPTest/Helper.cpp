#include "stdafx.h"
#include "Helper.h"
#include "MITM.h"


bool InputIp(const char* src, DWORD& dest)
{
	DWORD ip[4];
	if (sscanf_s(src, "%u.%u.%u.%u", &ip[0], &ip[1], &ip[2], &ip[3]) != 4)
		return false;
	BYTE* bDest = (BYTE*)&dest;
	bDest[0] = (BYTE)ip[0];
	bDest[1] = (BYTE)ip[1];
	bDest[2] = (BYTE)ip[2];
	bDest[3] = (BYTE)ip[3];
	return true;
}

AdapterHandle GetAdapterHandle()
{
	AdapterHandle adapter(nullptr, [](pcap_t* p){ pcap_close(p); });
	if (g_adapter == nullptr)
		return adapter;
	// open adapter
	char errBuf[PCAP_ERRBUF_SIZE];
	adapter.reset(pcap_open_live(g_adapter->name, 65536, 1, 1000, errBuf));
	if (adapter == nullptr)
		AfxMessageBox("Error in pcap_open_live: " + CString(g_adapter->name) + " is not supported by WinPcap", MB_ICONERROR);
	return adapter;
}

void SetFilter(pcap_t* adapter, const char* exp)
{
	ULONG netmask = g_adapter->addresses == nullptr ? 0x00FFFFFF : ((sockaddr_in*)g_adapter->addresses->netmask)->sin_addr.S_un.S_addr;
	bpf_program fcode;
	pcap_compile(adapter, &fcode, exp, 1, netmask);
	pcap_setfilter(adapter, &fcode);
}
