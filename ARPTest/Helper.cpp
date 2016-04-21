#include "stdafx.h"
#include "Helper.h"
#include "MITM.h"
#include "NetManager.h"
#include <direct.h>


AdapterHandle GetAdapterHandle()
{
	AdapterHandle adapter(nullptr, [](pcap_t* p){ pcap_close(p); });
	if (g_netManager.m_adapter == nullptr)
		return adapter;
	// open adapter
	char errBuf[PCAP_ERRBUF_SIZE];
	adapter.reset(pcap_open_live(g_netManager.m_adapter->name, 65536, 1, 1, errBuf));
	if (adapter == nullptr)
		AfxMessageBox("Error in pcap_open_live: " + CString(g_netManager.m_adapter->name) + " is not supported by WinPcap", MB_ICONERROR);
	return adapter;
}

void SetFilter(pcap_t* adapter, const char* exp)
{
	ULONG netmask = g_netManager.m_adapter->addresses == nullptr ? 0x00FFFFFF : 
		((sockaddr_in*)g_netManager.m_adapter->addresses->netmask)->sin_addr.S_un.S_addr;
	bpf_program fcode;
	pcap_compile(adapter, &fcode, exp, 1, netmask);
	pcap_setfilter(adapter, &fcode);
}

bool CreateDirs(const CString& path)
{
	if (PathFileExists(path))
		return true;
	int pos = path.ReverseFind(_T('\\'));
	if (pos != -1)
	{
		CString parent = path.Left(pos);
		if (!CreateDirs(parent))
			return false;
	}
	return CreateDirectory(path, NULL) != 0;
}
