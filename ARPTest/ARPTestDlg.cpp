/*
Copyright (C) 2015  xfgryujk

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

//  ARPTestDlg.cpp: the main dialog.
//

#include "stdafx.h"
#include "ARPTestDlg.h"
#include "ARPTest.h"
#include "NetManager.h"
#include "MITM.h"
#include "PacketHandlers.h"
#include "ThreadPool.h"
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
	if (!g_netManager.Init(errBuf))
	{
		CString msg = "Error in pcap_findalldevs: ";
		msg += errBuf;
		MessageBox(msg, NULL, MB_ICONERROR);
		DestroyWindow();
		return TRUE;
	}

	// show device list
	for (pcap_if_t* device = g_netManager.m_deviceList; device != nullptr; device = device->next)
		m_deviceDescList.AddString(device->description != nullptr ? device->description : "");
	if (m_deviceDescList.GetCount() <= 0)
	{
		MessageBox("No interface found! Make sure WinPcap is installed.", NULL, MB_ICONERROR);
		DestroyWindow();
		return TRUE;
	}
	m_deviceDescList.SetCurSel(0);
	OnLbnSelchangeList1();

	// init packet handlers
	g_packetHandlers.Init();

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// release
void CARPTestDlg::OnDestroy()
{
	CDialog::OnDestroy();

	g_mitm.StopAttack();
	theApp.m_isRunning = false;
	g_threadPool.StopThreads();
	g_netManager.Uninit();
}

/////////////////////////////////////////////////////////////////////////////////////////

// get adapter infomation and fill edits
void CARPTestDlg::OnLbnSelchangeList1()
{
	int index = m_deviceDescList.GetCurSel();
	if (!g_netManager.SelectAdapter(index))
	{
		MessageBox("Failed to get adapter infomation.", NULL, MB_ICONERROR);
		return;
	}

	// fill edits
	m_selfIpEdit.SetWindowText((CString)g_netManager.m_selfIp);
	m_selfMacEdit.SetWindowText((CString)g_netManager.m_selfMac);
	m_selfGatewayEdit.SetWindowText((CString)g_netManager.m_selfGateway);
}

// confirm device and scan hosts
void CARPTestDlg::OnBnClickedButton2()
{
	m_deviceDescList.EnableWindow(FALSE);
	m_confirmButton.EnableWindow(FALSE);
	m_attackButton.EnableWindow(TRUE);
	SetTimer(0, 3000, NULL);
	
	g_netManager.StartScanHost([this](IpAddress ip, MacAddress mac){
		// add to list
		int index = -1;
		if (ip != g_netManager.m_selfIp && ip != g_netManager.m_selfGateway)
		{
			auto& arpCheatConfig = g_mitm.m_arpCheat->GetConfig(ip);
			auto& mitmConfig = g_mitm.GetConfig(ip);
			auto& imageReplaceConfig = g_packetHandlers.imageReplace.GetConfig(ip);

			index = m_hostList.GetItemCount();
			m_hostList.InsertItem(index, "");
			m_hostList.SetItemText(index, 1, (CString)ip);
			m_hostList.SetItemText(index, 2, (CString)mac);
			CString tmp;
			if (arpCheatConfig.cheatTarget)
				tmp += "↑";
			if (arpCheatConfig.cheatGateway)
				tmp += "↓";
			m_hostList.SetItemText(index, 3, tmp);
			m_hostList.SetItemText(index, 4, mitmConfig.forward ? "True" : "False");
			m_hostList.SetItemData(index, (DWORD_PTR)ip);
		}

		// auto check
		if (index != -1 && m_autoCheckCheck.GetCheck())
			m_hostList.SetCheck(index);
	});
}

#pragma region Host Config
/////////////////////////////////////////////////////////////////////////////////////////
//
//                                      Host Config
//

// attack / display host information
void CARPTestDlg::OnLvnItemchangedList2(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	*pResult = 0;

	ARPCheat& arpCheat = *g_mitm.m_arpCheat;
	IpAddress ip = (DWORD)m_hostList.GetItemData(pNMLV->iItem);
	if (ip == 0)
		return;
	auto& arpConfig = arpCheat.GetConfig(ip);
	auto& mitmConfig = g_mitm.GetConfig(ip);
	auto& imageReplaceConfig = g_packetHandlers.imageReplace.GetConfig(ip);

	// select a new host
	if (pNMLV->uChanged == LVIF_STATE)
	{
		if ((pNMLV->uNewState & LVIS_SELECTED) != 0)
		{
			m_cheatTargetCheck.SetCheck(arpConfig.cheatTarget);
			m_cheatGatewayCheck.SetCheck(arpConfig.cheatGateway);
			m_forwardCheck.SetCheck(mitmConfig.forward);
			m_replaceImagesCheck.SetCheck(imageReplaceConfig.replaceImages);
			m_imagePathEdit.SetWindowText(imageReplaceConfig.imagePath);
			OnTimer(0);
			return;
		}
	}

#pragma region
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
#pragma endregion

	// attack or not
	arpCheat.SetConfig(ip, checked != 0, arpConfig.cheatTarget, arpConfig.cheatGateway);
}

IpAddress CARPTestDlg::GetCurSelIp(int& index)
{
	POSITION pos = m_hostList.GetFirstSelectedItemPosition();
	if (pos == nullptr)
		return 0;
	index = m_hostList.GetNextSelectedItem(pos);
	return (DWORD)m_hostList.GetItemData(index);
}

// cheat target
void CARPTestDlg::OnBnClickedCheck3()
{
	int index;
	IpAddress ip = GetCurSelIp(index);
	if (ip == 0)
		return;

	ARPCheat& arpCheat = *g_mitm.m_arpCheat;
	auto& config = arpCheat.GetConfig(ip);
	arpCheat.SetConfig(ip, config.attack, m_cheatTargetCheck.GetCheck() != 0, config.cheatGateway);

	CString tmp;
	if (config.cheatTarget)
		tmp += "↑";
	if (config.cheatGateway)
		tmp += "↓";
	m_hostList.SetItemText(index, 3, tmp);
}

// cheat gateway
void CARPTestDlg::OnBnClickedCheck4()
{
	int index;
	IpAddress ip = GetCurSelIp(index);
	if (ip == 0)
		return;

	ARPCheat& arpCheat = *g_mitm.m_arpCheat;
	auto& config = arpCheat.GetConfig(ip);
	arpCheat.SetConfig(ip, config.attack, config.cheatTarget, m_cheatGatewayCheck.GetCheck() != 0);

	CString tmp;
	if (config.cheatTarget)
		tmp += "↑";
	if (config.cheatGateway)
		tmp += "↓";
	m_hostList.SetItemText(index, 3, tmp);
}

// forward
void CARPTestDlg::OnBnClickedCheck1()
{
	int index;
	IpAddress ip = GetCurSelIp(index);
	if (ip == 0)
		return;

	auto& config = g_mitm.GetConfig(ip);
	g_mitm.SetConfig(ip, m_forwardCheck.GetCheck() != 0);

	m_hostList.SetItemText(index, 4, config.forward ? "True" : "False");
}

// replace images
void CARPTestDlg::OnBnClickedCheck2()
{
	int index;
	IpAddress ip = GetCurSelIp(index);
	if (ip == 0)
		return;

	auto& config = g_packetHandlers.imageReplace.GetConfig(ip);
	g_packetHandlers.imageReplace.SetConfig(ip, m_replaceImagesCheck.GetCheck() != 0, config.imagePath);
	
	m_hostList.SetItemText(index, 5, config.replaceImages ? config.imagePath : "");
}

// image path
void CARPTestDlg::OnEnKillfocusEdit1()
{
	int index;
	IpAddress ip = GetCurSelIp(index);
	if (ip == 0)
		return;

	CString path;
	m_imagePathEdit.GetWindowText(path);
	auto& config = g_packetHandlers.imageReplace.GetConfig(ip);
	g_packetHandlers.imageReplace.SetConfig(ip, config.replaceImages, path);

	m_hostList.SetItemText(index, 5, config.replaceImages ? config.imagePath : "");
}

// update status
void CARPTestDlg::OnTimer(UINT_PTR nIDEvent)
{
	if (nIDEvent == 0) // update status
	{
		int index;
		IpAddress ip = GetCurSelIp(index);
		if (ip == 0)
			return;

		auto& mitmConfig = g_mitm.GetConfig(ip);
		auto& imageReplaceConfig = g_packetHandlers.imageReplace.GetConfig(ip);

		CString status;
		status.Format("Sent %u, Received %u, Replaced %u", mitmConfig.send, mitmConfig.receive, imageReplaceConfig.replace);
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
	if (g_mitm.IsAttacking())
	{
		g_mitm.StopAttack();
		m_attackButton.EnableWindow(FALSE);
		return;
	}
	m_attackButton.EnableWindow(FALSE);

	g_mitm.StartAttack([this]{
		m_attackButton.SetWindowText("Stop");
		m_attackButton.EnableWindow(TRUE);
	}, [this]{
		if (theApp.m_isRunning)
		{
			m_attackButton.SetWindowText("Start");
			m_attackButton.EnableWindow(TRUE);
		}
	});
}
