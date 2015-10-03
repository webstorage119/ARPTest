
// ARPTestDlg.h : 头文件
//

#pragma once
#include "afxwin.h"
#include <pcap.h>


// CARPTestDlg 对话框
class CARPTestDlg : public CDialog
{
// 构造
public:
	CARPTestDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_ARPTEST_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnDestroy();
	afx_msg void OnLbnSelchangeList1();
	afx_msg void OnBnClickedButton2();

	pcap_if_t* GetAdapter();


public:
	CListBox m_deviceDescList;
	CEdit m_selfIpEdit;
	CEdit m_selfMacEdit;
	CEdit m_selfGatewayEdit;
	CListBox m_hostList;
	CEdit m_startIpEdit;
	CEdit m_stopIpEdit;
	CButton m_scanButton;
	CButton m_retransmissionCheck;
	CButton m_replaceImagesCheck;
	CEdit m_imagePathEdit;
	CButton m_attackButton;
};
