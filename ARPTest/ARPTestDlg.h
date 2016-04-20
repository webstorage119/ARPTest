
// ARPTestDlg.h : 头文件
//

#pragma once
#include "afxwin.h"
#include "TypeHelper.h"


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
	afx_msg void OnLvnItemchangedList2(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedCheck3();
	afx_msg void OnBnClickedCheck4();
	afx_msg void OnBnClickedCheck1();
	afx_msg void OnBnClickedCheck2();
	afx_msg void OnEnKillfocusEdit1();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnBnClickedButton3();

	IpAddress GetCurSelIp(int& index);


public:
	CListBox m_deviceDescList;
	CEdit m_selfIpEdit;
	CEdit m_selfMacEdit;
	CEdit m_selfGatewayEdit;
	CButton m_confirmButton;

	CListCtrl m_hostList;
	CButton m_cheatTargetCheck;
	CButton m_cheatGatewayCheck;
	CButton m_forwardCheck;
	CButton m_replaceImagesCheck;
	CEdit m_imagePathEdit;
	CStatic m_statusStatic;

	CButton m_attackButton;
	CButton m_checkAllButton;
	CButton m_autoCheckCheck;
};
