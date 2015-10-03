
// ARPTestDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"
#include <pcap.h>


// CARPTestDlg �Ի���
class CARPTestDlg : public CDialog
{
// ����
public:
	CARPTestDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_ARPTEST_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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
