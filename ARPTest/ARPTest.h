
// ARPTest.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CARPTestApp: 
// �йش����ʵ�֣������ ARPTest.cpp
//

class CARPTestApp : public CWinApp
{
public:
	CARPTestApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()

public:
	// is program running
	bool m_isRunning = true;
};

extern CARPTestApp theApp;