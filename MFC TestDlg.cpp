﻿
// MFC TestDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "MFC Test.h"
#include "MFC TestDlg.h"
#include "afxdialogex.h"
#include<Windows.h>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

HWND Dialog_Main = NULL;
HWND Edit_Pid = NULL;
HWND Edit_Path = NULL;
// CMFCTestDlg 对话框



CMFCTestDlg::CMFCTestDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MFCTEST_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCTestDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CMFCTestDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_Inject, &CMFCTestDlg::OnBnClickedButtonInject)
	ON_BN_CLICKED(IDC_BUTTON_SelectFile, &CMFCTestDlg::OnBnClickedButtonSelectfile)
END_MESSAGE_MAP()


// CMFCTestDlg 消息处理程序

BOOL CMFCTestDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	Dialog_Main = AfxGetApp()->GetMainWnd()->GetSafeHwnd();
	Edit_Pid = CMFCTestDlg::GetDlgItem(IDD_EDI_)
	Edit_Path = GetDlgItem(Dialog_Main, IDC_EDIT_Path);


	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMFCTestDlg::OnPaint()
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
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMFCTestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMFCTestDlg::OnBnClickedButtonInject()
{
	
	// TODO: 在此添加控件通知处理程序代码
}


void CMFCTestDlg::OnBnClickedButtonSelectfile()
{
	LPITEMIDLIST pil = NULL;
	INITCOMMONCONTROLSEX InitCtrls = { 0 };
	TCHAR szBuf[4096] = { 0 };
	BROWSEINFO bi = { 0 };


	bi.hwndOwner = NULL;
	bi.iImage = 0;
	bi.lParam = NULL;
	bi.lpfn = NULL;
	bi.lpszTitle = ("请选择文件路径");
	bi.pszDisplayName = szBuf;
	bi.ulFlags = BIF_BROWSEINCLUDEFILES;

	InitCommonControlsEx(&InitCtrls);

	pil = SHBrowseForFolder(&bi);

	if (NULL != pil)
	{
		SHGetPathFromIDList(pil, szBuf);
	
	}

	
	// TODO: 在此添加控件通知处理程序代码
}
