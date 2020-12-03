#pragma once
#include<Windows.h>

#pragma warning(disable:4996)


BOOL IsPeFile(PVOID pImageBase);//判断是否为PE文件

PIMAGE_NT_HEADERS GetNtHeaders(PVOID pImageBase);//获取NT头

PIMAGE_FILE_HEADER GetFileHeader(PVOID pImageBase);//获取PE头

PIMAGE_OPTIONAL_HEADER GetOptionalHeader(PVOID pImageBase);//获取可选PE头

PIMAGE_SECTION_HEADER GetFirstSectionHeader(PVOID pImageBase);//获取第一个节

DWORD FOAtoRVA(DWORD pFOA, PVOID pImageBase);//FOA转RVA

DWORD FOAtoRVA(DWORD pFOA, PVOID pImageBase);//RVA转FOA

BOOL CopyFileBufferToImageBuffer(PVOID pImageBase, PVOID* pFileBuffer);//拉伸pe文件
