#pragma once
#include<Windows.h>

#pragma warning(disable:4996)


BOOL IsPeFile(PVOID pImageBase);//�ж��Ƿ�ΪPE�ļ�

PIMAGE_NT_HEADERS GetNtHeaders(PVOID pImageBase);//��ȡNTͷ

PIMAGE_FILE_HEADER GetFileHeader(PVOID pImageBase);//��ȡPEͷ

PIMAGE_OPTIONAL_HEADER GetOptionalHeader(PVOID pImageBase);//��ȡ��ѡPEͷ

PIMAGE_SECTION_HEADER GetFirstSectionHeader(PVOID pImageBase);//��ȡ��һ����

DWORD FOAtoRVA(DWORD pFOA, PVOID pImageBase);//FOAתRVA

DWORD FOAtoRVA(DWORD pFOA, PVOID pImageBase);//RVAתFOA

BOOL CopyFileBufferToImageBuffer(PVOID pImageBase, PVOID* pFileBuffer);//����pe�ļ�
