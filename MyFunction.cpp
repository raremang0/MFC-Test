#include"MyFunction.h"

BOOL IsPeFile(PVOID pImageBase)
{
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;
	pDH = (PIMAGE_DOS_HEADER)pImageBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	if (pNtH->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	return TRUE;
}


PIMAGE_NT_HEADERS GetNtHeaders(PVOID pImageBase)
{
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;

	if (!IsPeFile(pImageBase))
		return NULL;

	pDH = (PIMAGE_DOS_HEADER)pImageBase;
	pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);

	return pNtH;
}


PIMAGE_FILE_HEADER GetFileHeader(PVOID pImageBase)
{
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_FILE_HEADER pFH = NULL;

	pNtH = GetNtHeaders(pImageBase);
	pFH = &pNtH->FileHeader;
	return pFH;
}


PIMAGE_OPTIONAL_HEADER GetOptionalHeader(PVOID pImageBase)
{
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_OPTIONAL_HEADER pOH = NULL;

	pNtH = GetNtHeaders(pImageBase);
	pOH = &pNtH->OptionalHeader;
	return pOH;
}


PIMAGE_SECTION_HEADER GetFirstSectionHeader(PVOID pImageBase)
{
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_SECTION_HEADER pSH = NULL;
	pNtH = GetNtHeaders(pImageBase);
	pSH = IMAGE_FIRST_SECTION(pNtH);
	return pSH;
}


//RVA transformed into FOA
DWORD RVAtoFOA(DWORD pRVA, PVOID pImageBase)
{
	PIMAGE_DOS_HEADER pDos = NULL;
	PIMAGE_FILE_HEADER pFile = NULL;
	PIMAGE_OPTIONAL_HEADER pOptional = NULL;
	PIMAGE_SECTION_HEADER pSection = NULL;

	pDos = (PIMAGE_DOS_HEADER)pImageBase;
	pFile = (PIMAGE_FILE_HEADER)((DWORD)pDos + pDos->e_lfanew + 4);
	pOptional = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER);
	pSection = (PIMAGE_SECTION_HEADER)((DWORD)pOptional + pFile->SizeOfOptionalHeader);

	PIMAGE_SECTION_HEADER pTempScetion = pSection;
	for (size_t i = 0; i < pFile->NumberOfSections; i++, pTempScetion++)
	{
		if ((pRVA >= pTempScetion->VirtualAddress) && (pRVA < pTempScetion->VirtualAddress + pTempScetion->Misc.VirtualSize))
		{
			//printf("RVAtoFOA:0x%x\n", pRVA - pTempScetion->VirtualAddress + pTempScetion->PointerToRawData);
			return pRVA - pTempScetion->VirtualAddress + pTempScetion->PointerToRawData;
		}
	}
	return 0;
}


//FOA transformed into RVA
DWORD FOAtoRVA(DWORD pFOA, PVOID pImageBase)
{
	PIMAGE_DOS_HEADER pDos = NULL;
	PIMAGE_FILE_HEADER pFile = NULL;
	PIMAGE_OPTIONAL_HEADER pOptional = NULL;
	PIMAGE_SECTION_HEADER pSection = NULL;

	pDos = (PIMAGE_DOS_HEADER)pImageBase;
	pFile = (PIMAGE_FILE_HEADER)((DWORD)pDos + pDos->e_lfanew + 4);
	pOptional = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER);
	pSection = (PIMAGE_SECTION_HEADER)((DWORD)pOptional + pFile->SizeOfOptionalHeader);

	PIMAGE_SECTION_HEADER pTempScetion = pSection;
	for (size_t i = 0; i < pFile->NumberOfSections; i++, pTempScetion++)
	{
		if ((pFOA >= pTempScetion->PointerToRawData) && (pFOA < pTempScetion->PointerToRawData + pTempScetion->SizeOfRawData))
		{
			//printf("FOAtoRVA:0x%x\n", pFOA - pTempScetion->PointerToRawData + pTempScetion->VirtualAddress);
			return pFOA - pTempScetion->PointerToRawData + pTempScetion->VirtualAddress;
		}
	}
	return 0;
}


BOOL CopyFileBufferToImageBuffer(PVOID pImageBase, PVOID* pFileBuffer)
{
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_FILE_HEADER pFH = NULL;
	PIMAGE_OPTIONAL_HEADER pOH = NULL;
	PIMAGE_SECTION_HEADER pSH = NULL;
	PIMAGE_SECTION_HEADER pTempSH = NULL;

	pNtH = GetNtHeaders(pImageBase);
	pFH = GetFileHeader(pImageBase);
	pOH = GetOptionalHeader(pImageBase);
	pSH = GetFirstSectionHeader(pImageBase);

	PVOID pTemp = malloc(pOH->SizeOfImage);
	memcpy(pTemp, pImageBase, pOH->SizeOfHeaders);
	pTemp = (PVOID)((DWORD)pTemp + pOH->SizeOfHeaders);
	pTempSH = pSH;
	for (int Count = 0; Count < pFH->NumberOfSections; pTemp=(PVOID)((DWORD)pTemp+pTempSH->Misc.VirtualSize))
	{
		//memcpy(pTemp,)
	}
}