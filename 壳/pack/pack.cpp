// pack.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "pack.h"

#include "../Stub/Stub.h"
#pragma comment(lib,"../Debug/Stub.lib")
#include "PE.h"
#include <Psapi.h>
#pragma  comment(lib,"psapi.lib")

// ���ǵ���������һ��ʾ��
PACK_API int npack=0;

// ���ǵ���������һ��ʾ����
PACK_API int fnpack(void)
{
	return 42;
}


// �����ѵ�����Ĺ��캯����
// �й��ඨ�����Ϣ������� pack.h
Cpack::Cpack()
{
	return;
}


int fnfilepath(CString filepath)
{
	// 1. ��ȡ���ӿǳ����PE��Ϣ
	PE objPE;
	objPE.InitPE(filepath);

	//���ܴ����  ������
	DWORD dwXorSize=objPE.XorCodeAndData(0x15);

	// 2. ����Ҫ����Ϣ���õ�Stub��
	HMODULE hMod = LoadLibrary(L"stub.dll");
	PGLOBAL_PARAM pstcParam = (PGLOBAL_PARAM)GetProcAddress(hMod, "g_stcParam");
	pstcParam->dwImageBase = objPE.m_dwImageBase;
	pstcParam->dwCodeSize = dwXorSize;
	pstcParam->dwOEP = objPE.m_dwImageBase+objPE.m_dwOEP;
	pstcParam->dwXorKey = 0x15;
	pstcParam->lpStartVA = (PBYTE)objPE.m_dwCodeBase;
	pstcParam->m_stcImportDir=objPE.m_stcImportDir;
	pstcParam->m_dwDataBase=objPE.m_dwDataBase;
	pstcParam->M_dwDataSize=objPE.m_dwDataSize;
	// 3. ���Stub����ε����ӿǳ�����
	// 3.1 ��ȡStub�����
	MODULEINFO ModInfo={0};
	GetModuleInformation (GetCurrentProcess(),hMod,&ModInfo,sizeof(MODULEINFO));
	PBYTE lpMod=new BYTE[ModInfo.SizeOfImage];
	memcpy_s(lpMod,ModInfo.SizeOfImage,hMod,ModInfo.SizeOfImage);
	PBYTE pCodeSection=NULL;
	DWORD dwCodeBaseRva=NULL;
	//pRelocAddrָ��������ε�VA   dwCodeBaseRva Ϊ�����ε�RVA(�����ַ)
	 DWORD dwSize = objPE.GetSectionData(lpMod,0,pCodeSection,dwCodeBaseRva);
	
	//�����£�����ӣ����ε�RVA
	DWORD dwNewSecRva=objPE.GetNewSectionRva();
	//��ȡ�ض�λ��Ϣ ���޸�
	objPE.FixReloc(lpMod,dwCodeBaseRva,dwNewSecRva);


	// 4. �޸ı��ӿǳ����OEP��ָ��stub
	//Ҫ�ض�λ��ַ-�ɻ�ַ-�ɶ���RVA+������RVA+�µļ��ػ�ַ����BUG��
	//dwStubOEPRVA=stub��ڵ�-���ػ�ַhmod
	DWORD dwStubOEPRVA = pstcParam->dwStart - (DWORD)hMod;
	//dwNewOEP=dwStubOEPRVA-stub��RVA(Ҳ������������ε�RVA)
	DWORD dwNewOEP=dwStubOEPRVA-dwCodeBaseRva;

	//�����µ�OEP
	objPE.SetNewOEP(dwNewOEP);
	//��������ַ
	objPE.ClearRandBase();
	objPE.ClearDataDir();

	if (objPE.AddSection(pCodeSection,dwSize,"12"))
	{
		AfxMessageBox(L"�ӿǳɹ�");
	}

	// 5. �޸�Stub���еĴ���

	// �ͷſռ�
	delete lpMod;
	lpMod = NULL;

	return TRUE;
}
