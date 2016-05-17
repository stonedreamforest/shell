// pack.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "pack.h"

#include "../Stub/Stub.h"
#pragma comment(lib,"../Debug/Stub.lib")
#include "PE.h"
#include <Psapi.h>
#pragma  comment(lib,"psapi.lib")

// 这是导出变量的一个示例
PACK_API int npack=0;

// 这是导出函数的一个示例。
PACK_API int fnpack(void)
{
	return 42;
}


// 这是已导出类的构造函数。
// 有关类定义的信息，请参阅 pack.h
Cpack::Cpack()
{
	return;
}


int fnfilepath(CString filepath)
{
	// 1. 读取被加壳程序的PE信息
	PE objPE;
	objPE.InitPE(filepath);

	//加密代码段  亦或加密
	DWORD dwXorSize=objPE.XorCodeAndData(0x15);

	// 2. 将必要的信息设置到Stub中
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
	// 3. 添加Stub代码段到被加壳程序中
	// 3.1 读取Stub代码段
	MODULEINFO ModInfo={0};
	GetModuleInformation (GetCurrentProcess(),hMod,&ModInfo,sizeof(MODULEINFO));
	PBYTE lpMod=new BYTE[ModInfo.SizeOfImage];
	memcpy_s(lpMod,ModInfo.SizeOfImage,hMod,ModInfo.SizeOfImage);
	PBYTE pCodeSection=NULL;
	DWORD dwCodeBaseRva=NULL;
	//pRelocAddr指向添加区段的VA   dwCodeBaseRva 为该区段的RVA(虚拟地址)
	 DWORD dwSize = objPE.GetSectionData(lpMod,0,pCodeSection,dwCodeBaseRva);
	
	//返回新（被添加）区段的RVA
	DWORD dwNewSecRva=objPE.GetNewSectionRva();
	//读取重定位信息 并修复
	objPE.FixReloc(lpMod,dwCodeBaseRva,dwNewSecRva);


	// 4. 修改被加壳程序的OEP，指向stub
	//要重定位地址-旧基址-旧段首RVA+新区段RVA+新的加载基址（有BUG）
	//dwStubOEPRVA=stub入口点-加载基址hmod
	DWORD dwStubOEPRVA = pstcParam->dwStart - (DWORD)hMod;
	//dwNewOEP=dwStubOEPRVA-stub的RVA(也就是新添加区段的RVA)
	DWORD dwNewOEP=dwStubOEPRVA-dwCodeBaseRva;

	//设置新的OEP
	objPE.SetNewOEP(dwNewOEP);
	//清除随机基址
	objPE.ClearRandBase();
	objPE.ClearDataDir();

	if (objPE.AddSection(pCodeSection,dwSize,"12"))
	{
		AfxMessageBox(L"加壳成功");
	}

	// 5. 修复Stub段中的代码

	// 释放空间
	delete lpMod;
	lpMod = NULL;

	return TRUE;
}
