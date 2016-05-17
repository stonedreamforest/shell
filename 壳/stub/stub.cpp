// stub.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "stub.h"


// 这是导出变量的一个示例
STUB_API int nstub=0;

// 这是导出函数的一个示例。
STUB_API int fnstub(void)
{
	return 42;
}

// 这是已导出类的构造函数。
// 有关类定义的信息，请参阅 stub.h
Cstub::Cstub()
{
	return;
}
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")



GLOBAL_PARAM g_stcParam;
//获取Kernel32 基址
DWORD GetKernel32Addr()
{
	DWORD dwKernel32Addr=0;
	__asm
	{
		push eax
		mov eax,dword ptr fs:[0x30]		// eax= peb的地址
		mov eax,[eax+0x0c]				// eax= 指向PEB_LDR_DATA结构
		mov eax,[eax+0x1c]				// eax= 模块初始化链表的头指针InInitializationOrderModuleList
		mov eax,[eax]					// eax= 列表中的第二个条目
		mov eax,[eax]					// eax= 列表肿的第二个条目
		mov eax,[eax+0x08]				// eax= 获取到的Kernel32.dll基址 （WIN7下获取的是kernelbase.dll）
		mov dwKernel32Addr,eax
		pop eax
	}
	return dwKernel32Addr;
}

DWORD MyGetProcAddress()
{
	DWORD dwBase=GetKernel32Addr();
	//获取DOS头
	PIMAGE_DOS_HEADER pDosH=(PIMAGE_DOS_HEADER)dwBase;
	//获取NT头
	PIMAGE_NT_HEADERS32 pNtH=(PIMAGE_NT_HEADERS32)(dwBase+pDosH->e_lfanew);
	//获取数据目录表
	PIMAGE_DATA_DIRECTORY pExportDir=pNtH->OptionalHeader.DataDirectory;//数据目录
	pExportDir = &(pExportDir[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	DWORD dwOffset = pExportDir->VirtualAddress;
	//获取导出表信息结构
	PIMAGE_EXPORT_DIRECTORY pExport=(PIMAGE_EXPORT_DIRECTORY)(dwBase+dwOffset);
	DWORD dwFunCount=pExport->NumberOfFunctions;
	DWORD dwFunNameCOunt=pExport->NumberOfNames;
	DWORD dwModOffset=pExport->Name;
	//取出三个表的函数地址
	//获取导出地址表
	PDWORD pEAT=(PDWORD)(dwBase+pExport->AddressOfFunctions);
	//获取导出名字表
	PDWORD pENT=(PDWORD)(dwBase+pExport->AddressOfNames);
	//获取导出序号表
	PWORD pEIT=(PWORD)(dwBase+pExport->AddressOfNameOrdinals);

	for (DWORD dwOrdinal=0;dwOrdinal<dwFunCount;dwOrdinal++)
	{
		if (!pEAT[dwOrdinal])
		{
			continue;
		}
		//获取序号
		DWORD dwID=pExport->Base+dwOrdinal;
		//获取导出函数地址
		DWORD dwFunAddrOffset=pEAT[dwOrdinal];
		for (DWORD dwIndex=0;dwIndex<dwFunNameCOunt;dwIndex++)
		{
			if (pEIT[dwIndex]==dwOrdinal)
			{
				//根据序号索引找到函数表的名字
				DWORD dwNameOffset=pENT[dwIndex];
				char *pFunName=(char*)((DWORD)dwBase+dwNameOffset);
				if (!strcmp(pFunName,"GetProcAddress"))
				{
					return dwBase+dwFunAddrOffset;
				}
			}			
		}
	}
}

fnExitProcess g_PfnExitProcess=nullptr;
fnGetModuleHandleA g_PfnGetModuleHandleA=nullptr;
fnGetProcAddress g_PfnGetProcAddress=nullptr;
fnLoadLibraryA g_PfnLoadLibraryA=nullptr;
fnVirtualAlloc g_PfnVirtualAlloc=nullptr;
fnVirtualProtect g_PfnVirtualProtect=nullptr;
fnMessageBox g_PfnMessageBoxA=nullptr;

void InitFun()
{
	DWORD dwBase=GetKernel32Addr();
	//根据kernel32基址找到GetProcAddress地址
	g_PfnGetProcAddress=(fnGetProcAddress)MyGetProcAddress();
	//根据GetProcAddress地址 得到任意函数地址
	g_PfnLoadLibraryA=(fnLoadLibraryA)g_PfnGetProcAddress((HMODULE)dwBase,"LoadLibraryA");
	g_PfnGetModuleHandleA=(fnGetModuleHandleA)g_PfnGetProcAddress((HMODULE)dwBase,"GetModuleHandleA");
	g_PfnVirtualProtect=(fnVirtualProtect)g_PfnGetProcAddress((HMODULE)dwBase,"VirtualProtect");
	HMODULE hUser32=g_PfnLoadLibraryA("user32.dll");
	g_PfnMessageBoxA=(fnMessageBox)g_PfnGetProcAddress(hUser32,"MessageBoxA");
	g_PfnExitProcess=(fnExitProcess)g_PfnGetProcAddress((HMODULE)dwBase,"ExitProcess");
	g_PfnVirtualAlloc=(fnVirtualAlloc)g_PfnGetProcAddress((HMODULE)dwBase,"VirtualAlloc");
}
 void Start()
 {
	 InitFun();
	 DWORD dwCodeBase=g_stcParam.dwImageBase+(DWORD)g_stcParam.lpStartVA;
	 DWORD dwOldProtect=0;
	 //开启可读可写属性
	 g_PfnVirtualProtect((LPBYTE)dwCodeBase,g_stcParam.dwCodeSize,PAGE_EXECUTE_READWRITE,&dwOldProtect);
	 //解密
	 XorCode();
	 g_PfnVirtualProtect((LPBYTE)dwCodeBase,g_stcParam.dwCodeSize,dwOldProtect,&dwOldProtect);

	 int nRet=g_PfnMessageBoxA(NULL,"欢迎使用加壳程序，是否运行主程序","提示",MB_YESNO);
	 if (nRet==IDYES)
	 {
		 //填充IAT
		 FixIAT();
		 __asm jmp g_stcParam.dwOEP
	 }
	 g_PfnExitProcess(0);
 }

 void FixIAT()
 {

	 DWORD dwImage = g_stcParam.dwImageBase;
	 // 1. 获取DOS头
	 PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dwImage;
	 // 2. 获取NT头
	 PIMAGE_NT_HEADERS32  pNt = (PIMAGE_NT_HEADERS32)(dwImage + pDos->e_lfanew);
	 // 3. 获取数据目录表
	 DWORD dwOffset = g_stcParam.m_stcImportDir.VirtualAddress;
	 // 4. 获取导入表信息结构
	 PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(dwImage + dwOffset);
	 DWORD dwOldProtect = 0;
	 g_PfnVirtualProtect((LPBYTE)(dwImage+g_stcParam.m_dwDataBase), g_stcParam.M_dwDataSize,
		 PAGE_EXECUTE_READWRITE, &dwOldProtect);

	 while (pImport->OriginalFirstThunk)
	 {
		 // 获取模块名称
		 DWORD dwModNameOffset = pImport->Name;
		 char* pModName = (char*)(dwImage + dwModNameOffset);
		 HMODULE hMod = g_PfnLoadLibraryA(pModName);
		 //5. 获取INT信息
		 DWORD dwINTOffset = pImport->FirstThunk;
		 DWORD dwIndex = 0;
		 do
		 {
			 PIMAGE_THUNK_DATA32 pINT = (PIMAGE_THUNK_DATA32)(dwImage + dwINTOffset + dwIndex);
			 DWORD dwINT = *(DWORD*)pINT;
			 if (!dwINT)
				 break;
			 BOOL bIsOrdinal = IMAGE_SNAP_BY_ORDINAL32(dwINT);
			 DWORD dwFunNameOffset = pINT->u1.AddressOfData;
			 PIMAGE_IMPORT_BY_NAME pstcFunName = (PIMAGE_IMPORT_BY_NAME)(dwImage + dwFunNameOffset);
			 if (bIsOrdinal)
			 {
				 //printf("->函数序号: %p\n", dwINT & 0x0000FFFF);
				 //DWORD dwAddr = g_pfnGetProcAddress(hMod, pstcFunName->Name);
			 }
			 else
			 {
				 //printf("->函数名称: %s\n", pstcFunName->Name);
				 DWORD dwAddr = g_PfnGetProcAddress(hMod, pstcFunName->Name);
				 // 加密函数函数地址
				 //DWORD dwCode = (DWORD)JMPIAT;
				 BYTE byByte[]={
					 0xe8, 0x01, 0x00, 0x00, 0x00,
					 0xe9, 0x58, 0xeb, 0x01, 0xe8, 
					 0xb8, 0x11, 0x11, 0x11, 0x11, 
					 0xeb, 0x01, 0x15, 0x35, 0x15,
					 0x15, 0x15, 0x15, 0xeb, 0x01, 
					 0xff, 0x50, 0xeb, 0x02, 0xff,
					 0x15, 0xc3};
				 PDWORD pAddr = (PDWORD)&(byByte[11]);
				 *pAddr = dwAddr ^ 0x15151515;
				 PBYTE pNewAddr = (PBYTE)g_PfnVirtualAlloc(0, sizeof(byByte), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				 memcpy(pNewAddr, byByte,sizeof(byByte));
				 // 创建新的IAT
				 *(DWORD*)pINT = (DWORD)pNewAddr;
			 }

			 dwIndex += 4;
		 } while (TRUE);
		 pImport++;
	 }
	 g_PfnVirtualProtect((LPBYTE)(dwImage + g_stcParam.m_dwDataBase), g_stcParam.M_dwDataSize,
		 dwOldProtect, &dwOldProtect);

 }


 void XorCode()
 {
	 PBYTE pBase = (PBYTE)((DWORD)g_stcParam.dwImageBase + g_stcParam.lpStartVA);

	 for (DWORD i = 0; i < g_stcParam.dwCodeSize; i++)
	 {
		 pBase[i] ^= 0x15;
	 }
 }

 void __declspec (naked) JMPIAT()
 {
	 __asm
	 {
		 call NEXT
			__emit 0xe9
NEXT:
		 pop eax
			 jmp NEXT1
			 __emit 0xe8
NEXT1:
		 mov eax,0x11111111
			 jmp NEXT2
			 __emit 0x15
NEXT2:
		 xor eax,0x15
			 jmp NEXT3
			 push eax
NEXT3:
		 push eax
			 jmp NEXT4
			 __emit 0xff
			 __emit 0x15
NEXT4:
			 retn

	 }
 }
