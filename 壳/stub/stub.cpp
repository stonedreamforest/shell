// stub.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "stub.h"


// ���ǵ���������һ��ʾ��
STUB_API int nstub=0;

// ���ǵ���������һ��ʾ����
STUB_API int fnstub(void)
{
	return 42;
}

// �����ѵ�����Ĺ��캯����
// �й��ඨ�����Ϣ������� stub.h
Cstub::Cstub()
{
	return;
}
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")



GLOBAL_PARAM g_stcParam;
//��ȡKernel32 ��ַ
DWORD GetKernel32Addr()
{
	DWORD dwKernel32Addr=0;
	__asm
	{
		push eax
		mov eax,dword ptr fs:[0x30]		// eax= peb�ĵ�ַ
		mov eax,[eax+0x0c]				// eax= ָ��PEB_LDR_DATA�ṹ
		mov eax,[eax+0x1c]				// eax= ģ���ʼ�������ͷָ��InInitializationOrderModuleList
		mov eax,[eax]					// eax= �б��еĵڶ�����Ŀ
		mov eax,[eax]					// eax= �б��׵ĵڶ�����Ŀ
		mov eax,[eax+0x08]				// eax= ��ȡ����Kernel32.dll��ַ ��WIN7�»�ȡ����kernelbase.dll��
		mov dwKernel32Addr,eax
		pop eax
	}
	return dwKernel32Addr;
}

DWORD MyGetProcAddress()
{
	DWORD dwBase=GetKernel32Addr();
	//��ȡDOSͷ
	PIMAGE_DOS_HEADER pDosH=(PIMAGE_DOS_HEADER)dwBase;
	//��ȡNTͷ
	PIMAGE_NT_HEADERS32 pNtH=(PIMAGE_NT_HEADERS32)(dwBase+pDosH->e_lfanew);
	//��ȡ����Ŀ¼��
	PIMAGE_DATA_DIRECTORY pExportDir=pNtH->OptionalHeader.DataDirectory;//����Ŀ¼
	pExportDir = &(pExportDir[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	DWORD dwOffset = pExportDir->VirtualAddress;
	//��ȡ��������Ϣ�ṹ
	PIMAGE_EXPORT_DIRECTORY pExport=(PIMAGE_EXPORT_DIRECTORY)(dwBase+dwOffset);
	DWORD dwFunCount=pExport->NumberOfFunctions;
	DWORD dwFunNameCOunt=pExport->NumberOfNames;
	DWORD dwModOffset=pExport->Name;
	//ȡ��������ĺ�����ַ
	//��ȡ������ַ��
	PDWORD pEAT=(PDWORD)(dwBase+pExport->AddressOfFunctions);
	//��ȡ�������ֱ�
	PDWORD pENT=(PDWORD)(dwBase+pExport->AddressOfNames);
	//��ȡ������ű�
	PWORD pEIT=(PWORD)(dwBase+pExport->AddressOfNameOrdinals);

	for (DWORD dwOrdinal=0;dwOrdinal<dwFunCount;dwOrdinal++)
	{
		if (!pEAT[dwOrdinal])
		{
			continue;
		}
		//��ȡ���
		DWORD dwID=pExport->Base+dwOrdinal;
		//��ȡ����������ַ
		DWORD dwFunAddrOffset=pEAT[dwOrdinal];
		for (DWORD dwIndex=0;dwIndex<dwFunNameCOunt;dwIndex++)
		{
			if (pEIT[dwIndex]==dwOrdinal)
			{
				//������������ҵ������������
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
	//����kernel32��ַ�ҵ�GetProcAddress��ַ
	g_PfnGetProcAddress=(fnGetProcAddress)MyGetProcAddress();
	//����GetProcAddress��ַ �õ����⺯����ַ
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
	 //�����ɶ���д����
	 g_PfnVirtualProtect((LPBYTE)dwCodeBase,g_stcParam.dwCodeSize,PAGE_EXECUTE_READWRITE,&dwOldProtect);
	 //����
	 XorCode();
	 g_PfnVirtualProtect((LPBYTE)dwCodeBase,g_stcParam.dwCodeSize,dwOldProtect,&dwOldProtect);

	 int nRet=g_PfnMessageBoxA(NULL,"��ӭʹ�üӿǳ����Ƿ�����������","��ʾ",MB_YESNO);
	 if (nRet==IDYES)
	 {
		 //���IAT
		 FixIAT();
		 __asm jmp g_stcParam.dwOEP
	 }
	 g_PfnExitProcess(0);
 }

 void FixIAT()
 {

	 DWORD dwImage = g_stcParam.dwImageBase;
	 // 1. ��ȡDOSͷ
	 PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dwImage;
	 // 2. ��ȡNTͷ
	 PIMAGE_NT_HEADERS32  pNt = (PIMAGE_NT_HEADERS32)(dwImage + pDos->e_lfanew);
	 // 3. ��ȡ����Ŀ¼��
	 DWORD dwOffset = g_stcParam.m_stcImportDir.VirtualAddress;
	 // 4. ��ȡ�������Ϣ�ṹ
	 PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(dwImage + dwOffset);
	 DWORD dwOldProtect = 0;
	 g_PfnVirtualProtect((LPBYTE)(dwImage+g_stcParam.m_dwDataBase), g_stcParam.M_dwDataSize,
		 PAGE_EXECUTE_READWRITE, &dwOldProtect);

	 while (pImport->OriginalFirstThunk)
	 {
		 // ��ȡģ������
		 DWORD dwModNameOffset = pImport->Name;
		 char* pModName = (char*)(dwImage + dwModNameOffset);
		 HMODULE hMod = g_PfnLoadLibraryA(pModName);
		 //5. ��ȡINT��Ϣ
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
				 //printf("->�������: %p\n", dwINT & 0x0000FFFF);
				 //DWORD dwAddr = g_pfnGetProcAddress(hMod, pstcFunName->Name);
			 }
			 else
			 {
				 //printf("->��������: %s\n", pstcFunName->Name);
				 DWORD dwAddr = g_PfnGetProcAddress(hMod, pstcFunName->Name);
				 // ���ܺ���������ַ
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
				 // �����µ�IAT
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
