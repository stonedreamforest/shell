#include "stdafx.h"
#include "PE.h"



PE::PE(void):m_dwFileSize(NULL),m_pFileBase(NULL),
	m_dwFileAlign(NULL),m_dwMemAlign(NULL)
{
}


PE::~PE(void)
{
	if (m_objFIle.m_hFile!=INVALID_HANDLE_VALUE&&m_pFileBase)
	{
		m_objFIle.Close();
		delete m_pFileBase;
		m_pFileBase=NULL;
	}

}

DWORD PE::RVA2OffSet(DWORD dwRVA, PIMAGE_NT_HEADERS32 pNt)
{
	DWORD dwOffset = 0;
	// 1. ��ȡ��һ�����νṹ��
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	// 2. ��ȡ��������
	DWORD dwSectionCount = pNt->FileHeader.NumberOfSections;
	// 3. ����������Ϣ��
	for (DWORD i = 0; i < dwSectionCount; i++)
	{
		// 4. ƥ��RVA���ڵ�����
		if (dwRVA >= pSection[i].VirtualAddress &&
			dwRVA < (pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize)
			)
		{   // �����Ӧ���ļ�ƫ��
			dwOffset = dwRVA - pSection[i].VirtualAddress +
				pSection[i].PointerToRawData;
			return dwOffset;
		}
	}
	return dwOffset;
}


DWORD PE::GetSectionData(PBYTE lpImage, DWORD dwSectionIndex, PBYTE& lpBuffer,DWORD& dwCodeBaseRva)
{
	// 1. ��ȡDOSͷ
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpImage;
	// 2. ��ȡNTͷ
	PIMAGE_NT_HEADERS32  pNt = (PIMAGE_NT_HEADERS32)((DWORD)lpImage + pDos->e_lfanew);
	// 3. ��ȡ��һ�����νṹ�� 
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	//��ȡ���ǣ��ĵ�һ���������ļ��еĴ�С
	DWORD dwSize = pSection[0].SizeOfRawData;
	//��ȡ����VA
	DWORD dwCodeAddr = (DWORD)lpImage + pSection[0].VirtualAddress;
	//ָ������VA
	lpBuffer = (PBYTE)dwCodeAddr;
	dwCodeBaseRva=pSection[0].VirtualAddress;
	return dwSize;
}

BOOL PE::InitPE(CString strPath)
{
	if (m_objFIle.m_hFile==INVALID_HANDLE_VALUE&&m_pFileBase)
	{
		m_objFIle.Close();
		delete m_pFileBase;
		m_pFileBase=NULL;
		return FALSE;
	}
	//��ֻ����ʽ���ļ�
	m_objFIle.Open(strPath,CFile::modeRead);
	//��ȡ�ļ���С ������һ����ȵĿռ�
	m_dwFileSize=(DWORD)m_objFIle.GetLength();
	m_pFileBase=new BYTE[m_dwFileSize];
	if (m_objFIle.Read(m_pFileBase,m_dwFileSize))
	{
		//��ȡDOSͷ
		PIMAGE_DOS_HEADER pDosH=(PIMAGE_DOS_HEADER)m_pFileBase;
		//��ȡNTͷ
		m_pNt=(PIMAGE_NT_HEADERS32)((DWORD)m_pFileBase+pDosH->e_lfanew);
		//��ȡ�ļ����롢�ڴ�������Ϣ
		m_dwFileAlign=m_pNt->OptionalHeader.FileAlignment;
		m_dwMemAlign=m_pNt->OptionalHeader.SectionAlignment;
		//��ȡ�����ַ ����ڵ㡢
		m_dwImageBase=m_pNt->OptionalHeader.ImageBase;
		m_dwOEP=m_pNt->OptionalHeader.AddressOfEntryPoint;
		//��ȡ�����ַ ������δ�С
		m_dwCodeBase=m_pNt->OptionalHeader.BaseOfCode;
		m_dwCodeSize=m_pNt->OptionalHeader.SizeOfCode;

		//��ȡ���һ�����κ�ĵ�ַ
		PIMAGE_SECTION_HEADER pSection=IMAGE_FIRST_SECTION(m_pNt);
		m_pLastSection =&pSection[m_pNt->FileHeader.NumberOfSections];
		m_dwDataBase=pSection[1].VirtualAddress;
		m_dwDataSize=pSection[1].SizeOfRawData;
		//��ȡ����Ŀ¼
		PIMAGE_DATA_DIRECTORY pDir=m_pNt->OptionalHeader.DataDirectory;
		//��ȡ�ض�λ��������IAT��
		memcpy(&m_stcRelocDir,	&(pDir[IMAGE_DIRECTORY_ENTRY_BASERELOC]),	sizeof(IMAGE_DATA_DIRECTORY));
		memcpy(&m_stcImportDir,	&(pDir[IMAGE_DIRECTORY_ENTRY_IMPORT]),		sizeof(IMAGE_DATA_DIRECTORY));
		memcpy(&m_stcIATDir,	&(pDir[IMAGE_DIRECTORY_ENTRY_IAT]),			sizeof(IMAGE_DATA_DIRECTORY));

		return TRUE;
	}
	return FALSE;
}

DWORD PE::XorCodeAndData(BYTE byXor)
{
	//��ȡ��һ�����νṹ��
	PIMAGE_SECTION_HEADER pSection=IMAGE_FIRST_SECTION(m_pNt);
	//��ȡ��������
	DWORD dwSectionCount=m_pNt->FileHeader.NumberOfSections;
	//����������Ϣ��
	m_dwCodeSize=0;
	//����ǰ��������
	for (DWORD i=0;i<2;i++)
	{
		m_dwCodeSize+=pSection[i].SizeOfRawData;
	}
	//�õ�ƫ��
	DWORD dwOffset=RVA2OffSet(pSection[0].VirtualAddress,m_pNt);
	//ָ��m_pFileBase+dwOffset��
	PBYTE pBase=(PBYTE)((DWORD)m_pFileBase+dwOffset); 
	//����
	for (DWORD i=0;i<m_dwCodeSize;i++)
	{
		pBase[i]^=byXor;
	}
	//���ر����ܵĴ���δ�С
	return m_dwCodeSize;
}

DWORD PE::GetNewSectionRva()
{
	
	//�ٶ� m_pLastSection =&pSection[m_pNt->FileHeader.NumberOfSections]=5  
	//�±��0��ʼ ��ʵ�ļ�Ϊ4 �����±�Ϊ-1
	//������Rva=���һ�����ε������ַ+
	//dwVIrtualSizeΪ lord pe�� rsize
	DWORD dwVIrtualSize=m_pLastSection[-1].Misc.VirtualSize;
	//ȡ��  ����  dwVIrtualSize=1A26 m_dwMemAlign =1000 ���ֵΪb26 Ϊ��
	if (dwVIrtualSize%m_dwMemAlign)
	{
		//ȡ��  dwVIrtualSize=���̵Ļ������϶������� 1000
		dwVIrtualSize=(dwVIrtualSize/m_dwMemAlign+1)*m_dwMemAlign;
	}
	else
	{
		dwVIrtualSize=(dwVIrtualSize/m_dwMemAlign)*m_dwMemAlign;
	}
	//�������ζ�����Rva
	return m_pLastSection[-1].VirtualAddress+dwVIrtualSize;
}

void PE::FixReloc(PBYTE lpImage, DWORD dwCodeBaseRva,DWORD dwCodeRva)
{
	//��ȡDOSͷ
	PIMAGE_DOS_HEADER pDos=(PIMAGE_DOS_HEADER)lpImage;
	//��ȡNTͷ
	PIMAGE_NT_HEADERS32 pNt=(PIMAGE_NT_HEADERS32)(pDos->e_lfanew+lpImage);
	//��ȡ����Ŀ¼��
	PIMAGE_DATA_DIRECTORY pRelocDir=pNt->OptionalHeader.DataDirectory;
	pRelocDir=&(pRelocDir[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	//��ȡ�ض�λĿ¼
	PIMAGE_BASE_RELOCATION pReloc=(PIMAGE_BASE_RELOCATION)((DWORD)lpImage+pRelocDir->VirtualAddress);
	typedef struct 
	{
		WORD Offset:12;		//��СΪ12BIT���ض�λƫ��
		WORD Type:4;		//��СΪ4BIT���ض�λ��Ϣ����ֵ
	}TypeOffset,*PTypeOffest;//����ʦ�ܽ��
	//ѭ������
	while (pReloc->VirtualAddress)
	{
		//�ҵ��ض�λ��һ��ƫ�Ƶĵ�ַ
		PTypeOffest pTypeOffset=(PTypeOffest)(pReloc+1);
		DWORD dwSize=sizeof(IMAGE_BASE_RELOCATION);
		DWORD dwCount=(pReloc->SizeOfBlock-dwSize)/2;
		for (DWORD i=0;i<dwCount;i++)
		{
			//
			if (*(PWORD)(&pTypeOffset[i])==NULL)
			{
				continue;
			}
			//�ض�λ�������ַ+ƫ��
			DWORD dwRva=pReloc->VirtualAddress+pTypeOffset[i].Offset;
			//VA(�����ַ)=���ػ�ַ+RVA
			PDWORD pRelocAddr=(PDWORD)((DWORD)lpImage+dwRva);
			//�ض�λ��ַ���������ض�λ 
			//Ҫ�ض�λ��ַ-�ɻ�ַ-�ɶ���RVA+������RVA+�µļ��ػ�ַ��������BUG��
			DWORD dwRelocCode=*pRelocAddr-pNt->OptionalHeader.ImageBase - dwCodeBaseRva +dwCodeRva+m_dwImageBase;
			//���Ѽ���õ��ض�λ��dwRelocCode ��pRelocAddr
			*pRelocAddr = dwRelocCode;
		}
		//ָ���¸��ṹ�壨4KB�ռ䣩
		pReloc=(PIMAGE_BASE_RELOCATION)((DWORD)pReloc+pReloc->SizeOfBlock);
	}
}

void PE::SetNewOEP(DWORD dwOEP)
{
	m_dwNewOEP=dwOEP;
}

void PE::ClearRandBase()
{
	m_pNt->OptionalHeader.DllCharacteristics=0;
}

void PE::ClearDataDir()
{
	// ����Ŀ¼ ���16��
	DWORD dwCount=16;
	for (DWORD i=0;i<dwCount;i++)
	{
		//��������������ַ�� ������ԴĿ¼ȫ�����s
		if (m_pNt->OptionalHeader.DataDirectory[i].VirtualAddress&&i!=2)
		{
			m_pNt->OptionalHeader.DataDirectory[i].VirtualAddress=0;
			m_pNt->OptionalHeader.DataDirectory[i].Size=0;
		}
	}
}

DWORD PE::AddSection(LPBYTE pBuffer,DWORD dwSize,PCHAR pszSectionName)
{
	//�޸��ļ�ͷ�е���������
	m_pNt->FileHeader.NumberOfSections++;
	//�������α���
	memset(m_pLastSection,0,sizeof(IMAGE_SECTION_HEADER));
	//д��������
	strcpy_s((char*)m_pLastSection->Name,IMAGE_SIZEOF_SHORT_NAME,pszSectionName);
	//���������С
	DWORD dwVirtualSize=0;
	//�����ļ���С
	DWORD dwSizeOfRawData=0;
	//���ļ����ص��ڴ�����Ҫ�Ĵ�С  
	DWORD dwSizeOfImage=m_pNt->OptionalHeader.SizeOfImage;
	//ȡ�� �鿴�ڴ��Ƿ���� 
	if (dwSizeOfImage%m_dwMemAlign)
	{
		// ȡ����ԭ��������+1  ����˵dwSizeOfImage=1726 ��������m_dwMemAlign=200 
		//��ʱdwSizeOfImage=1800
		dwSizeOfImage=(dwSizeOfImage/m_dwMemAlign+1)*m_dwMemAlign;
	}
	else
	{
		dwSizeOfImage=(dwSizeOfImage/m_dwMemAlign)*m_dwMemAlign;
	}

	//���ζ�����RVA(dwSize) /�ڴ�������� m_dwMemAlign
	if (dwSize%m_dwMemAlign)
	{
		dwVirtualSize=(dwSize/m_dwMemAlign+1)*m_dwMemAlign;
	}
	else
	{
		dwVirtualSize=(dwSize/m_dwMemAlign)*m_dwMemAlign;
	}

	//���ζ�����RVA(dwSize) /�ļ��������� m_dwMemAlign
	if (dwSize%m_dwFileAlign)
	{
		dwSizeOfRawData=(dwSize/m_dwFileAlign+1)*m_dwFileAlign;
	}
	else
	{
		dwSizeOfRawData=(dwSize/m_dwFileAlign)*m_dwFileAlign;
	}

	//��ȡ���µ���������ַ RVA
	m_pLastSection->VirtualAddress=(m_pLastSection[-1].VirtualAddress+(dwSize/m_dwMemAlign)*m_dwMemAlign);
	//�������ļ��е�ƫ��
	m_pLastSection->PointerToRawData=m_dwFileSize;
	//�������ļ��д�С
	m_pLastSection->SizeOfRawData=dwSizeOfRawData;
	//�������ڴ��д�С
	m_pLastSection->Misc.VirtualSize=dwVirtualSize;
	//��������
	m_pLastSection->Characteristics=0Xe0000040;

	//���� �ļ���С �����ļ� ��Ӵ���� ȷ����ڵ�
	m_pNt->OptionalHeader.SizeOfImage=dwSizeOfImage+dwVirtualSize;
	m_pNt->OptionalHeader.AddressOfEntryPoint=m_dwNewOEP+m_pLastSection->VirtualAddress;

	//��������ļ�·��
	CString strPath=m_objFIle.GetFilePath();
	TCHAR SzOutPath[MAX_PATH]={0};
	//��ȡ�ļ���׺��
	LPWSTR strSuffix=PathFindExtension(strPath);
	//Ŀ���ļ�·����SzOutPath
	wcsncpy_s(SzOutPath,MAX_PATH,strPath,wcslen(strPath));

	//�Ƴ���׺��
	PathRemoveExtension(SzOutPath);
	// ��·����󸽼ӡ�_1��
	wcscat_s(SzOutPath,MAX_PATH,L"_1");
	// ��·����󸽼Ӹոձ���ĺ�׺��
	wcscat_s(SzOutPath, MAX_PATH, strSuffix);                           

	//�����ļ�
	CFile objFile(SzOutPath,CFile::modeCreate|CFile::modeReadWrite);
	objFile.Write(m_pFileBase,(DWORD)m_objFIle.GetLength());
	//�Ƶ��ļ�β
	objFile.SeekToEnd();
	//��pBuffer ���մ�СdwSize д���ļ�
	objFile.Write(pBuffer,dwSize);
	//���ز�����ɺ�����һ�����ε���������ַ RAV
	return m_pLastSection->VirtualAddress;

}
