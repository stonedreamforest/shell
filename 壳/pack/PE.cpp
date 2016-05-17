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
	// 1. 获取第一个区段结构体
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	// 2. 获取区段数量
	DWORD dwSectionCount = pNt->FileHeader.NumberOfSections;
	// 3. 遍历区段信息表
	for (DWORD i = 0; i < dwSectionCount; i++)
	{
		// 4. 匹配RVA所在的区段
		if (dwRVA >= pSection[i].VirtualAddress &&
			dwRVA < (pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize)
			)
		{   // 计算对应的文件偏移
			dwOffset = dwRVA - pSection[i].VirtualAddress +
				pSection[i].PointerToRawData;
			return dwOffset;
		}
	}
	return dwOffset;
}


DWORD PE::GetSectionData(PBYTE lpImage, DWORD dwSectionIndex, PBYTE& lpBuffer,DWORD& dwCodeBaseRva)
{
	// 1. 获取DOS头
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpImage;
	// 2. 获取NT头
	PIMAGE_NT_HEADERS32  pNt = (PIMAGE_NT_HEADERS32)((DWORD)lpImage + pDos->e_lfanew);
	// 3. 获取第一个区段结构体 
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	//获取（壳）的第一个区段在文件中的大小
	DWORD dwSize = pSection[0].SizeOfRawData;
	//获取区段VA
	DWORD dwCodeAddr = (DWORD)lpImage + pSection[0].VirtualAddress;
	//指向区段VA
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
	//以只读方式打开文件
	m_objFIle.Open(strPath,CFile::modeRead);
	//获取文件大小 并开辟一块相等的空间
	m_dwFileSize=(DWORD)m_objFIle.GetLength();
	m_pFileBase=new BYTE[m_dwFileSize];
	if (m_objFIle.Read(m_pFileBase,m_dwFileSize))
	{
		//获取DOS头
		PIMAGE_DOS_HEADER pDosH=(PIMAGE_DOS_HEADER)m_pFileBase;
		//获取NT头
		m_pNt=(PIMAGE_NT_HEADERS32)((DWORD)m_pFileBase+pDosH->e_lfanew);
		//获取文件对齐、内存对齐等信息
		m_dwFileAlign=m_pNt->OptionalHeader.FileAlignment;
		m_dwMemAlign=m_pNt->OptionalHeader.SectionAlignment;
		//获取镜像基址 、入口点、
		m_dwImageBase=m_pNt->OptionalHeader.ImageBase;
		m_dwOEP=m_pNt->OptionalHeader.AddressOfEntryPoint;
		//获取代码基址 、代码段大小
		m_dwCodeBase=m_pNt->OptionalHeader.BaseOfCode;
		m_dwCodeSize=m_pNt->OptionalHeader.SizeOfCode;

		//获取最后一个区段后的地址
		PIMAGE_SECTION_HEADER pSection=IMAGE_FIRST_SECTION(m_pNt);
		m_pLastSection =&pSection[m_pNt->FileHeader.NumberOfSections];
		m_dwDataBase=pSection[1].VirtualAddress;
		m_dwDataSize=pSection[1].SizeOfRawData;
		//获取数据目录
		PIMAGE_DATA_DIRECTORY pDir=m_pNt->OptionalHeader.DataDirectory;
		//获取重定位、导出表、IAT、
		memcpy(&m_stcRelocDir,	&(pDir[IMAGE_DIRECTORY_ENTRY_BASERELOC]),	sizeof(IMAGE_DATA_DIRECTORY));
		memcpy(&m_stcImportDir,	&(pDir[IMAGE_DIRECTORY_ENTRY_IMPORT]),		sizeof(IMAGE_DATA_DIRECTORY));
		memcpy(&m_stcIATDir,	&(pDir[IMAGE_DIRECTORY_ENTRY_IAT]),			sizeof(IMAGE_DATA_DIRECTORY));

		return TRUE;
	}
	return FALSE;
}

DWORD PE::XorCodeAndData(BYTE byXor)
{
	//获取第一个区段结构体
	PIMAGE_SECTION_HEADER pSection=IMAGE_FIRST_SECTION(m_pNt);
	//获取区段数量
	DWORD dwSectionCount=m_pNt->FileHeader.NumberOfSections;
	//遍历区段信息表
	m_dwCodeSize=0;
	//加密前俩个区段
	for (DWORD i=0;i<2;i++)
	{
		m_dwCodeSize+=pSection[i].SizeOfRawData;
	}
	//得到偏移
	DWORD dwOffset=RVA2OffSet(pSection[0].VirtualAddress,m_pNt);
	//指向【m_pFileBase+dwOffset】
	PBYTE pBase=(PBYTE)((DWORD)m_pFileBase+dwOffset); 
	//加密
	for (DWORD i=0;i<m_dwCodeSize;i++)
	{
		pBase[i]^=byXor;
	}
	//返回被加密的代码段大小
	return m_dwCodeSize;
}

DWORD PE::GetNewSectionRva()
{
	
	//假定 m_pLastSection =&pSection[m_pNt->FileHeader.NumberOfSections]=5  
	//下标从0开始 真实的即为4 所已下标为-1
	//新区段Rva=最后一个区段的虚拟地址+
	//dwVIrtualSize为 lord pe的 rsize
	DWORD dwVIrtualSize=m_pLastSection[-1].Misc.VirtualSize;
	//取余  假如  dwVIrtualSize=1A26 m_dwMemAlign =1000 求得值为b26 为真
	if (dwVIrtualSize%m_dwMemAlign)
	{
		//取商  dwVIrtualSize=在商的基础加上对齐粒度 1000
		dwVIrtualSize=(dwVIrtualSize/m_dwMemAlign+1)*m_dwMemAlign;
	}
	else
	{
		dwVIrtualSize=(dwVIrtualSize/m_dwMemAlign)*m_dwMemAlign;
	}
	//返回区段对齐后的Rva
	return m_pLastSection[-1].VirtualAddress+dwVIrtualSize;
}

void PE::FixReloc(PBYTE lpImage, DWORD dwCodeBaseRva,DWORD dwCodeRva)
{
	//获取DOS头
	PIMAGE_DOS_HEADER pDos=(PIMAGE_DOS_HEADER)lpImage;
	//获取NT头
	PIMAGE_NT_HEADERS32 pNt=(PIMAGE_NT_HEADERS32)(pDos->e_lfanew+lpImage);
	//获取数据目录表
	PIMAGE_DATA_DIRECTORY pRelocDir=pNt->OptionalHeader.DataDirectory;
	pRelocDir=&(pRelocDir[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	//获取重定位目录
	PIMAGE_BASE_RELOCATION pReloc=(PIMAGE_BASE_RELOCATION)((DWORD)lpImage+pRelocDir->VirtualAddress);
	typedef struct 
	{
		WORD Offset:12;		//大小为12BIT的重定位偏移
		WORD Type:4;		//大小为4BIT的重定位信息类型值
	}TypeOffset,*PTypeOffest;//任老师总结的
	//循环遍历
	while (pReloc->VirtualAddress)
	{
		//找到重定位第一个偏移的地址
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
			//重定位的虚拟地址+偏移
			DWORD dwRva=pReloc->VirtualAddress+pTypeOffset[i].Offset;
			//VA(虚拟地址)=加载基址+RVA
			PDWORD pRelocAddr=(PDWORD)((DWORD)lpImage+dwRva);
			//重定位地址的内容做重定位 
			//要重定位地址-旧基址-旧段首RVA+新区段RVA+新的加载基址（可能有BUG）
			DWORD dwRelocCode=*pRelocAddr-pNt->OptionalHeader.ImageBase - dwCodeBaseRva +dwCodeRva+m_dwImageBase;
			//将已计算好的重定位的dwRelocCode 给pRelocAddr
			*pRelocAddr = dwRelocCode;
		}
		//指向下个结构体（4KB空间）
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
	// 数据目录 最多16个
	DWORD dwCount=16;
	for (DWORD i=0;i<dwCount;i++)
	{
		//凡是有相对虚拟地址的 除了资源目录全部清空s
		if (m_pNt->OptionalHeader.DataDirectory[i].VirtualAddress&&i!=2)
		{
			m_pNt->OptionalHeader.DataDirectory[i].VirtualAddress=0;
			m_pNt->OptionalHeader.DataDirectory[i].Size=0;
		}
	}
}

DWORD PE::AddSection(LPBYTE pBuffer,DWORD dwSize,PCHAR pszSectionName)
{
	//修改文件头中的区段数量
	m_pNt->FileHeader.NumberOfSections++;
	//增加区段表项
	memset(m_pLastSection,0,sizeof(IMAGE_SECTION_HEADER));
	//写入区段名
	strcpy_s((char*)m_pLastSection->Name,IMAGE_SIZEOF_SHORT_NAME,pszSectionName);
	//区段虚拟大小
	DWORD dwVirtualSize=0;
	//区段文件大小
	DWORD dwSizeOfRawData=0;
	//把文件加载到内存所需要的大小  
	DWORD dwSizeOfImage=m_pNt->OptionalHeader.SizeOfImage;
	//取余 查看内存是否对齐 
	if (dwSizeOfImage%m_dwMemAlign)
	{
		// 取商再原来基础上+1  比如说dwSizeOfImage=1726 对齐粒度m_dwMemAlign=200 
		//此时dwSizeOfImage=1800
		dwSizeOfImage=(dwSizeOfImage/m_dwMemAlign+1)*m_dwMemAlign;
	}
	else
	{
		dwSizeOfImage=(dwSizeOfImage/m_dwMemAlign)*m_dwMemAlign;
	}

	//区段对齐后的RVA(dwSize) /内存对齐粒度 m_dwMemAlign
	if (dwSize%m_dwMemAlign)
	{
		dwVirtualSize=(dwSize/m_dwMemAlign+1)*m_dwMemAlign;
	}
	else
	{
		dwVirtualSize=(dwSize/m_dwMemAlign)*m_dwMemAlign;
	}

	//区段对齐后的RVA(dwSize) /文件对齐粒度 m_dwMemAlign
	if (dwSize%m_dwFileAlign)
	{
		dwSizeOfRawData=(dwSize/m_dwFileAlign+1)*m_dwFileAlign;
	}
	else
	{
		dwSizeOfRawData=(dwSize/m_dwFileAlign)*m_dwFileAlign;
	}

	//获取到新的相对虚拟地址 RVA
	m_pLastSection->VirtualAddress=(m_pLastSection[-1].VirtualAddress+(dwSize/m_dwMemAlign)*m_dwMemAlign);
	//区段在文件中的偏移
	m_pLastSection->PointerToRawData=m_dwFileSize;
	//区段在文件中大小
	m_pLastSection->SizeOfRawData=dwSizeOfRawData;
	//区段在内存中大小
	m_pLastSection->Misc.VirtualSize=dwVirtualSize;
	//区段属性
	m_pLastSection->Characteristics=0Xe0000040;

	//增加 文件大小 创建文件 添加代码段 确定入口点
	m_pNt->OptionalHeader.SizeOfImage=dwSizeOfImage+dwVirtualSize;
	m_pNt->OptionalHeader.AddressOfEntryPoint=m_dwNewOEP+m_pLastSection->VirtualAddress;

	//生成输出文件路径
	CString strPath=m_objFIle.GetFilePath();
	TCHAR SzOutPath[MAX_PATH]={0};
	//获取文件后缀名
	LPWSTR strSuffix=PathFindExtension(strPath);
	//目标文件路径到SzOutPath
	wcsncpy_s(SzOutPath,MAX_PATH,strPath,wcslen(strPath));

	//移除后缀名
	PathRemoveExtension(SzOutPath);
	// 在路径最后附加“_1”
	wcscat_s(SzOutPath,MAX_PATH,L"_1");
	// 在路径最后附加刚刚保存的后缀名
	wcscat_s(SzOutPath, MAX_PATH, strSuffix);                           

	//创建文件
	CFile objFile(SzOutPath,CFile::modeCreate|CFile::modeReadWrite);
	objFile.Write(m_pFileBase,(DWORD)m_objFIle.GetLength());
	//移到文件尾
	objFile.SeekToEnd();
	//将pBuffer 按照大小dwSize 写入文件
	objFile.Write(pBuffer,dwSize);
	//返回操作完成后的最后一个区段的相对虚拟地址 RAV
	return m_pLastSection->VirtualAddress;

}
