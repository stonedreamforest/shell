#pragma once
class PE
{
public:
	PE(void);
	~PE(void);

	DWORD RVA2OffSet(DWORD dwRVA, PIMAGE_NT_HEADERS32  pNt);						//计算偏移
	DWORD GetSectionData(PBYTE lpImage, DWORD dwSectionIndex, PBYTE& lpBuffer,DWORD& dwCodeBaseRva);		//获取区段
	BOOL InitPE(CString strPath);
	DWORD XorCodeAndData(BYTE byXor);
	DWORD GetNewSectionRva();
	void FixReloc(PBYTE lpImage, DWORD dwCodeBaseRva,DWORD dwCodeRva);
	void SetNewOEP(DWORD dwOEP);
	void ClearRandBase();
	void ClearDataDir();
	DWORD AddSection(LPBYTE pBuffer,DWORD dwSize,PCHAR pszSectionName);
public:
	CFile m_objFIle;
	PIMAGE_SECTION_HEADER m_pLastSection;//获取最后一个区段
	PIMAGE_NT_HEADERS32 m_pNt;	//NT头	
	DWORD m_dwFileSize;			//文件大小
	LPBYTE m_pFileBase;			//文件基址
	DWORD m_dwFileAlign;		//文件对齐
	DWORD m_dwMemAlign;			//内存对齐
	DWORD m_dwImageBase;		//镜像基址
	DWORD m_dwOEP;				//入口点
	DWORD m_dwCodeBase;			//代码基址 RVA
	DWORD m_dwCodeSize;			//代码段大小
	DWORD m_dwNewOEP;			//将要设置新入口点

	DWORD m_dwDataBase;			//区段起始虚拟地址 RVA
	DWORD m_dwDataSize;			//区段大小
	IMAGE_DATA_DIRECTORY m_stcRelocDir;		//重定位表
	IMAGE_DATA_DIRECTORY m_stcImportDir;	//导出表
	IMAGE_DATA_DIRECTORY m_stcIATDir;		//IAT表
};

