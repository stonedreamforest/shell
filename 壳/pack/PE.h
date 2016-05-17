#pragma once
class PE
{
public:
	PE(void);
	~PE(void);

	DWORD RVA2OffSet(DWORD dwRVA, PIMAGE_NT_HEADERS32  pNt);						//����ƫ��
	DWORD GetSectionData(PBYTE lpImage, DWORD dwSectionIndex, PBYTE& lpBuffer,DWORD& dwCodeBaseRva);		//��ȡ����
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
	PIMAGE_SECTION_HEADER m_pLastSection;//��ȡ���һ������
	PIMAGE_NT_HEADERS32 m_pNt;	//NTͷ	
	DWORD m_dwFileSize;			//�ļ���С
	LPBYTE m_pFileBase;			//�ļ���ַ
	DWORD m_dwFileAlign;		//�ļ�����
	DWORD m_dwMemAlign;			//�ڴ����
	DWORD m_dwImageBase;		//�����ַ
	DWORD m_dwOEP;				//��ڵ�
	DWORD m_dwCodeBase;			//�����ַ RVA
	DWORD m_dwCodeSize;			//����δ�С
	DWORD m_dwNewOEP;			//��Ҫ��������ڵ�

	DWORD m_dwDataBase;			//������ʼ�����ַ RVA
	DWORD m_dwDataSize;			//���δ�С
	IMAGE_DATA_DIRECTORY m_stcRelocDir;		//�ض�λ��
	IMAGE_DATA_DIRECTORY m_stcImportDir;	//������
	IMAGE_DATA_DIRECTORY m_stcIATDir;		//IAT��
};

