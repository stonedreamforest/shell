// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� STUB_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// STUB_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
#ifdef STUB_EXPORTS
#define STUB_API __declspec(dllexport)
#else
#define STUB_API __declspec(dllimport)
#endif

// �����Ǵ� stub.dll ������
class STUB_API Cstub {
public:
	Cstub(void);
	// TODO: �ڴ�������ķ�����
};

extern STUB_API int nstub;

STUB_API int fnstub(void);



extern "C"
{
	typedef struct _GLOBAL_PARAM
	{
		DWORD dwStart;      // �������
		BOOL  bShowMessage;	// �Ƿ���ʾ������Ϣ
		DWORD dwOEP;		// ������ڵ�
		DWORD dwImageBase;  // ӳ���ַ
		PBYTE lpStartVA;	// ��ʼ�����ַ��������������
		PBYTE lpEndVA;	    // ���������ַ��������������
		DWORD dwCodeSize;   // �����С
		DWORD dwXorKey;     // ����KEY
		IMAGE_DATA_DIRECTORY m_stcImportDir;
		DWORD m_dwDataBase;
		DWORD M_dwDataSize;
	}GLOBAL_PARAM, *PGLOBAL_PARAM;

	extern STUB_API GLOBAL_PARAM g_stcParam;
	STUB_API int fnGetStub(void);
	STUB_API void fnSetStub(int n);
	

	typedef DWORD (WINAPI *fnGetProcAddress)( _In_ HMODULE hModule, _In_ LPCSTR lpProcName );
	typedef HMODULE(WINAPI *fnLoadLibraryA)( _In_ LPCSTR lpLibFileName );	
	typedef HMODULE (WINAPI *fnGetModuleHandleA)(_In_opt_ LPCSTR lpModuleName);
	typedef BOOL (WINAPI *fnVirtualProtect)(_In_  LPVOID lpAddress, _In_  SIZE_T dwSize, _In_  DWORD  flNewProtect,_Out_ PDWORD lpflOldProtect); 
	typedef void(WINAPI *fnExitProcess)( _In_ UINT uExitCode );
	typedef LPVOID(WINAPI *fnVirtualAlloc)(_In_opt_ LPVOID lpAddress,_In_ SIZE_T dwSize,_In_ DWORD flAllocationType,_In_ DWORD flProtect);
	typedef int (WINAPI *fnMessageBox)	( HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType );

	void  XorCode();
	DWORD GetKernel32Addr();
	DWORD MyGetProcAddress();
	void FixIAT();
	void JMPIAT();
	extern "C" void Start();
}