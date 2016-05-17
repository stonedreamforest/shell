// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 STUB_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// STUB_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
#ifdef STUB_EXPORTS
#define STUB_API __declspec(dllexport)
#else
#define STUB_API __declspec(dllimport)
#endif

// 此类是从 stub.dll 导出的
class STUB_API Cstub {
public:
	Cstub(void);
	// TODO: 在此添加您的方法。
};

extern STUB_API int nstub;

STUB_API int fnstub(void);



extern "C"
{
	typedef struct _GLOBAL_PARAM
	{
		DWORD dwStart;      // 启动入口
		BOOL  bShowMessage;	// 是否显示解密信息
		DWORD dwOEP;		// 程序入口点
		DWORD dwImageBase;  // 映像基址
		PBYTE lpStartVA;	// 起始虚拟地址（被异或加密区）
		PBYTE lpEndVA;	    // 结束虚拟地址（被异或加密区）
		DWORD dwCodeSize;   // 代码大小
		DWORD dwXorKey;     // 解密KEY
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