// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� PACK_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// PACK_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
#ifdef PACK_EXPORTS
#define PACK_API __declspec(dllexport)
#else
#define PACK_API __declspec(dllimport)
#endif

// �����Ǵ� pack.dll ������
class PACK_API Cpack {
public:
	Cpack(void);
	// TODO: �ڴ�������ķ�����
};

extern PACK_API int npack;

PACK_API int fnpack(void);
extern "C" PACK_API int fnfilepath(CString filepath);