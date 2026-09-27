#ifndef PE_WORKSHOP_WIN32_MIN_H
#define PE_WORKSHOP_WIN32_MIN_H

/* The samples intentionally use a tiny, readable subset of the Win32 ABI.
   Windows x64 uses 32-bit DWORD/BOOL and 64-bit pointers; no C runtime is needed. */
typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;
#define WINIMPORT __declspec(dllimport)
#define STD_OUTPUT_HANDLE ((DWORD)-11)

WINIMPORT HANDLE __stdcall GetStdHandle(DWORD standard_handle);
WINIMPORT BOOL __stdcall WriteFile(HANDLE file, const void *buffer,
    DWORD byte_count, DWORD *bytes_written, void *overlapped);
__declspec(noreturn) WINIMPORT void __stdcall ExitProcess(DWORD exit_code);
WINIMPORT char *__stdcall GetCommandLineA(void);
WINIMPORT int __stdcall MessageBoxA(void *owner, const char *text,
    const char *caption, unsigned int type);

#endif
