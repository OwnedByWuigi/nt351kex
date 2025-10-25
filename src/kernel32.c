#include <stddef.h>
#define WIN32_LEAN_AND_MEAN
#define _KERNEL32EXT_SOURCE
#define _WIN32_WINNT 0x0351

/* Define types missing or undefined for NT 3.51 compatibility */
typedef char* LPSTR;
typedef wchar_t* LPWSTR;
typedef unsigned long DWORD;
typedef unsigned long DWORD_PTR;

/* Define types missing in NT 3.51 headers to satisfy MinGW */
typedef enum _FINDEX_INFO_LEVELS {
    FindExInfoStandard,
    FindExInfoMaxInfoLevel
} FINDEX_INFO_LEVELS;

typedef enum _FINDEX_SEARCH_OPS {
    FindExSearchNameMatch,
    FindExSearchLimitToDirectories,
    FindExSearchLimitToDevices,
    FindExSearchMaxSearchOp
} FINDEX_SEARCH_OPS;

typedef struct _VALENTA {
    LPSTR ve_valuename;
    DWORD ve_valuelen;
    DWORD_PTR ve_valueptr;
    DWORD ve_type;
} VALENTA, *PVALENTA;

typedef struct _VALENTW {
    LPWSTR ve_valuename;
    DWORD ve_valuelen;
    DWORD_PTR ve_valueptr;
    DWORD ve_type;
} VALENTW, *PVALENTW;

#include <windows.h>

typedef LONG NTSTATUS;
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000L
#endif

/* Function pointer typedefs for NT functions */
typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);
typedef NTSTATUS (NTAPI *PFN_NtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType);
typedef ULONG (NTAPI *PFN_RtlNtStatusToDosError)(NTSTATUS Status);

/* Function pointer typedefs for available NT 3.51 APIs */
typedef DWORD (WINAPI *PFN_GetCurrentThreadId)(VOID);
typedef BOOL (WINAPI *PFN_DuplicateHandle)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
typedef VOID (WINAPI *PFN_Sleep)(DWORD);
typedef BOOL (WINAPI *PFN_CloseHandle)(HANDLE);
typedef VOID (WINAPI *PFN_RaiseException)(DWORD, DWORD, DWORD, const ULONG_PTR*);
typedef HANDLE (WINAPI *PFN_CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *PFN_IsDebuggerPresent)(VOID);
typedef HMODULE (WINAPI *PFN_GetModuleHandleW)(LPCWSTR);
typedef VOID (WINAPI *PFN_GetSystemTimeAsFileTime)(LPFILETIME);
typedef BOOL (WINAPI *PFN_QueryPerformanceCounter)(LARGE_INTEGER*);
typedef BOOL (WINAPI *PFN_GetVersionExW)(LPOSVERSIONINFOW);
typedef BOOL (WINAPI *PFN_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef DWORD (WINAPI *PFN_SuspendThread)(HANDLE);
typedef DWORD (WINAPI *PFN_ResumeThread)(HANDLE);
typedef HANDLE (WINAPI *PFN_CreateEventW)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
typedef BOOL (WINAPI *PFN_SetEvent)(HANDLE);
typedef BOOL (WINAPI *PFN_ResetEvent)(HANDLE);
typedef LPVOID (WINAPI *PFN_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *PFN_ReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef BOOL (WINAPI *PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PFN_GetExitCodeProcess)(HANDLE, LPDWORD);
typedef HLOCAL (WINAPI *PFN_LocalFree)(HLOCAL);
typedef VOID (WINAPI *PFN_InitializeCriticalSection)(LPCRITICAL_SECTION);
typedef DWORD (WINAPI *PFN_WaitForSingleObject)(HANDLE, DWORD);
typedef BOOL (WINAPI *PFN_VirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL (WINAPI *PFN_VirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);
typedef HANDLE (WINAPI *PFN_OpenProcess)(DWORD, BOOL, DWORD);
typedef DWORD (WINAPI *PFN_GetCurrentProcessId)(VOID);
typedef BOOL (WINAPI *PFN_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef DWORD (WINAPI *PFN_GetFileType)(HANDLE);
typedef HANDLE (WINAPI *PFN_CreateMutexW)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);
typedef BOOL (WINAPI *PFN_UnmapViewOfFile)(LPCVOID);
typedef BOOL (WINAPI *PFN_TerminateProcess)(HANDLE, UINT);
typedef HANDLE (WINAPI *PFN_CreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef LPVOID (WINAPI *PFN_MapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef LANGID (WINAPI *PFN_GetUserDefaultLangID)(VOID);
typedef LCID (WINAPI *PFN_GetUserDefaultLCID)(VOID);
typedef DWORD (WINAPI *PFN_GetTickCount)(VOID);
typedef HANDLE (WINAPI *PFN_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *PFN_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef HANDLE (WINAPI *PFN_GetCurrentProcess)(VOID);
typedef VOID (WINAPI *PFN_DeleteCriticalSection)(LPCRITICAL_SECTION);
typedef VOID (WINAPI *PFN_LeaveCriticalSection)(LPCRITICAL_SECTION);
typedef VOID (WINAPI *PFN_EnterCriticalSection)(LPCRITICAL_SECTION);
typedef BOOL (WINAPI *PFN_GetModuleHandleExW)(DWORD, LPCWSTR, HMODULE*);
typedef DWORD (WINAPI *PFN_GetLastError)(VOID);
typedef VOID (WINAPI *PFN_SetLastError)(DWORD);
typedef BOOL (WINAPI *PFN_FreeLibrary)(HMODULE);
typedef FARPROC (WINAPI *PFN_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryW)(LPCWSTR);
typedef int (WINAPI *PFN_MultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);
typedef DWORD (WINAPI *PFN_GetFileAttributesW)(LPCWSTR);
typedef DWORD (WINAPI *PFN_GetEnvironmentVariableW)(LPCWSTR, LPWSTR, DWORD);
typedef DWORD (WINAPI *PFN_GetModuleFileNameW)(HMODULE, LPWSTR, DWORD);
typedef DWORD (WINAPI *PFN_ExpandEnvironmentStringsW)(LPCWSTR, LPWSTR, DWORD);
typedef HMODULE (WINAPI *PFN_LoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef VOID (WINAPI *PFN_GetSystemInfo)(LPSYSTEM_INFO);
typedef BOOL (WINAPI *PFN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef SIZE_T (WINAPI *PFN_VirtualQuery)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef SIZE_T (WINAPI *PFN_VirtualQueryEx)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef int (WINAPI *PFN_lstrlenW)(LPCWSTR);
typedef VOID (WINAPI *PFN_DebugBreak)(VOID);
typedef BOOL (WINAPI *PFN_SetFilePointer)(HANDLE, LONG, PLONG, DWORD);
typedef BOOL (WINAPI *PFN_GetThreadContext)(HANDLE, LPCONTEXT);
typedef int (WINAPI *PFN_WideCharToMultiByte)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);

/* Function pointers */
static PFN_NtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
static PFN_NtFreeVirtualMemory pNtFreeVirtualMemory = NULL;
static PFN_RtlNtStatusToDosError pRtlNtStatusToDosError = NULL;
static PFN_GetCurrentThreadId pGetCurrentThreadId = NULL;
static PFN_DuplicateHandle pDuplicateHandle = NULL;
static PFN_Sleep pSleep = NULL;
static PFN_CloseHandle pCloseHandle = NULL;
static PFN_RaiseException pRaiseException = NULL;
static PFN_CreateThread pCreateThread = NULL;
static PFN_IsDebuggerPresent pIsDebuggerPresent = NULL;
static PFN_GetModuleHandleW pGetModuleHandleW = NULL;
static PFN_GetSystemTimeAsFileTime pGetSystemTimeAsFileTime = NULL;
static PFN_QueryPerformanceCounter pQueryPerformanceCounter = NULL;
static PFN_GetVersionExW pGetVersionExW = NULL;
static PFN_WriteProcessMemory pWriteProcessMemory = NULL;
static PFN_SuspendThread pSuspendThread = NULL;
static PFN_ResumeThread pResumeThread = NULL;
static PFN_CreateEventW pCreateEventW = NULL;
static PFN_SetEvent pSetEvent = NULL;
static PFN_ResetEvent pResetEvent = NULL;
static PFN_VirtualAllocEx pVirtualAllocEx = NULL;
static PFN_ReadProcessMemory pReadProcessMemory = NULL;
static PFN_CreateProcessW pCreateProcessW = NULL;
static PFN_GetExitCodeProcess pGetExitCodeProcess = NULL;
static PFN_LocalFree pLocalFree = NULL;
static PFN_InitializeCriticalSection pInitializeCriticalSection = NULL;
static PFN_WaitForSingleObject pWaitForSingleObject = NULL;
static PFN_VirtualFree pVirtualFree = NULL;
static PFN_VirtualFreeEx pVirtualFreeEx = NULL;
static PFN_OpenProcess pOpenProcess = NULL;
static PFN_GetCurrentProcessId pGetCurrentProcessId = NULL;
static PFN_VirtualProtectEx pVirtualProtectEx = NULL;
static PFN_GetFileType pGetFileType = NULL;
static PFN_CreateMutexW pCreateMutexW = NULL;
static PFN_UnmapViewOfFile pUnmapViewOfFile = NULL;
static PFN_TerminateProcess pTerminateProcess = NULL;
static PFN_CreateFileMappingW pCreateFileMappingW = NULL;
static PFN_MapViewOfFile pMapViewOfFile = NULL;
static PFN_GetUserDefaultLangID pGetUserDefaultLangID = NULL;
static PFN_GetUserDefaultLCID pGetUserDefaultLCID = NULL;
static PFN_GetTickCount pGetTickCount = NULL;
static PFN_CreateFileW pCreateFileW = NULL;
static PFN_ReadFile pReadFile = NULL;
static PFN_GetCurrentProcess pGetCurrentProcess = NULL;
static PFN_DeleteCriticalSection pDeleteCriticalSection = NULL;
static PFN_LeaveCriticalSection pLeaveCriticalSection = NULL;
static PFN_EnterCriticalSection pEnterCriticalSection = NULL;
static PFN_GetModuleHandleExW pGetModuleHandleExW = NULL;
static PFN_GetLastError pGetLastError = NULL;
static PFN_SetLastError pSetLastError = NULL;
static PFN_FreeLibrary pFreeLibrary = NULL;
static PFN_GetProcAddress pGetProcAddress = NULL;
static PFN_LoadLibraryW pLoadLibraryW = NULL;
static PFN_MultiByteToWideChar pMultiByteToWideChar = NULL;
static PFN_GetFileAttributesW pGetFileAttributesW = NULL;
static PFN_GetEnvironmentVariableW pGetEnvironmentVariableW = NULL;
static PFN_GetModuleFileNameW pGetModuleFileNameW = NULL;
static PFN_ExpandEnvironmentStringsW pExpandEnvironmentStringsW = NULL;
static PFN_LoadLibraryExA pLoadLibraryExA = NULL;
static PFN_GetSystemInfo pGetSystemInfo = NULL;
static PFN_VirtualProtect pVirtualProtect = NULL;
static PFN_VirtualQuery pVirtualQuery = NULL;
static PFN_VirtualQueryEx pVirtualQueryEx = NULL;
static PFN_lstrlenW plstrlenW = NULL;
static PFN_DebugBreak pDebugBreak = NULL;
static PFN_SetFilePointer pSetFilePointer = NULL;
static PFN_GetThreadContext pGetThreadContext = NULL;
static PFN_WideCharToMultiByte pWideCharToMultiByte = NULL;

static HMODULE hKernel32 = NULL;

static void EnsureNtProcs(void)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        hNtdll = LoadLibraryA("ntdll.dll");
    }
    if (hNtdll) {
        if (!pNtAllocateVirtualMemory) {
            pNtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)
                GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
        }
        if (!pNtFreeVirtualMemory) {
            pNtFreeVirtualMemory = (PFN_NtFreeVirtualMemory)
                GetProcAddress(hNtdll, "NtFreeVirtualMemory");
        }
        if (!pRtlNtStatusToDosError) {
            pRtlNtStatusToDosError = (PFN_RtlNtStatusToDosError)
                GetProcAddress(hNtdll, "RtlNtStatusToDosError");
        }
    }
}

static void EnsureKernel32Procs(void)
{
    if (!hKernel32) {
        hKernel32 = LoadLibraryA("kernel32.dll");
    }
    if (hKernel32) {
        pGetCurrentThreadId = (PFN_GetCurrentThreadId)GetProcAddress(hKernel32, "GetCurrentThreadId");
        pDuplicateHandle = (PFN_DuplicateHandle)GetProcAddress(hKernel32, "DuplicateHandle");
        pSleep = (PFN_Sleep)GetProcAddress(hKernel32, "Sleep");
        pCloseHandle = (PFN_CloseHandle)GetProcAddress(hKernel32, "CloseHandle");
        pRaiseException = (PFN_RaiseException)GetProcAddress(hKernel32, "RaiseException");
        pCreateThread = (PFN_CreateThread)GetProcAddress(hKernel32, "CreateThread");
        pIsDebuggerPresent = (PFN_IsDebuggerPresent)GetProcAddress(hKernel32, "IsDebuggerPresent");
        pGetModuleHandleW = (PFN_GetModuleHandleW)GetProcAddress(hKernel32, "GetModuleHandleW");
        pGetSystemTimeAsFileTime = (PFN_GetSystemTimeAsFileTime)GetProcAddress(hKernel32, "GetSystemTimeAsFileTime");
        pQueryPerformanceCounter = (PFN_QueryPerformanceCounter)GetProcAddress(hKernel32, "QueryPerformanceCounter");
        pGetVersionExW = (PFN_GetVersionExW)GetProcAddress(hKernel32, "GetVersionExW");
        pWriteProcessMemory = (PFN_WriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
        pSuspendThread = (PFN_SuspendThread)GetProcAddress(hKernel32, "SuspendThread");
        pResumeThread = (PFN_ResumeThread)GetProcAddress(hKernel32, "ResumeThread");
        pCreateEventW = (PFN_CreateEventW)GetProcAddress(hKernel32, "CreateEventW");
        pSetEvent = (PFN_SetEvent)GetProcAddress(hKernel32, "SetEvent");
        pResetEvent = (PFN_ResetEvent)GetProcAddress(hKernel32, "ResetEvent");
        pVirtualAllocEx = (PFN_VirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
        pReadProcessMemory = (PFN_ReadProcessMemory)GetProcAddress(hKernel32, "ReadProcessMemory");
        pCreateProcessW = (PFN_CreateProcessW)GetProcAddress(hKernel32, "CreateProcessW");
        pGetExitCodeProcess = (PFN_GetExitCodeProcess)GetProcAddress(hKernel32, "GetExitCodeProcess");
        pLocalFree = (PFN_LocalFree)GetProcAddress(hKernel32, "LocalFree");
        pInitializeCriticalSection = (PFN_InitializeCriticalSection)GetProcAddress(hKernel32, "InitializeCriticalSection");
        pWaitForSingleObject = (PFN_WaitForSingleObject)GetProcAddress(hKernel32, "WaitForSingleObject");
        pVirtualFree = (PFN_VirtualFree)GetProcAddress(hKernel32, "VirtualFree");
        pVirtualFreeEx = (PFN_VirtualFreeEx)GetProcAddress(hKernel32, "VirtualFreeEx");
        pOpenProcess = (PFN_OpenProcess)GetProcAddress(hKernel32, "OpenProcess");
        pGetCurrentProcessId = (PFN_GetCurrentProcessId)GetProcAddress(hKernel32, "GetCurrentProcessId");
        pVirtualProtectEx = (PFN_VirtualProtectEx)GetProcAddress(hKernel32, "VirtualProtectEx");
        pGetFileType = (PFN_GetFileType)GetProcAddress(hKernel32, "GetFileType");
        pCreateMutexW = (PFN_CreateMutexW)GetProcAddress(hKernel32, "CreateMutexW");
        pUnmapViewOfFile = (PFN_UnmapViewOfFile)GetProcAddress(hKernel32, "UnmapViewOfFile");
        pTerminateProcess = (PFN_TerminateProcess)GetProcAddress(hKernel32, "TerminateProcess");
        pCreateFileMappingW = (PFN_CreateFileMappingW)GetProcAddress(hKernel32, "CreateFileMappingW");
        pMapViewOfFile = (PFN_MapViewOfFile)GetProcAddress(hKernel32, "MapViewOfFile");
        pGetUserDefaultLangID = (PFN_GetUserDefaultLangID)GetProcAddress(hKernel32, "GetUserDefaultLangID");
        pGetUserDefaultLCID = (PFN_GetUserDefaultLCID)GetProcAddress(hKernel32, "GetUserDefaultLCID");
        pGetTickCount = (PFN_GetTickCount)GetProcAddress(hKernel32, "GetTickCount");
        pCreateFileW = (PFN_CreateFileW)GetProcAddress(hKernel32, "CreateFileW");
        pReadFile = (PFN_ReadFile)GetProcAddress(hKernel32, "ReadFile");
        pGetCurrentProcess = (PFN_GetCurrentProcess)GetProcAddress(hKernel32, "GetCurrentProcess");
        pDeleteCriticalSection = (PFN_DeleteCriticalSection)GetProcAddress(hKernel32, "DeleteCriticalSection");
        pLeaveCriticalSection = (PFN_LeaveCriticalSection)GetProcAddress(hKernel32, "LeaveCriticalSection");
        pEnterCriticalSection = (PFN_EnterCriticalSection)GetProcAddress(hKernel32, "EnterCriticalSection");
        pGetModuleHandleExW = (PFN_GetModuleHandleExW)GetProcAddress(hKernel32, "GetModuleHandleExW");
        pGetLastError = (PFN_GetLastError)GetProcAddress(hKernel32, "GetLastError");
        pSetLastError = (PFN_SetLastError)GetProcAddress(hKernel32, "SetLastError");
        pFreeLibrary = (PFN_FreeLibrary)GetProcAddress(hKernel32, "FreeLibrary");
        pGetProcAddress = (PFN_GetProcAddress)GetProcAddress(hKernel32, "GetProcAddress");
        pLoadLibraryW = (PFN_LoadLibraryW)GetProcAddress(hKernel32, "LoadLibraryW");
        pMultiByteToWideChar = (PFN_MultiByteToWideChar)GetProcAddress(hKernel32, "MultiByteToWideChar");
        pGetFileAttributesW = (PFN_GetFileAttributesW)GetProcAddress(hKernel32, "GetFileAttributesW");
        pGetEnvironmentVariableW = (PFN_GetEnvironmentVariableW)GetProcAddress(hKernel32, "GetEnvironmentVariableW");
        pGetModuleFileNameW = (PFN_GetModuleFileNameW)GetProcAddress(hKernel32, "GetModuleFileNameW");
        pExpandEnvironmentStringsW = (PFN_ExpandEnvironmentStringsW)GetProcAddress(hKernel32, "ExpandEnvironmentStringsW");
        pLoadLibraryExA = (PFN_LoadLibraryExA)GetProcAddress(hKernel32, "LoadLibraryExA");
        pGetSystemInfo = (PFN_GetSystemInfo)GetProcAddress(hKernel32, "GetSystemInfo");
        pVirtualProtect = (PFN_VirtualProtect)GetProcAddress(hKernel32, "VirtualProtect");
        pVirtualQuery = (PFN_VirtualQuery)GetProcAddress(hKernel32, "VirtualQuery");
        pVirtualQueryEx = (PFN_VirtualQueryEx)GetProcAddress(hKernel32, "VirtualQueryEx");
        plstrlenW = (PFN_lstrlenW)GetProcAddress(hKernel32, "lstrlenW");
        pDebugBreak = (PFN_DebugBreak)GetProcAddress(hKernel32, "DebugBreak");
        pSetFilePointer = (PFN_SetFilePointer)GetProcAddress(hKernel32, "SetFilePointer");
        pGetThreadContext = (PFN_GetThreadContext)GetProcAddress(hKernel32, "GetThreadContext");
        pWideCharToMultiByte = (PFN_WideCharToMultiByte)GetProcAddress(hKernel32, "WideCharToMultiByte");
    }
}

/* Exported functions for NT 3.51 available APIs */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"

__declspec(dllexport) DWORD WINAPI GetCurrentThreadId(VOID)
{
    EnsureKernel32Procs();
    return pGetCurrentThreadId ? pGetCurrentThreadId() : 0;
}

__declspec(dllexport) BOOL WINAPI DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions)
{
    EnsureKernel32Procs();
    if (!pDuplicateHandle) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pDuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
}

__declspec(dllexport) VOID WINAPI Sleep(DWORD dwMilliseconds)
{
    EnsureKernel32Procs();
    if (pSleep) pSleep(dwMilliseconds);
}

__declspec(dllexport) BOOL WINAPI CloseHandle(HANDLE hObject)
{
    EnsureKernel32Procs();
    if (!pCloseHandle) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pCloseHandle(hObject);
}

__declspec(dllexport) VOID WINAPI RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR* lpArguments)
{
    EnsureKernel32Procs();
    if (pRaiseException) pRaiseException(dwExceptionCode, dwExceptionFlags, nNumberOfArguments, lpArguments);
}

__declspec(dllexport) HANDLE WINAPI CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    EnsureKernel32Procs();
    if (!pCreateThread) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return pCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

__declspec(dllexport) BOOL WINAPI IsDebuggerPresent(VOID)
{
    EnsureKernel32Procs();
    return pIsDebuggerPresent ? pIsDebuggerPresent() : FALSE;
}

__declspec(dllexport) HMODULE WINAPI GetModuleHandleW(LPCWSTR lpModuleName)
{
    EnsureKernel32Procs();
    return pGetModuleHandleW ? pGetModuleHandleW(lpModuleName) : NULL;
}

__declspec(dllexport) VOID WINAPI GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
{
    EnsureKernel32Procs();
    if (pGetSystemTimeAsFileTime) pGetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
}

__declspec(dllexport) BOOL WINAPI QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount)
{
    EnsureKernel32Procs();
    if (!pQueryPerformanceCounter) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pQueryPerformanceCounter(lpPerformanceCount);
}

__declspec(dllexport) BOOL WINAPI GetVersionExW(LPOSVERSIONINFOW lpVersionInformation)
{
    EnsureKernel32Procs();
    if (!pGetVersionExW) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pGetVersionExW(lpVersionInformation);
}

__declspec(dllexport) BOOL WINAPI WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    EnsureKernel32Procs();
    if (!pWriteProcessMemory) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

__declspec(dllexport) DWORD WINAPI SuspendThread(HANDLE hThread)
{
    EnsureKernel32Procs();
    if (!pSuspendThread) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return (DWORD)-1; }
    return pSuspendThread(hThread);
}

__declspec(dllexport) DWORD WINAPI ResumeThread(HANDLE hThread)
{
    EnsureKernel32Procs();
    if (!pResumeThread) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return (DWORD)-1; }
    return pResumeThread(hThread);
}

__declspec(dllexport) HANDLE WINAPI CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName)
{
    EnsureKernel32Procs();
    if (!pCreateEventW) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return pCreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName);
}

__declspec(dllexport) BOOL WINAPI SetEvent(HANDLE hEvent)
{
    EnsureKernel32Procs();
    if (!pSetEvent) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pSetEvent(hEvent);
}

__declspec(dllexport) BOOL WINAPI ResetEvent(HANDLE hEvent)
{
    EnsureKernel32Procs();
    if (!pResetEvent) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pResetEvent(hEvent);
}

__declspec(dllexport) LPVOID WINAPI VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    EnsureNtProcs();
    if (hProcess == NULL || hProcess == GetCurrentProcess()) {
        return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    }
    if (!pNtAllocateVirtualMemory) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return NULL;
    }
    PVOID base = lpAddress;
    SIZE_T regionSize = dwSize;
    NTSTATUS st = pNtAllocateVirtualMemory(hProcess, &base, 0, &regionSize, flAllocationType, flProtect);
    if (st == STATUS_SUCCESS) {
        return base;
    }
    if (pRtlNtStatusToDosError) {
        SetLastError((DWORD)pRtlNtStatusToDosError(st));
    } else {
        SetLastError(ERROR_GEN_FAILURE);
    }
    return NULL;
}

__declspec(dllexport) BOOL WINAPI ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    EnsureKernel32Procs();
    if (!pReadProcessMemory) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

__declspec(dllexport) BOOL WINAPI CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    EnsureKernel32Procs();
    if (!pCreateProcessW) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

__declspec(dllexport) BOOL WINAPI GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode)
{
    EnsureKernel32Procs();
    if (!pGetExitCodeProcess) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pGetExitCodeProcess(hProcess, lpExitCode);
}

__declspec(dllexport) HLOCAL WINAPI LocalFree(HLOCAL hMem)
{
    EnsureKernel32Procs();
    if (!pLocalFree) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return hMem; }
    return pLocalFree(hMem);
}

__declspec(dllexport) VOID WINAPI InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    EnsureKernel32Procs();
    if (pInitializeCriticalSection) pInitializeCriticalSection(lpCriticalSection);
}

__declspec(dllexport) DWORD WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
{
    EnsureKernel32Procs();
    if (!pWaitForSingleObject) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return WAIT_FAILED; }
    return pWaitForSingleObject(hHandle, dwMilliseconds);
}

__declspec(dllexport) BOOL WINAPI VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    EnsureKernel32Procs();
    if (!pVirtualFree) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pVirtualFree(lpAddress, dwSize, dwFreeType);
}

__declspec(dllexport) BOOL WINAPI VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    EnsureNtProcs();
    if (hProcess == NULL || hProcess == GetCurrentProcess()) {
        return VirtualFree(lpAddress, dwSize, dwFreeType);
    }
    if (!pNtFreeVirtualMemory) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }
    PVOID base = lpAddress;
    SIZE_T regionSize = dwSize;
    NTSTATUS st = pNtFreeVirtualMemory(hProcess, &base, &regionSize, dwFreeType);
    if (st == STATUS_SUCCESS) {
        return TRUE;
    }
    if (pRtlNtStatusToDosError) {
        SetLastError((DWORD)pRtlNtStatusToDosError(st));
    } else {
        SetLastError(ERROR_GEN_FAILURE);
    }
    return FALSE;
}

__declspec(dllexport) HANDLE WINAPI OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    EnsureKernel32Procs();
    if (!pOpenProcess) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return pOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

__declspec(dllexport) DWORD WINAPI GetCurrentProcessId(VOID)
{
    EnsureKernel32Procs();
    return pGetCurrentProcessId ? pGetCurrentProcessId() : 0;
}

__declspec(dllexport) BOOL WINAPI VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    EnsureKernel32Procs();
    if (hProcess == NULL || hProcess == GetCurrentProcess()) {
        return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }
    if (!pVirtualProtectEx) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

__declspec(dllexport) DWORD WINAPI GetFileType(HANDLE hFile)
{
    EnsureKernel32Procs();
    if (!pGetFileType) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FILE_TYPE_UNKNOWN; }
    return pGetFileType(hFile);
}

__declspec(dllexport) HANDLE WINAPI CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName)
{
    EnsureKernel32Procs();
    if (!pCreateMutexW) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return pCreateMutexW(lpMutexAttributes, bInitialOwner, lpName);
}

__declspec(dllexport) BOOL WINAPI UnmapViewOfFile(LPCVOID lpBaseAddress)
{
    EnsureKernel32Procs();
    if (!pUnmapViewOfFile) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pUnmapViewOfFile(lpBaseAddress);
}

__declspec(dllexport) BOOL WINAPI TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    EnsureKernel32Procs();
    if (!pTerminateProcess) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pTerminateProcess(hProcess, uExitCode);
}

__declspec(dllexport) HANDLE WINAPI CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName)
{
    EnsureKernel32Procs();
    if (!pCreateFileMappingW) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return pCreateFileMappingW(hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}

__declspec(dllexport) LPVOID WINAPI MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
{
    EnsureKernel32Procs();
    if (!pMapViewOfFile) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return pMapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}

__declspec(dllexport) LANGID WINAPI GetUserDefaultLangID(VOID)
{
    EnsureKernel32Procs();
    return pGetUserDefaultLangID ? pGetUserDefaultLangID() : 0;
}

__declspec(dllexport) LCID WINAPI GetUserDefaultLCID(VOID)
{
    EnsureKernel32Procs();
    return pGetUserDefaultLCID ? pGetUserDefaultLCID() : 0;
}

__declspec(dllexport) DWORD WINAPI GetTickCount(VOID)
{
    EnsureKernel32Procs();
    return pGetTickCount ? pGetTickCount() : 0;
}

__declspec(dllexport) HANDLE WINAPI CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    EnsureKernel32Procs();
    if (!pCreateFileW) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return INVALID_HANDLE_VALUE; }
    return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

__declspec(dllexport) BOOL WINAPI ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    EnsureKernel32Procs();
    if (!pReadFile) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

__declspec(dllexport) HANDLE WINAPI GetCurrentProcess(VOID)
{
    EnsureKernel32Procs();
    return pGetCurrentProcess ? pGetCurrentProcess() : INVALID_HANDLE_VALUE;
}

__declspec(dllexport) VOID WINAPI DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    EnsureKernel32Procs();
    if (pDeleteCriticalSection) pDeleteCriticalSection(lpCriticalSection);
}

__declspec(dllexport) VOID WINAPI LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    EnsureKernel32Procs();
    if (pLeaveCriticalSection) pLeaveCriticalSection(lpCriticalSection);
}

__declspec(dllexport) VOID WINAPI EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    EnsureKernel32Procs();
    if (pEnterCriticalSection) pEnterCriticalSection(lpCriticalSection);
}

__declspec(dllexport) BOOL WINAPI GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule)
{
    EnsureKernel32Procs();
    if (!pGetModuleHandleExW) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pGetModuleHandleExW(dwFlags, lpModuleName, phModule);
}

__declspec(dllexport) DWORD WINAPI GetLastError(VOID)
{
    EnsureKernel32Procs();
    return pGetLastError ? pGetLastError() : ERROR_SUCCESS;
}

__declspec(dllexport) VOID WINAPI SetLastError(DWORD dwErrCode)
{
    EnsureKernel32Procs();
    if (pSetLastError) pSetLastError(dwErrCode);
}

__declspec(dllexport) BOOL WINAPI FreeLibrary(HMODULE hLibModule)
{
    EnsureKernel32Procs();
    if (!pFreeLibrary) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pFreeLibrary(hLibModule);
}

__declspec(dllexport) FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    EnsureKernel32Procs();
    if (!pGetProcAddress) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return pGetProcAddress(hModule, lpProcName);
}

__declspec(dllexport) HMODULE WINAPI LoadLibraryW(LPCWSTR lpLibFileName)
{
    EnsureKernel32Procs();
    if (!pLoadLibraryW) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return pLoadLibraryW(lpLibFileName);
}

__declspec(dllexport) int WINAPI MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar)
{
    EnsureKernel32Procs();
    if (!pMultiByteToWideChar) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
    return pMultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

__declspec(dllexport) DWORD WINAPI GetFileAttributesW(LPCWSTR lpFileName)
{
    EnsureKernel32Procs();
    if (!pGetFileAttributesW) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return INVALID_FILE_ATTRIBUTES; }
    return pGetFileAttributesW(lpFileName);
}

__declspec(dllexport) DWORD WINAPI GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize)
{
    EnsureKernel32Procs();
    if (!pGetEnvironmentVariableW) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
    return pGetEnvironmentVariableW(lpName, lpBuffer, nSize);
}

__declspec(dllexport) DWORD WINAPI GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
{
    EnsureKernel32Procs();
    if (!pGetModuleFileNameW) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
    return pGetModuleFileNameW(hModule, lpFilename, nSize);
}

__declspec(dllexport) DWORD WINAPI ExpandEnvironmentStringsW(LPCWSTR lpSrc, LPWSTR lpDst, DWORD nSize)
{
    EnsureKernel32Procs();
    if (!pExpandEnvironmentStringsW) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
    return pExpandEnvironmentStringsW(lpSrc, lpDst, nSize);
}

__declspec(dllexport) HMODULE WINAPI LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    EnsureKernel32Procs();
    if (!pLoadLibraryExA) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return pLoadLibraryExA(lpLibFileName, hFile, dwFlags);
}

__declspec(dllexport) VOID WINAPI GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)
{
    EnsureKernel32Procs();
    if (pGetSystemInfo) pGetSystemInfo(lpSystemInfo);
}

__declspec(dllexport) BOOL WINAPI VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    EnsureKernel32Procs();
    if (!pVirtualProtect) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return pVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

__declspec(dllexport) SIZE_T WINAPI VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
    EnsureKernel32Procs();
    if (!pVirtualQuery) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
    return pVirtualQuery(lpAddress, lpBuffer, dwLength);
}

__declspec(dllexport) SIZE_T WINAPI VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
    EnsureKernel32Procs();
    if (hProcess == NULL || hProcess == GetCurrentProcess()) {
        return VirtualQuery(lpAddress, lpBuffer, dwLength);
    }
    if (!pVirtualQueryEx) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return 0;
    }
    return pVirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
}

__declspec(dllexport) int WINAPI lstrlenW(LPCWSTR lpString)
{
    EnsureKernel32Procs();
    if (!plstrlenW) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
    return plstrlenW(lpString);
}

__declspec(dllexport) VOID WINAPI DebugBreak(VOID)
{
    EnsureKernel32Procs();
    if (pDebugBreak) pDebugBreak();
}

/* Exported functions for unavailable APIs */
__declspec(dllexport) VOID WINAPI GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo)
{
    /* Not available in NT 3.51; emulate with GetSystemInfo */
    EnsureKernel32Procs();
    if (pGetSystemInfo) pGetSystemInfo(lpSystemInfo);
    else SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
}

__declspec(dllexport) BOOL WINAPI SetInformationJobObject(HANDLE hJob, JOBOBJECTINFOCLASS JobObjectInformationClass, LPVOID lpJobObjectInformation, DWORD cbJobObjectInformationLength)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) BOOL WINAPI RegisterWaitForSingleObject(PHANDLE phNewWaitObject, HANDLE hObject, WAITORTIMERCALLBACK Callback, PVOID Context, ULONG dwMilliseconds, ULONG dwFlags)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) DWORD WINAPI GetProcessId(HANDLE Process)
{
    /* Not available in NT 3.51; return current process ID as fallback */
    EnsureKernel32Procs();
    if (!pGetCurrentProcessId || Process != GetCurrentProcess()) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return 0;
    }
    return pGetCurrentProcessId();
}

__declspec(dllexport) BOOL WINAPI GetQueuedCompletionStatus(HANDLE CompletionPort, LPDWORD lpNumberOfBytes, PULONG_PTR lpCompletionKey, LPOVERLAPPED* lpOverlapped, DWORD dwMilliseconds)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) BOOL WINAPI PostQueuedCompletionStatus(HANDLE CompletionPort, DWORD dwNumberOfBytesTransferred, ULONG_PTR dwCompletionKey, LPOVERLAPPED lpOverlapped)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) BOOL WINAPI TerminateJobObject(HANDLE hJob, UINT uExitCode)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) HANDLE WINAPI CreateIoCompletionPort(HANDLE FileHandle, HANDLE ExistingCompletionPort, ULONG_PTR CompletionKey, DWORD NumberOfConcurrentThreads)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

__declspec(dllexport) BOOL WINAPI SetHandleInformation(HANDLE hObject, DWORD dwMask, DWORD dwFlags)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) BOOL WINAPI GetProcessHandleCount(HANDLE hProcess, PDWORD pdwHandleCount)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) BOOL WINAPI AssignProcessToJobObject(HANDLE hJob, HANDLE hProcess)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) HANDLE WINAPI CreateJobObjectW(LPSECURITY_ATTRIBUTES lpJobAttributes, LPCWSTR lpName)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

__declspec(dllexport) HANDLE WINAPI CreateNamedPipeW(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return INVALID_HANDLE_VALUE;
}

__declspec(dllexport) BOOL WINAPI HeapSetInformation(HANDLE HeapHandle, HEAP_INFORMATION_CLASS HeapInformationClass, PVOID HeapInformation, SIZE_T HeapInformationLength)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) DWORD WINAPI SearchPathW(LPCWSTR lpPath, LPCWSTR lpFileName, LPCWSTR lpExtension, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR* lpFilePart)
{
    /* Not available in NT 3.51; emulate with GetFullPathNameW if possible */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

__declspec(dllexport) DWORD WINAPI GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer)
{
    /* Not available in NT 3.51; return ERROR_CALL_NOT_IMPLEMENTED */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

__declspec(dllexport) BOOL WINAPI ProcessIdToSessionId(DWORD dwProcessId, DWORD* pSessionId)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) DWORD WINAPI SignalObjectAndWait(HANDLE hObjectToSignal, HANDLE hObjectToWaitOn, DWORD dwMilliseconds, BOOL bAlertable)
{
    /* Not available in NT 3.51; emulate with SetEvent and WaitForSingleObject */
    EnsureKernel32Procs();
    if (!pSetEvent || !pWaitForSingleObject) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return WAIT_FAILED;
    }
    if (!pSetEvent(hObjectToSignal)) return WAIT_FAILED;
    return pWaitForSingleObject(hObjectToWaitOn, dwMilliseconds);
}

__declspec(dllexport) BOOL WINAPI GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
    /* Available in NT 3.51 but limited; forward with caution */
    EnsureKernel32Procs();
    if (!pGetThreadContext) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }
    return pGetThreadContext(hThread, lpContext);
}

__declspec(dllexport) DWORD WINAPI GetLongPathNameW(LPCWSTR lpszShortPath, LPWSTR lpszLongPath, DWORD cchBuffer)
{
    /* Not available in NT 3.51; return short path as-is */
    if (!lpszShortPath || !lpszLongPath) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    DWORD len = lstrlenW(lpszShortPath);
    if (len + 1 > cchBuffer) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return len + 1;
    }
    CopyMemory(lpszLongPath, lpszShortPath, (len + 1) * sizeof(WCHAR));
    return len;
}

__declspec(dllexport) BOOL WINAPI GetVolumePathNameW(LPCWSTR lpszFileName, LPWSTR lpszVolumePathName, DWORD cchBufferLength)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) BOOL WINAPI SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod)
{
    /* Not available in NT 3.51; emulate with SetFilePointer */
    EnsureKernel32Procs();
    if (!pSetFilePointer) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }
    DWORD result = pSetFilePointer(hFile, liDistanceToMove.LowPart, &liDistanceToMove.HighPart, dwMoveMethod);
    if (result == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
        return FALSE;
    }
    if (lpNewFilePointer) {
        lpNewFilePointer->LowPart = result;
        lpNewFilePointer->HighPart = liDistanceToMove.HighPart;
    }
    return TRUE;
}

__declspec(dllexport) BOOL WINAPI SetDllDirectoryW(LPCWSTR lpPathName)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) int WINAPI WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar)
{
    /* Available in NT 3.51 but limited codepage support */
    EnsureKernel32Procs();
    if (!pWideCharToMultiByte) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
    return pWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

__declspec(dllexport) BOOL WINAPI SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
    /* Not available in NT 3.51; return NULL to indicate no filter set */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

__declspec(dllexport) LONG WINAPI UnhandledExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
    /* Not available in NT 3.51; terminate process */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    TerminateProcess(GetCurrentProcess(), ExceptionInfo->ExceptionRecord->ExceptionCode);
    return EXCEPTION_EXECUTE_HANDLER;
}

__declspec(dllexport) BOOL WINAPI IsProcessorFeaturePresent(DWORD ProcessorFeature)
{
    /* Not available in NT 3.51; return FALSE for all features */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) VOID WINAPI InitializeSListHead(PSLIST_HEADER ListHead)
{
    /* Not available in NT 3.51; zero out SLIST_HEADER */
    if (ListHead) {
        ZeroMemory(ListHead, sizeof(SLIST_HEADER));
    } else {
        SetLastError(ERROR_INVALID_PARAMETER);
    }
}

__declspec(dllexport) BOOL WINAPI UnregisterWaitEx(HANDLE WaitHandle, HANDLE CompletionEvent)
{
    /* Not available in NT 3.51 */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

__declspec(dllexport) BOOL WINAPI InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount)
{
    /* Not available in NT 3.51; emulate with InitializeCriticalSection */
    EnsureKernel32Procs();
    if (!pInitializeCriticalSection) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }
    pInitializeCriticalSection(lpCriticalSection);
    return TRUE;
}

#pragma GCC diagnostic pop

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
    }
    return TRUE;
}