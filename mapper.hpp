#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>

// Target process name
const bool ERASE_ENTRY_POINT = true;
const bool ERASE_PE_HEADER = true;

const bool SUCCESS_MESSAGE = true;

class Injector {
private:
    PBYTE imageBase;
    HMODULE(WINAPI* loadLibraryA)(PCSTR);
    FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
    VOID(WINAPI* rtlZeroMemory)(PVOID, SIZE_T);

public:
    Injector(PBYTE imageBase, HMODULE(WINAPI* loadLibraryA)(PCSTR),
             FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR),
             VOID(WINAPI* rtlZeroMemory)(PVOID, SIZE_T))
        : imageBase(imageBase), loadLibraryA(loadLibraryA),
          getProcAddress(getProcAddress), rtlZeroMemory(rtlZeroMemory) {}

    DWORD loadLibrary() {
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(imageBase + ((PIMAGE_DOS_HEADER)imageBase)->e_lfanew);
        PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(imageBase
            + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        uintptr_t delta = (uintptr_t)(imageBase - ntHeaders->OptionalHeader.ImageBase);
        while (relocation->VirtualAddress) {
            WORD* relocationInfo = (WORD*)(relocation + 1);
            for (int i = 0, count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i < count; i++)
                if (relocationInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
                    *(PDWORD)(imageBase + (relocation->VirtualAddress + (relocationInfo[i] & 0xFFF))) += (DWORD)delta;

            relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
        }

        PIMAGE_IMPORT_DESCRIPTOR importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase
            + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (importDirectory->Characteristics) {
            PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)(imageBase + importDirectory->OriginalFirstThunk);
            PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(imageBase + importDirectory->FirstThunk);

            HMODULE module = loadLibraryA((LPCSTR)imageBase + importDirectory->Name);

            if (!module)
                return FALSE;

            while (originalFirstThunk->u1.AddressOfData) {
                uintptr_t Function = (uintptr_t)getProcAddress(module, originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ? (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF) : ((PIMAGE_IMPORT_BY_NAME)((LPBYTE)imageBase + originalFirstThunk->u1.AddressOfData))->Name);

                if (!Function)
                    return FALSE;

                firstThunk->u1.Function = (DWORD)Function;
                originalFirstThunk++;
                firstThunk++;
            }
            importDirectory++;
        }

        if (ntHeaders->OptionalHeader.AddressOfEntryPoint) {
            DWORD result = ((DWORD(__stdcall*)(HMODULE, DWORD, LPVOID))
                (imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint))
                ((HMODULE)imageBase, DLL_PROCESS_ATTACH, NULL);

#if ERASE_ENTRY_POINT
            rtlZeroMemory(imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint, 32);
#endif

#if ERASE_PE_HEADER
            rtlZeroMemory(imageBase, ntHeaders->OptionalHeader.SizeOfHeaders);
#endif
            return result;
        }
        return TRUE;
    }
};

void injectDllIntoProcess(const wchar_t* processName, PBYTE dllBytes) {
    HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processSnapshot == INVALID_HANDLE_VALUE)
        return;

    HANDLE process = NULL;
    PROCESSENTRY32W processInfo;
    processInfo.dwSize = sizeof(processInfo);

    if (Process32FirstW(processSnapshot, &processInfo)) {
        do {
            if (!lstrcmpW(processInfo.szExeFile, processName)) {
                process = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, processInfo.th32ProcessID);
                break;
            }
        } while (Process32NextW(processSnapshot, &processInfo));
    }
    CloseHandle(processSnapshot);

    if (!process)
        return;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllBytes + ((PIMAGE_DOS_HEADER)dllBytes)->e_lfanew);
    PBYTE executableImage = (PBYTE)VirtualAllocEx(process, NULL, ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    WriteProcessMemory(process, executableImage, dllBytes,
        ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
        WriteProcessMemory(process, executableImage + sectionHeaders[i].VirtualAddress,
        dllBytes + sectionHeaders[i].PointerToRawData, sectionHeaders[i].SizeOfRawData, NULL);

    Injector injector(executableImage, (HMODULE(WINAPI*)(PCSTR))LoadLibraryA, GetProcAddress, (VOID(NTAPI*)(PVOID, SIZE_T))GetProcAddress(LoadLibraryW(L"ntdll"), "RtlZeroMemory"));
    Injector* injectorMemory = (Injector*)VirtualAllocEx(process, NULL, sizeof(Injector), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    WriteProcessMemory(process, injectorMemory, &injector, sizeof(Injector), NULL);
    WaitForSingleObject(CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)[](LPVOID param) -> DWORD { return ((Injector*)param)->loadLibrary(); }, injectorMemory, 0, NULL), INFINITE);
    VirtualFreeEx(process, injectorMemory, 0, MEM_RELEASE);

    #if SUCCESS_MESSAGE
    char buf[100];
    sprintf_s(buf, sizeof(buf), "Dll successfully loaded into %ws at 0x%p", processName, (void*)executableImage);
    MessageBoxA(NULL, buf, "Success", MB_OK | MB_ICONINFORMATION);
    #endif
}
