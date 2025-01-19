#include "mapper.hpp"

int main(int argc, char* argv[]) {
    const wchar_t* processName = L"csgo.exe"; 
    PBYTE dllBytes = {

    };
    injectDllIntoProcess(processName, dllBytes);
    return 0;
}