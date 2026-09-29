// Wave 7 probe: standalone MSVC single-TU probe, no repo dependencies.
// Modes:
//   probe_wave7 prefetch <pf_file> <out_decompressed_file>
//   probe_wave7 amcache  <hive_copy_path> [nobackup]
//   probe_wave7 tasks    [mta|sta]
//   probe_wave7 wmi
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <winternl.h>
#include <comdef.h>
#include <taskschd.h>
#include <wbemidl.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// --- decompression types (not in winternl.h) ---
typedef NTSTATUS(NTAPI* RtlGetCompressionWorkSpaceSize_t)(
    USHORT CompressionFormatAndEngine,
    PULONG CompressBufferWorkSpaceSize,
    PULONG CompressFragmentWorkSpaceSize);

typedef NTSTATUS(NTAPI* RtlDecompressBufferEx_t)(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    PULONG FinalUncompressedSize,
    PVOID WorkSpace);

#ifndef COMPRESSION_FORMAT_XPRESS_HUFF
#define COMPRESSION_FORMAT_XPRESS_HUFF 4
#endif
#ifndef COMPRESSION_ENGINE_STANDARD
#define COMPRESSION_ENGINE_STANDARD 0
#endif

static void hex_dump(const unsigned char* buf, size_t n, char* out) {
    static const char* hx = "0123456789ABCDEF";
    for (size_t i = 0; i < n; ++i) {
        out[i * 3 + 0] = hx[(buf[i] >> 4) & 0xF];
        out[i * 3 + 1] = hx[buf[i] & 0xF];
        out[i * 3 + 2] = (i + 1 == n) ? '\0' : ' ';
    }
}

static int mode_prefetch(const std::wstring& pfPath, const std::wstring& outPath) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (!ntdll) { printf("ERROR: GetModuleHandleW(ntdll) failed, gle=%lu\n", GetLastError()); return 1; }

    auto pGetWs = (RtlGetCompressionWorkSpaceSize_t)GetProcAddress(ntdll, "RtlGetCompressionWorkSpaceSize");
    auto pDecompress = (RtlDecompressBufferEx_t)GetProcAddress(ntdll, "RtlDecompressBufferEx");
    printf("GetProcAddress(RtlGetCompressionWorkSpaceSize) = %p\n", (void*)pGetWs);
    printf("GetProcAddress(RtlDecompressBufferEx) = %p\n", (void*)pDecompress);
    if (!pGetWs || !pDecompress) { printf("ERROR: required export missing\n"); return 1; }

    std::ifstream f(pfPath, std::ios::binary);
    if (!f) { printf("ERROR: cannot open %ls\n", pfPath.c_str()); return 1; }
    std::vector<unsigned char> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    printf("Input file size: %zu bytes\n", data.size());
    if (data.size() < 8 || memcmp(data.data(), "MAM\x04", 4) != 0) {
        printf("ERROR: not a MAM-compressed prefetch file (first 4 bytes not MAM\\x04)\n");
        return 1;
    }
    uint32_t decompSize = 0;
    memcpy(&decompSize, data.data() + 4, 4);
    printf("Declared decompressed size (bytes 4-7 LE): %u\n", decompSize);

    ULONG compWorkspace = 0, fragWorkspace = 0;
    NTSTATUS wsStatus = pGetWs(COMPRESSION_FORMAT_XPRESS_HUFF | (COMPRESSION_ENGINE_STANDARD << 8),
                               &compWorkspace, &fragWorkspace);
    printf("RtlGetCompressionWorkSpaceSize NTSTATUS: 0x%08X, workspace=%lu\n", (unsigned)wsStatus, compWorkspace);

    std::vector<unsigned char> workspace(compWorkspace ? compWorkspace : 4096);
    std::vector<unsigned char> outBuf(decompSize);
    ULONG finalSize = 0;
    NTSTATUS st = pDecompress(
        COMPRESSION_FORMAT_XPRESS_HUFF,
        outBuf.data(), (ULONG)outBuf.size(),
        data.data() + 8, (ULONG)(data.size() - 8),
        &finalSize, workspace.data());

    printf("RtlDecompressBufferEx NTSTATUS: 0x%08X\n", (unsigned)st);
    printf("Decompressed size (final): %lu\n", finalSize);
    if (finalSize >= 8) {
        char hex[8 * 3];
        hex_dump(outBuf.data(), 8, hex);
        printf("First 8 bytes hex: %s\n", hex);
        printf("Bytes 4-7 as chars: %c%c%c%c\n", outBuf[4], outBuf[5], outBuf[6], outBuf[7]);
    }
    if (st == 0 /*STATUS_SUCCESS*/ && finalSize > 0) {
        std::ofstream of(outPath, std::ios::binary);
        of.write(reinterpret_cast<const char*>(outBuf.data()), finalSize);
        printf("Wrote decompressed payload to %ls (%lu bytes)\n", outPath.c_str(), finalSize);
    }
    return 0;
}

static int mode_amcache(const std::wstring& hivePath, bool noBackupPriv) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("ERROR: OpenProcessToken failed gle=%lu\n", GetLastError());
        return 1;
    }
    LUID luid{};
    LookupPrivilegeValueW(nullptr, SE_BACKUP_NAME, &luid);
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = noBackupPriv ? 0 : SE_PRIVILEGE_ENABLED;
    BOOL adj = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD adjGle = GetLastError();
    printf("AdjustTokenPrivileges(SeBackupPrivilege, %s) = %d, gle=%lu\n",
           noBackupPriv ? "disable" : "enable", adj, adjGle);

    HKEY hKey = nullptr;
    LSTATUS ls = RegLoadAppKeyW(hivePath.c_str(), &hKey, KEY_READ, REG_PROCESS_APPKEY, 0);
    printf("RegLoadAppKeyW(%s SeBackupPrivilege) LSTATUS: 0x%08X (%ld)\n",
           noBackupPriv ? "WITHOUT" : "WITH", (unsigned)ls, (long)ls);

    if (ls == ERROR_SUCCESS) {
        HKEY hSub = nullptr;
        LSTATUS ls2 = RegOpenKeyExW(hKey, L"Root\\InventoryApplicationFile", 0, KEY_READ, &hSub);
        printf("RegOpenKeyExW(Root\\\\InventoryApplicationFile) LSTATUS: 0x%08X\n", (unsigned)ls2);
        if (ls2 == ERROR_SUCCESS) {
            DWORD subKeyCount = 0;
            LSTATUS ls3 = RegQueryInfoKeyW(hSub, nullptr, nullptr, nullptr, &subKeyCount,
                                            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
            printf("RegQueryInfoKeyW LSTATUS: 0x%08X, subKeyCount=%lu\n", (unsigned)ls3, subKeyCount);
            RegCloseKey(hSub);
        }
        RegCloseKey(hKey);
    }
    CloseHandle(hToken);
    return 0;
}

static int mode_tasks(bool mta) {
    HRESULT hr = CoInitializeEx(nullptr, mta ? COINIT_MULTITHREADED : COINIT_APARTMENTTHREADED);
    printf("CoInitializeEx(%s) HRESULT: 0x%08X\n", mta ? "COINIT_MULTITHREADED" : "COINIT_APARTMENTTHREADED", (unsigned)hr);
    bool needUninit = SUCCEEDED(hr);

    ITaskService* pService = nullptr;
    HRESULT hrCreate = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                         IID_ITaskService, (void**)&pService);
    printf("CoCreateInstance(CLSID_TaskScheduler) HRESULT: 0x%08X\n", (unsigned)hrCreate);
    if (SUCCEEDED(hrCreate)) {
        _variant_t vEmpty;
        HRESULT hrConn = pService->Connect(vEmpty, vEmpty, vEmpty, vEmpty);
        printf("ITaskService::Connect HRESULT: 0x%08X\n", (unsigned)hrConn);
        if (SUCCEEDED(hrConn)) {
            ITaskFolder* pRoot = nullptr;
            HRESULT hrFolder = pService->GetFolder(_bstr_t(L"\\"), &pRoot);
            printf("GetFolder(\\\\) HRESULT: 0x%08X\n", (unsigned)hrFolder);
            if (SUCCEEDED(hrFolder)) {
                long total = 0;
                std::vector<ITaskFolder*> stack{ pRoot };
                while (!stack.empty()) {
                    ITaskFolder* f = stack.back();
                    stack.pop_back();
                    IRegisteredTaskCollection* pTasks = nullptr;
                    if (SUCCEEDED(f->GetTasks(TASK_ENUM_HIDDEN, &pTasks)) && pTasks) {
                        long cnt = 0;
                        pTasks->get_Count(&cnt);
                        total += cnt;
                        pTasks->Release();
                    }
                    ITaskFolderCollection* pSubs = nullptr;
                    if (SUCCEEDED(f->GetFolders(0, &pSubs)) && pSubs) {
                        long scnt = 0;
                        pSubs->get_Count(&scnt);
                        for (long i = 1; i <= scnt; ++i) {
                            ITaskFolder* sub = nullptr;
                            if (SUCCEEDED(pSubs->get_Item(_variant_t(i), &sub)) && sub) {
                                stack.push_back(sub);
                            }
                        }
                        pSubs->Release();
                    }
                    if (f != pRoot) f->Release();
                }
                pRoot->Release();
                printf("Recursive ITaskFolder::GetTasks(TASK_ENUM_HIDDEN) total count: %ld\n", total);
            }
        }
        pService->Release();
    }
    if (needUninit) CoUninitialize();
    return 0;
}

static int mode_wmi() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    printf("CoInitializeEx(COINIT_MULTITHREADED) for WMI HRESULT: 0x%08X\n", (unsigned)hr);
    bool needUninit = SUCCEEDED(hr);

    HRESULT hrSec = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    printf("CoInitializeSecurity HRESULT: 0x%08X\n", (unsigned)hrSec);

    IWbemLocator* pLoc = nullptr;
    HRESULT hrLoc = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    printf("CoCreateInstance(CLSID_WbemLocator) HRESULT: 0x%08X\n", (unsigned)hrLoc);
    if (SUCCEEDED(hrLoc)) {
        IWbemServices* pSvc = nullptr;
        HRESULT hrConn = pLoc->ConnectServer(_bstr_t(L"root\\subscription"), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pSvc);
        printf("ConnectServer(root\\\\subscription) HRESULT: 0x%08X\n", (unsigned)hrConn);
        if (SUCCEEDED(hrConn)) {
            CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
            IEnumWbemClassObject* pEnum = nullptr;
            HRESULT hrQ = pSvc->ExecQuery(_bstr_t(L"WQL"),
                _bstr_t(L"SELECT * FROM __FilterToConsumerBinding"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnum);
            printf("ExecQuery(__FilterToConsumerBinding) HRESULT: 0x%08X\n", (unsigned)hrQ);
            if (SUCCEEDED(hrQ)) {
                long total = 0;
                for (;;) {
                    IWbemClassObject* pObj = nullptr;
                    ULONG returned = 0;
                    HRESULT hrNext = pEnum->Next(10000, 1, &pObj, &returned);
                    if (hrNext != WBEM_S_NO_ERROR || returned == 0) {
                        printf("Next() final HRESULT: 0x%08X (returned=%lu)\n", (unsigned)hrNext, returned);
                        break;
                    }
                    total++;
                    pObj->Release();
                }
                printf("__FilterToConsumerBinding semisynchronous enumeration total: %ld\n", total);
                pEnum->Release();
            }
            pSvc->Release();
        }
        pLoc->Release();
    }
    if (needUninit) CoUninitialize();
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        printf("usage: probe_wave7 prefetch|amcache|tasks|wmi ...\n");
        return 2;
    }
    std::wstring mode = argv[1];
    if (mode == L"prefetch" && argc >= 4) {
        return mode_prefetch(argv[2], argv[3]);
    } else if (mode == L"amcache" && argc >= 3) {
        bool noBackup = (argc >= 4 && std::wstring(argv[3]) == L"nobackup");
        return mode_amcache(argv[2], noBackup);
    } else if (mode == L"tasks") {
        bool mta = !(argc >= 3 && std::wstring(argv[2]) == L"sta");
        return mode_tasks(mta);
    } else if (mode == L"wmi") {
        return mode_wmi();
    }
    printf("ERROR: bad arguments\n");
    return 2;
}
