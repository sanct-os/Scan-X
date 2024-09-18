#include <windows.h>
#include <vector>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <string>
#include <cstring>

constexpr size_t MAX_ADDRESSES = 50000;

auto rbx_pid_get(const TCHAR* rbx_process_name) -> DWORD {
    PROCESSENTRY32 rbx_pe;
    rbx_pe.dwSize = sizeof(PROCESSENTRY32);
    auto rbx_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(rbx_snap, &rbx_pe)) {
        do {
            if (_tcsicmp(rbx_pe.szExeFile, rbx_process_name) == 0) {
                CloseHandle(rbx_snap);
                return rbx_pe.th32ProcessID;
            }
        } while (Process32Next(rbx_snap, &rbx_pe));
    }
    CloseHandle(rbx_snap);
    return 0;
}

auto set_color_console() -> void {
    auto rbx_console = GetStdHandle(STD_OUTPUT_HANDLE);
    int rbx_color = rand() % 15 + 1;
    SetConsoleTextAttribute(rbx_console, rbx_color);
}

auto rbx_read_mem(HANDLE rbx_process, LPCVOID rbx_base_address, void* rbx_buffer, SIZE_T rbx_size) -> bool {
    return ReadProcessMemory(rbx_process, rbx_base_address, rbx_buffer, rbx_size, nullptr);
}

auto rbx_write_mem(HANDLE rbx_process, LPVOID rbx_base_address, LPCVOID rbx_buffer, SIZE_T rbx_size) -> bool {
    return WriteProcessMemory(rbx_process, rbx_base_address, rbx_buffer, rbx_size, nullptr);
}

auto rbx_scan_mem(HANDLE rbx_process, const std::string& search_value, size_t threshold, std::vector<LPVOID>& found_addresses) -> void {
    SYSTEM_INFO rbx_sys_info;
    GetSystemInfo(&rbx_sys_info);
    auto rbx_start_address = rbx_sys_info.lpMinimumApplicationAddress;
    auto rbx_end_address = rbx_sys_info.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION rbx_mbi;
    while (rbx_start_address < rbx_end_address) {
        if (VirtualQueryEx(rbx_process, rbx_start_address, &rbx_mbi, sizeof(rbx_mbi)) == sizeof(rbx_mbi)) {
            if (rbx_mbi.State == MEM_COMMIT && (rbx_mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                SIZE_T rbx_buffer_size = rbx_mbi.RegionSize;
                if (rbx_buffer_size > 1024 * 1024) {
                    rbx_buffer_size = 1024 * 1024;
                }
                std::vector<char> rbx_buffer(rbx_buffer_size);

                if (rbx_read_mem(rbx_process, rbx_mbi.BaseAddress, rbx_buffer.data(), rbx_buffer_size)) {
                    for (SIZE_T i = 0; i < rbx_buffer_size - search_value.size(); ++i) {
                        if (memcmp(rbx_buffer.data() + i, search_value.c_str(), search_value.size()) == 0) {
                            auto rbx_address = reinterpret_cast<LPVOID>(reinterpret_cast<std::uintptr_t>(rbx_mbi.BaseAddress) + i);
                            found_addresses.push_back(rbx_address);
                            if (found_addresses.size() >= threshold) return;
                        }
                    }
                }
            }
            rbx_start_address = reinterpret_cast<LPVOID>(reinterpret_cast<std::uintptr_t>(rbx_start_address) + rbx_mbi.RegionSize);
        }
        else {
            rbx_start_address = reinterpret_cast<LPVOID>(reinterpret_cast<std::uintptr_t>(rbx_start_address) + sizeof(MEMORY_BASIC_INFORMATION));
        }
    }
}

auto rbx_detect_and_edit(HANDLE rbx_process, const std::vector<LPVOID>& addresses, const std::string& new_value) -> void {
    for (const auto& address : addresses) {
        DWORD old_protect;
        if (VirtualProtectEx(rbx_process, address, new_value.size(), PAGE_EXECUTE_READWRITE, &old_protect)) {
            if (rbx_write_mem(rbx_process, address, new_value.c_str(), new_value.size())) {
                set_color_console();
                std::cout << "[*] Modified memory at address: " << address << std::endl;
            }
            else {
                std::cerr << "[e] Failed to write memory at address: " << address << std::endl;
            }
            if (!VirtualProtectEx(rbx_process, address, new_value.size(), old_protect, &old_protect)) {
                std::cerr << "[e] Failed to restore memory protection at address: " << address << std::endl;
            }
        }
        else {
            std::cerr << "[e] Failed to change memory protection for address: " << address << std::endl;
        }
    }
}

auto main() -> int {
    set_color_console();
    std::cout << "============ Pulsar Lite ============\n\n" << std::endl;
    set_color_console();
    std::cout << "*** Coded by ambulancity/adam ***\n\n\n" << std::endl;
    set_color_console();
    std::cout << "Usage: search for a value, edit it, and specify the max number of addresses to scan (default 50000).\n\n" << std::endl;
    srand(static_cast<unsigned int>(time(0)));

    HWND console_window = GetConsoleWindow();
    if (console_window != nullptr) {
        SetWindowPos(console_window, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
    }

    const TCHAR* rbx_process_name = _T("RobloxPlayerBeta.exe");
    auto rbx_pid = rbx_pid_get(rbx_process_name);

    if (rbx_pid == 0) {
        std::cerr << "[e] Process not found. Make sure Roblox is running." << std::endl;
        return 1;
    }

    auto rbx_proc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, rbx_pid);

    if (rbx_proc == nullptr) {
        std::cerr << "[e] Failed to open process." << std::endl;
        return 1;
    }

    std::vector<LPVOID> found_addresses;
    size_t threshold = MAX_ADDRESSES;

    std::cout << "Enter the value to search for: ";
    std::string search_value;
    std::getline(std::cin, search_value);

    std::cout << "Enter the threshold amount (number of matches required to stop scanning): ";
    std::string threshold_input;
    std::getline(std::cin, threshold_input);

    try {
        threshold = std::stoul(threshold_input);
    }
    catch (const std::invalid_argument&) {
        std::cerr << "[e] Invalid threshold amount, using default value " << MAX_ADDRESSES << std::endl;
        threshold = MAX_ADDRESSES;
    }

    std::cout << "Searching for addresses containing: " << search_value << std::endl;
    rbx_scan_mem(rbx_proc, search_value, threshold, found_addresses);

    if (found_addresses.empty()) {
        std::cerr << "[e] No addresses found." << std::endl;
        CloseHandle(rbx_proc);
        return 1;
    }

    std::cout << "[*] Found " << found_addresses.size() << " addresses." << std::endl;

    std::cout << "Enter the new value to write (must match the size of the search value): ";
    std::string new_value;
    std::getline(std::cin, new_value);

    if (new_value.size() != search_value.size()) {
        std::cerr << "[e] New value must be the same size as the search value." << std::endl;
        CloseHandle(rbx_proc);
        return 1;
    }

    rbx_detect_and_edit(rbx_proc, found_addresses, new_value);

    CloseHandle(rbx_proc);
    return 0;
}
