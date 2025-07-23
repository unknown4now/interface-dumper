/*
    ╔═════════════════════════════════════════════════════════════════╗
    ║   Engine Interface Scanner - Source Engine Interface Dumper     ║
    ║                                                                 ║
    ║               Author: (github.com/unknown4now)                  ║
    ║                          escription:                            ║
    ║                                                                 ║
    ║     - Scans running Source Engine games for registered.         ║
    ║        interfaces across all loaded modules (DLLs).             ║
    ║                                                                 ║
    ║     - Uses a thread pool for efficient, low-CPU scanning.       ║
    ║                                                                 ║
    ║     - Outputs results to both console and dump.txt.             ║
    ║                                                                 ║
    ║                        License: MIT                             ║
    ╚═════════════════════════════════════════════════════════════════╝
*/

#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_set>
#include <string>
#include <iomanip>
#include <cstdint>
#include <regex>
#include <thread>
#include <mutex>
#include <sstream>
#include <algorithm>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <functional>

// Structure for Source Engine interface registration linked list
struct InterfaceEntry {
    void* creation_function;
    const char* name_ptr;
    InterfaceEntry* next_entry;
};

// List of target executables
const char* Targets[] = {
    "cstrike_win64.exe", // Counter-Strike Source
    "hl2.exe",           // HL2, Source mods
    "dod.exe",           // Day of Defeat
    "tf2.exe",           // Team Fortress 2
    "left4dead2.exe",    // L4D2
    // Add more game executables here if needed
};

// Utility: Lowercase a string in-place
void to_lowercase(std::string& s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
}

// Find the first known running Source Engine game process
std::string find_first_running_game() {
    DWORD process_ids[1024], bytes_needed;
    if (!EnumProcesses(process_ids, sizeof(process_ids), &bytes_needed))
        return "";

    unsigned count = bytes_needed / sizeof(DWORD);
    for (unsigned i = 0; i < count; ++i) {
        DWORD pid = process_ids[i];
        if (pid == 0) continue;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProc) continue;

        HMODULE hModule;
        DWORD mod_bytes_needed;
        if (EnumProcessModules(hProc, &hModule, sizeof(hModule), &mod_bytes_needed)) {
            char exe_name[MAX_PATH];
            if (GetModuleBaseNameA(hProc, hModule, exe_name, MAX_PATH)) {
                std::string pname = exe_name;
                to_lowercase(pname);
                for (auto* known : Targets) {
                    std::string kn = known;
                    to_lowercase(kn);
                    if (pname == kn) {
                        CloseHandle(hProc);
                        return pname;
                    }
                }
            }
        }
        CloseHandle(hProc);
    }
    return "";
}

// Get the process ID by process name (case-insensitive)
DWORD get_process_id(const std::string& process_name) {
    DWORD process_ids[1024], bytes_needed;
    if (!EnumProcesses(process_ids, sizeof(process_ids), &bytes_needed))
        return 0;
    unsigned count = bytes_needed / sizeof(DWORD);
    for (unsigned i = 0; i < count; ++i) {
        DWORD pid = process_ids[i];
        if (pid == 0) continue;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProc) continue;

        HMODULE hModule;
        DWORD mod_bytes_needed;
        if (EnumProcessModules(hProc, &hModule, sizeof(hModule), &mod_bytes_needed)) {
            char exe_name[MAX_PATH];
            if (GetModuleBaseNameA(hProc, hModule, exe_name, MAX_PATH)) {
                std::string n = exe_name;
                to_lowercase(n);
                if (n == process_name) {
                    CloseHandle(hProc);
                    return pid;
                }
            }
        }
        CloseHandle(hProc);
    }
    return 0;
}

// Validate interface name: must match Source Engine versioned interface pattern
bool is_valid_interface(const char* name) {
    if (!name || strlen(name) < 5) return false;
    static std::regex interface_regex("^V[A-Za-z0-9_]+\\d{3}$");
    return std::regex_match(name, interface_regex);
}

// Dumps all valid interfaces in a module
void scan_module_for_interfaces(HANDLE hProc, const char* module_name, uintptr_t module_base, size_t module_size, std::stringstream& output) {
    std::unordered_set<std::string> found_interfaces;
    std::unordered_set<uintptr_t> visited_addresses;

    for (uintptr_t addr = module_base; addr < module_base + module_size - sizeof(InterfaceEntry); addr += 8) {
        InterfaceEntry entry{};
        if (!ReadProcessMemory(hProc, (void*)addr, &entry, sizeof(entry), nullptr))
            continue;
        // Pointer sanity: Name pointer must be inside module
        if ((uintptr_t)entry.name_ptr < module_base || (uintptr_t)entry.name_ptr > module_base + module_size)
            continue;
        char name_buffer[128]{};
        if (!ReadProcessMemory(hProc, entry.name_ptr, name_buffer, sizeof(name_buffer) - 1, nullptr))
            continue;
        if (!is_valid_interface(name_buffer))
            continue;
        if (visited_addresses.count(addr)) continue;
        visited_addresses.insert(addr);

        // Follow the linked list of InterfaceEntry nodes
        InterfaceEntry current = entry;
        uintptr_t current_addr = addr;
        while (true) {
            char iface_name_buf[128]{};
            if (!current.name_ptr ||
                !ReadProcessMemory(hProc, current.name_ptr, iface_name_buf, sizeof(iface_name_buf) - 1, nullptr))
                break;

            std::string interface_name(iface_name_buf);

            if (!interface_name.empty() &&
                found_interfaces.find(interface_name) == found_interfaces.end() &&
                is_valid_interface(interface_name.c_str())) {
                output << "[Module]    : " << std::left << std::setw(20) << module_name
                    << "[Interface] : " << std::left << std::setw(32) << interface_name
                    << "[Address]   : 0x" << std::hex << (uintptr_t)current_addr
                    << std::dec << std::endl;

                found_interfaces.insert(interface_name);
            }

            if (!current.next_entry ||
                !ReadProcessMemory(hProc, current.next_entry, &current, sizeof(current), nullptr))
                break;
            current_addr = (uintptr_t)current.next_entry;
        }
    }
}

// --- Thread pool implementation --- //
class WorkQueue {
public:
    using Job = std::function<void()>;

    WorkQueue(size_t num_workers) : stop_flag(false) {
        for (size_t i = 0; i < num_workers; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    Job job;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->cv.wait(lock, [this] { return stop_flag || !jobs.empty(); });
                        if (stop_flag && jobs.empty()) return;
                        job = std::move(jobs.front());
                        jobs.pop();
                    }
                    job();
                }
                });
        }
    }

    void enqueue(Job job) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            jobs.push(std::move(job));
        }
        cv.notify_one();
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            stop_flag = true;
        }
        cv.notify_all();
        for (std::thread& t : workers) {
            if (t.joinable()) t.join();
        }
    }

    ~WorkQueue() {
        stop();
    }

private:
    std::vector<std::thread> workers;
    std::queue<Job> jobs;
    std::mutex queue_mutex;
    std::condition_variable cv;
    bool stop_flag;
};

// Dumps all interfaces for all modules using a thread pool and sorts modules alphabetically
void parallel_interface_dump(std::ofstream& logfile, const std::string& proc_name, size_t thread_count = 4) {
    DWORD pid = get_process_id(proc_name);
    if (!pid) {
        logfile << "[!] No matching process found." << std::endl;
        return;
    }
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        logfile << "[!] Unable to open process." << std::endl;
        return;
    }
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        logfile << "[!] Module enumeration failed." << std::endl;
        CloseHandle(hProc);
        return;
    }

    unsigned module_count = cbNeeded / sizeof(HMODULE);

    // Collect modules for sorting
    struct ModuleInfo {
        std::string name;
        MODULEINFO modinfo;
        HMODULE hmod;
        unsigned original_idx;
    };
    std::vector<ModuleInfo> modules;

    for (unsigned i = 0; i < module_count; ++i) {
        char module_name[MAX_PATH];
        MODULEINFO modinfo;
        if (GetModuleBaseNameA(hProc, hMods[i], module_name, MAX_PATH) &&
            GetModuleInformation(hProc, hMods[i], &modinfo, sizeof(modinfo))) {
            modules.push_back(ModuleInfo{ module_name, modinfo, hMods[i], i });
        }
    }

    // Sort modules alphabetically by name (A-Z)
    std::sort(modules.begin(), modules.end(), [](const ModuleInfo& a, const ModuleInfo& b) {
        return _stricmp(a.name.c_str(), b.name.c_str()) < 0;
        });

    std::vector<std::stringstream> module_outputs(modules.size());
    WorkQueue pool(thread_count); // Thread pool

    std::atomic<unsigned> jobs_remaining((unsigned)modules.size());

    for (size_t i = 0; i < modules.size(); ++i) {
        const auto& m = modules[i];
        pool.enqueue([&, i, m]() {
            scan_module_for_interfaces(
                hProc,
                m.name.c_str(),
                reinterpret_cast<uintptr_t>(m.modinfo.lpBaseOfDll),
                m.modinfo.SizeOfImage,
                module_outputs[i]
            );
            --jobs_remaining;
            });
    }

    // Wait for all jobs to finish
    while (jobs_remaining > 0) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    pool.stop();

    // Output results in sorted order
    for (auto& out : module_outputs) {
        std::string s = out.str();
        if (!s.empty()) {
            std::cout << s;
            logfile << s;
        }
    }
    CloseHandle(hProc);
}

// --- Main Entry --- //
int main() {
    SetConsoleTitleA("Engine Interface Scanner (by unknown4now)");
    std::ofstream logfile("dump.txt");
    if (!logfile.is_open()) {
        std::cerr << "Couldn't open log file for writing!" << std::endl;
        return 1;
    }

    std::string proc_name = find_first_running_game();
    if (proc_name.empty()) {
        logfile << "No running Source Engine game found.\n";
        std::cout << "No running Source Engine game found.\n";
        return 0;
    }

    logfile << "[*] Scanning interfaces in " << proc_name << std::endl;
    std::cout << "[*] Scanning interfaces in " << proc_name << std::endl;

    // Use 4 threads by default (tweak for your system!)
    parallel_interface_dump(logfile, proc_name, 4);

    logfile << "\n[+] Dump complete! Output saved to dump.txt" << std::endl;
    std::cout << "\n[+] Dump complete! Output saved to dump.txt" << std::endl;
    logfile << "[*] Press Enter to exit..." << std::endl;
    std::cout << "[*] Press Enter to exit..." << std::endl;
    std::cin.get();
    logfile.close();
    return 0;
}
