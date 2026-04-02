#pragma once
#include <string>

class GuardController {
public:
    GuardController(const std::string& pinnedPath);
    ~GuardController();

    bool blockIP(const std::string& ipStr);
    bool unblockIP(const std::string& ipStr);
    void load_from_csv(const std::string& filename);
    bool blockIP_and_save(const std::string& ip, const std::string& filename);

private:
    std::string map_path_;
    int mapFd; // Just a standard integer, no BPF headers needed here!
};