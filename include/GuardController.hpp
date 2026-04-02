#pragma once
#include <string>

class GuardController {
public:
    GuardController(const std::string& pinnedPath);
    ~GuardController();

    bool blockIP(const std::string& ipStr);
    bool unblockIP(const std::string& ipStr);

private:
    int mapFd; // Just a standard integer, no BPF headers needed here!
};