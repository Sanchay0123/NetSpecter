#include "core/CaptureEngine.hpp"
#include "analytics/StatsTracker.hpp"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>" << std::endl;
        return 1;
    }

    std::string interface = argv[1];
    StatsTracker tracker;
    CaptureEngine engine(interface, tracker);

    if (!engine.init()) {
        std::cerr << "Could not initialize engine on " << interface << std::endl;
        return 1;
    }

    std::cout << "--- NetSpecter Active on " << interface << " ---" << std::endl;
    std::cout << "Press [Enter] to stop capture..." << std::endl;

    engine.start();

    // Wait for the user to press Enter
    std::cin.get(); 

    std::cout << "Stopping engine..." << std::endl;
    engine.stop();

    // --- THE ADDITION ---
    // Now we display the fruit of our labor
    tracker.print_summary(); 

    return 0;
}