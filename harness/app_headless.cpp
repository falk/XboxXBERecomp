// the host side without a window: settings at their defaults, the run folder as the exe folder
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <thread>

#include "app/app.h"

namespace app {

Settings& Get() {
    static Settings s;
    return s;
}
void Load() {}
void Save() {}
void ApplyDisplay() {}
Mode Desktop() { return {1280, 720}; }
Mode Output() { return Desktop(); }
float RenderScale(uint32_t) { return 1.0f; }
bool Widescreen() { return true; }

std::filesystem::path ExeDir() {
    static const std::filesystem::path dir = std::filesystem::current_path();
    return dir;
}
int Instance() {
    static const int n = [] {
        const char* e = std::getenv("INSTANCE");
        return e ? std::atoi(e) : 0;
    }();
    return n;
}
void* Window() { return nullptr; }

bool OpenSplash() { return false; }
void SplashFirstFrame() {}
void CloseSplash() {}
void OpenGameWindow(bool) {}
bool StartHandover() { return false; }
bool HandingOver() { return false; }
void FinishHandover() {}

std::recursive_mutex& UiLock() {
    static std::recursive_mutex m;
    return m;
}

// XBE_PACE=1: presents at 60 Hz, for menus whose idle timers count frames; else as fast as the game runs
void Pace() {
    static const bool pace = [] {
        const char* e = std::getenv("XBE_PACE");
        return e && *e == '1';
    }();
    if (!pace) return;
    using clock = std::chrono::steady_clock;
    static clock::time_point next = clock::now();
    next = std::max(next + std::chrono::microseconds(16667), clock::now() - std::chrono::milliseconds(50));
    std::this_thread::sleep_until(next);
}

}  // namespace app
