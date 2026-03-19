# DeepTrace-DPI

DeepTrace-DPI is a modular C++17 deep packet inspection project built with CMake.

Version 1 includes:

- Offline PCAP reading
- Ethernet, IPv4, TCP, and UDP parsing
- Readable packet summaries
- Safe bounds-checked parsing for malformed packets

Build:

```powershell
cmake -S . -B build
cmake --build build --config Release
```

Run:

```powershell
.\build\Release\deeptrace_dpi.exe .\data\sample.pcap 10
```
