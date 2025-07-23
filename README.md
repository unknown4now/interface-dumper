# interface-dumper

**interface-dumper** is a fast, modern, multithreaded C++ tool for scanning and dumping Source Engine interfaces from running games. It outputs all registered interfaces (with names, modules, and addresses) to both the console and a text file, making it useful for reverse engineers, modders, and Source Engine developers.

---

## Features

- 🚀 **Multithreaded**: Uses a thread pool for fast and efficient scanning with minimal CPU usage.
- 🔍 **Automatic Game Detection**: Finds the first running Source Engine game from a configurable target list.
- 📄 **Clean Output**: Dumps all found interfaces to both the console and `dump.txt`.
- 🛠️ **Minimal & Modern C++**: No external dependencies—just use a modern compiler and Windows SDK.
- 📝 **Open Source (MIT License)**

---

## Supported Games

By default, the tool scans for these popular Source Engine games (edit the `Targets[]` list in the code to add more):

- Counter-Strike: Source (`cstrike_win64.exe`)
- Half-Life 2 (`hl2.exe`)
- Day of Defeat (`dod.exe`)
- Team Fortress 2 (`tf2.exe`)
- Left 4 Dead 2 (`left4dead2.exe`)

---

## Usage

1. **Build**
    - Open the project in Visual Studio (or use your favorite C++17+ compiler on Windows).
    - Make sure you link against `Psapi.lib` (for module enumeration).

2. **Run**
    - Start your Source Engine game.
    - Run `Interface Dumper.exe`.
    - The tool will automatically detect the game, scan all modules, and output results to both the console and `dump.txt` in the current directory.

3. **Read Results**
    - Open `dump.txt` to see all found interfaces, grouped by module.
    - Example output:
      ```
      [Module]    : client.dll          [Interface] : VClient018                    [Address]   : 0x1A2B3C4D
      [Module]    : engine.dll          [Interface] : VEngineServer021              [Address]   : 0x2B3C4D5E
      ```

---

## How it Works

- Scans all modules (DLLs) loaded in the target process.
- For each module, walks memory and looks for Source Engine-style interface registration structures.
- Validates interface names against the well-known pattern (e.g., `VClient018`).
- Outputs the module name, interface name, and memory address for each found interface.
- Uses a thread pool to speed up scanning, while keeping CPU usage low.

---

## Why?

Interface lists are invaluable for:
- Game modding and tool development
- Reverse engineering and cheat detection
- Source Engine research and debugging

---

## Example

```
[*] Scanning interfaces in hl2.exe

[Module]    : client.dll          [Interface] : VClient018                    [Address]   : 0x1324abcd
[Module]    : engine.dll          [Interface] : VEngineServer021               [Address]   : 0x1a2b3c4d

[+] Dump complete! Output saved to dump.txt
[*] Press Enter to exit...
```

---

## Building

- Windows only, C++17 or newer.
- Requires the Windows SDK (for `Windows.h`, `Psapi.h`).
- **Link with**: `Psapi.lib`
- No external dependencies.

---

## Customization

- To support more games, just add their executable names to the `Targets[]` array at the top of the code.
- You can tune the number of worker threads (default: 4) in the call to `parallel_interface_dump` in `main()`.

---

## License

MIT License.  
See [LICENSE](LICENSE) for details.

---

## Credits

Author: [unknown4now](https://github.com/unknown4now)  
Original idea, code, and modern C++ implementation.

---

**Happy hacking!**
