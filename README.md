## RawInput2

An external software that ports [momentum mod's](https://momentum-mod.org/) ``m_rawinput 2`` behaviour. This option provides mouse interpolation which will ["line up with the tickrate properly without needing to have a specific framerate"](https://discord.com/channels/235111289435717633/356398721790902274/997026787995435088) (rio). The code for this isn't public and was reverse engineered from the game.

### Usage
* Launch the game in ``-insecure`` mode. (It wont work otherwise!)
* Run the application.
* Make sure to set ``m_rawinput 2`` in game for it to take effect.

### Building
* [Microsoft Detours](https://github.com/microsoft/Detours)
* It is required to put modules (detours.cpp, detours.h, disasm.cpp, modules.cpp) to the "RawInput2/Detours" directory.