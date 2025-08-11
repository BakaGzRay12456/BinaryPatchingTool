# Binary Patching Tool

A command-line utility for applying binary patches to files.

~~In fact, for some binary modifications.~~

## Features

- Colorful terminal interface
- Support for both iOS and Android platforms
- Easy navigation through available versions and patches
- Flexible patch application (single or all patches)
- Safe operation (creates patched copy without modifying original)
- Input validation and error handling

## Usage
1. Put your patch files:
versionList.json
patchFile.json
into target platform folder
2. Install required dependencies
3. Just run.


## Tips:
1. "Apply all patches" will run all the patches that you list.
2. When you use the patcher,it will copy the bin file then modify it,the original file won't be modified.
   

## Configuration
The tool relies on two JSON files per platform:

### versionList.json
```json
[
    {
        "version": "11.4.5",
        "patchFile": "Patches.json",
        "patchList": [
            {
                "Description": "The description of the first patch"
            },
            {
                "Description": "The description of the second patch"
            }
        ]
    },
    {
        "version": "6.1.6",
        "patchFile": "Patches2.json",
        "patchList": [
            {
                "Description": "The description of the first patch"
            },
            {
                "Description": "The description of the second patch"
            }
        ]
    }
]
```
### Patches.json
####  Special args list:
1. _INPUT:Require user typing a string -> Replace a string in the bin file
2. ~~TODO -> TOO LAZY??!~~
####  Json example:
```json
[
    {
        "name": "It's not very useful, but it can be used to distribute patches, right",
        "patches": [
            {
                "offset": "IDA VA",
                "code": "Assembly, HEX, string or Special args"
            },
            {
                "offset": "0x12557FC",
                "code": "nop"
            },
            {
                "offset": "0x10010086",
                "code": "mov w0,1\nbl 0x12557FC\n0xret"
            },
            {
                "offset": "0x1255C00",
                "code": "1F2003D5"
            }
        ]
    },
    {
        "patches": [
            {
                "offset": "0x13A3944",
                "code": "_INPUT"
            }
        ]
    }
]
```
