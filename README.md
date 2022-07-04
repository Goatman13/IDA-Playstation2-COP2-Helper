# IDA Playstation2 COP2 Helper
 Generate PlayStation 2 r5900 COP2 assembly.
 
## Usage
 Copy COP2.py into IDA plugins directory.
 Plugin check that instruction is really code, and not data.
 So run it after initial autoanalyze finished,
 otherwise it can miss instructions that are not yet assembled.
 To run plugin push ALT+SHIFT+1, or select it from Edit --> Plugins menu.

## Requirements
 No idea. Tested only with IDA 7.5, and using python3.  