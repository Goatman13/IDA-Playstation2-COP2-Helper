# IDA Playstation2 COP2 Helper
 Generate PlayStation 2 r5900 COP2 assembly.<br>
 Plugin is already obsolete, please use https://github.com/oct0xor/ida-emotionengine instead.
 
## Usage
 Copy COP2.py into IDA plugins directory.
 Plugin check that instruction is really code, and not data.
 So run it after initial autoanalyze finished,
 otherwise it can miss instructions that are not yet assembled.
 To run plugin push ALT+SHIFT+1, or select it from Edit --> Plugins menu.

## Requirements
 No idea. Tested only with IDA 7.5, and using python3. 
 
## Screenshots
Before:

![2](https://user-images.githubusercontent.com/101417270/177142010-4c120e86-3980-4812-b8c9-08a8c39c16d5.jpg)
![31](https://user-images.githubusercontent.com/101417270/177142052-7eea4f85-7211-4b07-a2ba-a3cc41291fe7.jpg)

After:

![21](https://user-images.githubusercontent.com/101417270/177142069-c81a8116-9bb3-4b01-93fc-aa5f8428287c.jpg)
![3](https://user-images.githubusercontent.com/101417270/177142080-902ceba9-1165-4a6f-8e36-dd69360f317a.jpg)
