# gd-rtti
Basic command line program to look at RTTI info from a running process.

## Usage
Here are all the commands:
```
open <pid>   - opens a process id (no exe name yet sorry)
ptr <addr>   - reads a pointer at an address
name <addr>  - outputs the name of the class at an addr
list <bytes> <addr>  - lists all the valid RTTI pointers up to addr + bytes,
                       sort of like listing the pointers of a struct
```

`<addr>` allows for special syntax for following pointer chains. for example:
`[[base + 0x123] + 10]`

## TODO:
- [] get info for cocos structs