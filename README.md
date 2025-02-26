# Token-Impersonation
 
## Build
```
windres app.rc -O coff -o app.o
gcc .\src\token_impersonation.c .\app.o -o .\output\token_impersonation_x64.exe -m64 -s
```

## Usage
```
token_impersonation_x64.exe <username> <command_line>
```

## Example
```
token_impersonation_x64.exe SYSTEM cmd.exe
```

## Notes
- Local Administrator is required
