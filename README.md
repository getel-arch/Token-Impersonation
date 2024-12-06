# Token-Impersonation
 
## Build
```
windres app.rc -O coff -o app.res
gcc .\src\token_impersonation.c .\app.res -o token_impersonation.exe -m64 -s
```