all: decrypt_win32.exe decrypt_win64.exe

.PHONY: clean
clean: 
	rm decrypt_win32.exe decrypt_win64.exe 2>/dev/null || /bin/true

decrypt_win32.exe: main.c Makefile
	i686-w64-mingw32-gcc main.c -O2 -o decrypt_win32.exe -lcrypt32
	i686-w64-mingw32-strip decrypt_win32.exe

decrypt_win64.exe: main.c Makefile
	x86_64-w64-mingw32-gcc main.c -Os -o decrypt_win64.exe -lcrypt32
	x86_64-w64-mingw32-strip decrypt_win64.exe

