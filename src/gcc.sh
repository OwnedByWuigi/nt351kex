#/bin/bash
i686-w64-mingw32-gcc -O2 -Wall -D_WIN32_WINNT=0x0351 -c kernel32.c -o kernel32.o
i686-w64-mingw32-gcc -shared -o kernel33.dll kernel32.o kernel32.def -nostartfiles -nodefaultlibs --disable-stdcall-fixup --enable-stdcall-fixup