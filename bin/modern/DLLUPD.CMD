@echo off

SETLOCAL
set action=install

if NOT "%1" == "" goto usage

rem
rem Set up our commands for non test mode

set shtools=shuttle inxtoreg mv rm imagecfg
set copycmd=copy
set rencmd=ren
set inxtoregcmd=inxtoreg
set delcmd=del
set rmdircmd=rmdir
set newdir=mkdir
set cdcmd=cd
set delboot=rm /x /d
set moveboot=mv /x /d
set rebootcmd=shuttle -x
set imagecfg40cmd=imagecfg -v 6.1 -b 7600
set imagecfg351cmd=imagecfg -v 3.51
set freespacecmd=shuttle -f
set freevschecksyscmd=shuttle -b
set freevscheckbincmd=shuttle -y
set adminprvcmd=shuttle -a
set ynccmd=shuttle -c
set rmassoccmd=shuttle -k
set restassoccmd=shuttle -z
set setshellcmd=shuttle -s
set setwelcomecmd=shuttle -w
set checkversioncmd=shuttle -l
set old_user=spbackup
rem
rem ************ Set up our lists of files.  These are the files that replace
rem ************ existing files so we should back them up first.
rem
set userexefiles=rundll32
set userdllfiles=comctl32 shdocvw crypt32 kernelbase

rem
rem ************  set these to the names of files that should be copied install
rem ************  directory to the %systemroot%\system32 directory
set system32exefiles=
set system32dllfiles=
set system32cplfiles=appwiz
set systemttffiles=marlett
set viewerexefiles=
set viewerdllfiles=
set miscfiles=

rem
rem ************  set these to the name of files that should be
rem ************  version stamp revised only
rem
set stampinuseexefiles=winlogon printman winfile
set stampinusedllfiles=mprui netui0 netui1 netui2 acledit
set stampexefiles=ntoskrnl ntkrnlmp
set stampdllfiles=

rem
rem ************  set this to the names of files that should be inxtoreg'd.
set inxfiles=shell


%delcmd% %SystemRoot%\system32\~* 2>nul

if exist %SystemRoot%\system32\~* goto renamerr
if exist %SystemRoot%\mstools\~* goto renamerr

%newdir% %SystemRoot%\system32\%old_user% 2>nul 1>nul
if NOT "%userexefiles%" == "" for %%i in (%userexefiles%) do (if exist %SystemRoot%\system32\%%i.exe %copycmd% %SystemRoot%\system32\%%i.exe %SystemRoot%\system32\%old_user%)
if NOT "%userdllfiles%" == "" for %%i in (%userdllfiles%) do (if exist %SystemRoot%\system32\%%i.dll %copycmd% %SystemRoot%\system32\%%i.dll %SystemRoot%\system32\%old_user%)
if NOT "%stampinuseexefiles%" == "" for %%i in (%stampinuseexefiles%) do (if exist %SystemRoot%\system32\%%i.exe %copycmd% %SystemRoot%\system32\%%i.exe %SystemRoot%\system32\%old_user%)
if NOT "%stampinusedllfiles%" == "" for %%i in (%stampinusedllfiles%) do (if exist %SystemRoot%\system32\%%i.dll %copycmd% %SystemRoot%\system32\%%i.dll %SystemRoot%\system32\%old_user%)

echo.
echo            **********************************************************
echo              A backup of the original files has been made in
echo              %SystemRoot%\system32\%old_user% for uninstall purposes.
echo            **********************************************************
echo.

:backup_done
rem
rem ************ Copy files into the appropriate system locations
rem
echo.
echo Copying files...

for %%i in (%userexefiles%) do (%copycmd% .\%%i.exe %SystemRoot%\system32\~%%i.exe && %moveboot% %SystemRoot%\system32\~%%i.exe %SystemRoot%\system32\%%i.exe)
for %%i in (%userdllfiles%) do (%copycmd% .\%%i.dll %SystemRoot%\system32\~%%i.dll && %moveboot% %SystemRoot%\system32\~%%i.dll %SystemRoot%\system32\%%i.dll)
for %%i in (%stampinuseexefiles%) do (%copycmd% %SystemRoot%\system32\%%i.exe %SystemRoot%\system32\~%%i.exe && %moveboot% %SystemRoot%\system32\~%%i.exe %SystemRoot%\system32\%%i.exe)
for %%i in (%stampinusedllfiles%) do (%copycmd% %SystemRoot%\system32\%%i.dll %SystemRoot%\system32\~%%i.dll && %moveboot% %SystemRoot%\system32\~%%i.dll %SystemRoot%\system32\%%i.dll)

for %%i in (%system32exefiles%) do (%copycmd% .\%%i.exe %SystemRoot%\system32\~%%i.exe && %moveboot% %SystemRoot%\system32\~%%i.exe %SystemRoot%\system32\%%i.exe)
for %%i in (%system32dllfiles%) do (%copycmd% .\%%i.dll %SystemRoot%\system32\~%%i.dll && %moveboot% %SystemRoot%\system32\~%%i.dll %SystemRoot%\system32\%%i.dll)
for %%i in (%system32cplfiles%) do (%copycmd% .\%%i.cpl %SystemRoot%\system32\~%%i.cpl && %moveboot% %SystemRoot%\system32\~%%i.cpl %SystemRoot%\system32\%%i.cpl)
for %%i in (%systemttffiles%)   do (%copycmd% .\%%i.ttf %SystemRoot%\system\~%%i.ttf   && %moveboot% %SystemRoot%\system\~%%i.ttf   %SystemRoot%\system\%%i.ttf)

for %%i in (%miscfiles%) do (%copycmd% %%i %SystemRoot%\system32\~%%i && %moveboot% %SystemRoot%\system32\~%%i %SystemRoot%\system32\%%i)

%newdir% %SystemRoot%\system32\viewers 2>nul 1>nul

for %%i in (%viewerexefiles%) do (%copycmd% %%i.exe %SystemRoot%\system32\viewers\~%%i.exe && %moveboot% %SystemRoot%\system32\viewers\~%%i.exe %SystemRoot%\system32\viewers\%%i.exe)
for %%i in (%viewerdllfiles%) do (%copycmd% %%i.exe %SystemRoot%\system32\viewers\~%%i.dll && %moveboot% %SystemRoot%\system32\viewers\~%%i.dll %SystemRoot%\system32\viewers\%%i.dll)
rem
rem ************* Version stamp exes
rem

for %%i in (%stampinuseexefiles%) do %imagecfg40cmd% %SystemRoot%\system32\~%%i.exe >nul
for %%i in (%stampinusedllfiles%) do %imagecfg40cmd% %SystemRoot%\system32\~%%i.dll >nul
for %%i in (%stampexefiles%) do (if exist %SystemRoot%\system32\%%i.exe %imagecfg40cmd% %SystemRoot%\system32\%%i.exe >nul)
for %%i in (%stampdllfiles%) do %imagecfg40cmd% %SystemRoot%\system32\%%i.dll >nul

rem
rem ************ Tell the user to reboot
rem

echo.
echo After rebooting you may uninstall by running '%0 /u'.
echo.

:needreboot
echo reboot needed
goto end

:usage
echo.
echo %0 [/u] : Install or uninstall the Shell Preview files
echo.
echo    - /u : Perform an uninstall instead of an install
echo.
goto end

rem
rem ************ Perform an uninstall
rem

:uninstall

echo.
rem
rem Check to make sure the old file exist
if not exist %SystemRoot%\system32\%old_user% goto cantundo
for %%i in (%userexefiles%) do (if not exist %SystemRoot%\system32\%old_user%\%%i.exe goto cantundo)
for %%i in (%userdllfiles%) do (if not exist %SystemRoot%\system32\%old_user%\%%i.dll goto cantundo)
for %%i in (%stampinuseexefiles%) do (if not exist %SystemRoot%\system32\%old_user%\%%i.exe goto cantundo)
for %%i in (%stampinusedllfiles%) do (if not exist %SystemRoot%\system32\%old_user%\%%i.dll goto cantundo)
%ynccmd% "yn" "Press 'y' to %action% the Shell Preview for Windows NT 3.51"
if errorlevel 1 goto end
echo.

rem
rem ************* Unversion stamp exes
rem

for %%i in (%stampexefiles%) do (if exist %SystemRoot%\system32\%%i.exe %imagecfg351cmd% %SystemRoot%\system32\%%i.exe >nul)
for %%i in (%stampdllfiles%) do %imagecfg351cmd% %SystemRoot%\system32\%%i.dll >nul

rem Restore progman as the default shell.
%setshellcmd% progman.exe

rem Restore the original NT 3.51 files
for %%i in (%userexefiles%) do (%moveboot% %SystemRoot%\system32\%old_user%\%%i.exe %SystemRoot%\system32\%%i.exe)
for %%i in (%userdllfiles%) do (%moveboot% %SystemRoot%\system32\%old_user%\%%i.dll %SystemRoot%\system32\%%i.dll)
for %%i in (%stampinuseexefiles%) do (%moveboot% %SystemRoot%\system32\%old_user%\%%i.exe %SystemRoot%\system32\%%i.exe)
for %%i in (%stampinusedllfiles%) do (%moveboot% %SystemRoot%\system32\%old_user%\%%i.dll %SystemRoot%\system32\%%i.dll)
%delcmd% /q /s %SystemRoot%\system32\viewers\*.*
%rmdircmd% /q /s %SystemRoot%\system32\viewers

rem
rem ************* Remove newly added associations
rem
echo.
echo Restoring original NT 3.51 registry settings.  Depending on the speed of
echo your machine, this could take one or two minutes...
echo.
%rmassoccmd% "*"
%rmassoccmd% .386
%rmassoccmd% .ani
%rmassoccmd% .bat
%rmassoccmd% .bfc
%rmassoccmd% .bmp
%rmassoccmd% .cmd
%rmassoccmd% .com
%rmassoccmd% .cpl
%rmassoccmd% .cur
%rmassoccmd% .dll
%rmassoccmd% .drv
%rmassoccmd% .exe
%rmassoccmd% .fnd
%rmassoccmd% .fon
%rmassoccmd% .grp
%rmassoccmd% .hlp
%rmassoccmd% .ico
%rmassoccmd% .inf
%rmassoccmd% .ini
%rmassoccmd% .lnk
%rmassoccmd% .pif
%rmassoccmd% .reg
%rmassoccmd% .rtf
%rmassoccmd% .scr
%rmassoccmd% .shb
%rmassoccmd% .shs
%rmassoccmd% .sys
%rmassoccmd% .ttf
%rmassoccmd% .txt
%rmassoccmd% .vxd
%rmassoccmd% .wav
%rmassoccmd% anifile
%rmassoccmd% AudioCD
%rmassoccmd% batfile
%rmassoccmd% Briefcase
%rmassoccmd% cmdfile
%rmassoccmd% comfile
%rmassoccmd% cplfile
%rmassoccmd% curfile
%rmassoccmd% Directory
%rmassoccmd% dllfile
%rmassoccmd% DocShortcut
%rmassoccmd% Drive
%rmassoccmd% drvfile
%rmassoccmd% exefile
%rmassoccmd% fndfile
%rmassoccmd% Folder
%rmassoccmd% fonfile
%rmassoccmd% hlpfile
%rmassoccmd% icofile
%rmassoccmd% inffile
%rmassoccmd% inifile
%rmassoccmd% lnkfile
%rmassoccmd% MSProgramGroup
%rmassoccmd% Network
%rmassoccmd% piffile
%rmassoccmd% QuickView
%rmassoccmd% regfile
%rmassoccmd% ShellScrap
%rmassoccmd% scrfile
%rmassoccmd% sysfile
%rmassoccmd% ttffile
%rmassoccmd% txtfile
%rmassoccmd% vxdfile

rem Add back default associations
%restassoccmd%

echo.
goto needreboot
:end
ENDLOCAL
echo.
