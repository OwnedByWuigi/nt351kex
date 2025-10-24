!include "MUI2.nsh"
Name "Windows NT 3.51 Extended Kernel"
OutFile "nt351kex.exe"
!define MUI_ICON "setup.ico"


!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Adding System32 DLLs"
  SetOutPath "$SYSDIR"
  ; Add application files to the installer
  File /r "..\bin\*"
SectionEnd
Section "Adding modern fonts"
  SetOutPath "C:\winnt35\system"
  File /r "..\fonts\*"
SectionEnd
Section "Fonts backup"
  CreateDirectory "C:\winnt35\fonts"
  ; Copy files from old dir to new dir for app compatibility (already on disk)
  ExecWait 'cmd /c copy "C:\winnt35\system\*.fon" "C:\winnt35\fonts\"'
  ExecWait 'cmd /c copy "C:\winnt35\system\*.ttf" "C:\winnt35\fonts\"'
  ExecWait 'cmd /c start /min regedt32 /i "$SYSDIR\modfonts.reg"'
SectionEnd