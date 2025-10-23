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