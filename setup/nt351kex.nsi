!include "MUI2.nsh"
Name "Windows NT 3.51 Extended Kernel"
OutFile "nt351kex.exe"
!define MUI_ICON "setup.ico"


!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; Name of the installer section
Section "Adding DLLs"

  ; Set the installation path
  SetOutPath "$SYSDIR"
  ; Add application files to the installer
  File /r "..\bin\*"

SectionEnd