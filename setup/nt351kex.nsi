; Name of the installer file
OutFile "nt351kex.exe"

; Name of the installer section
Section "NT 3.51 KernelEx"

  ; Set the installation path
  SetOutPath "$SYSDIR"
  ; Add application files to the installer
  File /r "..\bin\*"

SectionEnd