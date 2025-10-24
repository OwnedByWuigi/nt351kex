!include "MUI2.nsh"
Name "Windows NT 3.51 Extended Kernel"
OutFile "nt351kex.exe"
!define MUI_ICON "setup.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Installing updates"
  SetOutPath "C:\ie5"
  File /r "..\bin\ie5\*"
  ExecWait 'cmd /c C:\temp\setup.exe'
  ExecWait 'cmd /c C:\temp\se128-16.exe'
SectionEnd

Section "Adding System32 DLLs"
  SetOutPath "$SYSDIR"
  File /r "..\bin\system32\*"
SectionEnd

Section "Adding modern fonts"
  SetOutPath "C:\winnt35\system"
  File /r "..\fonts\*"
SectionEnd

Section "Fonts backup"
  CreateDirectory "C:\winnt35\fonts"
  ExecWait 'cmd /c copy "C:\winnt35\system\*.fon" "C:\winnt35\fonts\"'
  ExecWait 'cmd /c copy "C:\winnt35\system\*.ttf" "C:\winnt35\fonts\"'
  ExecWait 'cmd /c start /min regedt32 /i "$SYSDIR\modfonts.reg"'
SectionEnd

Section "Optional: NewShell"
    MessageBox MB_YESNO|MB_ICONQUESTION "Do you want to fully install NewShell? (CAUTION! THIS IS STILL IN EARLY BETA!)" IDYES do_yes IDNO do_no

    do_yes:
        SetOutPath "C:\temp"
        File /r "..\bin\newshell\*"
        ExecWait 'cmd /c C:\temp\SHUPDATE.CMD'
        Goto done

    do_no:
        Goto done

    done:
SectionEnd
Section "Restarting Windows"
    MessageBox MB_YESNO|MB_ICONEXCLAMATION "Windows NT 3.51 Extended Kernel needs to reboot Windows in order to finish installing. Reboot now?" IDYES do_reboot IDNO no_reboot

    do_reboot:
        Reboot
        Goto done

    no_reboot:
        MessageBox MB_OK "Please restart Windows later to complete the installation."
        Goto done

    done:
SectionEnd