!include "MUI2.nsh"
Name "Windows NT 3.51 Extended Kernel"
OutFile "nt351kex.exe"
!define MUI_ICON "setup.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "license.txt"
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Installing updates"
  MessageBox MB_YESNO|MB_ICONQUESTION "Do you want to install IE5? (Optional but better for more app compatibility)" IDYES do_yes IDNO do_no

    do_yes:
      SetOutPath "C:\temp"
      File /r "..\bin\ie5\*"
      ExecWait 'cmd /c C:\temp\setup.exe'
      ExecWait 'cmd /c C:\temp\se128-16.exe'
      Goto done

    do_no:
        Goto done

    done:
SectionEnd

Section "Adding System32 DLLs"
  SetOutPath "$SYSDIR"
  File /r "..\bin\system32\*"
SectionEnd

Section "Adding Modern DLLs in another dir"
  SetOutPath "C:\winnt35\modern"
  File /r "..\bin\modern2\*"
SectionEnd

Section "Adding modern fonts"
  SetOutPath "C:\temp"
  File /r "..\fonts\*"
SectionEnd

Section "Adding Modern DLLs"
  SetOutPath "C:\temp"
  File /r "..\bin\modern\*"
  ExecWait 'cmd /c C:\temp\DLLUPD.CMD'
SectionEnd

Section "Fonts backup"
  CreateDirectory "C:\winnt35\fonts"
  ExecWait 'cmd /c copy "C:\winnt35\system\*.fon" "C:\winnt35\fonts\"'
  ExecWait 'cmd /c copy "C:\winnt35\system\*.ttf" "C:\winnt35\fonts\"'
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