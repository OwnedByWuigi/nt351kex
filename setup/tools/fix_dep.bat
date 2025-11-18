set PATH=%PATH%;.\driver\Dist\tools
set PATH
srchrep.exe -R -src "c:\progra~1\ddk2000" -dest "$(BASEDIR2K)" *.dep
srchrep.exe -R -src "..\..\..\..\..\..\progra~1\ddk2000" -dest "$(BASEDIR2K)" *.dep
srchrep.exe -R -src "c:\progra~1\ddk" -dest "$(BASEDIR)" *.dep
srchrep.exe -R -src "..\..\..\..\..\..\progra~1\ddk" -dest "$(BASEDIR)" *.dep
srchrep.exe -R -src "e:\program files\devstudio" -dest "$(MSDEVROOT)" *.dep
srchrep.exe -R -src "..\..\..\..\..\..\..\progra~1\micros~1" -dest "$(MSDEVROOT)" *.dep
srchrep.exe -R -src "..\..\..\..\microsoft visual studio" -dest "$(MSDEVROOT)" *.dep
echo OK
