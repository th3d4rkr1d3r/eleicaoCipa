Outfile "InstaladorEleicaoCIPA.exe"
InstallDir $PROGRAMFILES\EleicaoCIPA

Section
  SetOutPath $INSTDIR
  File /r "C:\caminho\do\projeto\*"
  ExecWait '"$INSTDIR\python-3.9.7.exe" /quiet InstallAllUsers=1'
  ExecWait 'cmd /c "cd $INSTDIR && pip install -r requirements.txt"'
  CreateShortCut "$DESKTOP\Eleicao CIPA.lnk" "$INSTDIR\start.bat"
SectionEnd