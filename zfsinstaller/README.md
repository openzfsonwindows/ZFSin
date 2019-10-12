# Prerequisites:
- Inno Setup Compile 5.6.1 (or higher) installed
- Successful build of the the ZFSin project
  - Only architecture x64 and type release or debug are currently supported by the Inno installer. Other architectures might work with some tweaking of the .iss files.

# Building with GUI:

1. Open Inno Setup Compiler.

2. Tools &rightarrow; Configure Sign Tools
  - Need to add two signtools, signtoola and signtoolb
  - Examples of what to add for command of sign tool
    - signtoola
      - `C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64\signtool.exe sign /a /t http://timestamp.digicert.com /fd sha1 /d $qOpenZFS on Windows$q $f`
      - `C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64\signtool.exe sign /sha1 ab8e4f6b94cecfa4638847122b511e507e147c50 /n $qJoergen Lundman$q /t http://timestamp.digicert.com /fd sha1 /d $qOpenZFS on Windows$q $f`
    - signtoolb
      - `C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64\signtool.exe sign /a /as /tr http://timestamp.digicert.com /td sha256 /fd sha256 /d $qOpenZFS on Windows$q $f`
      - `C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64\signtool.exe sign /sha1 ab8e4f6b94cecfa4638847122b511e507e147c50 /as /n $qJoergen Lundman$q /tr http://timestamp.digicert.com /td sha256 /fd sha256 /d $qOpenZFS on Windows$q $f`


3. Open the openzfsonwindows-debug.iss or openzfsonwindows-release.iss.

4. Build &rightarrow; Compile to produce .exe Installer.



# Building with CLI:

1. (Optional) Add Inno setup to the system path.
  - Inno version 5- `set PATH="C:\Program Files (x86)\Inno Setup 5";%PATH%`
  - Inno version 6- `set PATH="C:\Program Files (x86)\Inno Setup 6";%PATH%`

2. Open a CMD windows, and `cd` to the ZFSinstaller directory

3. Run-
  - Release `iscc ZFSInstall-release.iss "/Ssigntoola=C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64\signtool.exe sign /a /t http://timestamp.digicert.com /fd sha1 /d $qOpenZFS on Windows$q $f" "/Ssigntoolb=C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64\signtool.exe sign /a /as /tr http://timestamp.digicert.com /td sha256 /fd sha256 /d $qOpenZFS on Windows$q $f"`
  - Debug `iscc ZFSInstall-debug.iss "/Ssigntoola=C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64\signtool.exe sign /a /t http://timestamp.digicert.com /fd sha1 /d $qOpenZFS on Windows$q $f" "/Ssigntoolb=C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64\signtool.exe sign /a /as /tr http://timestamp.digicert.com /td sha256 /fd sha256 /d $qOpenZFS on Windows$q $f"`
