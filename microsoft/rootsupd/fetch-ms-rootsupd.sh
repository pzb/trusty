#!/bin/bash
#curl -O http://download.microsoft.com/download/A/3/4/A34FC82E-6E96-49FE-B925-9A087168D1F4/rootsupd.exe
rm -f ADVPACK.DLL
curl -O http://download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/rootsupd.exe
cabextract rootsupd.exe
