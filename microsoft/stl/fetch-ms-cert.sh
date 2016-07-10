#!/bin/bash
SHA1="$1"
curl -O "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/${SHA1}.crt"
