#!/bin/bash
curl -O http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab
cabextract authrootstl.cab
curl -O http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab
cabextract disallowedcertstl.cab
curl -O http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcert.sst
