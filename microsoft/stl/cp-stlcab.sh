#!/bin/bash
FN="$1"
D=$(cabextract -l "$FN" | ruby -n -e 'l=$_.strip;next unless l.end_with?(".stl");puts l.split(" ")[2].split(".").reverse.join("-");')
B=$(basename "$FN")
if [ -e "$D/$B" ]; then
	HA=$(sha256sum "$FN" | cut -d' ' -f1)
	HB=$(sha256sum "$D/$B" | cut -d' ' -f1)
	if [ "$HA" != "$HB" ]; then
		echo "Conflicting files $FN and $D/$B"
		exit 1
	fi
	exit 0
fi
mkdir -p "$D"
cp "$FN" "$D/$B"
