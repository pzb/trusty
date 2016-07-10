#!/bin/bash
ls crts | while read FN; do
	HA=$(basename "$FN" .crt)
	HB=$(openssl x509 -inform DER -outform DER -in "crts/$FN" | openssl dgst -sha1 | cut -d' ' -f2)
	if [ "$HA" != "$HB" ]; then
		echo "$HA contains $HB"
	fi
done
