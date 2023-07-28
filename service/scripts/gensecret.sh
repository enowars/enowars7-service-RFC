#! /bin/bash

if test -f "/service/instance/secret.txt"; then
	:
else
	echo "$RANDOM+$RANDOM+$RANDOM" | shasum -a 256 | awk '{print $1}' > "/service/instance/secret.txt"
	chmod 555 /service/instance/secret.txt
fi