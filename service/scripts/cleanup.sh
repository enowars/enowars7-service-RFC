#!/bin/bash

validity_period=900
while true; do
	sqlite3 /service/instance/msp.sqlite "PRAGMA foreign_keys=ON; \
		DELETE FROM user WHERE init_time+$validity_period<$(date +%s);"

	sleep 60
done &
