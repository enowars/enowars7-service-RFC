#!/bin/bash

validity_period=1800
while true; do
	sqlite3 /service/instance/msp.sqlite "PRAGMA foreign_keys = ON; \
		DELETE FROM user WHERE init_time+$validity_period<$(date +%s);"
	sleep 30
done &
