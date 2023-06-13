#!/bin/bash

while true; do
	sqlite3 /service/instance/msp.sqlite "PRAGMA foreign_keys = ON; \
		DELETE FROM user WHERE init_time+60<$(date +%s);"
	sleep 30
done &
