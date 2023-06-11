#!/bin/bash

#/usr/bin/nginx -c /etc/nginx/nginx.conf
#/etc/init.d/nginx start

flask --app managedServiceProvider init-db
#flask --app managedServiceProvider run --host=0.0.0.0

#gunicorn -w 4 -b '127.0.0.1:6969' 'managedServiceProvider:create_app()'
gunicorn -w 4 -b '0.0.0.0:5000' 'managedServiceProvider:create_app()'

chmod 777 /service/instance/msp.sqlite
source /service/cleanup.sh

#validity_period=60
#while true; do
#	sqlite3 "./instance/msp.sqlite" "DELETE FROM user WHERE $(current_epoch)-init_time > $(validity_period)"
#	sqlite3 /service/instance/msp.sqlite "PRAGMA foreign_keys = ON; \
#		DELETE FROM user WHERE init_time+60<$(date +%s);"
#	/service/cleanup.sh
#	sleep 30
#done &
