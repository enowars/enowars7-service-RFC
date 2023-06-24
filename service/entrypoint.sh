#!/bin/bash

#/usr/bin/nginx -c /etc/nginx/nginx.conf
#/etc/init.d/nginx start

flask --app managedServiceProvider init-db
#flask --app managedServiceProvider run --host=0.0.0.0

chmod 777 /service/instance/msp.sqlite
source /service/cleanup.sh

#gunicorn -w 4 -b '127.0.0.1:6969' 'managedServiceProvider:create_app()'
#gunicorn -w 4 -b '0.0.0.0:5000' 'managedServiceProvider:create_app()'
gunicorn -c "gunicorn.conf.py" "managedServiceProvider:create_app()"
