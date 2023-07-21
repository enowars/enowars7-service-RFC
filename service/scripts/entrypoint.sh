#!/bin/bash

/usr/bin/nginx -c /etc/nginx/nginx.conf
/etc/init.d/nginx start


flask --app managedServiceProvider init-db
chmod 777 /service/instance/msp.sqlite


source /service/scripts/gensecret.sh
source /service/scripts/cleanup.sh


gunicorn -c "config/gunicorn.conf.py" "managedServiceProvider:create_app()"
