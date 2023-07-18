#!/bin/bash

/usr/bin/nginx -c /etc/nginx/nginx.conf
/etc/init.d/nginx start

flask --app managedServiceProvider init-db

chmod 777 /service/instance/msp.sqlite
source /service/scripts/cleanup.sh

echo "$RANDOM+$RANDOM+$RANDOM" | shasum -a 256 | export FLASK_KEY=$(awk '{print $1}')
gunicorn -c "config/gunicorn.conf.py" "managedServiceProvider:create_app()"
