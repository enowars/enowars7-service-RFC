#!/bin/bash

#sudo systemctl start nginx
#/usr/bin/nginx -c /etc/nginx/nginx.conf
#
flask --app managedServiceProvider init-db
#flask --app managedServiceProvider run --host=0.0.0.0
gunicorn -w 4 -b '0.0.0.0:5000' 'managedServiceProvider:create_app()'

