#!/bin/bash

/usr/bin/nginx -c /etc/nginx/nginx.conf
/etc/init.d/nginx start

flask --app managedServiceProvider init-db

chmod 777 /service/instance/msp.sqlite
source /service/scripts/cleanup.sh

if test -f "../instance/secret.txt"; then
	:
else
	echo "$RANDOM+$RANDOM+$RANDOM" | shasum -a 256 | awk '{print $1}' > "../instance/secret.txt"
	chmod 555 ../instance/secret.txt
fi

gunicorn -c "config/gunicorn.conf.py" "managedServiceProvider:create_app()"
