#!/bin/bash

flask --app managedServiceProvider init-db
flask --app managedServiceProvider run --host=0.0.0.0
