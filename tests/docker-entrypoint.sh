#!/bin/bash

echo "running migrations"
python3 manage.py migrate
echo "creating superuser (admin/admin)"
python3 manage.py createsuperuser
echo "starting development server"
python3 manage.py runserver 0.0.0.0:8000
