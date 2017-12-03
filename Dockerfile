FROM python:3-onbuild

WORKDIR .
RUN apt-get update && apt-get install -y \ 
    sqlite3 \
    libsqlite3-dev
RUN pip install --trusted-host pypi.python.org -r requirements-test.txt
RUN pip install -e .
RUN echo "django-x509 Installed"
WORKDIR tests/
CMD ["python", "manage.py", "migrate"]
CMD ["python", "manage.py", "createsuperuser"]
CMD ["python", "manage.py", "runserver"]
EXPOSE 8000

ENV NAME djangox509

