FROM python:3-onbuild

WORKDIR .
RUN apt-get update && apt-get install -y \
    sqlite3 \
    libsqlite3-dev
RUN pip3 install -U pip setuptools wheel
RUN pip3 install -e .
RUN echo "django-x509 Installed"
WORKDIR tests/
CMD ["./docker-entrypoint.sh"]
EXPOSE 8000

ENV NAME djangox509
