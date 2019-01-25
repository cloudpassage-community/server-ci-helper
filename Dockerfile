FROM halotools/python-sdk:ubuntu-16.04_sdk-1.2.3_py-2.7

WORKDIR /app/

COPY application.py /app/

CMD /usr/bin/python /app/application.py
