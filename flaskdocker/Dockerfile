FROM python:3.9

RUN apt-get update \
    && apt-get -y --no-install-recommends install \
        git 

WORKDIR /usr/src/app

COPY ./WebUI_YandexDisk /usr/src/app

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT [ "python" ]

CMD [ "app.py" ] 