FROM ubuntu:20.04
EXPOSE 8080/tcp

WORKDIR /webapp
COPY . /webapp/

ENV docker true
ENV DATABASE_URL sqlite:///db/db.sqlite
ENV SECRET_KEY "secret"

RUN apt update -y && apt install -y python3 python3.8-venv && touch docker
RUN python3 -m venv venv
RUN /webapp/venv/bin/pip install -r requirements.txt
RUN /webapp/venv/bin/python3 manage.py docker
ENTRYPOINT [ "/webapp/venv/bin/waitress-serve", "--call", "app:create_app"]