# waldemar.tk beta
Waldemar.tk beta website

#### All commads should be run from document root.

## Install and build Manually

Create a .env file containing:
- `DATABASE_URL`: The URI to the database (default: sqlite:///db/db.sqlite)
- `SECRET_KEY`: App secret key.
- `GITHUB_CLIENT_ID`: Github client id
- `GITHUB_CLIENT_SECRET`: Github client secret
- `MAIL_SERVER`: SMTP mail server
- `MAIL_PORT`: Mail port
- `MAIL_USERNAME`: Mail username
- `MAIL_DEFAULT_SENDER`: Mail adress from which mails should be sent
- `MAIL_PASSWORD`: Password for mailing account
- `MAIL_USE_TLS`: True if using starttls, else False
- `MAIL_USE_SSL`: True if using ssl, else False

Then run:
```
pip3 install -r requirements.txt
python3 manage.py prepare
```
To install dependencies and build the database

### Run a development server

```
flask run
```

### Run a production server

```
waitress-serve --call "app:create_app"
```
## Install via docker (standalone) Older build

```Docker
docker pull unfwalle/waldemar.tk:beta
docker volume create Database
docker volume create UserData
docker run \
    -dp 8080:8080 \
    --name Waldemar.tk \
    -e GITHUB_CLIENT_ID=yourgithubclientid \
    -e GITHUB_CLIENT_SECRET=yourgithubclientsecret \
    -v Database:/webapp/app/db \
    -v UserData:/webapp/app/static/user-uploads \
    unfwalle/waldemar.tk:beta
```

