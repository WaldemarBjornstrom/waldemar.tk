# waldemar.tk beta
Waldemar.tk beta website

#### All commads should be run from document root.

## Install and build Manually

Create a .env file containing:
- `DATABSE_URL`: The URI to the database (default: sqlite:///db/db.sqlite)
- `SECRET_KEY`: App secret key.
- `GITHUB_CLIENT_ID`: Github client id
- `GITHUB_CLIENT_SECRET`: Github client secret

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
## Install via docker

```Docker
docker pull unfwalle/waldemar.tk:beta
docker volume create Database
docker volume create UserData
docker run -dp 8080:8080 --name Waldemar.tk -v Database:/webapp/app/db -v UserData:/webapp/app/static/user-uploads unfwalle/waldemar.tk:beta
```

