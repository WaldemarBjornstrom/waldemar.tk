# waldemar.tk
Waldemar.tk website

## Install and build

```
pip3 install -r requirements.txt
python3 build.py
```

### Development server

from waldemar.tk root folder
```
flask run
```

### Production server

```
waitress-serve --call "app:create_app"
```
