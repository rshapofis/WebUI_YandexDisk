import jinja2
import flask
import requests
import json
import base64
import hashlib
from pymemcache.client import base
app = flask.Flask("FlaskYandexDisk")
app.secret_key = b'_5#sdsfL"F4Q8z\n\xec]/'
client = base.Client(('localhost', 11211))
types={"все": "","текст": "text", "видео" : "video",  "изображение": "image", "аудио": "audio", "приложение" : "application"}

# метод для основной страницы приложения может получать из POST параметр path для запроса уже по нему
@app.route('/', methods=['GET', 'POST'])
def main() -> flask.Response:
    if 'token' in flask.session:
        templateLoader = jinja2.FileSystemLoader(searchpath="./template")
        templateEnv = jinja2.Environment(loader=templateLoader)
        main_template = "template.html"
        template = templateEnv.get_template(main_template)
        path=flask.session.get("path", default="/")
        uppath="/"
        if flask.request.method == 'POST':
            path = "{}/".format(flask.request.form['path'].strip('\'').replace("disk:",""))
            flask.session["path"] = path
            uppath="/".join(path.split("/")[:-2])
        filter=flask.session.get("filter", default="все")
        result = client.get(create_well_formed_key(path))
        if result is None:
            refresh()
            result = client.get(create_well_formed_key(path))
        files=json.loads(result)
        return template.render(files=files, path=path, uppath=uppath, flask=flask,filter=filter, types=types)
    else:
        return flask.redirect(flask.url_for('login'))

# метод для установки значения фильтра в сессию   
@app.route('/setFilter', methods=['POST'])
def setFilter() -> flask.Response:
    flask.session["filter"]=flask.request.form['filter']
    return flask.redirect(flask.url_for('main'))

# метод для удаления значения фильтра из сессии  
@app.route('/popFilter', methods=['POST'])
def popFilter() -> flask.Response:
    flask.session.pop('filter', None)
    return flask.redirect(flask.url_for('main'))

# метод для перезаписи кэша по пути. путь берет из сессии, для текущей страницы.
@app.route('/refresh', methods=['POST'])
def refresh() -> flask.Response:
    path=flask.session.get("path", default="/")
    headers ={"Accept" : "application/json", "Authorization" : "OAuth {}".format(flask.session["token"])}
    params = {"path": path}
    url="https://cloud-api.yandex.net/v1/disk/resources"
    total=20
    limit=20
    offset=0
    files=[]
    while (total>=limit+offset):
        params["offset"]=offset
        r=requests.get(url, headers=headers, params=params)
        items=r.json()["_embedded"]["items"]
        total=r.json()["_embedded"]["total"]
        for i in items:
            temp=[i["name"],i["type"],i["path"]]
            if i["type"] == "file":
                temp.append(i["mime_type"])
            files.append(temp)
        offset+=20
    client.set(create_well_formed_key(path),json.dumps(files))
    return flask.redirect(flask.url_for('main'))


# метод для страница авторизации, запрашивает токен
@app.route('/login', methods=['GET', 'POST'])
def login() -> flask.Response:
    if flask.request.method == 'POST':
        flask.session["token"] = flask.request.form['token']
        return flask.redirect(flask.url_for('main'))
    if flask.request.method == 'GET':
        if 'token' in flask.session:
            return flask.redirect(flask.url_for('main'))
        else:
            templateLoader = jinja2.FileSystemLoader(searchpath="./template")
            templateEnv = jinja2.Environment(loader=templateLoader)
            login_template = "login.html"
            template = templateEnv.get_template(login_template)
            return template.render(flask=flask)

# метод для выхода из авторизации, убирает токен из сессии
@app.route('/logout')
def logout() -> flask.Response:
    flask.session.pop('token', None)
    return flask.redirect(flask.url_for('login'))

# метод для реализации загрузки через api файла
@app.route('/download', methods=['POST'])
def download() -> flask.Response:
    path = "{}/".format(flask.request.form['path'].strip('\'').replace("disk:",""))
    params = {"path": path }
    headers ={"Accept" : "application/json", "Authorization" : "OAuth {}".format(flask.session["token"])}
    url="https://cloud-api.yandex.net/v1/disk/resources/download"
    result=requests.get(url, headers=headers, params=params)
    temp=path.strip("/")
    response = flask.make_response(result.raw)
    response.headers.set('Content-Disposition', 'attachment', filename=temp.split("/")[-1])
    return response

#функция для формирования ключа для memcached
def create_well_formed_key(key):
    # Get rid of all spaces, control characters, etc using base64
    valid_key = base64.b64encode(key.encode()).decode()

    valid_key_length = len(valid_key)
    # 250 is the maximum memcached can handle
    if valid_key_length < 250:
        return valid_key

    valid_key = hashlib.md5(valid_key.encode()).hexdigest() + hashlib.sha1(valid_key.encode()).hexdigest() + str(valid_key_length)
    return valid_key