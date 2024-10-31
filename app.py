import jinja2
import flask
import requests
import json
import base64
import hashlib
import io
import zipfile
import datetime
from pymemcache.client import base
app = flask.Flask("FlaskYandexDisk")
# секретный ключ
app.secret_key = b'_5#sdsfL"F4Q8z\n\xec]/'
# Переменная для создания клиента memcached
client = base.Client(('localhost', 11211))
# Словарь для хранения типов файлов
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
        result = client.get(create_key(path))
        if result is None:
            setCache(path)
            result = client.get(create_key(path))
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

#метод для Получения списка файлов по задонному пути через api
def filesFromApi(path: str) -> list:
    headers ={"Accept" : "application/json", "Authorization" : "OAuth {}".format(flask.session["token"])}
    params = {"path": path}
    url="https://cloud-api.yandex.net/v1/disk/resources"
    total=20
    limit=20
    offset=0
    files=[]
    while (total>=offset):
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
    return files

# метод для записи кэша для задонного пути.
def setCache(path: str) -> list:
    files = filesFromApi(path)
    client.set(create_key(path),json.dumps(files))

# метод для перезаписи кэша для задонного пути. путь берет из сессии, для текущей страницы.
@app.route('/refresh', methods=['POST'])
def refresh() -> flask.Response:
    path=flask.session.get("path", default="/")
    setCache(path)
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

# метод для получаения файлов для каталога включая вложенные
def getfiles(l: list) ->list:
    files = []
    folders = [l[2]]
    while (len(folders) != 0):
        folder = folders.pop(0)
        folder_path="{}/".format(folder.replace("disk:",""))
        result = client.get(create_key(folder_path))
        if result is None:
            setCache(folder_path)
            result = client.get(create_key(folder_path))
        files_from_api=json.loads(result)
        for file in files_from_api:
            if file[1]=="dir":
                folders.append(format(file[2]))
            else:
                files.append([file[0],file[1],file[2]])
    return files

# метод для реализации загрузки через api файла
@app.route('/download', methods=['POST'])
def download() -> flask.Response:
    post_files=json.loads(flask.request.form['files'])
    files=[]
    for i in post_files["files"]:
        if i[1]=="dir":
            files.extend(getfiles(i))
        else:
            files.append(i)
    mem = io.BytesIO()
    for i in files:
        with zipfile.ZipFile(mem, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
            path = "{}/".format(i[2].replace("disk:",""))
            params = {"path": path }
            headers ={"Accept" : "application/json", "Authorization" : "OAuth {}".format(flask.session["token"])}
            url="https://cloud-api.yandex.net/v1/disk/resources/download"
            result=requests.get(url, headers=headers, params=params)
            temp=path.strip("/")
            file_name=temp[:-1]
            file=requests.get(result.json()['href'])
            zip_file.writestr(file_name,file.content)        
    mem.seek(0)
    return flask.send_file(mem, as_attachment=True, download_name="{}.zip".format(datetime.datetime.now()))

#функция для формирования ключа для memcached
def create_key(key) -> str:
    # Кодируем что бы избежать проблем с кодами символов и спец символами
    valid_key = base64.b64encode(key.encode()).decode()

    valid_key_length = len(valid_key)
    # 250 это максимальная длина для ключа
    if valid_key_length < 250:
        return valid_key

    valid_key = hashlib.md5(valid_key.encode()).hexdigest() + hashlib.sha1(valid_key.encode()).hexdigest() + str(valid_key_length)
    return valid_key