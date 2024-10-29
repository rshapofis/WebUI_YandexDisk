import jinja2
import flask
import requests
app = flask.Flask("FlaskYandexDisk")
app.secret_key = b'_5#sdsfL"F4Q8z\n\xec]/'

# метод для основной страницы приложения может получать из POST параметр path для запроса уже по нему
@app.route('/', methods=['GET', 'POST'])
def main() -> flask.Response:
    if 'token' in flask.session:
        templateLoader = jinja2.FileSystemLoader(searchpath="./template")
        templateEnv = jinja2.Environment(loader=templateLoader)
        main_template = "template.html"
        template = templateEnv.get_template(main_template)
        s = requests.Session()
        c=20
        files=[]
        headers ={"Accept" : "application/json", "Authorization" : "OAuth {}".format(flask.session["token"])}
        params = {"path": "/"}
        path="/"
        uppath="/"
        if flask.request.method == 'POST':
            path = "{}/".format(flask.request.form['path'].strip('\'').replace("disk:",""))
            uppath="/".join(path.split("/")[:-2])
            params = {"path": path }
        url="https://cloud-api.yandex.net/v1/disk/resources"
        total=20
        limit=20
        offset=0
        while (total>=limit+offset):
            params["offset"]=offset
            r=requests.get(url, headers=headers, params=params)
            items=r.json()["_embedded"]["items"]
            total=r.json()["_embedded"]["total"]
            for i in items:
                temp=[i["name"],i["type"],i["path"]]
                files.append(temp)
            offset+=20
        return template.render(files=files, path=path, uppath=uppath, flask=flask)
    else:
        return flask.redirect(flask.url_for('login'))

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