import os, subprocess, pickle, sqlite3, requests, yaml, jwt, random, hashlib
from flask import Flask, request, redirect, render_template_string, send_file, make_response
app = Flask(__name__)
app.secret_key = "supersecret123"

@app.route("/user")
def user():
    uid = request.args.get("id")
    db = sqlite3.connect("x.db")
    return str(db.execute("SELECT * FROM users WHERE id=" + uid).fetchall())

@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c1 " + host)
    subprocess.call("nslookup " + host, shell=True)
    return "ok"

@app.route("/file")
def f():
    return send_file(request.args["name"])

@app.route("/fetch")
def fetch():
    return requests.get(request.args.get("url")).text

@app.route("/hello")
def hello():
    return render_template_string("Hello " + request.args.get("name"))

@app.route("/go")
def go():
    return redirect(request.args.get("next"))

@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data)) + str(yaml.load(request.data))

@app.route("/me")
def me():
    t = request.headers.get("Authorization")
    return str(jwt.decode(t, options={"verify_signature": False}))

@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr")))

@app.route("/greet")
def greet():
    return make_response("<h1>" + request.args.get("n") + "</h1>")

def make_reset_token():
    return str(random.randint(100000, 999999))

def hashpw(p):
    return hashlib.md5(p.encode()).hexdigest()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
