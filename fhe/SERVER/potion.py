from flask import Flask

def make_potion():
    app = Flask(__name__)
    return app