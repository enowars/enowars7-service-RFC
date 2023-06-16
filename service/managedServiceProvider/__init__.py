import os
import secrets
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev', #CTF-NOTE not part of intended vulns, will be fixed   #secrets.token_hex(20),
        DATABASE=os.path.join(app.instance_path, 'msp.sqlite'),
    )

    # TODO; use for deployment behind nginx as proxy
    #app.wsgi_app = ProxyFix(
     #   app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
    #)

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    #intialize the database
    from . import db
    db.init_app(app)

    from . import auth
    app.register_blueprint(auth.bp)

    from . import blog
    app.register_blueprint(blog.bp)
    app.add_url_rule('/', endpoint='index')
    return app

