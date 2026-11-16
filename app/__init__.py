import os

from flask import Flask

from . import config, db


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    config.load_env()
    app.config.update(config.default_config())
    if test_config is None:
        app.config.update(config.secrets_from_env())
    else:
        app.config.update(test_config)

    for path in (os.path.dirname(app.config["DB_PATH"]), app.config["STORAGE_DIR"], app.config["KEYS_DIR"]):
        os.makedirs(path, exist_ok=True)

    db.init_app(app)
    with app.app_context():
        db.init_db()

    from . import auth, files
    app.register_blueprint(auth.bp)
    app.register_blueprint(files.bp)
    return app
