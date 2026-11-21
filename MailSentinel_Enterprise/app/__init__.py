import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import inspect, text
from config import config

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

def create_app(config_name=None):
    config_name = config_name or os.environ.get('FLASK_CONFIG', 'default')
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)

    from app.blueprints.main import main_bp
    from app.blueprints.analyzer import analyzer_bp
    from app.blueprints.history import history_bp
    from app.blueprints.api import api_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(analyzer_bp, url_prefix='/analyze')
    app.register_blueprint(history_bp, url_prefix='/history')
    app.register_blueprint(api_bp, url_prefix='/api')
    csrf.exempt(api_bp)

    with app.app_context():
        db.create_all()
        # Lightweight SQLite-compatible upgrade for databases created by earlier MailSentinel versions.
        columns = {column['name'] for column in inspect(db.engine).get_columns('email_records')}
        if 'analysis_json' not in columns:
            db.session.execute(text('ALTER TABLE email_records ADD COLUMN analysis_json TEXT'))
            db.session.commit()

    @app.errorhandler(400)
    def bad_request_error(error):
        return render_template('error.html', code=400, message="Bad request. Please check your submission."), 400
    @app.errorhandler(413)
    def too_large_error(error):
        return render_template('error.html', code=413, message="The uploaded request exceeds the 10 MB limit."), 413

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('error.html', code=404, message="The requested resource was not found."), 404
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('error.html', code=500, message="An internal server error occurred."), 500

    if not app.debug and not app.testing:
        os.makedirs('logs', exist_ok=True)
        handler = RotatingFileHandler('logs/mailsentinel.log', maxBytes=10240000, backupCount=10)
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
        handler.setLevel(logging.INFO)
        app.logger.addHandler(handler)
        app.logger.setLevel(logging.INFO)
    return app
