from flask_sqlalchemy import SQLAlchemy

# Single shared db instance imported by models and routes
db = SQLAlchemy()
