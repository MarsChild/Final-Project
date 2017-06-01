from __init__ import db
from db_setup import User

#create db and db tables
db.create_all()

db.session.add(User("Admin", "password"))

#commit the changes
db.session.commit()
