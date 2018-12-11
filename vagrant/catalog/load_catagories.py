# initialize Database
from models import Item, Catagory, Base, User
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

# comment the below to use postgresql instead of sqlite
engine = create_engine('sqlite:///catalog.db',
                       connect_args={'check_same_thread': False})
# un-comment the below to use postgres instead of sqlite
# update the username, password and the database name accordingly
#engine = create_engine('postgresql://username:password@localhost:5432/catalog')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


def create_catagories():
    '''
    This code loads the Database with some catagories.
    Exits if the database is already loaded.
    '''
    catagories = session.query(Catagory).all()
    if catagories:
        return 'catagories exists... Exiting...'
    catagory_list = ['Cloths', 'Electronics', 'Books', 'Software', 'toys',
                     'food', 'sports', 'other']
    for catagory in catagory_list:
        catagory = Catagory(name=catagory)
        session.add(catagory)
        session.commit()


if __name__ == '__main__':
    create_catagories()
