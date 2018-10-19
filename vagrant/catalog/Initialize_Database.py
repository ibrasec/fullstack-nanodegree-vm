# initialize Database
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine



auth = HTTPBasicAuth()

engine = create_engine('sqlite:///catalog.db',connect_args={'check_same_thread':False})

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


def CreateCatagories():
    catagories=session.query(Catagory).all()
    if catagories:
        return 'catagories exists... Exiting...'
    catagory_list = ['Cloths','Electronics','Books','Software','toys','food','sports','other']  
    for cat in catagory_list:
        catagory = Catagory(name=cat)
        session.add(catagory)
        session.commit()



if __name__ == '__main__':
    CreateCatagories()

