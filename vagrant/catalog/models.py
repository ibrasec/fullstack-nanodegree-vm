import datetime
from sqlalchemy import Column,Integer,String,ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random, string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String)
    email = Column(String)
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
    	s = Serializer(secret_key, expires_in = expiration)
    	return s.dumps({'id': self.id })

    @staticmethod
    def verify_auth_token(token):
    	s = Serializer(secret_key)
    	try:
    		data = s.loads(token)
    	except SignatureExpired:
    		#Valid Token, but expired
    		return None
    	except BadSignature:
    		#Invalid Token
    		return None
    	user_id = data['id']
    	return user_id


class Catagory(Base):
    __tablename__='catagory'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    
    @property
    def serialize(self):
        return {
                'id' : self.id,
                'name' : self.name
                }


class Item(Base):
    __tablename__='item'
    id = Column(Integer, primary_key=True, autoincrement=True)
    catagory_id = Column(Integer, ForeignKey("catagory.id"),nullable=False)
    title = Column(String)
    description = Column(String)
    author = Column(String)
    date = Column(DateTime, default=datetime.datetime.utcnow)
    image = Column(String)
    @property
    def serialize(self):
        return {
                'id' : self.id,
                'title' : self.title,
                'description': self.description,
                'cat_id': self.catagory_id
                }




engine = create_engine('sqlite:///catalog.db',connect_args={'check_same_thread':False})


Base.metadata.create_all(engine)



