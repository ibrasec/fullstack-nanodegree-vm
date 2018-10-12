from models import Item,Catagory, Base
from flask import Flask, jsonify, request, url_for, abort, g, render_template
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from flask import session as login_session
from flask_httpauth import HTTPBasicAuth
import json,random,string

#NEW IMPORTS
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests


import random,string

# create a state token to prevent requests
# store it in the session for later validation
# login page



auth = HTTPBasicAuth()

engine = create_engine('sqlite:///catalog.db',pool_pre_ping=True)

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()





  

app = Flask(__name__)

#CreateCatagories()



# home page
@app.route('/', methods=['GET','POST'])
def home():
    catagory_obj = session.query(Catagory).all()
    items = session.query(Item).all()
    ll = [i for i in items ]
    #for i in catagory_:print i.name
    return render_template('home.html',catagory = catagory_obj)
    return 'homepage'




# items per catagory page
@app.route('/catalog/<catagory_name>/items')
def itemInCatalog(catagory_name):
    return "items per catagory page"


# item description page
@app.route('/catalog/<catagory_name>/<item_name>')
def item_catalog(catagory_name, item_name):
    return 'item description page'


# create item page
@app.route('/catalog/newitem', methods = [ 'GET','POST' ] )
def add_item():
    if request.method == 'GET':
        #return 'insinde add item'
        return render_template('newitem.html')
    elif request.method == 'POST':
        title_ = request.form['title']
        catagory = request.form['catagory']
        description = request.form['description']
        exists = session.query(Item).filter_by( title = title_).first()
        if exists:
            return 'This item already exists'
        item = Item(title = title_ )
        item.description = description
        item.catagory = catagory
        session.add(item)
        session.commit()
        return jsonify({'catagory_item':item.title})



# edit item page
@app.route('/catalog/<item_name>/edit')
def edit_item( item_name ):
    if request.method == 'GET':
        #return 'insinde add item'
        return render_template('edititem.html')
    elif request.method == 'POST':
        title_ = request.form['title']
        catagory = request.form['catagory']
        description = request.form['description']
        exists = session.query(Item).filter_by( title = title_).first()
        if exists:
            return 'This item already exists'
        item = Item(title = title_ )
        item.description = description
        item.catagory = catagory
        session.update(item)
        session.commit()
        return jsonify({'catagory_item':item.title})


# delete item page
@app.route('/catalog/<item_name>/delete')
def delete_item(item_name):
    return 'Delete this item'


# catalog API
@app.route('/catalog.json')
def catalog_json():
    item = session.query(Item).all()
    return 'json-catalog'
    #item = session.query(Item).all()
    #return jsonify( { 'catalog':[i for i in item] })



if __name__ == '__main__':
    app.debug = True
    #app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    app.run(host='0.0.0.0', port=5000)
