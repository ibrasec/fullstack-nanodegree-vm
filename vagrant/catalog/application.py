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



def CreateCatagories():
    catagories=session.query(Catagory).all()
    if catagories:
        return 'catagories exists'
    catagory_list = ['Cloths','Electronics','Books','Software','toys','food','sports','other']  
    for cat in catagory_list:
        catagory = Catagory(name=cat)
        session.add(catagory)
        session.commit()


#CreateCatagories()



# home page
@app.route('/', methods=['GET','POST'])
def home():
    catagories = session.query(Catagory).all()
    items = session.query(Item).all()
    return render_template('home.html',catagories = catagories, items = items)





# items per catagory page
@app.route('/catalog/<catagory_name>/items')
def itemInCatagory(catagory_name):
    catagories = session.query(Catagory).all()
    catagory = session.query(Catagory).filter_by(name = catagory_name).one()
    items = session.query(Item).filter_by(catagory_id = catagory.id).all()
    print len(items)
    return render_template('catagory_items.html',catagories = catagories, catagory = catagory, items = items, counter = len(items) )
    return "items found in %s" % catagory_name






# item description page
@app.route('/catalog/<catagory_name>/<item_name>')
def itemDescription(catagory_name, item_name):
    item = session.query(Item).filter_by(title = item_name).one()
    return render_template('itemDescription.html', item = item)



# create item page
@app.route('/catalog/newitem', methods = [ 'GET','POST' ] )
def add_item():
    if request.method == 'GET':
        #return 'insinde add item'
        catagories = session.query(Catagory).all()
        return render_template('newitem.html', catagories = catagories)
    elif request.method == 'POST':
        title_ = request.form['title']
        catagory = request.form['catagory']
        description = request.form['description']
        exists = session.query(Item).filter_by( title = title_).first()
        if exists:
            return 'This item already exists'
        item = Item(title = title_ )
        item.description = description
        catagory_object = session.query(Catagory).filter_by(name = catagory).one()
        item.catagory_id = catagory_object.id
        session.add(item)
        session.commit()
        return render_template('home.html')
        #return jsonify({'catagory_item':item.title})



# edit item page
@app.route('/catalog/<item_name>/edit', methods =['GET','POST'])
def edit_item( item_name ):
    if request.method == 'GET':
        #return 'insinde add item'
        catagories = session.query(Catagory).all()
        return render_template('edititem.html',catagories=catagories, item_name = item_name)
    elif request.method == 'POST':
        #
        item = session.query(Item).filter_by(title = item_name).one() 
        # deleting the previouse item
        session.delete(item)
        session.commit()
        # Adding the passed data 
        title_ = request.form['title']
        catagory = request.form['catagory']
        description = request.form['description']
        item = Item(title = title_)
        item.description = description
        catagory_object = session.query(Catagory).filter_by(name = catagory).one()
        item.catagory_id = catagory_object.id
        session.add(item)
        session.commit()
        return jsonify({'catagory_item':item.title})


# delete item page
@app.route('/catalog/<item_name>/delete', methods = ['GET','POST'])
def delete_item(item_name):
    if request.method == 'GET':
        return render_template('deleteitem.html', item_name = item_name)
    elif request.method == 'POST':
        item = session.query(Item).filter_by(title = item_name).one()
        session.delete(item)
        session.commit()
        return render_template('home.html')

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
