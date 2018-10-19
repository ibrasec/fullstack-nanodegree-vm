from models import Item,Catagory, Base, User
from flask import Flask, jsonify, request, url_for, abort, g, render_template, redirect, session
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

from functools import wraps
import random,string

# create a state token to prevent requests
# store it in the session for later validation
# login page




auth = HTTPBasicAuth()

engine = create_engine('sqlite:///catalog.db',connect_args={'check_same_thread':False})

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)

###################################################
# default adding catagories if the database is lost
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
###################################################



# check if the user is logged-in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in login_session:
            return f(*args, **kwargs)
        else:
            #flash('','danger')
            #return redirect(url_for('login'))
            return 'You are unauthorized'
    return wrap



@auth.verify_password
def verify_password(username_or_token, password):
    # try to see if it is a token first
    print 'inside verify password function'
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(username = username_or_token).one()
    else:
        user = session.query(User).filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    print 'inside verif password to return user',user
    g.user = user
    return True






@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token':token.decode('ascii')})


# login page
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            print username,password
        except:
            username = request.json.get('username')
            password = request.json.get('password')
        if username is None or password is None:
            abort(400) # missing arguments
        if not verify_password(username, password):
            abort(400) # existing user
        user = User(username = username)
        user.hash_password(password)
        login_session['logged_in'] = True
        login_session['username'] = user.username
        #login_session(user)
        return redirect('/',302)
        

@app.route('/logout')
def logout():
    login_session.clear()
    return redirect(url_for('home'))



@app.route('/signup', methods = ['GET','POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username is None or password is None:
            abort(400) # missing arguments
        if session.query(User).filter_by(username = username).first() is not None:
            abort(400) # existing user
    print 'out of signup if'
    user = User(username = username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return redirect(url_for('login'),302)



# just for checking
# to be deleted once done troubleshooting
@app.route('/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username, 'password' : user.password_hash})



# home page
@app.route('/', methods=['GET','POST'])
def home():
    catagories = session.query(Catagory).all()
    items = session.query(Item).all()
    return render_template('home.html',catagories = catagories, items = items )





# items per catagory page
@app.route('/catalog/<catagory_name>/items')
def itemInCatagory(catagory_name):
    catagories = session.query(Catagory).all()
    catagory = session.query(Catagory).filter_by(name = catagory_name).first()
    items = session.query(Item).filter_by(catagory_id = catagory.id).all()
    return render_template('catagory_items.html',catagories = catagories, catagory = catagory, items = items, counter = len(items))







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
        return redirect('/',302)
        #return jsonify({'catagory_item':item.title})



# edit item page
@app.route('/catalog/<item_name>/edit', methods =['GET','POST'])
@is_logged_in
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
@auth.login_required
def delete_item(item_name):
    print 'inside delete function'
    print g,dir(g),'user' in g
    if request.method == 'GET':
        return render_template('deleteitem.html', item_name = item_name)
    elif request.method == 'POST':
        item = session.query(Item).filter_by(title = item_name).one()
        session.delete(item)
        session.commit()
        return redirect('/',302)

# catalog API
@app.route('/catagory.json')
def catagory_api():
    output = []
    catagories = session.query(Catagory).all()
    for catagory in catagories:
        catagory_dict = catagory.serialize 
        items = session.query(Item).filter_by(catagory_id = catagory.id).all()
        for item in items:
            catagory_dict['items'] = list( item.serialize  )
        output.append( catagory_dict )

    return jsonify({'catagory':output})


if __name__ == '__main__':
    app.secret_key=''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    app.debug = True
    #app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    app.run(host='0.0.0.0', port=5000)
