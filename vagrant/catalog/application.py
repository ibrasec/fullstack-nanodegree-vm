from models import Item,Catagory, Base, User 
from flask import Flask, jsonify, request, url_for, abort, g, render_template, redirect, session, flash
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
import random,string, datetime

from datetime import timedelta
from flask import session, app



def LastUpdate(item_object):
    '''
    a function that returns the delta time from the time the user has created
    or updated his/her item.
    The passed item must be an sqlalchemy object
    example:
    >>> LastUpdate(item_object)
    3 seconds
    >>> LastUpdate(item_object)
    3 days
    >>> LastUpdate(item_object)
    3 hr and 1 min
    '''
    try:
        delta = datetime.datetime.now() - item_object.date
    except:
        pass
    # for plural or singular
    x = lambda x: 's' if x > 1 else ''
    # check if the delta is within days
    if delta.days > 0:
        return '%s day%s' % ( str( delta.days ), x(delta.days) )
    # check if the delta is within seconds
    elif delta.seconds <= 60: 
        return '%s seconds' % str( delta.seconds ) 
    # check if the delta is within minutes
    elif delta.seconds <= 3600:
        minutes = delta.seconds // 60
        return '%s minute%s' %( str( minutes ), x( minutes ) )
    # check if the delta is within hours
    else:
        hours =  delta.seconds // 3600 
        minutes = str( ( delta.seconds - hours * 3600 ) // 60  )
        return '%s hr and %s min' %(str(hours) , minutes) 



CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']



auth = HTTPBasicAuth()

engine = create_engine('sqlite:///catalog.db',connect_args={'check_same_thread':False})

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)


# User Session expires after 5 minutes
@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=15)



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


#####################
# test lvh.me
@app.route('/routelvhme')
def routelvhme():
    print 'We are inside routelvhme'
    return redirect('/clientOAuth')


##############


@app.route('/clientOAuth')
def startOAuth():
    return render_template('clientOAuth.html')


@app.route('/oauth/<provider>', methods = ['POST'])
def login_provider(provider):
    #STEP 1 - Parse the auth code
    print 'We Are inside login_provider'
    print request, dir(request)
    print  request.data
    auth_code = request.data
    print "Step 1 - Complete, received auth code %s" % auth_code
    if provider == 'google':
        #STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
          
        # Check that the access token is valid.
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'

        print "Step 2 Complete! Access Token : %s " % credentials.access_token

        #STEP 3 - Find User or make a new one
        
        #Get user info
        h = httplib2.Http()
        userinfo_url =  "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt':'json'}
        answer = requests.get(userinfo_url, params=params)
      
        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']
     
        #see if user exists, if it doesn't make a new one
        user = session.query(User).filter_by(email=email).first()
        if not user:
            user = User(username = name, picture = picture, email = email)
            session.add(user)
            session.commit()

        #STEP 4 - Make token
        token = user.generate_auth_token(600)

        #STEP 5 - Send back token to the client 
        login_session['logged_in'] = True
        login_session['username']=user.username
        g.user = user
        return redirect(url_for('home'),302)
        #return jsonify({'token': token.decode('ascii')})
        
        #return jsonify({'token': token.decode('ascii'), 'duration': 600})
    else:
        return 'Unrecoginized Provider'


# create a state token to prevent requests
# store it in the session for later validation
# login page
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
            flash("The username or password is incorrect")
            return redirect('/login',302)
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
        email = request.form['email']
        if username is None or password is None:
            abort(400) # missing arguments
        if session.query(User).filter_by(username = username).first() is not None:
            flash("This username Already exist")
            return redirect('/signup',302)
    user = User(username = username)
    user.hash_password(password)
    user.email = email
    session.add(user)
    session.commit()
    login_session['logged_in'] = True
    login_session['username'] = user.username
    return redirect(url_for('home'),302)



# just for checking
# to be deleted once done troubleshooting
@app.route('/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username, 'password' : user.password_hash})


# Route page section ----------------------

# home page
@app.route('/', methods=['GET','POST'])
def home():
    catagories = session.query(Catagory).all()
    items = session.query(Item).order_by(Item.date.desc()).limit(10)
    return render_template('home.html',catagories = catagories, items = items )


# items per catagory page
@app.route('/catalog/<catagory_name>/items')
def itemInCatagory(catagory_name):
    catagories = session.query(Catagory).all()
    catagory = session.query(Catagory).filter_by(name = catagory_name).first()
    items = session.query(Item).filter_by(catagory_id = catagory.id).all()
    return render_template('catagory_items.html',catagories = catagories,
                         catagory = catagory, items = items,
                         counter = len(items))


# item description page
@app.route('/catalog/<catagory_name>/<item_name>')
def itemDescription(catagory_name, item_name):
    item = session.query(Item).filter_by(title = item_name).first()
    last_update = LastUpdate(item)
    return render_template('itemDescription.html', item = item,
                            lastupdate = last_update )


# create item page
@app.route('/catalog/newitem', methods = [ 'GET','POST' ] )
@is_logged_in
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
        item.author = login_session['username']
        session.add(item)
        session.commit()
        return redirect('/',302)
        #return jsonify({'catagory_item':item.title})


# edit item page
@app.route('/catalog/<item_name>/edit', methods =['GET','POST'])
@is_logged_in
def edit_item( item_name ):
    item = session.query(Item).filter_by(title = item_name).one() 
    if request.method == 'GET':
        #return 'insinde add item'
        catagories = session.query(Catagory).all()
        return render_template('edititem.html',catagories=catagories, item_name = item.title)
    elif request.method == 'POST':
        print type(item.date)
        if login_session['username'] == item.author:
            # deleting the previouse item
            session.delete(item)
            session.commit()
            # Adding the passed data 
            title_ = request.form['title']
            catagory = request.form['catagory']
            description = request.form['description']
            item = Item(title = title_)
            item.description = description
            catagory_object = session.query(Catagory).filter_by(name = catagory).first()
            item.catagory_id = catagory_object.id
            item.author = login_session['username']
            session.add(item)
            session.commit()
            return redirect(url_for('home'),302)
            return jsonify({'catagory_item':item.title})
        else:
            return 'You are not authorized to Edit this item'


# delete item page
@app.route('/catalog/<item_name>/delete', methods = ['GET','POST'])
@is_logged_in
def delete_item(item_name):
    item = session.query(Item).filter_by(title = item_name).one()    
    if request.method == 'GET':
        return render_template('deleteitem.html', item_name = item_name)
    elif request.method == 'POST':
        if login_session['username'] == item.author:
            item = session.query(Item).filter_by(title = item_name).one()
            session.delete(item)
            session.commit()
            return redirect(url_for('home'),302)
        else:
            return 'You are not authorized to Delete this item'


# return all catalog API
@app.route('/catalog.json')
def catalog_api():
    output = []
    catagories = session.query(Catagory).all()
    for catagory in catagories:
        catagory_dict = catagory.serialize   # {id:'',name:''}
        catagory_dict['items'] = []
        items = session.query(Item).filter_by(catagory_id = catagory.id).all()
        # {id:,name:,title:[{},{},{}]}
        for item in items:
            catagory_dict['items'].append( item.serialize  )
        output.append( catagory_dict )

    return jsonify({'catagory':output})


# return a certain catagory api
@app.route('/catalog/<catagory_name>.json')
def catagory_api(catagory_name):
    catagory = session.query(Catagory).filter_by(name = catagory_name).one()
    items = session.query(Item).filter_by(catagory_id = catagory.id).all()
    if items != None and catagory !=None:
        output = [ item.serialize for item in items]
        return jsonify({catagory_name: output })
    return 'Item or catagory not found'
    

# return a certain items api
@app.route('/catalog/<catagory_name>/<item_name>.json')
def item_api(catagory_name,item_name):
    item = session.query(Item).filter_by(title = item_name).first()
    if item != None:
        return jsonify({item_name: item.serialize })  
    return 'Item or catagory not found'






if __name__ == '__main__':
    app.secret_key=''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    app.debug = True
    #app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    app.run(host='0.0.0.0', port=5000)
