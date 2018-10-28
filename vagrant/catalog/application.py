from models import Item, Catagory, Base, User
from flask import Flask, jsonify, request, url_for, abort, g, render_template
from flask import session, app, redirect, flash
from flask import make_response
from flask import send_from_directory
from flask import session as login_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from flask_httpauth import HTTPBasicAuth
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import requests
import os
import datetime
import json
import random
import string
import load_catagories
from functools import wraps
# for uploading
from werkzeug.utils import secure_filename


# defining variables
UPLOAD_FOLDER = './static/img/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
CLIENT_ID = json.loads(
            open('client_secrets.json', 'r').read())['web']['client_id']

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# defining allowed files when uploading images
def allowed_file(filename):
    '''
    To check if the filename is in fomat something.xxx
    where xxx is defined in the ALLOWED_EXTENSIONS variable
    return True or False
    '''
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# defining random string to be used to generate CSRF token
def random_string():
    return ''.join(random.choice(
            string.ascii_uppercase + string.digits) for x in xrange(32))


# check the last time an item has been updated/created
def LastUpdate(item_date):
    '''
    a function that returns the delta time from the time the user has created
    or updated his/her item.
    The passed item must be of datetime type
    example:
    >>> LastUpdate(datetime.datetime(2018, 10, 28, 5, 21, 51, 938984))
    3 days
    '''
    try:
        delta = datetime.datetime.now() - item_date
    except:
        pass

    # for plural or singular check
    def x(value):
        if value > 1:
            return 's'
    # check if the delta is within days
    if delta.days > 0:
        return '%s day%s' % (str(delta.days), x(delta.days))
    # check if the delta is within seconds
    elif delta.seconds <= 60:
        return '%s seconds' % str(delta.seconds)
    # check if the delta is within minutes
    elif delta.seconds <= 3600:
        minutes = delta.seconds // 60
        return '%s minute%s' % (str(minutes), x(minutes))
    # check if the delta is within hours
    else:
        hours = delta.seconds // 3600
        minutes = str((delta.seconds - hours * 3600) // 60)
        return '%s hr and %s min' % (str(hours), minutes)


auth = HTTPBasicAuth()

engine = create_engine(
        'sqlite:///catalog.db', connect_args={'check_same_thread': False})

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# check if the Database is already filled with catagories
def load_database():
    catagories = session.query(Catagory).all()
    if catagories:
        return 'catagories exists... Exiting...'
    else:
        print 'Loading pre-defined catagories...'
        print 'Please wait...'
        load_catagories.create_catagories()
        print 'All catagories has been loaded'


# ----- CSRF section -------------
@app.before_request
def csrf_protect():
    # to apply csrf when a POST is sent and the target url is no 'oauth'
    # this might need more enhancement but it works.
    if request.method == "POST" and 'oauth' not in request.url:
        token = login_session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(403)


def generate_csrf_token():
    if '_csrf_token' not in login_session:
        login_session['_csrf_token'] = random_string()
    return login_session['_csrf_token']


app.jinja_env.globals['csrf_token'] = generate_csrf_token
# ------ End of CSRF section ------


# check if the user is logged-in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in login_session:
            return f(*args, **kwargs)
        else:
            # if the user is not logged-in
            # and trys to access a protected resource
            return render_template('/forbidden.html')
    return wrap


@auth.verify_password
def verify_password(username_or_token, password):
    # try to see if it is a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(username=username_or_token).one()
    else:
        user = session.query(User).filter_by(
                username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


# for third party login
@app.route('/oauth/<provider>', methods=['POST'])
def login_provider(provider):
    # STEP 1 - Parse the auth code
    auth_code = request.data
    # print "Step 1 - Complete, received auth code %s" % auth_code
    if provider == 'google':
        # STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets(
                    'client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(
                json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        # Check that the access token is valid.
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
               % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'
        # STEP 3 - Find User or make a new one
        # Get user info
        h = httplib2.Http()
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)
        data = answer.json()
        name = data['name']
        picture = data['picture']
        email = data['email']
        # see if user exists, if it doesn't make a new one
        user = session.query(User).filter_by(email=email).first()
        if not user:
            user = User(username=name, picture=picture, email=email)
            session.add(user)
            session.commit()
        # STEP 4 - Make token
        token = user.generate_auth_token(600)
        # STEP 5 - Send back token to the client
        login_session['logged_in'] = True
        login_session['username'] = user.username
        g.user = user
        return redirect(url_for('home'), 302)
    else:
        return 'Unrecoginized Provider'


# create a state token to prevent requests
# store it in the session for later validation
# login page
@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


# login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
        except:
            username = request.json.get('username')
            password = request.json.get('password')
        if username is None or password is None:
            abort(400)  # missing arguments
        if not verify_password(username, password):
            flash("The username or password is incorrect")
            return redirect('/login', 302)
        user = User(username=username)
        user.hash_password(password)
        login_session['logged_in'] = True
        login_session['username'] = user.username
        return redirect('/', 302)


# logout page
@app.route('/logout')
def logout():
    login_session.clear()
    return redirect(url_for('home'))


# signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        if username is None or password is None:
            abort(400)  # missing arguments
        if session.query(User)\
                .filter_by(username=username).first() is not None:
            flash("This username Already exist")
            return redirect('/signup', 302)
    user = User(username=username)
    user.hash_password(password)
    user.email = email
    session.add(user)
    session.commit()
    login_session['logged_in'] = True
    login_session['username'] = user.username
    return redirect(url_for('home'), 302)


# home page
@app.route('/', methods=['GET', 'POST'])
def home():
    catagories = session.query(Catagory).all()
    items = session.query(Item).order_by(Item.date.desc()).limit(10)
    return render_template('home.html', catagories=catagories, items=items)


# items per catagory page
@app.route('/catalog/<catagory_name>/items')
def catagory_items(catagory_name):
    catagories = session.query(Catagory).all()
    catagory = session.query(Catagory).filter_by(name=catagory_name).first()
    items = session.query(Item).filter_by(catagory_id=catagory.id).all()
    return render_template('catagoryItems.html', catagories=catagories,
                           catagory=catagory, items=items, counter=len(items))


# item description page
@app.route('/catalog/<catagory_name>/<item_name>')
def item_description(catagory_name, item_name):
    item = session.query(Item).filter_by(title=item_name).first()
    last_update = LastUpdate(item.date)
    return render_template('itemDescription.html', item=item,
                           lastupdate=last_update)


# create item page
@app.route('/catalog/newitem', methods=['GET', 'POST'])
@is_logged_in
def add_item():
    if request.method == 'GET':
        catagories = session.query(Catagory).all()
        return render_template('newitem.html', catagories=catagories)
    elif request.method == 'POST':
        title_ = request.form['title']
        catagory = request.form['catagory']
        description = request.form['description']
        exists = session.query(Item).filter_by(title=title_).first()
        if exists:
            flash('This item already exists')
            return redirect(request.url, 302)
        item = Item(title=title_)
        item.description = description
        catagory_object = session.query(Catagory).\
            filter_by(name=catagory).one()
        item.catagory_id = catagory_object.id
        item.author = login_session['username']
        if 'file' not in request.files:
            # print 'file not in request.files', request.files
            item.image = 'picture.png'
        else:
            file = request.files['file']
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                item.image = filename
            else:
                flash("Uploaded file format must be .png .jpg .jpeg or gif")
                return redirect(request.url, 302)
        session.add(item)
        session.commit()
        return redirect('/', 302)


# edit item page
@app.route('/catalog/<item_name>/edit', methods=['GET', 'POST'])
@is_logged_in
def edit_item(item_name):
    item = session.query(Item).filter_by(title=item_name).one()
    if request.method == 'GET':
        # check if the logged-in user is the one who has created the item
        if login_session['username'] == item.author:
            catagories = session.query(Catagory).all()
            return render_template('edititem.html', catagories=catagories,
                                   item_name=item.title)
        else:
            return render_template('/notAuthorized.html')
    elif request.method == 'POST':
        if login_session['username'] == item.author:
            title_ = request.form['title']
            catagory = request.form['catagory']
            description = request.form['description']
            catagory_object = session.query(Catagory).filter_by(name=catagory)\
                                                     .first()
            item.description = description
            # check if there is an uploaded image
            if 'file' not in request.files:
                filename = 'picture.png'
            else:
                file = request.files['file']
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'],
                              filename))
                else:
                    flash("This uploaded filetype must be .png .jpg .jpeg")
                    return redirect(request.url, 302)
            session.query(Item).filter_by(id=item.id).\
                update({Item.catagory_id: catagory_object.id,
                        Item.title: title_, Item.date: datetime.datetime.now(),
                        Item.description: description,
                        Item.author: login_session['username'],
                        Item.image: filename})
            session.commit()
            return redirect(url_for('home'), 302)
        else:
            return 'You are not authorized to Edit this item'


# delete item page
@app.route('/catalog/<item_name>/delete', methods=['GET', 'POST'])
@is_logged_in
def delete_item(item_name):
    item = session.query(Item).filter_by(title=item_name).one()
    if request.method == 'GET':
        # check if the logged-in user is the one who has created the item
        if login_session['username'] == item.author:
            return render_template('deleteitem.html', item_name=item_name)
        else:
            # redirect the user to notAuthorized page if he didn't
            # created the item
            return render_template('/notAuthorized.html')
    elif request.method == 'POST':
        if login_session['username'] == item.author:
            item = session.query(Item).filter_by(title=item_name).one()
            session.delete(item)
            session.commit()
            return redirect(url_for('home'), 302)
        else:
            return 'You are not authorized to Delete this item'


# ------ API section ------
# return all catalog API
@app.route('/catalog.json')
def catalog_api():
    output = []
    catagories = session.query(Catagory).all()
    for catagory in catagories:
        catagory_dict = catagory.serialize
        catagory_dict['items'] = []
        items = session.query(Item).filter_by(catagory_id=catagory.id).all()
        for item in items:
            catagory_dict['items'].append(item.serialize)
        output.append(catagory_dict)

    return jsonify({'catagory': output})


# return a certain catagory api
@app.route('/catalog/<catagory_name>.json')
def catagory_api(catagory_name):
    try:
        catagory = session.query(Catagory).filter_by(name=catagory_name).one()
    except:
        # this is to notify the user if he is looking for
        # an undefined catagory name
        return jsonify({'catagory name was not found': catagory_name})
    items = session.query(Item).filter_by(catagory_id=catagory.id).all()
    output = [item.serialize for item in items]
    return jsonify({catagory_name: output})


# return a certain items api
@app.route('/catalog/<catagory_name>/<item_name>.json')
def item_api(catagory_name, item_name):
    item = session.query(Item).filter_by(title=item_name).first()
    if item is not None:
        return jsonify({item_name: item.serialize})
    # this is to notify the user if he is looking for
    # an undefined catagory or item name
    return jsonify({'item or catagory name was not found': [catagory_name,
                                                            item_name]})


# Not found page
@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404


if __name__ == '__main__':
    load_database()
    app.secret_key = ''.join(random.choice(
                string.ascii_uppercase + string.digits) for x in xrange(32))
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
