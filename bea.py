
from flask import Flask,request,make_response,jsonify
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
import datetime
from functools import wraps
from oauthlib.oauth2.rfc6749 import tokens
from oauthlib.oauth2 import Server


application = app = Flask(__name__)

app.config['SECRET_KEY']='secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Users2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    public_id = db.Column(db.String(50),unique=True)
    Full_name = db.Column(db.String(80))
    User_password = db.Column(db.String(80))
    bearer_token = db.Column(db.String(80), unique=True)

def Token(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None

        try:
            auth = request.authorization
            if not auth.Token:
                return jsonify({'message': 'token missing1'}), 401
            elif ('Token' in auth):
                token = auth.Bearer_Token
        except:
            if'Bearer-token' in request.headers:
                token=request.headers['Bearer-token']
        if not token:
            return jsonify({'message': 'token missing','auth':auth}),401
        try:
            current_user = Users.query.filter_by(bearer_token = token).first()
        except:
            return jsonify({'message': 'not a valid token'}), 401
        return f(current_user,*args,**kwargs)
    return decorated





@app.route('/',methods=['GET','POST'])
@Token
def Hello_world(current_user):
    return("Hello World")

#
#
# @app.route('/create',methods=['POST'])
# def Create_user():
#     data = request.get_json()
#     hashed_password = generate_password_hash(data['password'],method='sha256')
#     new_user = Users(public_id= str(uuid.uuid4()),Full_name=data['name'],User_password =hashed_password,bearer_token=str(uuid.uuid4()))
#     db.session.add(new_user)
#     db.session.commit()
#     return 'User Created'


#
# @app.route('/login',)
# def login():
#     auth = request.authorization
#     if not auth or not auth.username or not auth.password:
#         return make_response("Not verified",401,{'WWW-Authenticate':'Basic realm="Login requtired!"'})
#     user = Users.query.filter_by(Full_name=auth.username).first()
#     if not user:
#         return make_response("Not verified",401,{'WWW-Authenticate':'Basic realm="Login requtired!"'})
#     if check_password_hash(user.User_password,auth.password):
#         token = user.bearer_token
#
#         return jsonify({'token': token,'auth':auth})
#     return make_response("Not verified",401,{'WWW-Authenticate':'Basic realm="Login requtired!"'})


if __name__ == '__main__':
    app.run(host='0.0.0.0',port=80,debug=True)
