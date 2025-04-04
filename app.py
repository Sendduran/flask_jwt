from flask import Flask, request, jsonify, make_response, render_template, session
import jwt
import time
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = 'd2c45c09095b440d8be4f9ba15726335'

users = {
    'customer' : {'password': 'customer', 'role': 'customer', 'apiCount':0 , 'apiLastCall' : None, 'apiWindowStart': None},
    'manager' : {'password': 'manager', 'role': 'manager',  'apiCount':0 , 'apiLastCall' : None, 'apiWindowStart': None},
    'admin' : {'password': 'admin', 'role': 'admin',  'apiCount':0 , 'apiLastCall' : None, 'apiWindowStart': None}
}


@app.route('/login', methods = ['GET','POST'])
def login():
    auth = request.authorization
    if not auth or not auth['username'] or not auth['password']:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    user = users.get(auth.username)
    if not user or user['password'] != auth.password:
        return make_response('Invalid User or Password', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    token = jwt.encode({
        'username': auth.username,
        'role': user['role']} , app.config['SECRET_KEY'] )
    
    return jsonify({'token': token})


def role_required(roles):
    def wrapper (f):
        @wraps(f)
        def decorated_role_access(*args , **kwargs):
            token = request.headers['Authorization'].split(" ")[0]
            print(token)
            if not token : 
                return jsonify({'message': 'Token is missing !'}), 403             
            try :                  
                decoded_jwt = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])            
            except:
                return jsonify({'message': 'Invalid Token ! '}), 403
            
            if decoded_jwt['role'] not in roles:
                return jsonify({'message': 'You are not authorized !' }) , 401
                    
            return f (*args , **kwargs)
        return decorated_role_access
    return wrapper
        
def token_rate_limiter(max_requests = 4 , window_seconds = 60):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):            
            token = request.headers["Authorization"]
            if not token : 
                return jsonify({'message': 'Token is missing !'}), 403             
            try :                  
                decoded_jwt = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])            
            except:
                    return jsonify({'message': 'Invalid Token !'}), 403
            username = decoded_jwt['username']
            
            user = users[username]
            current_time = time.time()

            # Initialize rate limiting for user if first call
            if user['apiWindowStart'] is None:
                user['apiWindowStart'] = current_time
                user['apiCount'] = 0
            
            # Reset counter if window has expired
            if current_time - user['apiWindowStart'] > window_seconds:
                user['apiCount'] = 0
                user['apiWindowStart'] = current_time
            
            # Check if rate limit exceeded
            if user['apiCount'] >= max_requests:
                time_remaining = window_seconds - (current_time - user['apiWindowStart'])
                return jsonify({
                    'message': 'Rate limit exceeded',
                    'retry_after_seconds': int(time_remaining),
                    'limit': max_requests,
                    'window_seconds': window_seconds
                }), 429
            
            # Update call count and timestamp
            user['apiCount'] += 1
            user['apiLastCall'] = current_time


            return f(*args, **kwargs)
        return wrapper
    return decorator
               

       

# accessible by all roles
@app.route('/orders/view', methods=['POST'])
@role_required(['admin', 'customer', 'manager'])
@token_rate_limiter(4, 60)
def view_orders():    
    return ''

# accessible by manager, admin
@app.route('/orders/update')
@role_required(['admin', 'manager'])
def update_orders():
    return ''

# accessible by admin only
@app.route('/orders/delete')
@role_required(['admin'])
def delete_orders():
    return ''


if __name__ == '__main__':
    app.run(debug=True)