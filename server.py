import http.server
import ssl
import json
from urllib.parse import parse_qs, urlparse
import jwt
import datetime
import hashlib
import base64
import os
from dotenv import load_dotenv
import sqlite3
import html
from http.cookies import SimpleCookie
import uuid


load_dotenv()

SECRET_KEY = os.environ.get('SECRET_KEY')
SESSIONS = {}
if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set for application")

def create_session(username):
    session_id = str(uuid.uuid4())
    SESSIONS[session_id] = username
    return session_id

def get_user_by_session(session_id):
    return SESSIONS.get(session_id)

def hash_password(password):
    return base64.b64encode(hashlib.sha256(password.encode()).digest()).decode()

'''def create_token(username):
    payload = {
       'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=5, minutes=30)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def decode_token(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None'''
    
def sanitize_input(data):
    return {k: html.escape(v[0]) for k, v in data.items()}

def load_template(filename):
    with open(os.path.join('templates', filename), 'r') as file:
        return file.read()
    


def get_user(username):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT username, password_hash FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    return user

def delete_user(user_id):
    conn=sqlite3.connect('database.db')
    c=conn.cursor()
    result=c.execute('DELETE FROM users WHERE user_id=?',(user_id,))
    conn.close()
    return result

# Utility function to add user to the database
def add_user(name, username, password, email, phonenumber):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (name, username, password_hash, email, phone_number) VALUES (?, ?, ?, ?, ?)', 
              (name, username, password, email, phonenumber))
    conn.commit()
    conn.close()

def get_buses(from_city, to_city):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        SELECT buses.id, buses.bus_name, buses.bus_fare, buses.ac, buses.available_seats 
        FROM buses 
        JOIN routes ON buses.route_id = routes.id 
        WHERE routes.route_start = ? AND routes.route_end = ?
    ''', (from_city, to_city))
    buses = c.fetchall()
    conn.close()
    return buses

def get_bus_details(bus_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        SELECT buses.id, buses.bus_name, buses.bus_fare, buses.available_seats, routes.route_start, routes.route_end 
        FROM buses 
        JOIN routes ON buses.route_id = routes.id 
        WHERE buses.id = ?
    ''', (bus_id,))
    bus = c.fetchone()
    conn.close()
    return bus

class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def serve_static_file(self, path, content_type):
        try:
            with open(path, 'rb') as file:
                self.send_response(200)
                self.send_header('Content-type', content_type)
                self.end_headers()
                self.wfile.write(file.read())
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'File not found')
    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query = parse_qs(parsed_path.query)
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(load_template('index.html').encode())
        elif self.path == '/login':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(load_template('login.html').encode())
        elif self.path == '/register':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(load_template('register.html').encode())
        elif self.path == '/dashboard':
            session_id = self.get_cookie('session_id') #session
            username = get_user_by_session(session_id)
            if username:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(load_template('dashboard.html').encode())
            else:
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Unauthorized'}).encode())
            '''token = self.headers.get('Authorization') #code for token handling
            if token:
                token = token.split(' ')[1]
                decoded_token = decode_token(token)
                if decoded_token:
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    username = decoded_token['username']
                    self.wfile.write(json.dumps({'username': username}).encode())
                    return
            self.send_response(401)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Unauthorized'}).encode())'''
            '''self.send_response(200) #without token
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(load_template('dashboard.html').encode())
            return'''
        elif self.path.startswith('/book'):
            bus_id = self.path.split('bus_id=')[-1]
            self.send_response(200)
            print("ok")
            self.send_header('content-type','text/html')
            self.end_headers()
            booking_page = load_template('book.html').replace('{{bus_id}}', bus_id)
            self.wfile.write(booking_page.encode())
        elif self.path=='/profile':
            self.send_response(200)
            self.send_header('content-type','text/html')
            self.end_headers()
            self.wfile.write(load_template('profile.html').encode())
        elif self.path.startswith('/busdetails'):
            bus_id = query.get('bus_id', [None])[0]
            if bus_id:
                bus = get_bus_details(bus_id)
                if bus:
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        'bus_name': bus[1],
                        'bus_fare': bus[2],
                        'available_seats': bus[3],
                        'route_start': bus[4],
                        'route_end': bus[5]
                    }).encode())
                    return
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Bus not found'}).encode())
        elif path == '/menu.html':
            self.send_response(200)
            self.send_header('content-type','text/html')
            self.end_headers()
            self.wfile.write(load_template('menu.html').encode())
        elif path.startswith('/static'):
            # Serve static files like CSS
            content_type = 'text/css' if path.endswith('.css') else 'application/octet-stream'
            self.serve_static_file(path[1:], content_type)
        else:
            self.send_response(404)
            self.end_headers()
        
        

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        raw_data = parse_qs(post_data.decode())
        data = sanitize_input(raw_data)

        if self.path == '/login':
            username = data.get('username')
            password = data.get('password')
            user = get_user(username)
            if user and user[1] == hash_password(password):
                session_id = create_session(username)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Set-Cookie', f'session_id={session_id}; HttpOnly')
                self.end_headers()
                self.wfile.write(json.dumps({'message': 'Login successful'}).encode())
                '''token = create_token(username) #token
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'token': token}).encode())'''
            else:
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Invalid credentials'}).encode())
        elif self.path == '/register':
            name = data.get('name')[0]
            username = data.get('username')
            password = data.get('password')
            email = data.get('email')[0]
            phonenumber = data.get('phone_number')[0]

            if not get_user(username):
               add_user(name, username, hash_password(password), email, phonenumber)
               session_id=create_session(username)
               self.send_response(200)
               self.send_header('conten-type','application/json')
               self.send_header('Set-Cookie', f'session_id={session_id}; HttpOnly')
               self.end_headers()
               self.wfile.write(json.dumps({'message': 'Registration successful'}).encode())

               '''add_user(name, username, hash_password(password), email, phonenumber) #token
                token = create_token(username)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'token': token}).encode())'''
            else:
                self.send_response(409)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'User already exists'}).encode())
        elif self.path == '/buses':
            data = json.loads(post_data)
            from_city = data['from']
            to_city = data['to']
            buses = get_buses(from_city, to_city)
            buses_list = [{'id': bus[0], 'bus_name': bus[1], 'bus_fare': bus[2], 'ac': bus[3], 'available_seats': bus[4]} for bus in buses]

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(buses_list).encode())
        elif self.path == '/book':
            session_id = self.get_cookie('session_id') #session
            username = get_user_by_session(session_id)
            if username:
                data = json.loads(post_data)
                bus_id = data['bus_id']
                # Add booking logic here
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'message': 'Booking successful'}).encode())
            else:
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Unauthorized'}).encode())
            '''token = self.headers.get('Authorization').split(' ')[1] #token
            decoded_token = decode_token(token)
            if decoded_token:
                data = json.loads(post_data)
                bus_id = data['bus_id']
                # Add booking logic here
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'message': 'Booking successful'}).encode())'''
            
        elif self.path.startswith('/delete'):
            id=self.headers.id
            result=delete_user(id)
            if result:
                self.send_response(200)
                
    def get_cookie(self, name):
        if 'Cookie' in self.headers:
            cookies = SimpleCookie(self.headers['Cookie'])
            if name in cookies:
                return cookies[name].value
        return None

if __name__ == '__main__':
    httpd = http.server.HTTPServer(('localhost', 4443), RequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='key.pem', certfile='cert.pem', server_side=True)
    print("Serving on https://localhost:4443")
    httpd.serve_forever()