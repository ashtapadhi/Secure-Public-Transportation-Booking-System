import http.server
import ssl
import json
from urllib.parse import parse_qs
import jwt
import datetime
import hashlib
import base64
import os
from dotenv import load_dotenv
import sqlite3
load_dotenv()

SECRET_KEY = os.environ.get('SECRET_KEY')

if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set for application")





def hash_password(password):
    return base64.b64encode(hashlib.sha256(password.encode()).digest()).decode()

def create_token(username):
    payload={
        'username':username,
        'exp':datetime.datetime.utcnow() + datetime.timedelta(hours=5,minutes=30)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    print(f"Token created: {token}")  # Debugging output
    return token

def decode_token(token):
    try:
        decoded=jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        print(f"Token decoded: {decoded}") 
        return decoded
    
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def load_template(filename):
    with open(os.path.join('templates', filename), 'r') as file:
        return file.read()

def get_user(username):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT username, password FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    return user

# Utility function to add user to the database
def add_user(name,username, password,email):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (name,username, password,email) VALUES (?, ?,?,?)', (name,username, password,email))
    conn.commit()
    conn.close()


class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print("header",self.headers)
        if self.path=='/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(load_template('index.html').encode())
        elif self.path=='/login':
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(load_template('login.html').encode())
        elif self.path=='/register':
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(load_template('register.html').encode())
        elif self.path=='/dashboard':
            token=self.headers.get('Authorization')
            print(f"Received token: {token}")
            if token:
                token=token.split(' ')[1]
                decoded_token=decode_token(token)
                if decoded_token:
                    self.send_response(200)
                    self.send_header('Content-type','application/jason')
                    self.end_headers()
                    username=decoded_token['username']
                    self.wfile.write(json.dumps({'username': username}).encode())
                    return
            self.send_response(401)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Unauthorized'}).encode())




    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = parse_qs(post_data.decode())


        if self.path == '/login':
            username = data.get('username')[0]
            password = data.get('password')[0]
            user = get_user(username)
            if user and user[1] == hash_password(password):
                token = create_token(username)
                self.send_response(200)
                print("allgood")
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'token': token}).encode())
            else:
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Invalid credentials'}).encode())
        elif self.path == '/register':
            name=data.get('name')[0]
            username = data.get('username')[0]
            password = data.get('password')[0]
            email=data.get('email')[0]

            if not get_user(username):
                add_user(name,username, hash_password(password),email)
                token = create_token(username)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'token': token}).encode())
            else:
                self.send_response(409)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'User already exists'}).encode())

    


if __name__ == '__main__':
    httpd = http.server.HTTPServer(('localhost', 4443), RequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket,
                                  keyfile='key.pem',
                                  certfile='cert.pem',
                                  server_side=True)
    print("Serving on https://localhost:4443")
    httpd.serve_forever()