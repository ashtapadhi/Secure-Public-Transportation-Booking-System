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
import http.cookies 
import uuid
import requests

load_dotenv()

SECRET_KEY = os.environ.get('SECRET_KEY')
SESSIONS = {}
if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set for application")

def create_session(user_id):
    session_id = str(uuid.uuid4())
    SESSIONS[session_id] = user_id
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
    c.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    return user
def get_user_details(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT name, username, email, phone_number FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    return user


def delete_user(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        rows_affected = c.rowcount
        conn.close()
        return rows_affected > 0
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.close()
        return False

# Utility function to add user to the database
def add_user(name, username, password, email, phonenumber):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (name, username, password_hash, email, phone_number) VALUES (?, ?, ?, ?, ?)', 
              (name, username, password, email, phonenumber))
    conn.commit()
    conn.close()

def update_user(user_id, name, username, email, phone):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        UPDATE users
        SET name = ?, username = ?, email = ?, phone_number = ?
        WHERE id = ?
    ''', (name, username, email, phone, user_id)) 
    conn.commit()
    conn.close()

def add_booking(user_id,bus_id,route_id,bus_name,route_start,route_end,travel_date,no_of_pass,total_fare):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO booking_details (user_id,bus_id,route_id,bus_name,route_start,route_end,booking_date,seats_booked,total_fare ) VALUES (?, ?, ?, ?, ?,?,?,?,?)', 
              (user_id,bus_id,route_id,bus_name,route_start,route_end,travel_date,no_of_pass,total_fare))
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
        SELECT buses.id, buses.bus_name, buses.bus_fare, buses.available_seats, routes.route_start, routes.route_end, route_id 
        FROM buses 
        JOIN routes ON buses.route_id = routes.id 
        WHERE buses.id = ?
    ''', (bus_id,))
    bus = c.fetchone()
    conn.close()
    return bus

def get_booking_details(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        SELECT id,user_id,bus_id,bus_name,route_start,route_end,booking_date,seats_booked,total_fare FROM booking_details WHERE user_id=?
    ''', (user_id,))
    booking = c.fetchall()
    conn.close()
    return booking

def get_route_details(route_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        SELECT route_start,route_end FROM routes WHERE id=?
    ''', (route_id,))
    route = c.fetchone()
    conn.close()
    return route

def get_user_from_booking(booking_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        SELECT user_id FROM booking_details WHERE id=?
    ''', (booking_id,))
    user = c.fetchone()
    conn.close()
    return user

def cancel_booking(booking_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        c.execute('DELETE FROM booking_details WHERE id = ?', (booking_id,))
        conn.commit()
        rows_affected = c.rowcount
        conn.close()
        return rows_affected > 0
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.close()
        return False

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
            user_id = get_user_by_session(session_id)
            print("user ", user_id)
            if user_id:
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
        elif self.path.startswith('/bookpage'):
            bus_id = self.path.split('bus_id=')[-1]
            self.send_response(200)
            print("ok")
            self.send_header('content-type','text/html')
            self.end_headers()
            booking_page = load_template('book.html').replace('{{bus_id}}', bus_id)
            self.wfile.write(booking_page.encode())
        elif self.path=='/profile':
            session_id = self.get_cookie('session_id') #session
            user_id = get_user_by_session(session_id)
            if user_id:
                self.send_response(200)
                self.send_header('content-type','text/html')
                self.end_headers()
                self.wfile.write(load_template('profile.html').encode())
            else:
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Unauthorized'}).encode())

            
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
        elif self.path == '/menu.html':
            self.send_response(200)
            self.send_header('content-type','text/html')
            self.end_headers()
            self.wfile.write(load_template('menu.html').encode())
        elif self.path.startswith('/static'):
            # Serve static files like CSS
            content_type = 'text/css' if path.endswith('.css') else 'application/octet-stream'
            self.serve_static_file(path[1:], content_type)
        elif self.path=='/userdetails':
            session_id = self.get_cookie('session_id') #session
            user_id = get_user_by_session(session_id)
            print("session:",user_id)
            if user_id:
                user=get_user_details(user_id)
                if user:
                    print("nam: ",user[2])
                    self.send_response(200)
                    #self.send_header('content-type','text/html')
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        'name': user[0],
                        'username': user[1],
                        'email': user[2],
                        'phone_number': user[3]
                    }).encode())
                    return
                    #self.wfile.write(load_template('profile.html').encode())
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'user details not found'}).encode())
        elif self.path=="/editdetails":
            session_id = self.get_cookie('session_id') #session
            user_id = get_user_by_session(session_id)
            if user_id:
                user=get_user_details(user_id)
                if user:
                    self.send_response(200)
                    #self.send_header('content-type','text/html')
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        'name': user[0],
                        'username': user[1],
                        'email': user[2],
                        'phone_number': user[3]
                    }).encode())
                    return
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'user details not found'}).encode())

        elif self.path=="/edit":
            session_id = self.get_cookie('session_id') #session
            user_id = get_user_by_session(session_id)
            if user_id:
                self.send_response(200)
                self.send_header('content-type','text/html')
                self.end_headers()
                self.wfile.write(load_template('edituser.html').encode())
            else:
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Unauthorized'}).encode())
        elif self.path=="/mybookings":
            session_id = self.get_cookie('session_id') #session
            user_id = get_user_by_session(session_id)
            if user_id:
                  bookings=get_booking_details(user_id)
                
                  if bookings:
                    booking_list = [{'booking_id': booking[0],
                        'busname': booking[3],
                        'from': booking[4],
                        'to':booking[5],
                        'traveldate': booking[6],
                        'noofseats': booking[7],
                        'totalfare':booking[8]} for booking in bookings]
               
                    self.send_response(200)
                    #self.send_header('content-type','text/html')
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(booking_list).encode())
                    
                    return
                    #self.wfile.write(load_template('profile.html').encode())
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'booking details not found'}).encode())
        elif self.path=="/bookings":
            session_id = self.get_cookie('session_id') #session
            user_id = get_user_by_session(session_id)
            if user_id:
                self.send_response(200)
                self.send_header('content-type','text/html')
                self.end_headers()
                self.wfile.write(load_template('mybooking.html').encode())
            else:
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Unauthorized'}).encode())

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
            if user and user[2] == hash_password(password):
                session_id = create_session(user[0])
                cookie = http.cookies.SimpleCookie()
                cookie['session_id'] = session_id
                cookie['session_id']['path'] = '/'
                cookie['session_id']['httponly'] = True
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Set-Cookie', cookie.output(header='', sep=''))
                #self.send_header('Set-Cookie', f'session_id={session_id}; HttpOnly')
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
            name = data.get('name')
            username = data.get('username')
            password = data.get('password')
            email = data.get('email')
            phonenumber = data.get('phone_number')

            if not get_user(username):
               add_user(name, username, hash_password(password), email, phonenumber)
               user = get_user(username)
               session_id = create_session(user[0])
               cookie = http.cookies.SimpleCookie()
               cookie['session_id'] = session_id
               cookie['session_id']['path'] = '/'
               cookie['session_id']['httponly'] = True
               self.send_response(200)
               self.send_header('conten-type','application/json')
               self.send_header('Set-Cookie', cookie.output(header='', sep=''))
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
            user_id = get_user_by_session(session_id)
            if user_id:
                data = json.loads(post_data)
                bus_id = data['bus_id']
                bus_details=get_bus_details(bus_id)
                bus_name=bus_details[1]
                route_id=bus_details[5]
                route_start=bus_details[3]
                route_end=bus_details[4]
                no_of_pass=data['no_of_pass']
                totalfare=data['total_fare']
                travel_date=data['travel_date']
                add_booking(user_id,bus_id,route_id,bus_name,route_start,route_end,travel_date,no_of_pass,totalfare)
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
            
       
        elif self.path=='/logout':
            session_id = self.get_cookie('session_id')
            if session_id and session_id in SESSIONS:
                del SESSIONS[session_id]
            cookie = http.cookies.SimpleCookie()
            cookie['session_id'] = ''
            cookie['session_id']['path'] = '/'
            cookie['session_id']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Set-Cookie', cookie.output(header='', sep=''))
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Logout successful'}).encode())
        elif self.path=='/editdetails':
            session_id = self.get_cookie('session_id') #session
            user_id = get_user_by_session(session_id)
            if user_id:
                name = data.get('name')
                username = data.get('username')
                email = data.get('email')
                phonenumber = data.get('phone_number')
                user=get_user_details(user_id)
                oldusername= user[1]
                if oldusername!=username:


                    if not get_user(username):
                        update_user(user_id,name,username,email,phonenumber)
                        self.send_response(200)
                        self.send_header('conten-type','application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'message': 'Registration successful'}).encode())
                    else:
                        self.send_response(409)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'error': 'Username already taken, Please try another username'}).encode())
                else:
                    update_user(user_id,name,username,email,phonenumber)
                    self.send_response(200)
                    self.send_header('conten-type','application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'message': 'Registration successful'}).encode())
            else:
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Invalid session'}).encode())

        else:
            self.send_response(401)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Invalid session'}).encode())
    

    def do_DELETE(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query = parse_qs(parsed_path.query)
        if self.path.startswith('/cancel'):
            booking_id = query.get('booking_id', [None])[0]
            if not booking_id:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'booking_id is required'}).encode())
                return
            session_id = self.get_cookie('session_id') #session
            current_user_id = get_user_by_session(session_id)
            user_id=get_user_from_booking(booking_id)
            if not user_id:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'booking inot found'}).encode())
                return
            if user_id[0]!=current_user_id:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'unauthorized to cancel booking'}).encode())
                return
            result=cancel_booking(booking_id)
            if result:
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'message': 'successfully cancelled'}).encode())
            else:
                self.send_response(404)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'cancellation not possible'}).encode())
            
        elif self.path.startswith('/delete'):
            #data = json.loads(post_data)
            #user_id = data['user_id']
            session_id = self.get_cookie('session_id') #session
            user_id = get_user_by_session(session_id)
            result=delete_user(user_id)
            if result:
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'message': 'successfully deleted'}).encode())
            else:
                self.send_response(404)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Deletion not possible'}).encode())

    def get_cookie(self, name):
        if 'Cookie' in self.headers:
            cookies = http.cookies.SimpleCookie(self.headers['Cookie'])
            if name in cookies:
                return cookies[name].value
        return None

if __name__ == '__main__':
    httpd = http.server.HTTPServer(('localhost', 4443), RequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='key.pem', certfile='cert.pem', server_side=True)
    print("Serving on https://localhost:4443")
    httpd.serve_forever()