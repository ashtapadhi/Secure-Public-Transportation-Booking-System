import http.server
import ssl
import json
from urllib.parse import parse_qs, urlparse
import hashlib
import base64
import os
import sqlite3
import html
import http.cookies 
import uuid
import datetime
from datetime import datetime
from datetime import timedelta



def create_session(user_id):
    session_id = str(uuid.uuid4())
    expiry = datetime.now() + timedelta(hours=1,)
    add_session(session_id,user_id,expiry)
    return session_id

def hash_password(password):
    return base64.b64encode(hashlib.sha256(password.encode()).digest()).decode()
    
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

def get_seat_availability(bus_id,travel_date):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT available_seats FROM bus_availability WHERE bus_id = ? and travel_date=?', (bus_id,travel_date))
    seats = c.fetchone()
    conn.close()
    return seats

def set_seat_availability(bus_id,travel_date,available_seats):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO bus_availability (bus_id,travel_date,available_seats ) VALUES (?, ?, ?)', (bus_id,travel_date,available_seats))
    conn.commit()
    conn.close()

def increase_seats(seats_booked,bus_id,travel_date):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        UPDATE bus_availability
        SET available_seats =available_seats+ ? WHERE bus_id = ? and travel_date=?
    ''', (seats_booked,bus_id,travel_date)) 
    conn.commit()
    conn.close()

def decrease_seats(seats_booked,bus_id,travel_date):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        UPDATE bus_availability
        SET available_seats =available_seats- ? WHERE bus_id = ? and travel_date=?
    ''', (seats_booked,bus_id,travel_date)) 
    conn.commit()
    conn.close()

def booked_seats(bus_id,date):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        SELECT count(id) FROM booking_details WHERE bus_id=? and booking_date=?
    ''', (bus_id,date))
    booking = c.fetchall()
    conn.close()
    return booking

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
        SELECT user_id,seats_booked,bus_id,booking_date FROM booking_details WHERE id=?
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

def add_session(session_id,user_id,expiry):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
            INSERT INTO sessions (session_id, user_id, expires_at) 
            VALUES (?, ?, ?)
        ''', (session_id, user_id, expiry))
    conn.commit()
    conn.close()

def get_current_user(session_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT user_id, expires_at FROM sessions WHERE session_id = ?', (session_id,))
    session = c.fetchone()
    conn.close()
    return session

def delete_session(session_id):

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:

        c.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
        conn.close()
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
            user_id = self.get_user_by_session()
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
        elif self.path.startswith('/bookpage'):
            bus_id = query.get('bus_id', [None])[0]
            travel_date = query.get('travel_date', [None])[0]
            self.send_response(200)
            print("ok")
            self.send_header('content-type','text/html')
            self.end_headers()
            booking_page = load_template('book.html')
            booking_page = booking_page.replace('{{bus_id}}', bus_id)
            booking_page = booking_page.replace('{{travel_date}}', travel_date)
            self.wfile.write(booking_page.encode())
        elif self.path=='/profile':
            user_id = self.get_user_by_session()
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
            travel_date=query.get('travel_date', [None])[0]
            print(travel_date)
            if bus_id:
                bus = get_bus_details(bus_id)
                print("travel__date",travel_date)
                available_seats=get_seat_availability(bus_id,travel_date)
                print("available seats",available_seats)
                if bus:
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        'bus_name': bus[1],
                        'bus_fare': bus[2],
                        'available_seats': available_seats,
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
            user_id = self.get_user_by_session()
            if user_id:
                user=get_user_details(user_id)
                if user:
                    #print("nam: ",user[2])
                    self.send_response(200)
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
        elif self.path=="/editdetails":
            user_id = self.get_user_by_session()
            if user_id:
                user=get_user_details(user_id)
                if user:
                    self.send_response(200)
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
            user_id = self.get_user_by_session()
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
            user_id = self.get_user_by_session()
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
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(booking_list).encode())          
                    return
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'booking details not found'}).encode())
        elif self.path=="/bookings":
            user_id = self.get_user_by_session()
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
                self.end_headers()
                self.wfile.write(json.dumps({'message': 'Login successful'}).encode())
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
            else:
                self.send_response(409)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'User already exists'}).encode())
        elif self.path == '/buses':
            data = json.loads(post_data)
            from_city = data['from']
            to_city = data['to']
            travel_date=data['traveldate']
            print("ok till now")
            buses_list=[]
            buses = get_buses(from_city, to_city)
            for bus in buses:
                    available_seats = get_seat_availability(bus[0], travel_date)
                    if available_seats is not None: 
                        print("available seats none")
                        seats_available = available_seats
                    else:
                        print("setting available seats")
                        set_seat_availability(bus[0], travel_date, bus[4])
                        seats_available = bus[4]

                    buses_list.append({
                            'id': bus[0],
                            'bus_name': bus[1],
                            'bus_fare': bus[2],
                            'ac': bus[3],
                            'available_seats': seats_available
                    })


            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(buses_list).encode())

        elif self.path == '/book':
            user_id = self.get_user_by_session()
            if user_id:
                data = json.loads(post_data)
                bus_id = data['bus_id']
                bus_details=get_bus_details(bus_id)
                bus_name=bus_details[1]
                route_id=bus_details[5]
                route_start=bus_details[4]
                route_end=bus_details[5]
                no_of_pass=data['no_of_pass']
                totalfare=data['total_fare']
                travel_date=data['travel_date']
                print("travel date", travel_date)
                add_booking(user_id,bus_id,route_id,bus_name,route_start,route_end,travel_date,no_of_pass,totalfare)
                decrease_seats(no_of_pass,bus_id,travel_date)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'message': 'Booking successful'}).encode())
            else:
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Unauthorized'}).encode())

            
       
        elif self.path=='/logout':
            session_id = self.get_cookie()
            sessions=get_current_user(session_id)
            if session_id and sessions:
                delete_session(session_id)
            cookie = http.cookies.SimpleCookie()
            cookie['session_id'] = ''
            cookie['session_id']['path'] = '/'
            cookie['session_id']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Set-Cookie', cookie.output(header='', sep=''))
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Logout successful'}).encode())
     

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
            current_user_id = self.get_user_by_session()
            user=get_user_from_booking(booking_id)
            if not user:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'booking inot found'}).encode())
                return
            if user[0]!=current_user_id:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'unauthorized to cancel booking'}).encode())
                return
            result=cancel_booking(booking_id)
            increase_seats(user[1],user[2],user[3])
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
            user_id = self.get_user_by_session()
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
    def do_PUT(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        raw_data = parse_qs(post_data.decode())
        data = sanitize_input(raw_data)
        if self.path=='/editdetails':
            user_id = self.get_user_by_session()
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

    def get_user_by_session(self):
        session_id=self.get_cookie()
        session=get_current_user(session_id)
        if session:
            user_id, expires_at = session
            if datetime.now() < datetime.fromisoformat(expires_at):
                return user_id

        return None
    def get_cookie(self):
        cookies = self.headers.get('Cookie')
        if not cookies:
            return None
        cookies = cookies.split('; ')
        session_id = None
        for cookie in cookies:
            if cookie.startswith('session_id='):
                session_id = cookie.split('=')[1]
                return session_id
        if not session_id:
            return None


if __name__ == '__main__':
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='cert.pem',keyfile='key.pem')
    context.check_hostname=False
    with http.server.HTTPServer(('localhost', 443), RequestHandler) as httpd:
        httpd.socket=context.wrap_socket(httpd.socket,server_side=True)
        print("Serving on https://localhost:443")
        httpd.serve_forever()
   