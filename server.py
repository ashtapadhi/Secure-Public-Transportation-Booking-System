import http.server
import ssl
import json
from urllib.parse import parse_qs, urlparse, quote
from cryptography.fernet import Fernet
import bcrypt
import hashlib
import base64
import os
from pysqlcipher3 import dbapi2 as sqlite
import html
import http.cookies
import uuid
import datetime
from datetime import datetime, timedelta
from dotenv import load_dotenv
import secrets
import random

load_dotenv()

#load confidential info from environment
db_name = os.getenv('DB_NAME')

key= os.getenv('KEY')
cipher_suite = Fernet(key)

#template management function

def load_template(filename, nonce):
    """Load HTML template from the templates directory and replace the nonce placeholder."""
    with open(os.path.join('templates', filename), 'r') as file:
        template = file.read()
        # Replace the nonce placeholder with the actual nonce
        return template.replace('{{nonce}}', nonce)
    

#security functions    
    
# Generate anti-CSRF token
def generate_csrf_token():
    return secrets.token_hex(16)  # Generate a 32-character random token


def hash_data(data):
    """Hash the data using SHA-256 and base64 encoding."""
    if isinstance(data, str):
        data_bytes = data.encode()
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        raise ValueError("Data must be a string or bytes.")

    hashed_data = hashlib.sha256(data_bytes).digest()
    encoded_data = base64.b64encode(hashed_data).decode()
    return encoded_data
    

def hash_password(password):
    """Hash the user password using bcrypt and encoding."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def verify_password(entered_password,password):
    """Verify user password using bcrypt."""
    return bcrypt.checkpw(entered_password.encode('utf-8'), password.encode('utf-8'))

def sanitize_input(data):
    """Sanitize user input to prevent XSS attacks."""
    sanitized_query = {}
    for key, values in data.items():
        sanitized_values = []
        for value in values:
            # Sanitize by removing leading and trailing spaces
            sanitized_value = value.strip()
            # Add more sanitization checks as needed, such as type validation, regex matching, etc.
            sanitized_values.append(sanitized_value)
        sanitized_query[key] = sanitized_values
    return {k: html.escape(v[0]) for k, v in sanitized_query.items()}


# function to encrypt data
def encrypt_data(data, cipher_suite):
    # Ensure data is bytes-like object
    if isinstance(data, str):
        data = data.encode('utf-8')
    encrypted_data = cipher_suite.encrypt(data)
    return encrypted_data

#function to decrypt data
def decrypt_data(encrypted_data,cipher_suite):
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

# Database Operations


#session management functions

def create_session(user_id):
    """Create a new session for the user."""
    session_id = str(uuid.uuid4())
    expiry = datetime.now() + timedelta(hours=1)
    encrypted_session_id=encrypt_data(session_id,cipher_suite)
    encrypted_expiry=encrypt_data(str(expiry),cipher_suite)
    session_id_hash=hash_data(session_id)
    add_session(encrypted_session_id, user_id, encrypted_expiry,session_id_hash)
    return session_id


def add_session(session_id, user_id, expiry,session_id_hash):
    """Add a new session to the database."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('''
        INSERT INTO sessions (session_id, user_id, expires_at,session_id_hash) 
        VALUES (?, ?, ?,?)
    ''', (session_id, user_id, expiry,session_id_hash))
    conn.commit()
    conn.close()


def get_current_user(session_id):
    """Retrieve current user session information by session_id."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    hashed_session_id=hash_data(session_id)
    c.execute('SELECT user_id, expires_at FROM sessions WHERE session_id_hash = ?', (hashed_session_id,))
    session = c.fetchone()
    if session:
        user_id, encrypted_expiry= session
        decrypted_expiry = decrypt_data(encrypted_expiry,cipher_suite)
        session_with_decrypted_data = (user_id, decrypted_expiry)
        conn.close()
        return session_with_decrypted_data
    else:
        conn.close()
        return None



def delete_session(session_id):
    """Delete a session by session_id."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    hashed_session_id=hash_data(session_id)
    try:
        #encrypted_session_id=encrypt_data(session_id,cipher_suite)
        c.execute('DELETE FROM sessions WHERE session_id_hash = ?', (hashed_session_id,))
        conn.commit()
        rows_affected = c.rowcount
        conn.close()
        return rows_affected > 0
    except sqlite.Error as e:
        print(f"Database error: {e}")
        conn.close()
        return False
    


#user management functions
def get_user(username):
    """Retrieve user details from the database."""
    hashed_username=hash_data(username)
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('SELECT id, username, password_hash FROM users WHERE username_hash = ?', (hashed_username,))
    user = c.fetchone()
    if user:
        user_id, encrypted_username, encrypted_password= user
        decrypted_username = decrypt_data(encrypted_username,cipher_suite)
        decrypted_password = decrypt_data(encrypted_password,cipher_suite)
        user_with_decrypted_data = (user_id, decrypted_username, decrypted_password)
        conn.close()
        return user_with_decrypted_data
    else:
        conn.close()
        return None


def get_user_details(user_id):
    """Retrieve user details by user_id from the database."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('SELECT name, username, email, phone_number FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    if user:
        name, encrypted_username, encrypted_email, encrypted_phone = user
        decrypted_username = decrypt_data(encrypted_username,cipher_suite)
        decrypted_email = decrypt_data(encrypted_email,cipher_suite)
        decrypted_phone = decrypt_data(encrypted_phone,cipher_suite)
        user_with_decrypted_data = (name, decrypted_username, decrypted_email, decrypted_phone)
        conn.close()
        return user_with_decrypted_data
    else:
        conn.close()
        return None
        
        


def delete_user(user_id):
    """Delete user from the database."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    try:
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        rows_affected = c.rowcount
        conn.close()
        return rows_affected > 0
    except sqlite.Error as e:
        print(f"Database error: {e}")
        conn.close()
        return False


def add_user(name, username, password, email, phonenumber):
    """Add a new user to the database."""
    encrypted_username=encrypt_data(username,cipher_suite)
    encrypted_password=encrypt_data(password,cipher_suite)
    encrypted_email=encrypt_data(email,cipher_suite)
    encrypted_phonenumber=encrypt_data(phonenumber,cipher_suite)
    hashed_username=hash_data(username)
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('INSERT INTO users (name, username, password_hash, email, phone_number, username_hash) VALUES (?, ?, ?, ?, ?,?)', 
              (name, encrypted_username, encrypted_password, encrypted_email, encrypted_phonenumber,hashed_username))
    conn.commit()
    conn.close()


def update_user(user_id, name, username, email, phone):
    """Update user details in the database."""
    encrypted_username=encrypt_data(username,cipher_suite)
    encrypted_email=encrypt_data(email,cipher_suite)
    encrypted_phonenumber=encrypt_data(phone,cipher_suite)
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('''
        UPDATE users
        SET name = ?, username = ?, email = ?, phone_number = ?
        WHERE id = ?
    ''', (name, encrypted_username, encrypted_email, encrypted_phonenumber, user_id)) 
    conn.commit()
    conn.close()

def update_password(user_id,new_password):
    """Update user password in the database."""
    encrypted_password=encrypt_data(new_password,cipher_suite)
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('''
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
    ''', (encrypted_password, user_id)) 
    conn.commit()
    conn.close()

def get_user_from_booking(booking_id):
    """Retrieve user details from booking information."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('''
        SELECT user_id, seats_booked, bus_id, booking_date 
        FROM booking_details 
        WHERE id = ?
    ''', (booking_id,))
    user = c.fetchone()
    conn.close()
    return user

#booking management functions
    
def add_booking(user_id, bus_id, route_id, bus_name, route_start, route_end, travel_date, no_of_pass, total_fare):
    """Add a new booking to the database."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('INSERT INTO booking_details (user_id, bus_id, route_id, bus_name, route_start, route_end, booking_date, seats_booked, total_fare) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', 
              (user_id, bus_id, route_id, bus_name, route_start, route_end, travel_date, no_of_pass, total_fare))
    conn.commit()
    conn.close()

def booked_seats(bus_id, date):
    """Count the number of booked seats for a specific bus and date."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('''
        SELECT count(id) FROM booking_details WHERE bus_id = ? AND booking_date = ?
    ''', (bus_id, date))
    booking = c.fetchall()
    conn.close()
    return booking


def get_booking_details(user_id):
    """Retrieve booking details for a specific user."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('''
        SELECT id, user_id, bus_id, bus_name, route_start, route_end, booking_date, seats_booked, total_fare 
        FROM booking_details 
        WHERE user_id = ?
    ''', (user_id,))
    booking = c.fetchall()
    conn.close()
    return booking


def cancel_booking(booking_id):
    """Cancel a booking by booking_id."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    try:
        c.execute('DELETE FROM booking_details WHERE id = ?', (booking_id,))
        conn.commit()
        rows_affected = c.rowcount
        conn.close()
        return rows_affected > 0
    except sqlite.Error as e:
        print(f"Database error: {e}")
        conn.close()
        return False

#bus management functions

def get_buses(from_city, to_city):
    """Retrieve buses between two cities."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('''
        SELECT buses.id, buses.bus_name, buses.bus_fare, buses.ac, buses.available_seats 
        FROM buses 
        JOIN routes ON buses.route_id = routes.id 
        WHERE routes.route_start = ? AND routes.route_end = ?
    ''', (from_city.lower(), to_city.lower()))
    buses = c.fetchall()
    conn.close()
    return buses


def get_bus_details(bus_id):
    """Retrieve bus details by bus_id."""
    conn = sqlite.connect(db_name)
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


def get_seat_availability(bus_id, travel_date):
    """Retrieve seat availability for a specific bus and date."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('SELECT available_seats FROM bus_availability WHERE bus_id = ? AND travel_date = ?', (bus_id, travel_date))
    seats = c.fetchone()
    conn.close()
    return seats


def set_seat_availability(bus_id, travel_date, available_seats):
    """Set seat availability for a specific bus and date."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('INSERT INTO bus_availability (bus_id, travel_date, available_seats) VALUES (?, ?, ?)', (bus_id, travel_date, available_seats))
    conn.commit()
    conn.close()


def increase_seats(seats_booked, bus_id, travel_date):
    """Increase available seats for a specific bus and date."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('''
        UPDATE bus_availability
        SET available_seats = available_seats + ? 
        WHERE bus_id = ? AND travel_date = ?
    ''', (seats_booked, bus_id, travel_date)) 
    conn.commit()
    conn.close()


def decrease_seats(seats_booked, bus_id, travel_date):
    """Decrease available seats for a specific bus and date."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('''
        UPDATE bus_availability
        SET available_seats = available_seats - ? 
        WHERE bus_id = ? AND travel_date = ?
    ''', (seats_booked, bus_id, travel_date)) 
    conn.commit()
    conn.close()



def get_route_details(route_id):
    """Retrieve route details by route_id."""
    conn = sqlite.connect(db_name)
    c = conn.cursor()
    c.execute('''
        SELECT route_start, route_end FROM routes WHERE id = ?
    ''', (route_id,))
    route = c.fetchone()
    conn.close()
    return route


class RequestHandler(http.server.BaseHTTPRequestHandler):

    # Helper function to send static files
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

    # Helper function to send HTML response
    def send_html_response(self, status, template):
        # Generate a random nonce
        nonce = base64.b64encode(random.getrandbits(64).to_bytes(8, 'big')).decode()
        csp_header = (
            f"default-src 'self'; "
            f"script-src 'self' 'strict-dynamic' 'nonce-{nonce}' https:; "
            f"style-src 'self' ; "
            f"object-src 'none'; "
            f"base-uri 'none'; "
            f"frame-ancestors 'self'; "
            f"worker-src 'self'; "
            f"form-action 'self';"
        )
        self.send_response(status)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Security-Policy', csp_header)
        self.end_headers()
        self.wfile.write(load_template(template,nonce).encode())


    # Helper function to send JSON response
    def send_json_response(self,status, data):
        # Generate a random nonce
        nonce = base64.b64encode(random.getrandbits(64).to_bytes(8, 'big')).decode()
        csp_header = (
            f"default-src 'self'; "
            f"script-src 'self' 'strict-dynamic' 'nonce-{nonce}' https:; "
            f"style-src 'self' ; "
            f"object-src 'none'; "
            f"base-uri 'none'; "
            f"frame-ancestors 'self'; "
            f"worker-src 'self'; "
            f"form-action 'self';"
        )
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Content-Security-Policy', csp_header)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    # Helper function to send error response in JSON format
    def send_error_response(self,status, message):
        # Generate a random nonce
        nonce = base64.b64encode(random.getrandbits(64).to_bytes(8, 'big')).decode()
        csp_header = (
            f"default-src 'self'; "
            f"script-src 'self' 'strict-dynamic' 'nonce-{nonce}' https:; "
            f"style-src 'self' ; "
            f"object-src 'none'; "
            f"base-uri 'none'; "
            f"frame-ancestors 'self'; "
            f"worker-src 'self'; "
            f"form-action 'self';"
        )
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Content-Security-Policy', csp_header)
        self.end_headers()
        self.wfile.write(json.dumps({'error': message}).encode())

    # Helper function to send cookie response
    def send_cookie_response(self, status_code, cookie_name, cookie_value, data, cookie_expires=None,cookie_path='/'):
        cookie = http.cookies.SimpleCookie()
        cookie[cookie_name] = cookie_value
        cookie[cookie_name]['path'] = cookie_path
        cookie[cookie_name]['httponly'] = True
        if cookie_expires:
            cookie[cookie_name]['expires'] = cookie_expires
        self.send_response(status_code)
        # Generate a random nonce
        nonce = base64.b64encode(random.getrandbits(64).to_bytes(8, 'big')).decode()
        csp_header = (
            f"default-src 'self'; "
            f"script-src 'self' 'strict-dynamic' 'nonce-{nonce}' https:; "
            f"style-src 'self' ; "
            f"object-src 'none'; "
            f"base-uri 'none'; "
            f"frame-ancestors 'self'; "
            f"worker-src 'self'; "
            f"form-action 'self';"
        )
        self.send_header('Content-type', 'application/json')
        self.send_header('Set-Cookie', cookie.output(header='', sep=''))
        self.send_header('Content-Security-Policy', csp_header)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    #function to handle GET requests
    def do_GET(self):
        # Parse the URL path
        parsed_path = urlparse(self.path)
        raw_path=parsed_path.path
        # Sanitize the path
        path = parsed_path.path.strip('/')  # Remove leading and trailing slashes
        path = quote(path, safe='/')  # Quote the path to handle special characters

        # Parse the query parameters
        parsed_query = parse_qs(parsed_path.query)
        query=sanitize_input(parsed_query)

        # Handle root path
        if path == '':
            self.send_html_response(200, 'index.html')
    
        # Handle login page
        elif path == 'login':
            self.send_html_response(200, 'login.html')
    
        # Handle registration page
        elif path == 'register':
            self.send_html_response(200, 'register.html')
    
        # Handle dashboard page, requiring user authentication
        elif path == 'dashboard':
            user_id = self.get_user_by_session()
            if user_id:
                self.send_html_response(200, 'dashboard.html')
            else:
                self.send_error_response(401, 'Unauthorized')
    
        # Handle booking page with dynamic content
        elif path.startswith('bookpage'):
            bus_id = query.get('bus_id', [None])[0]
            travel_date = query.get('travel_date', [None])[0]
            # Generate a random nonce
            nonce = base64.b64encode(random.getrandbits(64).to_bytes(8, 'big')).decode()
            csp_header = (
                f"default-src 'self'; "
                f"script-src 'self' 'strict-dynamic' 'nonce-{nonce}' https:; "
                f"style-src 'self' ; "
                f"object-src 'none'; "
                f"base-uri 'none'; "
                f"frame-ancestors 'self'; "
                f"worker-src 'self'; "
                f"form-action 'self';"
            )
            booking_page = load_template('book.html',nonce)
            booking_page = booking_page.replace('{{bus_id}}', bus_id)
            booking_page = booking_page.replace('{{travel_date}}', travel_date)
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Content-Security-Policy', csp_header)
            self.end_headers()
            self.wfile.write(booking_page.encode())
    
        # Handle profile page, requiring user authentication
        elif path == 'profile':
            user_id = self.get_user_by_session()
            if user_id:
                self.send_html_response(200, 'profile.html')
            else:
                self.send_error_response(401, 'Unauthorized')
    
        # Handle bus details, returning JSON response
        elif path.startswith('busdetails'):
            bus_id = query.get('bus_id', [None])[0]
            travel_date = query.get('travel_date', [None])

            if bus_id:
                bus = get_bus_details(bus_id)
                available_seats = get_seat_availability(bus_id, travel_date)
                if bus:
                    self.send_json_response(200, {
                        'bus_name': bus[1],
                        'bus_fare': bus[2],
                        'available_seats': available_seats,
                        'route_start': bus[4],
                        'route_end': bus[5]
                    })
                    return
            self.send_error_response(404, 'Bus not found')
    
        # Handle menu page
        elif path == 'menu.html':
            self.send_html_response(200, 'menu.html')
    
        # Serve static files (e.g., CSS)
        elif path.startswith('static'):
            content_type = 'text/css' if path.endswith('.css') else 'application/octet-stream'
            self.serve_static_file(raw_path[1:], content_type)
    
        # Handle user details, returning JSON response
        elif path == 'userdetails':
            user_id = self.get_user_by_session()
            if user_id:
                user = get_user_details(user_id)
                if user:
                    self.send_json_response(200, {
                        'name': user[0],
                        'username': user[1],
                        'email': user[2],
                        'phone_number': user[3]
                    })
                    return
            self.send_error_response(404, 'User details not found')
    
        # Handle edit details, returning JSON response
        elif path == 'editdetails':
            user_id = self.get_user_by_session()
            if user_id:
                user = get_user_details(user_id)
                if user:
                    self.send_json_response(200, {
                        'name': user[0],
                        'username': user[1],
                        'email': user[2],
                        'phone_number': user[3]
                    })
                    return
            self.send_error_response(404, 'User details not found')
    
        # Handle edit user page, requiring user authentication
        elif path == 'edit':
            user_id = self.get_user_by_session()
            if user_id:
                self.send_html_response(200, 'edituser.html')
            else:
                self.send_error_response(401, 'Unauthorized')

        # Handle change password page, requiring user authentication
        elif path == 'changepassword':
            user_id = self.get_user_by_session()
            if user_id:
                self.send_html_response(200, 'changepassword.html')
            else:
                self.send_error_response(401, 'Unauthorized')
    
        # Handle my bookings, returning JSON response
        elif path == 'mybookings':
            user_id = self.get_user_by_session()
            if user_id:
                bookings = get_booking_details(user_id)
                if bookings:
                    booking_list = [{'booking_id': booking[0],
                                    'busname': booking[3],
                                    'from': booking[4],
                                    'to': booking[5],
                                    'traveldate': booking[6],
                                    'noofseats': booking[7],
                                    'totalfare': booking[8]} for booking in bookings]
                    self.send_json_response(200, booking_list)
                    return
            self.send_error_response(404, 'Booking details not found')
    
        # Handle bookings page, requiring user authentication
        elif path == 'bookings':
            user_id = self.get_user_by_session()
            if user_id:
                self.send_html_response(200, 'mybooking.html')
            else:
                self.send_error_response(401, 'Unauthorized')
    
        # Handle unknown paths
        else:
            self.send_response(404)
            self.end_headers()

        
        

    #Function to handle POST request   
    def do_POST(self):
        # Read request data
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        raw_data = parse_qs(post_data.decode())
        data = sanitize_input(raw_data)

        # Handle different POST requests based on the path
        if self.path == '/login':
            # Process login request
            username = data.get('username')
            password = data.get('password')
            user = get_user(username)
            if user and verify_password(password,user[2]):
                # Successful login
                session_id = create_session(user[0])
                self.send_cookie_response(200, 'session_id', session_id,{'message': 'Login successful'})
            else:
                # Invalid credentials
                self.send_error_response(401, 'Invalid credentials')

        elif self.path == '/register':
            # Process registration request
            name = data.get('name')
            username = data.get('username')
            password = data.get('password')
            email = data.get('email')
            phonenumber = data.get('phone_number')

            if not get_user(username):
                # User does not exist, add new user
                add_user(name, username, hash_password(password), email, phonenumber)
                user = get_user(username)
                session_id = create_session(user[0])
                self.send_cookie_response(200, 'session_id', session_id,{'message': 'Registration successful'})         
            else:
                # User already exists
                self.send_error_response(409, 'User already exists')

        elif self.path == '/buses':
            # Process bus search request
            data = json.loads(post_data)
            from_city = data['from']
            to_city = data['to']
            travel_date = data['traveldate']
            buses_list = []
            buses = get_buses(from_city, to_city)
            if buses:
                for bus in buses:
                    available_seats = get_seat_availability(bus[0], travel_date)
                    if available_seats is not None:
                        seats_available = available_seats
                    else:
                        set_seat_availability(bus[0], travel_date, bus[4])
                        seats_available = bus[4]

                    buses_list.append({
                        'id': bus[0],
                        'bus_name': bus[1],
                        'bus_fare': bus[2],
                        'ac': bus[3],
                        'available_seats': seats_available
                    })

                self.send_json_response(200, buses_list)
            else:
                self.send_error_response(400,'No buses available in this route')

        elif self.path == '/book':
            # Process booking request
            user_id = self.get_user_by_session()
            if user_id:
                data = json.loads(post_data)
                bus_id = data['bus_id']
                bus_details = get_bus_details(bus_id)
                bus_name = bus_details[1]
                route_id = bus_details[5]
                route_start = bus_details[4]
                route_end = bus_details[5]
                no_of_pass = data['no_of_pass']
                totalfare = data['total_fare']
                travel_date = data['travel_date']

                add_booking(user_id, bus_id, route_id, bus_name, route_start, route_end, travel_date, no_of_pass, totalfare)
                decrease_seats(no_of_pass, bus_id, travel_date)
                self.send_json_response(200, {'message': 'Booking successful'})
            else:
                self.send_error_response(401, 'Unauthorized')

        elif self.path == '/logout':
            # Process logout request
            session_id = self.get_cookie()
            sessions = get_current_user(session_id)
            if session_id and sessions:
                delete_session(session_id)
            self.send_cookie_response(200, 'session_id',{'message': 'Logout successful'}, 'Thu, 01 Jan 1970 00:00:00 GMT','')
            self.send_json_response(200, )

        else:
            # Invalid session
            self.send_error_response(401, 'Invalid session')


    #Function to handle DELETE request
    def do_DELETE(self):
        # Parse the request path and query
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query = parse_qs(parsed_path.query)
    
        # Handle DELETE requests
        if self.path.startswith('/cancel'):
            # Process cancel booking request
            booking_id = query.get('booking_id', [None])[0]
            if not booking_id:
                self.send_error_response(400, 'Booking_id is required')
                return

            # Check if the user is authorized to cancel the booking
            current_user_id = self.get_user_by_session()
            user = get_user_from_booking(booking_id)
            if not user:
                self.send_error_response(400, 'Booking is not found')
                return
            if user[0] != current_user_id:
                self.send_error_response(400, 'Unauthorized to cancel booking')
                return

            # Cancel the booking and update seat availability
            result = cancel_booking(booking_id)
            increase_seats(user[1], user[2], user[3])
            if result:
                self.send_json_response(200, {'message': 'Successfully cancelled'})
            else:
                self.send_error_response(404, 'Cancellation not possible')
            
        elif self.path.startswith('/delete'):
            # Process delete user request
            user_id = self.get_user_by_session()
            result = delete_user(user_id)
            if result:
                self.send_json_response(200, {'message': 'Successfully deleted'})
            else:
                self.send_error_response(404, 'Deletion not possible')
        else:
            # Invalid session
            self.send_error_response(401, 'Invalid session')

    #Function to handle PUT request
    def do_PUT(self):
        # Read request data for PUT requests
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        raw_data = parse_qs(post_data.decode())
        data = sanitize_input(raw_data)

        if self.path == '/editdetails':
            # Process edit user details request
            user_id = self.get_user_by_session()
            if user_id:
                name = data.get('name')
                username = data.get('username')
                email = data.get('email')
                phonenumber = data.get('phone_number')
                user = get_user_details(user_id)
                oldusername = user[1]
                if oldusername != username:
                    # Check if the new username is available
                    if not get_user(username):
                        update_user(user_id, name, username, email, phonenumber)
                        self.send_json_response(200, {'message': 'Registration successful'})
                    else:
                        self.send_error_response(409, 'Username already taken, Please try another username')
                else:
                    # Update user details
                    update_user(user_id, name, username, email, phonenumber)
                    self.send_json_response(200, {'message': 'Registration successful'})
            else:
                self.send_error_response(401, 'Invalid session')
        elif self.path == '/changepassword':
            # Process change password request
            user_id = self.get_user_by_session()
            user_details=get_user_details(user_id)
            password_hash=get_user(user_details[1])[2]
            old_password=data.get('currentPassword')
            new_password=data.get('newPassword')
            if user_details and verify_password(old_password,password_hash):
                update_password(user_id,hash_password(new_password))
                self.send_json_response(200, {'message': 'Password updated successfully'})
            else:
                self.send_error_response(404, 'Provided current password is wrong.')
        else:
            # Invalid session
            self.send_error_response(401, 'Invalid session')


    
    def get_user_by_session(self):
        # Get the user ID from the session
        session_id = self.get_cookie()
        session = get_current_user(session_id)
        if session:
            user_id, expires_at = session
            if datetime.now() < datetime.fromisoformat(expires_at):
                return user_id
        return None

    def get_cookie(self):
        # Get the session ID from the cookies
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
    # Create an SSL context and load the SSL certificate and key for the server
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
    # Disable hostname check (for localhost)
    context.check_hostname = False
    
    # Create an HTTP server instance with the custom RequestHandler and wrap the socket with the SSL context
    with http.server.HTTPServer(('localhost', 443), RequestHandler) as httpd:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print("Serving on https://localhost:443")
        httpd.serve_forever()

