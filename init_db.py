from pysqlcipher3 import dbapi2 as sqlite


#Connection with Database
conn = sqlite.connect('database.db')
conn.execute("PRAGMA foreign_keys = ON")
c = conn.cursor()

# Create table users
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    username BLOB UNIQUE NOT NULL,
    password_hash BLOB NOT NULL,
    email BLOB UNIQUE NOT NULL,
    phone_number BLOB,
    username_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Create table routes
c.execute(''' 
CREATE TABLE IF NOT EXISTS routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    route_name TEXT NOT NULL,
    route_start TEXT NOT NULL,
    route_end TEXT NOT NULL,
    connected_cities TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Create table buses
c.execute('''
CREATE TABLE IF NOT EXISTS buses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bus_name TEXT NOT NULL,
    route_id INTEGER NOT NULL,
    bus_fare REAL NOT NULL,
    ac INTEGER NOT NULL,
    available_seats INTEGER NOT NULL,
    duration TEXT NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (route_id) REFERENCES routes(id) ON DELETE CASCADE
)
''')

# Create table booking_details
c.execute('''
CREATE TABLE IF NOT EXISTS booking_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    bus_id INTEGER NOT NULL,
    route_id INTEGER NOT NULL,
    bus_name TEXT NOT NULL,
    route_start TEXT NOT NULL,
    route_end TEXT NOT NULL,
    booking_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    seats_booked INTEGER NOT NULL,
    total_fare REAL NOT NULL,
    customer_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone_number TEXT,
    duration TEXT NOT NULL,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (bus_id) REFERENCES buses(id) ON DELETE CASCADE,
    FOREIGN KEY (route_id) REFERENCES routes(route_id) ON DELETE CASCADE
)
''')

# Create table cancelled_booking_details
c.execute('''
CREATE TABLE IF NOT EXISTS cancelled_booking_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    bus_id INTEGER NOT NULL,
    route_id INTEGER NOT NULL,
    bus_name TEXT NOT NULL,
    route_start TEXT NOT NULL,
    route_end TEXT NOT NULL,
    booking_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    seats_booked INTEGER NOT NULL,
    total_fare REAL NOT NULL,
    customer_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone_number TEXT,
    duration TEXT NOT NULL,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (bus_id) REFERENCES buses(id) ON DELETE CASCADE,
    FOREIGN KEY (route_id) REFERENCES routes(route_id) ON DELETE CASCADE
)
''')

# Create table completed_bookings
c.execute('''
CREATE TABLE IF NOT EXISTS completed_bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    bus_id INTEGER NOT NULL,
    route_id INTEGER NOT NULL,
    bus_name TEXT NOT NULL,
    route_start TEXT NOT NULL,
    route_end TEXT NOT NULL,
    booking_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    seats_booked INTEGER NOT NULL,
    total_fare REAL NOT NULL,
    customer_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone_number TEXT,
    duration TEXT NOT NULL,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (bus_id) REFERENCES buses(id) ON DELETE CASCADE,
    FOREIGN KEY (route_id) REFERENCES routes(route_id) ON DELETE CASCADE
)
''')

# Create table sessions
c.execute('''CREATE TABLE IF NOT EXISTS sessions (
    session_id BLOB PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at BLOB NOT NULL,
    session_id_hash text NOT NULL,
    csrf_token text NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)'''
)

# Create table bus_availability
c.execute('''
CREATE TABLE IF NOT EXISTS bus_availability (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bus_id INTEGER NOT NULL,
    travel_date DATE NOT NULL,
    available_seats INTEGER NOT NULL,
    FOREIGN KEY (bus_id) REFERENCES buses(id) ON DELETE CASCADE,
    UNIQUE (bus_id, travel_date)
)
''')


# Trigger to update the updated_at column on row update 
c.execute('''
CREATE TRIGGER IF NOT EXISTS update_users_updated_at
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = old.id;
END;
''')

c.execute('''
CREATE TRIGGER IF NOT EXISTS update_routes_updated_at
AFTER UPDATE ON routes
FOR EACH ROW
BEGIN
    UPDATE routes SET updated_at = CURRENT_TIMESTAMP WHERE id = old.id;
END;
''')

c.execute('''
CREATE TRIGGER IF NOT EXISTS update_buses_updated_at
AFTER UPDATE ON buses
FOR EACH ROW
BEGIN
    UPDATE buses SET updated_at = CURRENT_TIMESTAMP WHERE id = old.id;
END;
''')

c.execute('''
CREATE TRIGGER IF NOT EXISTS update_booking_details_updated_at
AFTER UPDATE ON booking_details
FOR EACH ROW
BEGIN
    UPDATE booking_details SET updated_at = CURRENT_TIMESTAMP WHERE id = old.id;
END;
''')

c.execute('''
CREATE TRIGGER IF NOT EXISTS move_to_cancelled
AFTER DELETE ON booking_details
FOR EACH ROW
BEGIN
    INSERT INTO cancelled_booking_details (
        user_id, bus_id, route_id, bus_name, route_start, route_end,
        booking_date, seats_booked, total_fare, customer_name, email, phone_number,
        duration, start_time, end_time
    )
    VALUES (
        OLD.user_id, OLD.bus_id, OLD.route_id, OLD.bus_name, OLD.route_start, OLD.route_end,
        OLD.booking_date, OLD.seats_booked, OLD.total_fare, OLD.customer_name, OLD.email, OLD.phone_number,
        OLD.duration, OLD.start_time, OLD.end_time
    );
END;
''')

# Create trigger to move completed bookings
c.execute('''
CREATE TRIGGER IF NOT EXISTS move_completed_booking
AFTER UPDATE OF end_time ON booking_details
FOR EACH ROW
WHEN NEW.end_time < CURRENT_TIMESTAMP
BEGIN
    INSERT INTO completed_bookings (
        user_id, bus_id, route_id, bus_name, route_start, route_end,
        booking_date, seats_booked, total_fare, customer_name, 
        email, phone_number, duration, start_time, end_time, completed_at
    ) VALUES (
        NEW.user_id, NEW.bus_id, NEW.route_id, NEW.bus_name, NEW.route_start, NEW.route_end,
        NEW.booking_date, NEW.seats_booked, NEW.total_fare, NEW.customer_name, 
        NEW.email, NEW.phone_number, NEW.duration, NEW.start_time, NEW.end_time, CURRENT_TIMESTAMP
    );
    DELETE FROM booking_details WHERE id = NEW.id;
END;
''')

#Database connection close
conn.commit()
conn.close()
