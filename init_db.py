import sqlite3


#Connection with Database
conn = sqlite3.connect('database.db')
conn.execute("PRAGMA foreign_keys = ON")
c = conn.cursor()

# Create table users
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone_number TEXT,
    booked_routes TEXT,
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (bus_id) REFERENCES buses(id) ON DELETE CASCADE,
    FOREIGN KEY (route_id) REFERENCES routes(route_id) ON DELETE CASCADE
)
''')

# Create table sessions
c.execute('''CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
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


#Database connection close
conn.commit()
conn.close()
