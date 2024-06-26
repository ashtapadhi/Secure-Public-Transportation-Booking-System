import json
import sqlite3
from datetime import datetime

#Function to add routes
def insert_route():
    #inputs from user
    route_name = input("Enter route name: ").lower()
    route_start = input("Enter route start: ").lower()
    route_end = input("Enter route end: ").lower()
    connected_cities = input("Enter connected cities (comma-separated): ")
    connected_cities_lower = [city.strip().lower() for city in connected_cities.split(',')]
    connected_cities_json = json.dumps(connected_cities_lower)
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
    INSERT INTO routes (route_name, route_start, route_end, connected_cities)
    VALUES (?, ?, ?, ?)
    ''', (route_name, route_start, route_end, connected_cities_json))
    conn.commit()
    conn.close()
    print("Route added successfully.")

#Function to add bus
def insert_bus():
    #inputs from user
    bus_name = input("Enter bus name: ").lower()
    route_id = int(input("Enter route ID: "))
    bus_fare = float(input("Enter bus fare: "))
    ac = input("Is the bus AC (yes/no): ").lower() == 'yes'
    available_seats = int(input("Enter number of available seats: "))
    duration = input("Enter duration (HH:MM): ").strip()
    start_time_str = input("Enter start time (HH:MM): ").strip()
    end_time_str = input("Enter end time (HH:MM): ").strip()
    
    # Convert time strings to time objects
    start_time = datetime.strptime(start_time_str, "%H:%M").time()
    end_time = datetime.strptime(end_time_str, "%H:%M").time()
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
    INSERT INTO buses (bus_name, route_id, bus_fare, ac, available_seats, duration, start_time, end_time)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (bus_name, route_id, bus_fare, ac, available_seats, duration, str(start_time), str(end_time)))
    conn.commit()
    conn.close()
    print("Bus added successfully.")



    
#Function for menu driven program
def menu():
    while True:
        print("\nMenu:")
        print("1. Insert Route")
        print("2. Insert Bus")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            insert_route()
        elif choice == '2':
            insert_bus()
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    menu()