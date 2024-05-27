# Secure Public Transportation Booking System

This project is a secure public transportation booking system that allows users to create accounts, search for bus routes, book tickets, view their bookings, and cancel bookings. 

## Table of Contents

- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Security Measures](#security-measures)


## Features

- **User Authentication:** Users can register, log in, and log out securely.
- **Profile Management:** Users can view and edit their profile details.
- **Bus Search:** Users can search for available buses based on routes and travel dates.
- **Booking:** Users can book tickets for available buses.
- **Booking Management:** Users can view and cancel their bookings.
- **Secure Transactions:** Ensures secure handling of user data and booking transactions.

## Technologies Used

- **Backend:** Python, SQLite, HTTP server
- **Frontend:** HTML, CSS, JavaScript 
- **Security:** HTTPS, Password Hashing, Session Management

## Installation

1. **Clone the repository:**
   ```bash https://github.com/ashtapadhi/SPT-Ticket-Booking.git```
   
2. **Set up a virtual environment:**
```bash python -m venv venv```
  ```bash source venv/bin/activate```  # On Windows, use `venv\Scripts\activate`

4. **Install dependencies:**

```bash pip install -r requirements.txt```

## Usage

- **Access the application:**
Open a web browser and go to http://localhost:4443.

- **Register and log in:**
Create a new account or log in with your credentials.

- **Search for buses:**
Use the dashboard to search for available buses based on your travel route and date.

- **Book a ticket:**
Select a bus from the search results and book a ticket.

- **View and manage bookings:**
View your bookings and cancel them if necessary.

- **View and manage user profile:**
View user profile and edit details if necessary

- **Delete account:**
Open profile and delete account if necessary

- **Logout:**
Users can logout after use


## API Endpoints

- **User Registration:** POST /register
- **User Login:** POST /login
- **User Logout:** POST /logout
- **Delete Account:** DELETE /delete

- **Get User Profile:** GET /profile
- **Update User Profile:** PUT /edit_details
- **Search Buses:** POST /search
- **Book a Ticket:** POST /book
- **View Bookings:** GET /bookings
- **Cancel Booking:** DELETE /cancel

## Security Measures

- **HTTPS:** Ensures secure communication between the client and server.
- **Password Hashing:** User passwords are hashed before storing in the database.
- **Session Expiry:** Sessions are validated against expiry time during requests.





   
