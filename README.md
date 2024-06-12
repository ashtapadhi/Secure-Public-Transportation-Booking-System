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
- **Secure Transactions:** Ensures secure handling of user data.

## Technologies Used

- **Backend:** Python, SQLite, HTTP server
- **Frontend:** HTML, CSS, JavaScript 
- **Security:** HTTPS, Password Hashing, Session Management

## Installation

1. **Clone the repository:**
   ```https://github.com/ashtapadhi/SPT-Ticket-Booking.git```
   
2. **Set up a virtual environment:**
```python -m venv venv```
  ```source venv/bin/activate```  # On Windows, use `venv\Scripts\activate`

4. **Install dependencies:**

```pip install -r requirements.txt```

5. **Generate certificate and key:**

```openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365```

6. **Initialize database:**
```python init_db.py```

7. **Generate key for encryption:**
```python generate_key.py```

8. **Set environment variables:**
To configure the project, you need to set up the following environment variables in a `.env` file in the root directory of the project. Here is an example of what your `.env` file should look like:

```plaintext
SECRET_KEY="your_secret_key_here"
DB_NAME="your_database_name_here"
KEY="your_key_here"

## Usage

- **Add route and bus details:**
```python admin.py```
use the menu-driven program to enter bus details and route details.

- **Run the application:**
 ```pyhton server.py```

- **Access the application:**
Open a web browser and go to https://localhost:4443.

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
Users can logout after using the system


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





   
