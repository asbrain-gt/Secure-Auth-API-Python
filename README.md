# Secure User Authentication & Social API
This project is a RESTful backend API built with Python and Flask designed with a "security first" approach with JWT authentication, password salting/hashing, and role-based access control. The core focus of this project was implementing authentication and authorization logic from scratch rather than relying on external libraries. 

## Key Security Features
- **Custom JWT Implementation:** manual logic for encoding, decoding, and verifying **JSON Web Tokens (HS256)** to manage user sessions
- **Crypographic Data Protection:** uses **SHA-256 hashing with unique salts** to ensure password integrity
- **SQL Injection Mitigation:** database interactions done using **parameterized queries** with SQLite3 to prevent malicious input from compromising the system
- **Role-Based Access Control (RBAC):** logic to differentiate between standard users and **moderators** to authorize sensitive actions
- **Input Validation & Fail-Safe Logic:** password complexity checks and fail-safe error handling to ensure system stability at all times

## Technical Toolkit
- **Language:** Python
- **Framework:** Flask
- **Database:** SQLite3 (SQL)
- **Data Interchange:** JSON
- **Security:** HMAC-SHA256, Base64URL Encoding

## Database Schema
The system uses a relational database structure from an SQL initialization script. Key tables include: users (profile data, unique salts and statuses), passwords (salted password hashes linked to user IDs), and posts/follows/likes (social graph and content ownership)

## How to Run
1. Have **Python 3** and **Flask** installed
2. Include a secret key in a local key.txt file (*excluded from version control*)
3. Run app2.py (*the system will automatically initialize the database using the provided .sql schema on the first launch*)

### Acknowledgements 
Dr. Betty Cheng & Dr. James Mariani, Professors of Computer Science & Engineering at Michigan State University. 
CSE 380 SS26