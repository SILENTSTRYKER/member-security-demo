# Member Security Demo

A secure web application demonstrating authentication, authorization, and database security using **Supabase**, **PostgreSQL**, and **Row Level Security (RLS)**.

This project was developed as part of a software engineering technical assessment to demonstrate secure application development, identify an authorization vulnerability, and implement an effective mitigation.

---

# Live Demo

**Application**

https://member-security-demo.netlify.app/

---

# GitHub Repository

https://github.com/SILENTSTRYKER/member-security-demo

---

# Overview

The Member Security Demo allows authenticated users to securely sign in and access their member information.

The application demonstrates the complete authentication flow using Supabase Authentication while protecting sensitive member data through PostgreSQL Row Level Security policies.

A proof-of-concept exploit is included to demonstrate the vulnerability before the security fix and verify that the implemented authorization policy successfully mitigates the issue.

---

# Features

- Secure user authentication
- Secure logout
- PostgreSQL database
- Row Level Security (RLS)
- Member dashboard
- Protected member records
- Apple-inspired responsive interface
- Loading state while retrieving data
- Smooth card hover animations
- Proof-of-concept exploit
- GitHub version control
- Netlify deployment

---

# Technologies Used

## Frontend

- HTML5
- CSS3
- JavaScript (ES6)

## Backend

- Supabase
- PostgreSQL

## Security

- Supabase Authentication
- PostgreSQL Row Level Security (RLS)

## Deployment

- GitHub
- Netlify

---

# Project Architecture

```
Browser
    │
    ▼
Login Page
    │
    ▼
Supabase Authentication
    │
    ▼
Member Dashboard
    │
    ▼
Supabase PostgreSQL Database
            │
            ▼
    Row Level Security Policies
```

---

# Authentication Flow

1. User enters an email and password.
2. Supabase validates the credentials.
3. A secure authenticated session is created.
4. The user is redirected to the dashboard.
5. The dashboard requests member data from Supabase.
6. PostgreSQL evaluates the Row Level Security policy before returning any records.

---

# Vulnerability

Initially, authenticated users could execute the following query:

```javascript
.from("members")
.select("*")
```

Because no Row Level Security policy existed, every authenticated user could retrieve every member record stored in the database.

This represented an authorization vulnerability because authentication alone does not determine what data a user should be allowed to access.

---

# Proof-of-Concept Exploit

The project includes an `exploit.js` script that demonstrates the vulnerability.

The script:

- Authenticates as a valid user
- Requests all member records
- Displays every record returned by the database

After the security fix, the exact same script only returns the authenticated user's own record, demonstrating that Row Level Security is successfully enforcing authorization.

---

# Security Fix

Row Level Security was enabled on the `members` table.

A policy was created that only allows authenticated users to access rows associated with their own account.

Conceptually:

```sql
user_id = auth.uid()
```

After implementing the policy:

- John Smith can only view John's record.
- Jane Doe can only view Jane's record.
- Jalen Barnes can only view Jalen's record.

Authorization is enforced by PostgreSQL rather than relying on the frontend, following the principle of least privilege.

---


---

# Running the Project

Clone the repository:

```bash
git clone https://github.com/SILENTSTRYKER/member-security-demo.git
```

Navigate into the project:

```bash
cd member-security-demo
```

Install dependencies:

```bash
npm install
```

Run the exploit demonstration:

```bash
node exploit.js
```

Run the frontend using Live Server or another local web server.

---

# Future Improvements

Potential future enhancements include:

- Role-Based Access Control (RBAC)
- Multi-Factor Authentication (MFA)
- Password reset functionality
- Audit logging
- Automated testing
- Administrative dashboard
- REST API layer

---

# Key Learning Outcomes

This project demonstrates:

- Secure authentication
- Secure authorization
- PostgreSQL Row Level Security
- Vulnerability assessment
- Security mitigation
- Git version control
- GitHub workflows
- Cloud deployment with Netlify

---

# Author

**Jalen Barnes**

