# Member Security Demo

A secure web application demonstrating authentication, authorization, and database security using **Supabase**, **PostgreSQL**, and **Row Level Security (RLS)**.

This project was developed as part of a software engineering technical assessment to demonstrate secure application development, identify a real authorization vulnerability, prove its impact, and implement an effective database-level remediation.

---

# Live Demo

**Application**

https://member-security-demo.netlify.app/

---

# GitHub Repository

https://github.com/SILENTSTRYKER/member-security-demo

---

# Overview

The Member Security Demo allows authenticated users to securely sign in and access their own protected member information.

The application uses Supabase Authentication to establish the user's identity and PostgreSQL Row Level Security to determine which database records that user is allowed to access.

A proof-of-concept assessment script demonstrates the original authorization vulnerability and verifies that the security fix prevents users from accessing records belonging to other members.

The project also includes an interactive security dashboard that validates authorized access and simulates an attempted cross-user data request.

---

# Features

- Secure email and password authentication
- Secure logout
- Authenticated session validation
- PostgreSQL database
- Row Level Security policies
- Protected member records
- Authorized-access validation
- Unauthorized-access simulation
- Returned-row ownership verification
- Security validation score
- Client-side security activity timeline
- Responsive security dashboard
- Environment-variable protection for demo credentials
- Proof-of-concept security assessment script
- GitHub version control
- Netlify deployment

---

# Technologies Used

## Frontend

- HTML5
- CSS3
- JavaScript ES6

## Backend

- Supabase
- PostgreSQL

## Security

- Supabase Authentication
- PostgreSQL Row Level Security
- JWT-based authenticated sessions
- Least-privilege access
- Row ownership validation
- Environment variables

## Deployment and Development

- Node.js
- Git
- GitHub
- Netlify

---

# Project Architecture

```text
Browser
    │
    ▼
Login Page
    │
    ▼
Supabase Authentication
    │
    ▼
Authenticated User Session
    │
    ▼
Security Dashboard
    │
    ▼
Supabase JavaScript Client
    │
    ▼
PostgreSQL Members Table
    │
    ▼
Row Level Security Policy
    │
    ▼
Only rows where user_id = auth.uid()