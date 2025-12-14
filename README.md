# Secure Authentication Platform

A security-focused authentication platform built with Django, designed to demonstrate real-world authentication, identity, and authorization security practices.

This project focuses on **how authentication systems fail** and how to build them **correctly** using modern cryptography and defensive techniques.

---

## What This Project Demonstrates

- Secure password storage (Argon2 / PBKDF2)
- Token-based authentication (JWT access & refresh tokens)
- Token rotation and revocation
- Brute-force protection and rate limiting
- Secure password reset flows
- Authentication audit logging
- OWASP Top 10 authentication risks

---

## Security Topics Covered

- Password hashing (Argon2, PBKDF2)
- Salting and password policies
- JWT signing and expiration
- Refresh token rotation
- Session vs token authentication
- Account lockout and rate limiting
- Authentication event auditing

---

## Core Features

- Secure user registration and login
- JWT-based authentication
- Refresh token rotation
- Login rate limiting
- Password reset with time-bound tokens
- Optional MFA (TOTP)
- Authentication audit logs
- Secure cookie configuration

---

## Why This Project Exists

Authentication is one of the most common failure points in web applications.
This project demonstrates **how authentication should be designed**, not just how to make it work.

---

## Intended Audience

- Security Engineers
- Backend Developers
- Application Security (AppSec)
- Anyone designing authentication systems

---

## Disclaimer

This project is for educational and defensive security purposes only.
