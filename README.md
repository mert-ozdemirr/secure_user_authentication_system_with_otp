# Secure User Authentication System with Public Key Encryption and OTP

This project implements a secure user authentication system using public key encryption (RSA), hashing (SHA-256), and hash chain-based One-Time Passwords (OTP). The system consists of a Flask-based client and a server-side authentication mechanism, ensuring secure credential storage and login verification.

Key Features:
* User Registration – Users register with a username and password, which are hashed using SHA-256 or MD5 before storage.
* Encrypted User Database – User credentials are stored in a text-based database, encrypted using the RSA algorithm for secure storage.
* User Login with OTP Authentication –
  Users enter their credentials for initial authentication.
  If credentials are valid, an OTP (One-Time Password) is required for second-step verification.
* Hash Chain-Based OTP –
  OTPs are generated using iterative SHA-256 hashing (100 times).
  The OTPs are used in reverse order for authentication, ensuring one-time usage and replay attack prevention.
* Client-Server Architecture – The project follows a Flask-based frontend with a server-side authentication system handling secure database operations and encryption.
