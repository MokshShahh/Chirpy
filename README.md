# CHIRPY

This project is a backend service developed in **Go** that replicates core functionalities of a platform like Twitter. It features a robust server, complete with persistent data storage using a **PostgreSQL** database and comprehensive **user authentication**.

## Routes Overview

| Method | Endpoint | Description | Authentication |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/users` | Registers a new user with email and password, returning the user object. | **None** |
| `POST` | `/api/login` | Authenticates a user. Returns a short-lived **JWT** (Access Token) and a long-lived **Refresh Token** upon successful password match. | **None** |
| `POST` | `/api/refresh` | Handles refreshing an expired JWT using a valid Refresh Token. | **Refresh Token** |
| `POST` | `/api/chirps` | **Creates a new chirp**. Requires a valid JWT in the Authorization header. | **JWT (Access Token)** |
| `GET` | `/api/chirps` | Retrieves all chirps in chronological order. | **None** |
| `GET` | `/api/chirps/{id}` | Retrieves a single chirp by ID. | **None** |
| `GET` | `/api/healthz` | Checks server readiness. | **None** |
| `GET` | `/admin/metrics` | Admin view for file server hit count. | **None** |
| `POST`| `/api/reset` | Resets the server hit counter and deletes users (Dev mode only). | **None** |

## ONGOING WORK
* **JWT Authentication Middleware:** Implementing middleware to secure Chirp creation and other authenticated endpoints.
