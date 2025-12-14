# Chirpy API Documentation

Chirpy is a social media application backend focused on posting short messages (Chirps). This document serves as a complete reference for all available API endpoints, authentication methods, and functionality. Basically an X clone to learn GO.

---

## **Application Overview**

Chirpy is built on Go and uses PostgreSQL for data persistence. It features user authentication (JWT/Refresh Tokens), Chirp management, basic metrics tracking, and a webhook for user upgrades.

---

## **API Endpoints Reference**

This section outlines all available API endpoints, grouped by resource.

### **Server Status and Metrics**

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/healthz` | Checks the server readiness. Returns `200 OK` and the text `OK` if the server is up. |
| `GET` | `/admin/metrics` | Returns an HTML page displaying the total file server hits. |
| `POST` | `/api/reset` | **(Admin/Dev Only)** Resets the file server hit counter to zero and deletes all user data from the database. Only works when the `PLATFORM` environment variable is set to `dev`. |

### **User & Authentication Endpoints**

| Method | Endpoint | Description | Authentication | Request Body | Response Body (Success) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/users` | Creates a new user with an email and password. | None | `{"email": "user@example.com", "password": "a_secure_password"}` | `{"id": "...", "created_at": "...", "updated_at": "...", "email": "..."}` |
| `POST` | `/api/login` | Authenticates a user. Returns a time-limited **JWT** and a persistent **Refresh Token**. | None | `{"email": "user@example.com", "password": "a_secure_password"}` | `{"id": "...", "email": "...", "token": "...", "refresh_token": "..."}` |
| `PUT` | `/api/users` | Updates the authenticated user's email and password. | JWT (Bearer) | `{"email": "new_email@example.com", "password": "a_new_password"}` | `{"email": "new_email@example.com"}` |
| `POST` | `/api/refresh` | Generates a new JWT using a valid Refresh Token. | Refresh Token (Bearer) | None | `{"token": "new_jwt_token"}` |
| `POST` | `/api/revoke` | Invalidates (revokes) the provided Refresh Token, forcing the user to log in again to receive a new one. | Refresh Token (Bearer) | None | `204 No Content` |

### **Chirp Endpoints**

| Method | Endpoint | Description | Authentication | Request Body | Response Body (Success) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/chirps` | Creates a new chirp. The body must be less than 140 characters. | JWT (Bearer) | `{"body": "My first chirp!", "user_id": "..."}` | Chirp object (`id`, `body`, `user_id`, `created_at`, `updated_at`) |
| `GET` | `/api/chirps` | Returns a list of all chirps. Can be filtered by author and sorted. | None | None | Array of Chirp objects |
| `GET` | `/api/chirps/{id}` | Returns a single chirp by its unique ID. Returns `404 Not Found` if the ID is invalid. | None | None | Single Chirp object |
| `DELETE` | `/api/chirps/{id}` | Deletes a chirp. Requires the authenticated user (via Refresh Token) to be the chirp's author. | Refresh Token (Bearer) | None | `204 No Content` |

> **Query Parameters for `GET /api/chirps`:**
> * `author_id`: Filter chirps by the author's user ID (UUID).
> * `sort`: Sorts chirps by creation time. Accepts `asc` (default) or `desc`.

### **Webhooks**

| Method | Endpoint | Description | Authentication | Request Body | Response Body (Success) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/polka/webhooks` | Receives payment events. If the `event` is `user.upgraded`, it sets the corresponding user's `is_chirpy_red` status to true in the database. | API Key (HTTP Header `Authorization: ApiKey {POLKA_KEY}`) | `{"event": "user.upgraded", "data": {"user_id": "a_user_uuid"}}` | `204 No Content` |