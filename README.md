# Jamison Protection

A full-stack workforce management platform designed for private security operations.
Jamison Protection streamlines scheduling, workforce coordination, payroll tracking, security logging, and hiring management through a centralized web application.

---

## Overview

This project was developed to modernize and simplify operations for a growing security company. The platform allows administrators and security personnel to manage shifts, interviews, payroll, daily security reports, and workforce scheduling from a unified system.

The application includes separate dashboards for administrators and workers, authentication systems, scheduling tools, interview management, and operational tracking features.

---
## Live Website

[Visit Jamison Protection](https://www.jamisonprotection.com/)
---
# Features

## Authentication & Security

* Secure login system
* Session-based authentication
* Protected admin and worker views
* Role-based dashboard access

---

## Owner / Admin Features

* Create and manage shifts
* View all scheduled shifts
* Shift calendar system
* Filter shifts by worker/date
* Payroll management
* Security log management
* Worker hour submissions
* Interview management dashboard
* Candidate scheduling tools
* Resume and cover letter uploads
* Worker management system

---

## Worker Features

* Worker dashboard
* View available shifts
* Claim open shifts
* Personal shift tracking
* Calendar integration
* Hour submission system
* Daily security log reporting
* Work history tracking

---

# Tech Stack

## Frontend

* HTML5
* CSS3
* JavaScript

## Backend

* Node.js
* Express.js

## Database

* MongoDB

## Additional Technologies

* Cloudinary
* bcrypt
* dotenv
* Session authentication
* File uploads
* Calendar integration

---

# Screenshots

## Landing Page

<img width="1272" height="1263" alt="d82ed2a5-641c-4568-9414-f1972e014ed7" src="https://github.com/user-attachments/assets/98ddf4cf-7cdd-40bd-809a-ce0d215941d6" />

Professional homepage introducing the company and services with a modern dark-themed UI.

---

## Login System
<img width="1272" height="1268" alt="1e5797ca-ff56-4acf-9022-60bb79aced1f" src="https://github.com/user-attachments/assets/8cc002e3-a19d-423d-8b76-d10452d7b581" />


Secure login page with protected authentication routing for workers and administrators.

---

## Owner Dashboard

<img width="1257" height="1260" alt="bce5ffe1-d777-4fff-9d39-caee0761cb6f" src="https://github.com/user-attachments/assets/d0aaaeac-768d-44bb-bc3d-c308e76a07fa" />

Administrative dashboard for:

* shift creation
* scheduling
* worker management
* payroll access
* security logs
* interview management

---

## Interview Management System

<img width="1257" height="1270" alt="b9167081-42d7-4d7c-91ae-91be7e3a650a" src="https://github.com/user-attachments/assets/29ad6950-7bba-460d-a658-d5e852638dcd" />
Recruitment and interview tracking system featuring:

* resume uploads
* interview scheduling
* candidate tracking
* hiring status management
* notes system

---

## Worker Dashboard

<img width="1253" height="1242" alt="71bf86b5-d395-46c0-a28c-10b2d850ebd2" src="https://github.com/user-attachments/assets/19fee548-118d-474e-af28-664845a4c680" />
Worker-facing dashboard allowing employees to:

* claim shifts
* view schedules
* access shift calendars
* manage assigned work

---

## Hour Logging & Security Logs

<img width="1258" height="1266" alt="518decc4-edb7-4e52-b342-f7abc3591435" src="https://github.com/user-attachments/assets/6fc82dd3-1a69-42d0-81a7-acb6ab245a17" />

Integrated workforce reporting tools including:

* payroll hour submission
* daily security logs
* location tracking
* incident reporting

---

# Installation

Clone the repository:

```bash
git clone https://github.com/Jamisonsa/JamisonProtection.git
```

Navigate into the project directory:

```bash
cd JamisonProtection
```

Install dependencies:

```bash
npm install
```

Create a `.env` file:

```env
MONGO_URI=your_mongodb_uri
SESSION_SECRET=your_secret
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
```

Run the application:

```bash
node server.js
```

---

# Future Improvements

* Two-factor authentication
* Mobile responsiveness improvements
* SMS/email notifications
* Real-time shift updates
* Advanced analytics dashboard
* GPS check-in/check-out
* PWA/mobile app support
* Role permission management
* Automated payroll exporting

---

# Project Status

Currently under active development and continuously expanding with new workforce management features.

---

# Author

Sanaa Jamison
