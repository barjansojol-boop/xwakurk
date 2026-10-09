# Xwakurk Basic School website

A responsive starter website for Xwakurk Basic School with English, Kurdish Sorani, Arabic, student registration/login, teacher-only text announcements, and recorded voice announcements.

## What is included
- Responsive website layout designed for mobile and desktop.
- Language switcher for English, Kurdish Sorani, and Arabic. Kurdish and Arabic use right-to-left layout.
- Student registration and login; passwords are stored as bcrypt hashes.
- Separate first-teacher setup flow protected by a secret setup code. Public registration cannot create teacher accounts.
- Teacher-only dashboard to publish text announcements and audio recordings.
- SQLite database for accounts and announcements.
- Basic protections: security headers, authentication rate limits, server-side role checks, HTTP-only session cookies, and audio file type/size checks.

## Run locally
1. Install Node.js 18 or newer: https://nodejs.org/
2. Extract the ZIP.
3. Open a terminal inside this folder and run `npm install`.
4. Copy `.env.example` to `.env`.
5. Change `SESSION_SECRET` and `TEACHER_SETUP_CODE` in `.env` to private, strong values.
6. Run `npm start`.
7. Open `http://localhost:3000`.

## Set up a teacher account
1. Open the site and choose **Teacher setup**.
2. Enter the teacher name, email, password, and the private `TEACHER_SETUP_CODE` from `.env`.
3. The teacher setup route closes once the first teacher account is created.
4. Keep the setup code private. Do not put `.env` in a public repository.

## Importing to GitHub / hosting
If by “giftup” you mean GitHub, extract the ZIP and upload the project files to a repository. Do not upload `.env`, `node_modules`, database files, or private student information.
This project requires a Node.js server and persistent storage. A static-only host cannot run its login/database/audio backend. When deploying, use a host that supports Node.js and persistent storage for `data/` and `uploads/`, set the environment variables in the host dashboard, and enable HTTPS. Set `NODE_ENV=production`.

## Important
This is a functional starter, not a website already online. It has not been configured for your school's real hosting account. Before collecting real student data, have a school administrator review privacy, account recovery, backups, teacher access, and hosting. Voice messages require microphone permission in the browser and are limited to 5 MB.
