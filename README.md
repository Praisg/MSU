# Medical Appointment & Stroke Management System

## Overview

This is a Flask web application designed for managing medical appointments and detailed stroke patient data. It supports multiple user roles (Patient, Technician, Doctor) with specific dashboards and functionalities. Data is stored using CSV files.

**Features:**
*   User Signup, Login, Logout with Role Selection
*   Role-based Dashboards:
    *   **Patient:** View profile, book/view appointments, view stroke data.
    *   **Technician:** Manage patient stroke data (Medical History, CT Results, NIHSS Assessments).
    *   **Doctor:** Review pending NIHSS assessments, view patient data, add clinical notes.
*   Appointment Scheduling System
*   Stroke Data Management (History, CT, NIHSS, Notes)
*   API Endpoints for Data Management

## Prerequisites

*   Python 3
*   Flask

## Setup & Installation

1.  **Clone the repository (if applicable):**
    ```bash
    git clone <your-repository-url>
    cd <repository-directory>
    ```
    (If you already have the files, just navigate to the project directory)

2.  **Install dependencies:**
    It's recommended to use a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```
    Install Flask:
    ```bash
    pip install Flask
    ```

## Running the Application

1.  **Ensure you are in the project's root directory.**
2.  **Run the Flask application:**
    ```bash
    python3 app.py
    ```
3.  The application will start in debug mode. Open your web browser and navigate to:
    `http://127.0.0.1:5001` (or the address shown in the terminal output).

## Data Files

The application uses the following CSV files (created automatically on first run if they don't exist):

*   `users.csv`: Stores user credentials and profile information.
*   `appointments.csv`: Stores appointment details.
*   `medical_history.csv`: Stores patient medical history.
*   `ct_results.csv`: Stores patient CT scan results.
*   `stroke_assessment.csv`: Stores patient NIHSS stroke assessments.
*   `doctor_notes.csv`: Stores notes added by doctors.

## Usage

*   Navigate to the application URL.
*   **Sign Up:** Create a new account, selecting your role (Patient, Technician, or Doctor).
*   **Login:** Log in with your email, password, and selected role.
*   You will be redirected to the dashboard corresponding to your role.
    *   **Patients:** Can update their profile, book appointments, and view their medical/stroke data.
    *   **Technicians:** Can select patients (using their email) to view and add medical history, CT results, and NIHSS assessments.
    *   **Doctors:** Can view pending NIHSS assessments submitted by technicians, view patient data, and add notes.

## Notes

*   This application uses CSV files for simplicity. For production use, consider migrating to a database.
*   Password storage is currently plain text and should be enhanced with hashing for security in a real-world scenario.
