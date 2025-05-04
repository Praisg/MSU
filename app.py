from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from datetime import datetime, timedelta
from functools import wraps
import csv
import os
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production

# Constants
DOCTORS = ['Mr. Gavi', 'Miss Siamwi', 'Mrs Ladonna']
TIME_SLOTS = [
    f"{hour:02d}:{minute:02d}"
    for hour in range(9, 17)
    for minute in range(0, 60, 30)
]

# File paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
USERS_CSV = os.path.join(BASE_DIR, 'users.csv')
APPOINTMENTS_CSV = os.path.join(BASE_DIR, 'appointments.csv')
# Add new CSV file paths for stroke data
MEDICAL_HISTORY_CSV = os.path.join(BASE_DIR, 'medical_history.csv')
CT_RESULTS_CSV = os.path.join(BASE_DIR, 'ct_results.csv')
STROKE_ASSESSMENT_CSV = os.path.join(BASE_DIR, 'stroke_assessment.csv')
DOCTOR_NOTES_CSV = os.path.join(BASE_DIR, 'doctor_notes.csv')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            flash('Please login first.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_file_permissions():
    """Check if necessary files are accessible and have correct permissions"""
    files = [USERS_CSV, APPOINTMENTS_CSV]
    for file_path in files:
        dir_path = os.path.dirname(file_path)
        try:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            if not os.path.exists(file_path):
                open(file_path, 'a').close()
            if not os.access(file_path, os.R_OK | os.W_OK):
                logger.error(f"Permission denied for {file_path}")
                return False
        except Exception as e:
            logger.error(f"Error checking permissions: {e}")
            return False
    return True

def initialize_csv_files():
    """Initialize all CSV files with headers if they don't exist"""
    files_to_initialize = {
        USERS_CSV: ['Email', 'Password', 'First_Name', 'Last_Name', 'Mobile_Number', 'Address', 'DOB', 'Sex', 'Role'],
        APPOINTMENTS_CSV: ['Doctor', 'Date', 'Time', 'Patient_Email', 'Patient_Name', 'Booking_Time'],
        MEDICAL_HISTORY_CSV: ['Patient_Email', 'Timestamp', 'Medical_History', 'Current_Medications', 'Allergies', 'Previous_Strokes'],
        CT_RESULTS_CSV: ['Patient_Email', 'Timestamp', 'Scan_Details', 'Results', 'Critical_Findings'],
        STROKE_ASSESSMENT_CSV: ['Patient_Email', 'Timestamp', 'Start_Time', 'End_Time', 'NIHSS_Score', 'BP', 'HR', 'O2_Sat', 'Assessment_Notes', 'Doctor_Approval_Status', 'Approving_Doctor_ID', 'Treatment_Prescribed'],
        DOCTOR_NOTES_CSV: ['Patient_Email', 'Timestamp', 'Doctor_ID', 'Notes']
    }
    try:
        for file_path, headers in files_to_initialize.items():
            dir_path = os.path.dirname(file_path)
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            if not os.path.exists(file_path):
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)
                logger.info(f"Created {os.path.basename(file_path)} at {file_path}")
    except Exception as e:
        logger.error(f"Error initializing CSV files: {e}")
        raise

def get_user_details(email):
    """Get user details from users.csv"""
    try:
        with open(USERS_CSV, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['Email'].strip() == email.strip():
                    return {k: v.strip() for k, v in row.items()}
        logger.warning(f"User not found: {email}")
    except Exception as e:
        logger.error(f"Error reading user details: {e}")
    return None

def update_user_details(email, details):
    """Update user details in users.csv"""
    try:
        rows = []
        updated = False
        with open(USERS_CSV, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            for row in reader:
                if row['Email'].strip() == email.strip():
                    row.update(details)
                    updated = True
                rows.append(row)

        if updated:
            with open(USERS_CSV, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows)
            logger.info(f"Updated details for user: {email}")
            return True
        logger.warning(f"No user found to update: {email}")
    except Exception as e:
        logger.error(f"Error updating user details: {e}")
    return False

def get_user_appointments(email):
    """Get appointments for a specific user"""
    appointments = []
    try:
        if os.path.exists(APPOINTMENTS_CSV):
            with open(APPOINTMENTS_CSV, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['Patient_Email'].strip() == email.strip():
                        appointments.append(row)
    except Exception as e:
        logger.error(f"Error getting appointments: {e}")
    return appointments

def is_time_slot_available(doctor, date, time_slot):
    """Check if a time slot is available for a doctor on a specific date"""
    try:
        if os.path.exists(APPOINTMENTS_CSV):
            with open(APPOINTMENTS_CSV, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if (row['Doctor'] == doctor and
                        row['Date'] == date and
                        row['Time'] == time_slot):
                        return False
    except Exception as e:
        logger.error(f"Error checking time slot: {e}")
    return True

def get_available_dates():
    """Return available dates starting from tomorrow up to 30 days"""
    dates = []
    start_date = datetime.now().date() + timedelta(days=1)
    for i in range(30):
        current_date = start_date + timedelta(days=i)
        # Exclude weekends (5 = Saturday, 6 = Sunday)
        if current_date.weekday() not in [5, 6]:
            dates.append(current_date.strftime('%Y-%m-%d'))
    return dates

def book_appointment_helper(doctor, date, time_slot, user_email, user_name):
    """Helper function to handle appointment booking"""
    try:
        if not is_time_slot_available(doctor, date, time_slot):
            return False, "Time slot no longer available"

        appointments = []
        headers = ['Doctor', 'Date', 'Time', 'Patient_Email',
                  'Patient_Name', 'Booking_Time']

        if os.path.exists(APPOINTMENTS_CSV):
            with open(APPOINTMENTS_CSV, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                appointments = list(reader)

        new_appointment = {
            'Doctor': doctor,
            'Date': date,
            'Time': time_slot,
            'Patient_Email': user_email,
            'Patient_Name': user_name,
            'Booking_Time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        appointments.append(new_appointment)

        with open(APPOINTMENTS_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(appointments)

        return True, "Appointment booked successfully"
    except Exception as e:
        logger.error(f"Error in book_appointment_helper: {e}")
        return False, str(e)

# Routes
@app.route('/')
def index():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        if get_user_details(email):
            flash('Email already registered')
            return redirect(url_for('signup'))

        try:
            is_empty = True
            if os.path.exists(USERS_CSV):
                with open(USERS_CSV, 'r', encoding='utf-8') as f:
                    is_empty = len(f.readlines()) <= 1

            if is_empty:
                with open(USERS_CSV, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Email', 'Password', 'First_Name', 'Last_Name',
                                   'Mobile_Number', 'Address', 'DOB', 'Sex', 'Role'])
                    writer.writerow([
                        email,
                        password,
                        request.form['first_name'].strip(),
                        request.form['last_name'].strip(),
                        request.form['mobile'].strip(),
                        request.form['address'].strip(),
                        request.form['dob'].strip(),
                        request.form['sex'].strip(),
                        request.form['role'].strip() or 'Patient'
                    ])
            else:
                with open(USERS_CSV, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        email,
                        password,
                        request.form['first_name'].strip(),
                        request.form['last_name'].strip(),
                        request.form['mobile'].strip(),
                        request.form['address'].strip(),
                        request.form['dob'].strip(),
                        request.form['sex'].strip(),
                        request.form['role'].strip() or 'Patient'
                    ])

            logger.info(f"New user registered: {email}")
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error in signup: {e}")
            flash('Registration failed. Please try again.')

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        selected_role = request.form.get('role') # Get selected role from form
        user = get_user_details(email)

        if not selected_role:
             flash('Please select your role.', 'warning')
             return render_template('login.html')

        if user and user['Password'] == password:
            stored_role = user.get('Role', 'Patient') # Get stored role

            # Validate selected role against stored role
            if selected_role == stored_role:
                session['user_email'] = user['Email']
                session['user_role'] = stored_role # Use the validated role
                logger.info(f"Login successful for {email}, Role: {session['user_role']}")
                flash(f"Welcome back, {user['First_Name']}!", 'success')

                # Redirect based on the validated role
                if session['user_role'] == 'Technician':
                    return redirect(url_for('stroke_profile'))
                elif session['user_role'] == 'Doctor':
                    return redirect(url_for('doctor_dashboard'))
                else: # Default to Patient dashboard
                    return redirect(url_for('dashboard'))
            else:
                # Role mismatch
                flash(f'Login failed: Role mismatch for user {email}. Expected {stored_role}, but selected {selected_role}.', 'danger')
                logger.warning(f"Role mismatch for {email}. Stored: {stored_role}, Selected: {selected_role}")
        else:
            # Invalid credentials
            flash('Invalid email or password.', 'danger')
            logger.warning(f"Failed login attempt for {email}")

    # GET request or failed login
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    flash('Logged out successfully!')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Explicitly check if user is a Patient for this dashboard
    if session.get('user_role') != 'Patient':
        # Redirect non-patients to their appropriate dashboard
        if session.get('user_role') == 'Technician':
            flash('Access denied. Redirecting to Technician dashboard.', 'warning')
            return redirect(url_for('stroke_profile'))
        elif session.get('user_role') == 'Doctor':
            flash('Access denied. Redirecting to Doctor dashboard.', 'warning')
            return redirect(url_for('doctor_dashboard'))
        else:
            # Fallback for unknown roles
            flash('Access denied. Unknown role.', 'danger')
            return redirect(url_for('login'))

    # --- Original Patient dashboard logic --- 
    user_email = session['user_email']
    user = get_user_details(user_email)
    if user:
        appointments = get_user_appointments(user_email)
        available_dates = get_available_dates()
        history = get_csv_data(MEDICAL_HISTORY_CSV, 'Patient_Email', user_email)
        ct_results = get_csv_data(CT_RESULTS_CSV, 'Patient_Email', user_email)
        assessments = get_csv_data(STROKE_ASSESSMENT_CSV, 'Patient_Email', user_email)
        notes = get_csv_data(DOCTOR_NOTES_CSV, 'Patient_Email', user_email)
        history.sort(key=lambda x: x.get('Timestamp', ''), reverse=True)
        ct_results.sort(key=lambda x: x.get('Timestamp', ''), reverse=True)
        assessments.sort(key=lambda x: x.get('Timestamp', ''), reverse=True)
        notes.sort(key=lambda x: x.get('Timestamp', ''), reverse=True)

        return render_template('dashboard.html',
                             user=user,
                             appointments=appointments,
                             doctors=DOCTORS,
                             time_slots=TIME_SLOTS,
                             available_dates=available_dates,
                             medical_history=history,
                             ct_results=ct_results,
                             stroke_assessments=assessments,
                             doctor_notes=notes)
    else:
        flash('User details not found.', 'error')
    return redirect(url_for('logout'))
    # --- End Original Patient dashboard logic --- 

@app.route('/book_appointment', methods=['POST'])
@login_required
def book_appointment():
    doctor = request.form['doctor']
    date = request.form['appointment_date']
    time_slot = request.form['time_slot']
    user = get_user_details(session['user_email'])

    if not user:
        flash('User details not found.')
        return redirect(url_for('dashboard'))

    success, message = book_appointment_helper(
        doctor,
        date,
        time_slot,
        session['user_email'],
        f"{user['First_Name']} {user['Last_Name']}"
    )

    flash(message)
    if success:
        logger.info(f"Appointment booked for {session['user_email']}")
    else:
        logger.error(f"Failed to book appointment: {message}")

    return redirect(url_for('dashboard'))

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    details = {
        'First_Name': request.form['first_name'].strip(),
        'Last_Name': request.form['last_name'].strip(),
        'Mobile_Number': request.form['mobile'].strip(),
        'Address': request.form['address'].strip(),
        'DOB': request.form['dob'].strip(),
        'Sex': request.form['sex'].strip()
    }

    if update_user_details(session['user_email'], details):
        flash('Profile updated successfully!')
    else:
        flash('Failed to update profile')

    return redirect(url_for('dashboard'))


@app.route('/get_available_slots/<doctor>/<date>')
def available_slots(doctor, date):
    slots = [slot for slot in TIME_SLOTS
             if is_time_slot_available(doctor, date, slot)]
    return jsonify({'slots': slots})


@app.route('/api/appointments')
def get_appointments_api():
    try:
        appointments = []
        if os.path.exists(APPOINTMENTS_CSV):
            with open(APPOINTMENTS_CSV, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                appointments = list(reader)

        # Get all appointments with patient details
        enhanced_appointments = []
        for app in appointments:
            # Get patient details including DOB and Sex
            patient_details = get_user_details(app['Patient_Email'])

            enhanced_appointment = {
                'id': len(enhanced_appointments) + 1,
                'doctor': app['Doctor'],
                'date': app['Date'],
                'time': app['Time'],
                'patient': {
                    'email': app['Patient_Email'],
                    'name': app['Patient_Name'],
                    'dob': patient_details.get('DOB', '') if patient_details else '',
                    'sex': patient_details.get('Sex', '') if patient_details else '',
                    'mobile': patient_details.get('Mobile_Number', '') if patient_details else '',
                    'address': patient_details.get('Address', '') if patient_details else ''
                },
                'booking_time': app.get('Booking_Time', ''),
                'status': 'scheduled'
            }
            enhanced_appointments.append(enhanced_appointment)

        response = {
            'status': 'success',
            'data': {
                'appointments': enhanced_appointments,
                'meta': {
                    'total': len(enhanced_appointments),
                    'timestamp': datetime.now().isoformat()
                }
            }
        }

        return jsonify(response)
    except Exception as e:
        logger.error(f"Error in API: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'data': None
        }), 500

# Helper functions to read stroke data
def get_csv_data(file_path, filter_key=None, filter_value=None):
    """Reads data from a CSV file, optionally filtering by a key-value pair."""
    data = []
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if filter_key and filter_value:
                        if row.get(filter_key, '').strip() == filter_value.strip():
                            data.append(row)
                    else:
                        data.append(row)
    except Exception as e:
        logger.error(f"Error reading {file_path}: {e}")
    return data

# Route for the stroke profile dashboard
@app.route('/stroke_profile')
@login_required
def stroke_profile():
    # Ensure only Technicians can access
    if session.get('user_role') != 'Technician':
        flash('Access denied. You must be a Technician.', 'danger')
        if session.get('user_role') == 'Doctor':
            return redirect(url_for('doctor_dashboard'))
        # Default redirect for Patients or others
        return redirect(url_for('dashboard')) 

    # --- Original Technician dashboard logic --- 
    try:
        all_users = get_csv_data(USERS_CSV)
        # Filter to show only Patients in the dropdown, not other staff
        patients = [
            {'Email': u['Email'], 'First_Name': u['First_Name'], 'Last_Name': u['Last_Name']}
            for u in all_users if u.get('Role', 'Patient') == 'Patient'
        ]
        return render_template('stroke_profile.html', patients=patients)
    except Exception as e:
        # ... error handling ...
        logger.error(f"Error loading stroke profile page: {e}")
        flash('Could not load stroke profile page.', 'error')
        # Redirect back to an appropriate safe page, maybe login if roles are broken
        return redirect(url_for('login')) 
    # --- End Original Technician dashboard logic --- 

# API endpoint to get combined data for a selected patient
@app.route('/api/stroke_patient_data/<patient_email>')
@login_required
def get_stroke_patient_data_api(patient_email):
    try:
        details = get_user_details(patient_email)
        history = get_csv_data(MEDICAL_HISTORY_CSV, 'Patient_Email', patient_email)
        ct_results = get_csv_data(CT_RESULTS_CSV, 'Patient_Email', patient_email)
        assessments = get_csv_data(STROKE_ASSESSMENT_CSV, 'Patient_Email', patient_email)
        notes = get_csv_data(DOCTOR_NOTES_CSV, 'Patient_Email', patient_email)

        if not details:
            return jsonify({'status': 'error', 'message': 'Patient details not found'}), 404

        # Sort data by timestamp if available (newest first)
        history.sort(key=lambda x: x.get('Timestamp', ''), reverse=True)
        ct_results.sort(key=lambda x: x.get('Timestamp', ''), reverse=True)
        assessments.sort(key=lambda x: x.get('Timestamp', ''), reverse=True)
        notes.sort(key=lambda x: x.get('Timestamp', ''), reverse=True)

        response = {
            'status': 'success',
            'data': {
                'details': details,
                'history': history, # Could return only latest or all
                'ct_results': ct_results,
                'assessments': assessments,
                'notes': notes
            }
        }
        return jsonify(response)

    except Exception as e:
        logger.error(f"Error fetching patient data for {patient_email}: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error fetching patient data'}), 500

# API endpoint to save doctor notes
@app.route('/api/save_notes', methods=['POST'])
@login_required
def save_notes_api():
    try:
        data = request.json
        patient_email = data.get('patient_email')
        notes_text = data.get('notes')
        doctor_id = session.get('user_email') # Assuming logged-in user is the doctor

        if not patient_email or not notes_text:
            return jsonify({'status': 'error', 'message': 'Missing patient email or notes'}), 400

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        new_note = [
            patient_email,
            timestamp,
            doctor_id,
            notes_text
        ]

        with open(DOCTOR_NOTES_CSV, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(new_note)

        logger.info(f"Note saved for patient {patient_email} by doctor {doctor_id}")
        return jsonify({'status': 'success', 'message': 'Notes saved successfully'})

    except Exception as e:
        logger.error(f"Error saving notes: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error saving notes'}), 500

# New API endpoint to save NIHSS assessment
@app.route('/api/save_nihss', methods=['POST'])
@login_required
def save_nihss_api():
    try:
        data = request.json
        patient_email = data.get('patient_email')
        nihss_score = data.get('nihss_score_total')
        start_time = data.get('start_time', 'N/A')
        end_time = data.get('end_time', datetime.now().strftime('%H:%M:%S'))
        assessment_notes = data.get('assessment_notes', '')
        timestamp = data.get('timestamp', datetime.now().isoformat())

        if not patient_email or nihss_score is None:
            return jsonify({'status': 'error', 'message': 'Missing patient email or NIHSS score'}), 400

        # Prepare row data for CSV including new doctor review fields
        new_assessment = [
            patient_email,
            timestamp,
            start_time,
            end_time,
            str(nihss_score),
            data.get('bp', 'N/A'),
            data.get('hr', 'N/A'),
            data.get('o2_sat', 'N/A'),
            assessment_notes,
            'Pending',  # Doctor_Approval_Status - Default to Pending
            '',         # Approving_Doctor_ID - Default to empty
            ''          # Treatment_Prescribed - Default to empty
        ]

        with open(STROKE_ASSESSMENT_CSV, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(new_assessment)

        logger.info(f"NIHSS assessment saved for patient {patient_email} with score {nihss_score}")
        return jsonify({'status': 'success', 'message': 'NIHSS assessment saved successfully', 'total_score': nihss_score})

    except Exception as e:
        logger.error(f"Error saving NIHSS assessment: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error saving NIHSS assessment'}), 500

# New API endpoint to save Medical History entry
@app.route('/api/save_medical_history', methods=['POST'])
@login_required
def save_medical_history_api():
    try:
        data = request.json
        patient_email = data.get('patient_email')
        history = data.get('medical_history')
        meds = data.get('current_medications', '')
        allergies = data.get('allergies', '')
        prev_strokes = data.get('previous_strokes', '')

        if not patient_email or not history:
            return jsonify({'status': 'error', 'message': 'Missing patient email or history summary'}), 400

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Headers: ['Patient_Email', 'Timestamp', 'Medical_History', 'Current_Medications', 'Allergies', 'Previous_Strokes']
        new_history_entry = [
            patient_email,
            timestamp,
            history,
            meds,
            allergies,
            prev_strokes
        ]

        with open(MEDICAL_HISTORY_CSV, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(new_history_entry)

        logger.info(f"Medical history entry saved for patient {patient_email}")
        return jsonify({'status': 'success', 'message': 'Medical history entry saved successfully'})

    except Exception as e:
        logger.error(f"Error saving medical history: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error saving medical history'}), 500

# New API endpoint to save CT Results entry
@app.route('/api/save_ct_results', methods=['POST'])
@login_required
def save_ct_results_api():
    try:
        data = request.json
        patient_email = data.get('patient_email')
        scan_details = data.get('scan_details')
        results = data.get('results')
        critical_findings = data.get('critical_findings', '')

        if not patient_email or not scan_details or not results:
            return jsonify({'status': 'error', 'message': 'Missing patient email, scan details, or results summary'}), 400

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Headers: ['Patient_Email', 'Timestamp', 'Scan_Details', 'Results', 'Critical_Findings']
        new_ct_entry = [
            patient_email,
            timestamp,
            scan_details,
            results,
            critical_findings
        ]

        with open(CT_RESULTS_CSV, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(new_ct_entry)

        logger.info(f"CT result entry saved for patient {patient_email}")
        return jsonify({'status': 'success', 'message': 'CT result entry saved successfully'})

    except Exception as e:
        logger.error(f"Error saving CT results: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error saving CT results'}), 500

# Doctor Dashboard Route (already has role check)
@app.route('/doctor_dashboard')
@login_required
def doctor_dashboard():
    if session.get('user_role') != 'Doctor':
        # ... (existing redirect logic) ...
        flash('Access denied. You must be a Doctor.', 'danger')
        if session.get('user_role') == 'Technician':
             return redirect(url_for('stroke_profile'))
        return redirect(url_for('dashboard'))
    
    # --- Original Doctor dashboard logic --- 
    try:
        # ... fetch pending assessments ... 
        all_assessments = get_csv_data(STROKE_ASSESSMENT_CSV)
        pending_assessments = [
            a for a in all_assessments
            if a.get('Doctor_Approval_Status', 'Pending') == 'Pending'
        ]
        for assessment in pending_assessments:
            patient = get_user_details(assessment['Patient_Email'])
            assessment['Patient_Name'] = f"{patient.get('First_Name', '')} {patient.get('Last_Name', '')}" if patient else 'Unknown'

        return render_template('doctor_dashboard.html', assessments=pending_assessments)
    except Exception as e:
        # ... error handling ...
        logger.error(f"Error loading doctor dashboard: {e}", exc_info=True)
        flash("Error loading dashboard data.", "danger")
        return render_template('doctor_dashboard.html', assessments=[])
    # --- End Original Doctor dashboard logic --- 

# Ensure startup check initializes all files
@app.before_request
def startup_check():
    if not hasattr(app, '_initialized'):
        try:
            if not check_file_permissions():
                logger.error("File permission check failed!")
                # Handle error appropriately, maybe return 500 or raise
                raise PermissionError("Cannot access required files")
            initialize_csv_files() # This now initializes all CSVs
            app._initialized = True # Mark as initialized
            logger.info("Application initialized successfully.")
        except Exception as e:
            logger.critical(f"Application initialization failed: {e}", exc_info=True)
            # Prevent app from starting if initialization fails
            raise RuntimeError(f"Application initialization failed: {e}")

if __name__ == '__main__':
    app.run(debug=True, port=5001) # Running on port 5001 again
