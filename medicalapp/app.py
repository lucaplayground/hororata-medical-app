from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify, flash, get_flashed_messages
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime, timedelta, time
import mysql.connector 
import connect
import re
from re import search
import bcrypt
import logging

app = Flask(__name__)
app.secret_key = 'group_project2'
dbconn = None
connection = None


def getCursor():
    global dbconn
    global connection
    connection = mysql.connector.connect(user=connect.dbuser, password=connect.dbpass, host=connect.dbhost, database=connect.dbname, port=connect.dbport, autocommit=True)
    dbconn = connection.cursor(buffered=True)
    return dbconn


# List of Utility Functions
# a function checking if the user is logged in
def is_logged_in():
    return 'loggedin' in session  # True or False


# a function checking if the user is authroised to access a page
def is_authorised(role, user_id):
    if session.get('user_id') == user_id and session.get('role') == role:
        return True
    return False


# a function checking if a doctor is authorised to access a patient's info
def is_my_doctor(connection, patient_id):
    connection.execute('SELECT patient_id, doctor_id FROM patients WHERE patient_id = %s', (patient_id,))
    my_doctor = connection.fetchone()
    return (session.get('doctor_id') == my_doctor[1])  # True or False


# a function that encrypt a given password
def encrypt_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password, salt


# a function checking password strength
def is_password_strong(password):
    if len(password) < 8 or not search("[A-Z]", password) or not search("[0-9]", password):
        return False, 'Password must be at least 8 characters long, contain an uppercase letter and a number. '
    else:
        return True, ''


# a function that performs necessary checks and allows users to update their passwords
def update_password(user_id, old_password, new_password):
    connection = getCursor()
    try:
        # fetch the current password from the database
        connection.execute('SELECT password FROM users WHERE user_id = %s', (user_id,))
        current_password = connection.fetchone()[0]
        
        # check if the old password is correct
        if bcrypt.checkpw(old_password.encode('utf-8'), current_password.encode('utf-8')):
            # Update the password in the database
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            connection.execute('UPDATE users SET password = %s WHERE user_id = %s', (hashed_password, user_id))
            return True, "Password updated successfully."
        else:
            return False, "Incorrect old password."
    except Exception as e:
        print(f"An error occurred: {e}")
        return False, "An error occurred while updating the password."


# a function calculate patients' age, for payment purpose
def calculate_age(dob):
    today = datetime.today().date()
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


# a function that calculate appointment's charge based on the appt_type and patient's age
def calculate_appt_charge(appt_type, age):
    connection = getCursor()
    # Determine age group
    age_group = 'Under 14' if age < 14 else 'Over 14'

    # Fetch the price from the database
    connection.execute('SELECT price from prices WHERE appt_type=%s AND age_group=%s', (appt_type, age_group))
    result = connection.fetchone()

    if result:
        return result[0]
    else:
        return 'Price not found. '


# a function that fetches the appointment with extra details by appt_id
def get_appt_by_id(connection, id):
    
    query = '''
    SELECT
        a.appt_id,
        a.status,
        DATE_FORMAT(a.date, '%d/%m/%Y') as nz_date,
        DATE_FORMAT(a.time, '%H:%i') as nz_time,
        patients.fname,
        patients.lname,
        COALESCE(doctors.fname, nurses.fname) AS staff_fname,
        COALESCE(doctors.lname, nurses.lname) AS staff_lname,
        CASE
            WHEN doctors.doctor_id IS NOT NULL THEN 'Doctor'
            WHEN nurses.nurse_id IS NOT NULL THEN 'Nurse'
            ELSE 'Unknown'
        END AS staff_role,
        prices.price,
        patients.patient_id
    FROM appointments a
    JOIN patients ON a.patient_id = patients.patient_id
    LEFT JOIN doctors ON a.doctor_id = doctors.doctor_id
    LEFT JOIN nurses ON a.nurse_id = nurses.nurse_id
    JOIN prices ON a.price_id = prices.price_id
    LEFT JOIN invoices ON a.appt_id = invoices.appt_id
    WHERE a.appt_id = %s;
    '''

    connection.execute(query, (id,))
    return connection.fetchone()


# a function to update appointment notes
def update_appt_notes(connection, appt_id, new_notes):
    try:
        connection.execute('UPDATE appointments SET notes=%s WHERE appt_id=%s', (new_notes, appt_id))
        print(f"Updating notes for appt_id: {appt_id}, new_notes: {new_notes}")
        flash('Appointment notes have been updated', 'success')
    except Exception as e:
        flash(f'An error occurred: {e}', 'danger')


# a function that fetches available time slots based on nurse's id
def get_nurse_slots(nurse_id):
    connection = getCursor()
    query = '''
        SELECT slots.slot_time, nurse_slots.available_date
        FROM nurse_slots
        JOIN slots ON nurse_slots.slot_id = slots.slot_id
        WHERE nurse_slots.nurse_id = %s  
        '''
    # AND available_date BETWEEN CURDATE() AND CURDATE() + INTERVAL 7 DAY
    connection.execute(query,(nurse_id,))
    nurse_slots = []
    # Iterate over the results and organize them into a dictionary
    for row in connection.fetchall():
        slot_time, available_date = row 
        formatted_date = available_date.strftime('%d/%m/%Y')  # Format the date if available_date is a datetime object
        slot_hours, slot_minutes = divmod(slot_time.seconds, 3600)
        slot_minutes //= 60
        slot_time_obj = datetime.strptime(f"{slot_hours:02}:{slot_minutes:02}", "%H:%M").time()  # Create time object
        formatted_time = slot_time_obj.strftime('%H:%M')  # Format the time
        nurse_slots.append({'slot_time': formatted_time, 'available_date': formatted_date})
    return nurse_slots


# a function that fetches available time slots based on doctor's id
def get_doctor_slots(doctor_id):
    connection = getCursor()
    query = '''
        SELECT slots.slot_time, doctor_slots.available_date
        FROM doctor_slots
        JOIN slots ON doctor_slots.slot_id = slots.slot_id
        WHERE doctor_slots.doctor_id = %s
        ORDER BY available_date;
        '''
    # AND available_date BETWEEN CURDATE() AND CURDATE() + INTERVAL 7 DAY
    connection.execute(query, (doctor_id,))
    doctor_slots = []
    # Iterate over the results and organize them into a dictionary
    for row in connection.fetchall():
        slot_time, available_date = row 
        formatted_date = available_date.strftime('%d/%m/%Y')  # Format the date if available_date is a datetime object
        slot_hours, slot_minutes = divmod(slot_time.seconds, 3600)
        slot_minutes //= 60
        slot_time_obj = datetime.strptime(f"{slot_hours:02}:{slot_minutes:02}", "%H:%M").time()  # Create time object
        formatted_time = slot_time_obj.strftime('%H:%M')  # Format the time
        doctor_slots.append({'slot_time': formatted_time, 'available_date': formatted_date})
    return doctor_slots


# a function that reformat time
def timedelta_to_normal_calculator(time):
    hours, minutes = divmod(time.seconds, 3600)
    minutes //= 60
    time_obj = datetime.strptime(f"{hours:02}:{minutes:02}", "%H:%M").time()  # Create time object
    formatted_time = time_obj.strftime('%H:%M')  # Format the time
    return formatted_time


# a function that reformat time
def transfer_to_timedelta_calculator(time):
    hours, minutes = map(int, time.split(':'))
    return timedelta(hours=hours, minutes=minutes)


# List of Routes
# Shared
# Redirect logged-in users to home page, other users to login page
@app.route('/')
def index():
    if 'loggedin' in session:
        # redirect to dashboard if the user is logged in
        return redirect(url_for('home'))
    # redirect to login page if user is not logged in
    return redirect(url_for('login'))


# display contact us page
@app.route('/contact_us')
def contact_us():
    return render_template('contact_us.html')


# display contact us page
@app.route('/about_us')
def about_us():
    connection = getCursor()
    connection.execute('SELECT fname, lname, gender, specialty, language, photo FROM doctors;')
    doctor_data = connection.fetchall()
    connection.execute('SELECT fname, lname, gender, photo FROM nurses;')
    nurse_data = connection.fetchall()
    return render_template('about_us.html', doctor_data=doctor_data, nurse_data=nurse_data)


# Login
@app.route('/login', methods=['GET', 'POST'], endpoint='login')
def login():

    connection = getCursor()

    # detect the request type
    if request.method == 'POST':
        # create variables for easy access
        username = request.form['username']
        password = request.form['password']
    
        if username and password:
            # check if username exists
            try:
                connection.execute('SELECT * FROM users WHERE username = %s', (username,))
                account = connection.fetchone()
            except Exception as e:
                flash('An error occurred while accessing the database. ', 'danger')
                print(f'Database error: {e}')
                return render_template('login.html')
            # if username exists
            if account:
                # check the password
                if bcrypt.checkpw(password.encode('utf-8'), account[2].encode('utf-8')):
                    # save session data
                    session['loggedin'] = True
                    session['user_id'] = account[0]
                    session['username'] = account[1]
                    session['role'] = account[3]
                    # redirect to role-based dashboard
                    return redirect(url_for('home'))
                else:
                    flash('Incorrect password. ', 'warning')
            else:
                flash('Incorrect username. ', 'warning')
    return render_template('login.html')


# Routes users to different dashboards and save specific session data based on their roles
@app.route('/home')
def home():
    connection = getCursor()
    # check if user is logged in
    if 'loggedin' in session:
        role = session['role']
        user_id = session['user_id']
        connection.execute(f'SELECT * FROM {role.lower()}s WHERE user_id = %s', (user_id,))
        user_data = connection.fetchone()

        # save role-specific ID in the session
        session[f'{role.lower()}_id'] = user_data[0]
        return redirect(url_for('dashboard_home', role=role, user_id=user_id))

    # redirect to login page if user is not logged in
    return redirect(url_for('login'))


# Displays different dashboards based on user role
@app.route('/home/<string:role>/<int:user_id>')
def dashboard_home(role, user_id):

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised(role, user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403

    # choose the template based on the role
    template_map = {
        'Doctor': '/doctor_nurse/doctor_home.html',
        'Nurse': '/doctor_nurse/nurse_home.html',
        'Reception': '/reception/reception_home.html',
        'Patient': '/patient/patient_home.html',
        'Admin': 'admin/admin_home.html'
    }
    template_name = template_map.get(role)

    return render_template(template_name, user_id=user_id, role=role)


# Logout route, removing all stored session data
@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('role', None)
    session.pop('patient_id', None)
    session.pop('doctor_id', None)
    session.pop('nurse_id', None)
    session.pop('reception_id', None)
    session.pop('admin_id', None)
    # Redirect to login page
    return redirect(url_for('login'))


# Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    today = datetime.now().strftime('%Y-%m-%d')
    connection = getCursor()

    # Fetch doctors for dropdown
    connection.execute('SELECT * FROM doctors')
    doctors = connection.fetchall()

    # Register : It's registration page which should be pushed data by patients
    if request.method == 'POST':
        form_data = request.form.to_dict()

        # check if username exists
        connection.execute("SELECT * FROM users WHERE username = %s", [form_data['username']])
        exist_user = connection.fetchone()
        if exist_user:
            flash('The username is used.', 'warning')
            return render_template('register.html', form_data=form_data, today=today, doctors=doctors)
        
        # check if email address exists
        connection.execute("SELECT * FROM patients WHERE email = %s", [form_data['email']])
        exist_email = connection.fetchone()

        if exist_email:
            flash('The email is used.', 'warning')
            return render_template('register.html', form_data=form_data, today=today, doctors=doctors)
        # Validate password - confirm_password
        if form_data['password'] != form_data['confirm_password']:
            flash('Password and Confirm Password must be same.', 'warning')
            return render_template('register.html', form_data=form_data, today=today, doctors=doctors)
        # Validate contact_number
        if not form_data['contact_num'].isdigit():
            flash('Phone number should contain only digits.', 'warning')
            return render_template('register.html', form_data=form_data, today=today, doctors=doctors)
        
        # check password strength
        strong_password, msg = is_password_strong(form_data['password'])
        if not strong_password:
            flash(msg, 'warning')
            return render_template('register.html', form_data=form_data, today=today, doctors=doctors)
        
        # Encrypt password
        hashed_password, salt = encrypt_password(form_data['password'])

        # Save User info to user table
        insert_query = "INSERT INTO users (username, password, role, salt) VALUES (%s, %s, 'Patient',%s)"
        connection.execute(insert_query, (form_data['username'], hashed_password, salt))
        user_id = connection.lastrowid

        # Save patient info to patients table
        insert_query = """INSERT INTO patients (user_id, gender, fname, lname, contact_num, email, dob, address, doctor_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        selected_doctor_id = form_data.get('doctor')  # Get the selected doctor_id from the form
        connection.execute(insert_query, (user_id, form_data['gender'], form_data['fname'], form_data['lname'], form_data['contact_num'], form_data['email'], form_data['dob'], form_data['address'], selected_doctor_id))
        session['patient_id'] = connection.lastrowid

        # Render register_confirmation.html
        return render_template('register_confirmation.html')
    return render_template('register.html', today=today, doctors=doctors)


# Register - handle AJAX request for fetching doctor details to display
@app.route('/get_doctor_details/<int:doctor_id>')
def get_doctor_details(doctor_id):
    connection = getCursor()
    connection.execute("SELECT * FROM doctors WHERE doctor_id = %s", [doctor_id])
    doctor = connection.fetchone()
    doctor_dict = {
        'fname': doctor[2],
        'lname': doctor[3],
        'gender': doctor[4],
        'specialty': doctor[5],
        'language': doctor[6],
        'photo': doctor[7]
    }
    return jsonify(doctor_dict)


# Profile route, redirects users based on their roles
@app.route('/profile/<string:role>')
def profile(role):
    # Get role and user_id from session
    role = session.get('role')
    user_id = session.get('user_id')

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised(role, user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403

    if role and user_id:
        role_to_route = {
            'Admin': 'general_profile',
            'Reception': 'general_profile',
            'Doctor': 'doctor_profile',
            'Nurse': 'nurse_profile',
            'Patient': 'patient_profile'
        }
        return redirect(url_for(role_to_route.get(role, 'login'), role=role, user_id=user_id))
    else:
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))


# General profile route for admin users and reception staff
@app.route('/profile/<string:role>/<int:user_id>', methods=['GET', 'POST'])
def general_profile(role, user_id):

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised(role, user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    table_name = role.lower() + 's'
    connection = getCursor()

    if request.method == 'POST':
        # get form data
        new_fname = request.form['fname']
        new_lname = request.form['lname']

        # update user profile in the database
        connection.execute(f'UPDATE {table_name} SET fname=%s, lname=%s WHERE user_id=%s', (new_fname, new_lname, user_id))
        flash('Profile updated successfully', 'success')
        return redirect(url_for('general_profile', role=role, user_id=user_id))
    else:
        # fetch current user data from the database
        connection.execute(f'SELECT users.username, {table_name}.fname, {table_name}.lname FROM {table_name} INNER JOIN users ON {table_name}.user_id = users.user_id WHERE {table_name}.user_id = %s', (user_id,))
        user_data = connection.fetchone()
        return render_template('general_profile.html', user_data=user_data, role=role, user_id=user_id)


# Handle password change request
@app.route('/change_password/<int:user_id>', methods=['GET', 'POST'])
def change_password(user_id):
    role = session.get('role')

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised(role, user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    if request.method == 'POST':
        # Get form data
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # check if new password and confirm password match
        if new_password != confirm_password:
            flash('New password and confirm password do not match.', 'warning')
            return render_template('change_password.html')

        # check password strength
        strong_password, msg = is_password_strong(new_password)
        if not strong_password:
            flash(msg, 'warning')
            return render_template('change_password.html')

        # Update password
        success, update_msg = update_password(user_id, current_password, new_password)
        if success:
            flash(update_msg, 'success')
            return redirect(url_for('profile', role=session['role'], user_id=user_id)) 
        flash(update_msg, 'warning')
    return render_template('change_password.html')


# Patient specific routes
# Patient Profile
@app.route('/profile/patient/<int:user_id>', methods=['GET', 'POST'])
def patient_profile(user_id):

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Patient', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    connection = getCursor()
    try:
        if request.method == 'POST':
            new_fname = request.form['fname']
            new_lname = request.form['lname']
            new_contact_num = request.form['contact_num']
            new_address = request.form['address']
            new_email = request.form['email']
            
            connection.execute('UPDATE patients SET fname=%s, lname=%s, contact_num=%s, address=%s, email=%s WHERE user_id=%s', 
                               (new_fname, new_lname, new_contact_num, new_address, new_email, user_id))
            flash('Profile updated successfully', 'success')

        connection.execute('SELECT users.username, patients.fname, patients.lname, patients.gender, patients.dob, patients.contact_num, patients.address, patients.email FROM patients INNER JOIN users ON patients.user_id = users.user_id WHERE patients.user_id = %s', 
                           (user_id,))
        user_data = connection.fetchone()
        return render_template('patient/patient_profile.html', user_data=user_data, user_id=user_id)

    except Exception as e:
        print(f"Internal Error: {e}")
        flash("An error occurred while processing your request.", 'error')
        return render_template('patient/patient_profile.html')


# Patient's health records
@app.route('/home/patient/<int:user_id>/health_records')
def health_records(user_id):
    patient_id = session.get('patient_id')

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Patient', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    connection = getCursor()

    try:
        # Fetch the assigned doctor's name for the patient
        connection.execute('SELECT doctors.fname, doctors.lname FROM patients JOIN doctors ON patients.doctor_id = doctors.doctor_id WHERE patients.user_id = %s', (user_id,))
        doctor_name = connection.fetchone()

        # Fetch the health records of the patient
        connection.execute('SELECT * FROM health_records WHERE patient_id = %s', (patient_id,))
        health_records = connection.fetchall()

        if health_records:
            # print(health_records)
            return render_template('patient/health_records.html', doctor_name=doctor_name, health_records=health_records, user_id=user_id, patient_id=patient_id)
        else:
            flash("No health records found.", 'info')
            return render_template('patient/health_records.html')

    except Exception as e:
        print(f"Internal Error: {e}")
        flash("An error occurred while processing your request.", 'error')
        return render_template('patient/health_records.html', doctor_name=doctor_name), 500


# Patient's Health Records
@app.route('/home/patient/<int:user_id>/<int:patient_id>/test_results')
def get_test_results(user_id, patient_id):
    connection = getCursor()

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Patient', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    patient_id = session.get('patient_id')
    print(patient_id)
    role = session.get('role')
    connection.execute('SELECT health_records.test_results FROM health_records WHERE patient_id=%s', (patient_id,))
    test_results = connection.fetchone()
    if not test_results:
        flash('No result available. ', 'warning')
        return redirect(url_for('health_records', user_id=user_id))

    return render_template('/doctor_nurse/view_test_results.html', test_results=test_results, patient_id=patient_id, user_id=user_id, role=role)


# Patient - view my appointments
@app.route('/home/patient/<int:user_id>/my_appt', methods=['GET', 'POST'])
def my_appt(user_id):

    # check if user is logged in
    if not is_logged_in():
        return redirect(url_for('login', msg='You must log in to view the edit page.'))
    # check if user is authorized to access this page
    if not is_authorised('Patient', user_id):
        return render_template('403.html'), 403

    connection = getCursor()

    doctor_nurse_filter = request.args.get('doctor_nurse_filter', 'All')
    status_filter = request.args.get('status_filter', 'All')
    type_filter = request.args.get('type_filter', 'All')

    selected_role = doctor_nurse_filter
    selected_status = status_filter

    # Define SQL query for filtering
    query = '''
            SELECT a.date, a.time, u.role, COALESCE(d.fname, n.fname) AS fname, COALESCE(d.lname, n.lname) AS lname, a.type, a.status, a.appt_id, a.notes
            FROM appointments a
            LEFT JOIN patients p ON a.patient_id = p.patient_id
            LEFT JOIN doctors d ON a.doctor_id = d.doctor_id
            LEFT JOIN nurses n ON a.nurse_id = n.nurse_id
            LEFT JOIN users u ON
                (d.user_id = u.user_id AND u.role = 'Doctor')
                OR
                (n.user_id = u.user_id AND u.role = 'Nurse')
            WHERE p.user_id = %s
            AND (u.role = %s OR %s = 'All')
            AND (a.status = %s OR %s = 'All')
            AND (a.type = %s OR %s = 'All')  -- Add this line for Type filter
            ORDER BY a.status, a.date, a.time ASC;
            '''
            
    parameters = [user_id, selected_role, selected_role, selected_status, selected_status, type_filter, type_filter]  # Update parameters

    if selected_role != "All":
        query += ' AND u.role = %s'
        parameters.append(selected_role)

    if selected_status != "All":
        query += ' AND a.status = %s'
        parameters.append(selected_status)

    if type_filter != "All":  # Add this condition to apply Type filter
        query += ' AND a.type = %s'
        parameters.append(type_filter)

    # Execute the query with filter parameters
    connection.execute(query, parameters)
    appointments = connection.fetchall()

    # Modify the date and time format in the 'appointments' list
    appointments = list(appointments)  # Convert the result to a list to make it mutable

    for i in range(len(appointments)):
        date_str = str(appointments[i][0])
        time_str = str(appointments[i][1])

        new_date = datetime.strptime(date_str, '%Y-%m-%d').strftime('%d-%m-%Y')

        if time_str:  # Check if time_str is not empty
            time_parts = time_str.split(':')
            if len(time_parts) == 3:
                new_time = f"{time_parts[0]}:{time_parts[1]}"  # Extract 'hh:mm' portion
            else:
                new_time = "Invalid time format"
        else:
            new_time = "No time provided"

        # Update the tuple with the new date and time format
        appointments[i] = (new_date, new_time) + appointments[i][2:]

    return render_template('patient/my_appt.html', appointments=appointments, user_id=user_id,
                           doctor_nurse_filter=doctor_nurse_filter, status_filter=status_filter, 
                           type_filter=type_filter,  # Add this line for Type filter
                           selected_role=selected_role, selected_status=selected_status)


# Patient - View my prescription
@app.route('/home/patient/<int:user_id>/my_prescription', methods=['GET', 'POST'])
def my_prescriptions(user_id):
    connection = getCursor()

    # check if user is logged in
    if not is_logged_in():
        return redirect(url_for('login', msg='You must log in to view the edit page.'))
    # check if user is authorized to access this page
    if not is_authorised('Patient', user_id):
        return render_template('403.html'), 403
    
    patient_id = session.get('patient_id')
    query = """
        SELECT 
            DATE_FORMAT(p.date, '%d/%m/%Y') AS prescription_date,
            p.medication AS medication,
            CONCAT('Dr. ', d.fname, ' ', d.lname) AS doctor_name,
            CASE
                WHEN p.repeatable = 1 THEN 'Yes'
                ELSE 'No'
            END AS repeatable,
            p.prescription_id AS prescription_id
        FROM prescriptions p
        JOIN doctors d ON p.doctor_id = d.doctor_id
        WHERE p.patient_id = %s
        ORDER BY p.date DESC;
        """
    connection.execute(query, (patient_id,))
    prescription_data = connection.fetchall()

    return render_template('/patient/my_prescriptions.html', prescription_data=prescription_data)


# Patient - Repeat a repeatable prescription
@app.route('/home/patient/<int:user_id>/repeat_prescription/<int:prescription_id>', methods=['GET', 'POST'])
def repeat_prescription(user_id, prescription_id):

    # check if user is logged in
    if not is_logged_in():
        return redirect(url_for('login', msg='You must log in to view the edit page.'))
    # check if user is authorized to access this page
    if not is_authorised('Patient', user_id):
        return render_template('403.html'), 403
    
    # Get original prescription details
    connection = getCursor()
    query = "SELECT * FROM prescriptions WHERE prescription_id = %s"
    connection.execute(query, (prescription_id,))
    original_prescription = connection.fetchone()

    # Create new prescription based on the original
    query = """INSERT INTO prescriptions (patient_id, doctor_id, medication, date, repeatable)
               VALUES (%s, %s, %s, NOW(), %s)"""
    connection.execute(query, (original_prescription[1], 
                               original_prescription[2],
                               original_prescription[3],
                               original_prescription[5]))

    flash('Prescription has been repeated.', 'success')
    return redirect(url_for('my_prescriptions', user_id=user_id))


# Patient - Book an appt, choose an appointment type
@app.route('/home/patient/<int:user_id>/select_appointment_type', methods=['GET', 'POST'])
def select_appointment_type(user_id):
    cursor = getCursor()
    cursor.execute("SELECT appt_type, age_group, price FROM prices")
    prices = cursor.fetchall()
    if request.method == 'POST':
        appt_type = request.form.get('appt_type')
        return redirect(url_for('select_staff_type', user_id=user_id, appt_type=appt_type))
    return render_template('patient/select_appointment_type.html', user_id=user_id, prices=prices)


# Patient - Book an appt, choose a staff type
@app.route('/home/patient/<int:user_id>/<appt_type>/select_staff_type', methods=['GET', 'POST'])
def select_staff_type(user_id, appt_type):
    if request.method == 'POST':
        staff_type = request.form.get('staff_type')
        return redirect(url_for('select_specific_staff', user_id=user_id, staff_type=staff_type, appt_type=appt_type))
    return render_template('patient/select_staff_type.html', user_id=user_id)


# Patient - Book an appt, choose a staff
@app.route('/home/patient/<int:user_id>/<staff_type>/<appt_type>/select_specific_staff', methods=['GET', 'POST'])
def select_specific_staff(user_id, staff_type, appt_type):
    cursor = getCursor()
    if staff_type == "doctor":
        cursor.execute('SELECT doctor_id, fname, lname FROM doctors WHERE doctor_id = (SELECT doctor_id FROM patients WHERE user_id = %s)', (user_id,))
    else:  # staff_type == "nurse"
        cursor.execute('SELECT nurse_id, fname, lname FROM nurses')
    staff_list = cursor.fetchall()
    if request.method == 'POST':
        staff_id = request.form.get('selected_staff_id')
        return redirect(url_for('select_time_slot', user_id=user_id, staff_type=staff_type, staff_id=staff_id, appt_type=appt_type))
    
    return render_template('patient/select_specific_staff.html', user_id=user_id, staff_list=staff_list, staff_type=staff_type, appt_type=appt_type)


# Patient - Book an appt, choose a time slot
@app.route('/home/patient/<int:user_id>/select_time_slot/<staff_type>/<int:staff_id>/<appt_type>', methods=['GET', 'POST'])
def select_time_slot(user_id, staff_type, staff_id, appt_type):
    cursor = getCursor()
    today = datetime.now().date()
    upcoming_dates = [(today + timedelta(days=i)).strftime('%d/%m/%Y') for i in range(7)]
    
    # Fetch the name and available slots of the selected staff
    if staff_type == "doctor":
        cursor.execute('SELECT fname, lname FROM doctors WHERE doctor_id = %s', (staff_id,))
        staff = cursor.fetchone()
        cursor.execute('''
            SELECT ds.available_date, s.slot_time 
            FROM slots s
            JOIN doctor_slots ds ON s.slot_id = ds.slot_id
            WHERE ds.doctor_id = %s AND ds.available_date >= %s
        ''', (staff_id, today))
    else:  # staff_type == "nurse"
        cursor.execute('SELECT fname, lname FROM nurses WHERE nurse_id = %s', (staff_id,))
        staff = cursor.fetchone()
        cursor.execute('''
            SELECT ns.available_date, s.slot_time 
            FROM slots s
            JOIN nurse_slots ns ON s.slot_id = ns.slot_id
            WHERE ns.nurse_id = %s AND ns.available_date >= %s
        ''', (staff_id, today))
    
    staff_name = f"{staff[0]} {staff[1]}"
    available_slots = cursor.fetchall()
    
    # Filter out slots that have already been booked
    cursor.execute('''
        SELECT date, time FROM appointments
        WHERE (doctor_id = %s OR nurse_id = %s) AND status = 'Upcoming'
    ''', (staff_id, staff_id))
    booked_slots = cursor.fetchall()
    available_slots = [slot for slot in available_slots if (slot[0], slot[1]) not in booked_slots]
    
    # Format the results for display
    available_slots_with_dates = [(slot[0].strftime('%d/%m/%Y'), (slot[1].seconds // 3600, (slot[1].seconds // 60) % 60)) for slot in available_slots]
    formatted_slots_with_dates = [(date, f"{h:02d}:{m:02d}") for date, (h, m) in available_slots_with_dates]
    
    if request.method == 'POST':
        selected_date, selected_time = request.form.get('selected_slot').split(',')
        
        # Convert selected_date to MySQL date format
        day, month, year = map(int, selected_date.split('/'))
        mysql_date_format = f"{year}-{month:02d}-{day:02d}"
        
        slot_hour, slot_minute = map(int, selected_time.split(':'))
        appointment_time = time(slot_hour, slot_minute)

        # Fetch patient_id from patients table using user_id
        cursor.execute('SELECT patient_id FROM patients WHERE user_id = %s', (user_id,))
        result = cursor.fetchone()
        if result:
            patient_id = result[0]
        else:
            print(f"No patient found with user_id: {user_id}")
            return "Error: No patient found", 400

        # Fetch the patient's date of birth to determine the price
        cursor.execute('SELECT dob FROM patients WHERE user_id = %s', (user_id,))
        dob = cursor.fetchone()[0]
        age = calculate_age(dob)
        print(age)
        age_group = "Under 14" if age <= 14 else "Over 14"

        # Fetch the price_id based on appointment type and age group
        cursor.execute('SELECT price_id FROM prices WHERE appt_type = %s AND age_group = %s', (appt_type, age_group))
        price_id = cursor.fetchone()[0]

        try:
            if staff_type == "doctor":
                cursor.execute('''
                    INSERT INTO appointments (patient_id, doctor_id, date, time, type, price_id, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 'Upcoming')
                ''', (patient_id, staff_id, mysql_date_format, appointment_time, appt_type, price_id))
            else:  # staff_type == "nurse"
                cursor.execute('''
                    INSERT INTO appointments (patient_id, nurse_id, date, time, type, price_id, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 'Upcoming')
                ''', (patient_id, staff_id, mysql_date_format, appointment_time, appt_type, price_id))

        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return "Error: Unable to book appointment", 500

        if appt_type == "Virtual" and age <= 14:
            return render_template('patient/payment_confirmation.html', user_id=user_id)
        elif appt_type == "Virtual":
            return redirect(url_for('pay_for_appointment', user_id=user_id, staff_type=staff_type, staff_id=staff_id, appt_type=appt_type, price_id=price_id))
        else:
            return render_template('patient/appt_success.html', user_id=user_id)

    return render_template('patient/select_time_slot.html', user_id=user_id, staff_type=staff_type, staff_name=staff_name, staff_id=staff_id, upcoming_dates=upcoming_dates, slots=formatted_slots_with_dates, appt_type=appt_type)


# Patient - Book an appt, pay for the booking
@app.route('/home/patient/<int:user_id>/pay_for_appointment/<staff_type>/<int:staff_id>/<appt_type>/<int:price_id>', methods=['GET', 'POST'])
def pay_for_appointment(user_id, staff_type, staff_id, appt_type, price_id):
    connection = getCursor()

    # Fetch the price based on the price_id
    connection.execute("SELECT price FROM prices WHERE price_id = %s", (price_id,))
    amount = connection.fetchone()[0]

    if request.method == 'POST':
        # Save payment data into the 'payments' table
        insert_query = "INSERT INTO payments (invoice_id, patient_id, amount, date, payment_method) VALUES(NULL, %s, %s, %s, 'Credit Card')"
        patient_id = session['patient_id']
        connection.execute(insert_query, (patient_id, amount, datetime.today()))
        print("Payment data saved successfully")

        return render_template('patient/payment_confirmation.html', user_id=user_id)

    return render_template('patient/payment_appt.html', amount=amount, user_id=user_id, staff_type=staff_type, staff_id=staff_id, appt_type=appt_type, price_id=price_id)


# Patient - view payment history
@app.route('/home/patient/<int:user_id>/payment_history')
def payment_history(user_id):
    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Patient', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    connection = getCursor()
    query = '''
    SELECT
        DATE_FORMAT(p.date, '%d/%m/%Y') as pay_date,
        p.amount,
        p.payment_method,
        DATE_FORMAT(a.date, '%d/%m/%Y') as appt_date,
        DATE_FORMAT(a.time, '%H:%i') as appt_time,
        a.type,
        COALESCE(doctors.fname, nurses.fname) AS staff_fname,
        COALESCE(doctors.lname, nurses.lname) AS staff_lname,
        CASE
            WHEN doctors.doctor_id IS NOT NULL THEN 'Doctor'
            WHEN nurses.nurse_id IS NOT NULL THEN 'Nurse'
            ELSE 'Unknown'
        END AS staff_role
    FROM payments p
    JOIN invoices ON p.invoice_id = invoices.invoice_id
    LEFT JOIN appointments a ON a.appt_id = invoices.appt_id
    LEFT JOIN doctors ON a.doctor_id = doctors.doctor_id
    LEFT JOIN nurses ON a.nurse_id = nurses.nurse_id
    WHERE p.patient_id=%s
    ORDER BY p.date;
    '''
    connection.execute(query, (session['patient_id'],))
    payment_data = connection.fetchall()
    return render_template('patient/payment_history.html', payment_data=payment_data)


# Patient - View Unpaid Invoices
@app.route('/home/patient/<int:user_id>/unpaid_invoices', methods=['GET', 'POST'])
def unpaid_invoices(user_id):
    connection = getCursor()

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Patient', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403

    patient_id = session.get('patient_id')
    query = """
        SELECT
            a.type AS appt_type,
            CASE
                WHEN doctors.fname IS NOT NULL THEN CONCAT('Dr. ', doctors.fname, ' ', doctors.lname)
                WHEN nurses.fname IS NOT NULL THEN CONCAT('Nurse ', nurses.fname, ' ', nurses.lname)
                ELSE 'N/A'
            END AS medical_staff,
            DATE_FORMAT(a.date, '%d/%m/%Y') as appt_date,
            DATE_FORMAT(a.time, '%H:%i') as appt_time,
            invoices.amount AS invoice_amount,
            invoices.invoice_id
        FROM invoices
        JOIN appointments a ON invoices.appt_id = a.appt_id
        LEFT JOIN doctors ON a.doctor_id = doctors.doctor_id
        LEFT JOIN nurses ON a.nurse_id = nurses.nurse_id
        WHERE a.patient_id = %s AND invoices.status = 'Unpaid'
        ORDER BY appt_date, appt_time;
        """

    connection.execute(query, (patient_id,))
    unpaid_invoice_data = connection.fetchall()
    
    if not unpaid_invoice_data:
        flash("You don't have any unpaid invoices.", "warning")

    return render_template('patient/unpaid_invoices.html', unpaid_invoice_data=unpaid_invoice_data)


# Patient - pay for the invoice
@app.route('/home/patient/<int:user_id>/pay_invoice/<int:invoice_id>', methods=['GET', 'POST'])
def pay_invoice(user_id, invoice_id):
    cursor = getCursor()

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Patient', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    # Fetch the patient_id using user_id
    cursor.execute('SELECT patient_id FROM patients WHERE user_id = %s', (user_id,))
    patient = cursor.fetchone()
    if not patient:
        return "Patient not found", 404
    patient_id = patient[0]

    # Fetch the invoice details
    cursor.execute('SELECT amount, status FROM invoices WHERE invoice_id = %s', (invoice_id,))
    invoice = cursor.fetchone()

    if not invoice:
        return "Invoice not found", 404

    if invoice[1] == "Paid":
        return "This invoice has already been paid.", 400

    if request.method == 'POST':
        # Update the invoice status to 'Paid'
        cursor.execute('UPDATE invoices SET status = "Paid" WHERE invoice_id = %s', (invoice_id,))

        # Insert the payment record
        cursor.execute('''
            INSERT INTO payments (invoice_id, patient_id, amount, date, payment_method)
            VALUES (%s, %s, %s, %s, 'Credit Card')
        ''', (invoice_id, patient_id, invoice[0], datetime.now().date()))

        flash('Thank you for your payment. Your invoice has been successfully paid.', 'success')
        return redirect(url_for('unpaid_invoices', user_id=user_id))
    return render_template('patient/pay_invoice.html', user_id=user_id, invoice=invoice)


# Doctor & Nurse routes
# Doctor Profile
@app.route('/profile/doctor/<int:user_id>', methods=['GET', 'POST'])
def doctor_profile(user_id):

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Doctor', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    connection = getCursor()
    try:
        if request.method == 'POST':
            new_fname = request.form['fname']
            new_lname = request.form['lname']
            new_specialty = request.form['specialty']
            new_language = request.form['language']
            
            connection.execute('UPDATE doctors SET fname=%s, lname=%s, specialty=%s, language=%s WHERE user_id=%s', 
                               (new_fname, new_lname, new_specialty, new_language, user_id))
            flash('Profile updated successfully', 'success')
            return redirect(url_for('doctor_profile', user_id=user_id))

        connection.execute('SELECT users.username, doctors.fname, doctors.lname, doctors.gender, doctors.specialty, doctors.language FROM doctors INNER JOIN users ON doctors.user_id = users.user_id WHERE doctors.user_id = %s', 
                           (user_id,))
        user_data = connection.fetchone()
        if user_data:
            return render_template('doctor_nurse/doctor_profile.html', user_data=user_data, user_id=user_id)
        else:
            flash("No profile data found.", 'info')
            return render_template('doctor_nurse/doctor_profile.html')
    
    except Exception as e:
        print(f"Internal Error: {e}")
        flash("An error occurred while processing your request.", 'error')
        return render_template('doctor_nurse/doctor_profile.html'), 500


# Doctor - list all patients/specific patients with a prescribe medication link  
@app.route('/home/doctor/<int:user_id>/prescriptions', methods=["GET", "POST"])
def prescription_history(user_id):

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Doctor', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    connection = getCursor()
    query = '''
        SELECT
            p.prescription_id,
            DATE_FORMAT(p.date, '%d/%m/%Y') as nz_date,
            patients.fname,
            patients.lname,
            p.medication,
            CASE
                WHEN p.repeatable = 1 THEN 'Yes'
                ELSE 'No'
            END AS repeatable
        FROM prescriptions p
        JOIN patients ON p.patient_id = patients.patient_id
        LEFT JOIN doctors ON p.doctor_id = doctors.doctor_id
        ORDER BY p.date DESC;
        '''
    connection.execute(query)
    prescription_data = connection.fetchall()
    
    return render_template('doctor_nurse/prescription_history.html', user_id=user_id, prescription_data=prescription_data)


# Doctor - Prescribe Medication
## Select a patient
@app.route('/home/doctor/<int:user_id>/prescribe_medication/select_patient', methods=['GET', 'POST'])
def select_patient(user_id):
    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Doctor', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    if request.method == 'POST':
        selected_patient_id = request.form.get('patient_id')
        if selected_patient_id:
            return redirect(url_for('prescribe_medication', user_id=user_id, patient_id=selected_patient_id))

    doctor_id = session['doctor_id']
    
    # Fetch the list of registered patients for this doctor
    connection = getCursor()
    query = "SELECT * FROM patients WHERE doctor_id = %s"
    connection.execute(query, (doctor_id,))
    patients = connection.fetchall()
    
    return render_template('/doctor_nurse/select_patient.html', user_id=user_id, patients=patients)


## Add Prescription details
@app.route('/home/doctor/<int:user_id>/prescribe_medication/<int:patient_id>', methods=["GET", "POST"])
def prescribe_medication(user_id, patient_id):

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Doctor', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    connection = getCursor()
    query = "SELECT * FROM patients WHERE patient_id = %s"
    connection.execute(query, (patient_id,))
    patient = connection.fetchone()

    if request.method == 'POST':

        # Get form data
        medication = request.form.get('medication')
        repeatable = request.form.get('repeatable')

        # Convert repeatable to a boolean or integer
        repeatable = 1 if repeatable == 'on' else 0

        # Insert into database
        query = "INSERT INTO prescriptions (patient_id, doctor_id, date, medication, repeatable) VALUES (%s, %s, NOW(), %s, %s)"
        connection.execute(query, (patient_id, session['doctor_id'], medication, repeatable))

        flash('Prescription successfully added!', 'success')
        return redirect(url_for('prescription_history', user_id=user_id))

    return render_template('/doctor_nurse/prescribe_medication.html', user_id=user_id, patient_id=patient_id, patient=patient)


# Nurse Profile
@app.route('/profile/nurse/<int:user_id>', methods=['GET', 'POST'])
def nurse_profile(user_id):

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Nurse', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403

    connection = getCursor()
    try:
        if request.method == 'POST':
            new_fname = request.form['fname']
            new_lname = request.form['lname']
            
            connection.execute('UPDATE nurses SET fname=%s, lname=%s WHERE user_id=%s', (new_fname, new_lname, user_id))
            flash('Profile updated successfully', 'success')

        connection.execute('SELECT users.username, nurses.fname, nurses.lname, nurses.gender FROM nurses INNER JOIN users ON nurses.user_id = users.user_id WHERE nurses.user_id = %s', (user_id,))
        user_data = connection.fetchone()
        if user_data:
            return render_template('doctor_nurse/nurse_profile.html', user_data=user_data, user_id=user_id)
        else:
            flash("No profile data found.", 'info')
            return render_template('doctor_nurse/nurse_profile.html')

    except Exception as e:
        print(f"Internal Error: {e}")
        flash("An error occurred while processing your request.", 'error')
        return render_template('doctor_nurse/nurse_profile.html')


# Doctor & Nurse - View appointments
@app.route('/home/<string:role>/<int:user_id>/my_appointments', methods=['GET', 'POST'])
def view_appointments(role, user_id):

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised(role, user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403

    connection = getCursor()
    selected_appt_id = None

    if request.method == 'POST':
        selected_appt_id = request.form.get('appt_id')  # Get the selected appointment ID
        if selected_appt_id:
            new_notes = request.form['notes']
            update_appt_notes(connection, selected_appt_id, new_notes)

    query = '''
    SELECT
        DATE_FORMAT(a.date, '%d/%m/%Y') as nz_date,
        DATE_FORMAT(a.time, '%H:%i') as nz_time,
        a.*, patients.fname, patients.lname, patients.patient_id
    FROM appointments a
    JOIN patients ON a.patient_id = patients.patient_id
    LEFT JOIN doctors ON a.doctor_id = doctors.doctor_id
    LEFT JOIN nurses ON a.nurse_id = nurses.nurse_id
    WHERE (doctors.user_id = %s AND 'Doctor' = %s) OR (nurses.user_id = %s AND 'Nurse' = %s)
    ORDER BY a.status;
    '''

    connection.execute(query, (user_id, role, user_id, role))
    appt_data = connection.fetchall()

    return render_template('/doctor_nurse/view_appointments.html', appt_data=appt_data, role=role, user_id=user_id, selected_appt_id=selected_appt_id)


# Doctor & Nurse - Add appt notes
@app.route('/home/<string:role>/<int:user_id>/add_notes', methods=['GET', 'POST'])
def add_notes(role, user_id):

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised(role, user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403

    appt_id = request.args.get('appt_id')
    connection = getCursor()

    if not appt_id:
        flash('No appointment is selected.', 'warning')
        return redirect(url_for('view_appointments', role=role, user_id=user_id))

    if request.method == 'POST':
        new_notes = request.form['notes']
        update_appt_notes(connection, appt_id, new_notes)
        return redirect(url_for('view_appointments', role=role, user_id=user_id))
    else:
        connection.execute("SELECT notes FROM appointments WHERE appt_id = %s", (appt_id,))
        current_notes = connection.fetchone()

        return render_template('/doctor_nurse/add_notes.html', current_notes=current_notes, user_id=user_id, role=role, appt_id=appt_id)


# Doctor & Nurse - complete an appt
@app.route('/home/<string:role>/<int:user_id>/complete_appt', methods=['GET', 'POST'])
def complete_appointment(role, user_id):
    
    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised(role, user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    connection = getCursor()
    appt_id = request.args.get('appt_id')
    connection.execute('SELECT appointments.status FROM appointments WHERE appt_id=%s', (appt_id,))
    current_status = connection.fetchone()

    if not appt_id:
        flash('No appointment is selected.', 'warning')
        return redirect(url_for('view_appointments', role=role, user_id=user_id))
    if current_status[0] == 'Completed':
        flash('This appointment has already been completed. ', 'warning')
        return redirect(url_for('view_appointments', role=role, user_id=user_id))
    if current_status[0] == 'Cancelled':
        flash('Cancelled appointment cannot be completed. ', 'warning')
        return redirect(url_for('view_appointments', role=role, user_id=user_id))

    connection.execute('UPDATE appointments SET status=%s WHERE appt_id=%s', ('Completed', appt_id))
    flash('Appointment has been completed', 'success')

    return redirect(url_for('view_appointments', role=role, user_id=user_id))


# Doctors - view a list of registered patients
@app.route('/home/doctor/<int:user_id>/mypatients')
def my_patients(user_id):
    connection = getCursor()

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Doctor', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    connection.execute('''
        SELECT
            patients.*,
            DATE_FORMAT(patients.dob, '%d/%m/%Y') as nz_date
        FROM patients
        WHERE patients.doctor_id =(
        SELECT doctor_id FROM doctors WHERE user_id = %s
        );
    ''', (user_id,))

    patients = connection.fetchall()

    return render_template('doctor_nurse/doctor_my_patients.html', patients=patients, user_id=user_id)


# Doctor & Nurse - view and update a patient's health records
@app.route('/home/<string:role>/<int:user_id>/<int:patient_id>/health_records', methods=['GET', 'POST'])
def manage_health_records(role, patient_id, user_id):
    connection = getCursor()
    
    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised(role, user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    if session['role'] == 'Doctor':
        if not is_my_doctor(connection, patient_id):
            return render_template('403.html'), 403

    if request.method == 'POST':
        blood_type = request.form.get('blood_type')
        allergies = request.form.get('allergies')
        medications = request.form.get('medications')
        medical_conditions = request.form.get('medical_conditions')
        surgeries = request.form.get('surgeries')
        family_history = request.form.get('family_history')
        notes = request.form.get('notes')
        query = '''
            UPDATE health_records
            SET blood_type=%s, allergies=%s, medications=%s, medical_conditions=%s,
            surgeries=%s, family_history=%s, notes=%s
            WHERE patient_id=%s
        '''
        connection.execute(query, (blood_type, allergies, medications, medical_conditions, surgeries, family_history, notes, patient_id))
        flash('Update successful', 'success')

    # Fetch health records to render
    connection.execute('SELECT * FROM health_records WHERE patient_id = %s', (patient_id,))
    health_records = connection.fetchall()

    # Fetch patient's data
    connection.execute('SELECT p.patient_id, p.fname, p.lname FROM patients p WHERE patient_id=%s', (patient_id,))
    patient_data = connection.fetchone()

    return render_template('doctor_nurse/manage_health_records.html', user_id=user_id, health_records=health_records, patient_data=patient_data)


# Doctor & Nurse - view patient's test results
@app.route('/home/<string:role>/<int:user_id>/<int:patient_id>/test_results')
def view_test_results(role, patient_id, user_id):
    connection = getCursor()
    
    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised(role, user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    if session['role'] == 'Doctor':
        if not is_my_doctor(connection, patient_id):
            return render_template('403.html'), 403

    connection.execute('SELECT health_records.test_results FROM health_records WHERE patient_id=%s', (patient_id,))
    test_results = connection.fetchone()
    if not test_results:
        flash('No result available. ', 'warning')
        return redirect(url_for('my_patients', user_id=user_id))
    
    # Fetch the patient's info
    connection.execute('SELECT p.patient_id, p.fname, p.lname FROM patients p WHERE patient_id=%s', (patient_id,))
    patient_data = connection.fetchone()
    
    return render_template('/doctor_nurse/view_test_results.html', test_results=test_results, patient_data=patient_data, role=role)


# Nurse - view patient's details
@app.route('/home/nurse/<int:user_id>/patient/<int:patient_id>')
def view_patient_details(user_id, patient_id):
    connection = getCursor()
    connection.execute('''
        SELECT
            patients.*,
            DATE_FORMAT(patients.dob, '%d/%m/%Y') as nz_date,
            doctors.fname, doctors.lname
        FROM patients
        LEFT JOIN doctors ON patients.doctor_id = doctors.doctor_id
        WHERE patients.patient_id = %s
    ''', (patient_id,))

    patient_data = connection.fetchall()
    return render_template('doctor_nurse/nurse_view_patient_details.html', patient_data=patient_data, user_id=user_id)


# Doctor - manage roster
@app.route('/home/doctor/<int:user_id>/roster', methods=['GET', 'POST'])
def doctor_myroster(user_id):
    connection = getCursor()
    connection.execute('SELECT doctor_id FROM doctors WHERE user_id = %s', (user_id,))
    this_doctor_id = connection.fetchone()
    doctor_id = this_doctor_id[0]
    
    # Fetch available slots for the next week
    cursor = getCursor()
    cursor.execute("SELECT * FROM slots")
    slots = cursor.fetchall()
    formatted_slots = []
    for slot in slots:
        slot_id, slot_time = slot
        formatted_time = timedelta_to_normal_calculator(slot_time)
        formatted_slots.append({'slot_id': slot_id, 'formatted_time': formatted_time})

    if request.method == 'POST':
        connection = getCursor()
        slot_id = request.form['slot_time']  # This will contain the selected slot_id
        date = request.form['date']
        # Check if the slot already exists in the doctor's roster for the selected date
        existing_slot_query = "SELECT * FROM doctor_slots WHERE doctor_id = %s AND slot_id = %s AND available_date = %s;"
        connection.execute(existing_slot_query, (doctor_id, slot_id, date))
        existing_slot = connection.fetchone()

        if existing_slot:
            # Slot already exists, show a message to the user
            flash('Duplicated slot, please try again', 'warning')
        else:
            # Slot does not exist, insert it into the doctor's roster
            connection.execute('INSERT INTO doctor_slots (doctor_id, slot_id, available_date) VALUES (%s, %s, %s)', (doctor_id, slot_id, date))
            doctor_slots = get_doctor_slots(doctor_id)
            flash('New slot is added successfully.', 'success')
    
    # Get the doctor_id from the user_id
    doctor_slots = get_doctor_slots(doctor_id)
    
    # Filter out old slots
    today = datetime.today().date()
    doctor_slots = [slot for slot in doctor_slots if datetime.strptime(slot['available_date'], '%d/%m/%Y').date() >= today]

    return render_template('doctor_nurse/doctor_roster.html', slots=formatted_slots, doctor_slots=doctor_slots, user_id=user_id, today=today)


# Nurse - manage roster
@app.route('/home/nurse/<int:user_id>/roster', methods=['GET', 'POST'])
def nurse_roster(user_id):
    connection = getCursor()
    connection.execute('SELECT nurse_id FROM nurses WHERE user_id = %s', (user_id,))
    this_nurse_id = connection.fetchone()
    nurse_id = this_nurse_id[0]

    # Fetch available slots for the next week
    cursor = getCursor()
    cursor.execute("SELECT * FROM slots")
    slots = cursor.fetchall()
    formatted_slots = []
    for slot in slots:
        slot_id, slot_time = slot
        formatted_time = timedelta_to_normal_calculator(slot_time)
        formatted_slots.append({'slot_id': slot_id, 'formatted_time': formatted_time})

    if request.method == 'POST':
        connection = getCursor()
        slot_id = request.form['slot_time']  # This will contain the selected slot_id
        date = request.form['date']
        # Check if the slot already exists in the nurse's roster for the selected date
        existing_slot_query = "SELECT * FROM nurse_slots WHERE nurse_id = %s AND slot_id = %s AND available_date = %s"
        connection.execute(existing_slot_query, (nurse_id, slot_id, date))
        existing_slot = connection.fetchone()
        # print(existing_slot)

        if existing_slot:
            # Slot already exists, show a message to the user
            flash('Duplicated slot, please try again', 'warning')
        else:
            # Slot does not exist, insert it into the nurse's roster
            connection.execute('INSERT INTO nurse_slots (nurse_id, slot_id, available_date) VALUES (%s, %s, %s)', (nurse_id, slot_id, date))
            nurse_slots = get_nurse_slots(nurse_id)
            flash('New slot is added successfully.', 'success')
    
    # Get the nurse_id from the user_id
    nurse_slots = get_nurse_slots(nurse_id)

    # Filter out old slots
    today = datetime.today().date()
    nurse_slots = [slot for slot in nurse_slots if datetime.strptime(slot['available_date'], '%d/%m/%Y').date() >= today]

    return render_template('doctor_nurse/nurse_roster.html', slots=formatted_slots, nurse_slots=nurse_slots, user_id=user_id, today=today)


# Receptionist - view selected patient's profile
@app.route('/home/reception/<int:user_id>/patients', methods=["GET", 'POST'])
def reception_view_patients(user_id):
    connection = getCursor()
    if request.method == 'POST':
        search_query = request.form['search_query']
        connection = getCursor()

        # Search for patients by name or phone number
        connection.execute('''
                SELECT patients.*, doctors.fname, doctors.lname, DATE_FORMAT(patients.dob, '%d/%m/%Y')
                FROM patients
                LEFT JOIN doctors ON patients.doctor_id = doctors.doctor_id
                WHERE patients.fname LIKE %s OR patients.lname LIKE %s OR patients.contact_num LIKE %s
            ''', (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'))

        patients_data = connection.fetchall()
        return render_template('reception/patient_profiles.html', patients=patients_data, search_query=search_query)
        
    # Handle GET request (initial page load)
    connection.execute('''
    SELECT patients.*, doctors.fname AS doctor_fname, doctors.lname AS doctor_lname, DATE_FORMAT(patients.dob, '%d/%m/%Y')
    FROM patients
    LEFT JOIN doctors ON patients.doctor_id = doctors.doctor_id
    ''')
    patients_data = connection.fetchall()
    return render_template('reception/patient_profiles.html', patients=patients_data, search_query='')


# Receptionist - Schedule appoinment for patient
@app.route('/home/reception/<int:user_id>/search_patient', methods=['GET', 'POST'])
def search_patient(user_id):
    cursor = getCursor()
    patients = []

    if request.method == 'POST':
        search_query = request.form.get('search_query')
        cursor.execute('SELECT patient_id, fname, lname FROM patients WHERE fname LIKE %s OR lname LIKE %s', (f"%{search_query}%", f"%{search_query}%"))
        patients = cursor.fetchall()

        if not patients:
            flash("This patient cannot be found, please try again.", 'warning')
    
    return render_template('reception/search_patient.html', patients=patients, user_id=user_id)


# Receptionist - schedule appt for patient, select a staff
@app.route('/home/reception/<int:user_id>/select_staff/<int:patient_id>', methods=['GET', 'POST'])
def select_staff(user_id, patient_id):
    if request.method == 'POST':
        staff_type = request.form.get('staff_type')
        return redirect(url_for('view_slots', user_id=user_id, patient_id=patient_id, staff_type=staff_type))
    
    return render_template('reception/select_staff.html', user_id=user_id, patient_id=patient_id)


# Receptionist - schedule appt for patient, view available time slots
@app.route('/home/reception/<int:user_id>/view_slots/<int:patient_id>/<staff_type>', methods=['GET', 'POST'])
def view_slots(user_id, patient_id, staff_type):
    cursor = getCursor()
    today = datetime.now().date()
    upcoming_dates = [(today + timedelta(days=i)).strftime('%d/%m/%Y') for i in range(7)]
    
    if staff_type == "doctor":
        cursor.execute('''
            SELECT d.doctor_id, d.fname, d.lname, ds.available_date, s.slot_time 
            FROM doctors d
            JOIN doctor_slots ds ON d.doctor_id = ds.doctor_id
            JOIN slots s ON ds.slot_id = s.slot_id
        ''')
    else:  # staff_type == "nurse"
        cursor.execute('''
            SELECT n.nurse_id, n.fname, n.lname, ns.available_date, s.slot_time 
            FROM nurses n
            JOIN nurse_slots ns ON n.nurse_id = ns.nurse_id
            JOIN slots s ON ns.slot_id = s.slot_id
        ''')
    
    staff_slots = cursor.fetchall()
    
    # Organize the data for display
    organized_slots = {}
    for staff in staff_slots:
        staff_name = f"{staff[1]} {staff[2]}"
        date_str = staff[3].strftime('%d/%m/%Y')
        time_str = (staff[4].seconds // 3600, (staff[4].seconds // 60) % 60)
        
        if staff_name not in organized_slots:
            organized_slots[staff_name] = {}
        
        if date_str not in organized_slots[staff_name]:
            organized_slots[staff_name][date_str] = []
        
        organized_slots[staff_name][date_str].append(time_str)
    
    return render_template('reception/view_slots.html', user_id=user_id, patient_id=patient_id, staff_type=staff_type, organized_slots=organized_slots, upcoming_dates=upcoming_dates)


# Receptionist - schedule appt for patient, confirm booking
@app.route('/home/reception/<int:user_id>/confirm_booking/<int:patient_id>/<staff_type>/<path:staff_name>/<int:year>/<int:month>/<int:day>/<appointment_time>', methods=['GET', 'POST'])
def confirm_booking(user_id, patient_id, staff_type, staff_name, year, month, day, appointment_time):
    cursor = getCursor()
    
    # Reconstruct the date from the year, month, and day components
    appointment_date = f"{day}/{month}/{year}"
    
    # Format the time correctly
    hours, minutes = appointment_time.split(':')
    formatted_time = f"{hours}:{minutes.zfill(2)}"
    
    if request.method == 'POST':
        # Convert date and time to appropriate format
        formatted_date = datetime.strptime(appointment_date, "%d/%m/%Y").date()
        actual_time = datetime.strptime(formatted_time, "%H:%M").time()
        
        # Identify the staff ID
        staff_id_column = f"{staff_type}_id"
        cursor.execute(f"SELECT {staff_id_column} FROM {staff_type}s WHERE CONCAT(fname, ' ', lname) = %s", (staff_name,))
        staff_id = cursor.fetchone()[0]
        
        # Fetch the patient's date of birth to determine the price
        cursor.execute('SELECT dob FROM patients WHERE patient_id = %s', (patient_id,))
        dob = cursor.fetchone()[0]
        age = calculate_age(dob)  # Assuming you have this function defined
        age_group = "Under 14" if age <= 14 else "Over 14"

        # Fetch the price_id based on appointment type and age group
        cursor.execute('SELECT price_id FROM prices WHERE appt_type = %s AND age_group = %s', ('In-person', age_group))
        price_id = cursor.fetchone()[0]

        # Insert the appointment into the database
        try:
            cursor.execute(f'''
                INSERT INTO appointments (patient_id, {staff_id_column}, date, time, type, price_id, status)
                VALUES (%s, %s, %s, %s, 'In-person', %s, 'Upcoming')
            ''', (patient_id, staff_id, formatted_date, actual_time, price_id))
            
            # Redirect to a success page
            return render_template('reception/booking_success.html', user_id=user_id)
        
        except mysql.connector.Error as err:
            print(f"Error: {err}")
    
    return render_template('reception/confirm_booking.html', user_id=user_id, patient_id=patient_id, staff_type=staff_type, staff_name=staff_name, date=appointment_date, time=formatted_time)


# Receptionist - view a list of all prescriptions
@app.route('/home/reception/<int:user_id>/prescriptions')
def all_prescriptions(user_id):
    
    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Reception', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403

    connection = getCursor()
    query = '''
    SELECT
        p.prescription_id,
        DATE_FORMAT(p.date, '%d/%m/%Y') as nz_date,
        patients.fname,
        patients.lname,
        doctors.fname,
        doctors.lname,
        p.medication,
        CASE
            WHEN p.repeatable = 1 THEN 'Yes'
            ELSE 'No'
		END AS repeatable
    FROM prescriptions p
    JOIN patients ON p.patient_id = patients.patient_id
    LEFT JOIN doctors ON p.doctor_id = doctors.doctor_id
    ORDER BY p.date;
    '''
    connection.execute(query)
    prescription_data = connection.fetchall()
    return render_template('reception/all_prescriptions.html', prescription_data=prescription_data)


# Receptionist - view a list of all appointments
@app.route('/home/<string:role>/<int:user_id>/appointments')
def all_appt(role, user_id):

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised(role, user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403

    connection = getCursor()
    query = '''
    SELECT
        a.appt_id,
        DATE_FORMAT(a.date, '%d/%m/%Y') as nz_date,
        DATE_FORMAT(a.time, '%H:%i') as nz_time,
        patients.fname AS patient_fname,
        patients.lname AS patient_lname,
        COALESCE(doctors.fname, nurses.fname) AS staff_fname,
        COALESCE(doctors.lname, nurses.lname) AS staff_lname,
        CASE
            WHEN doctors.doctor_id IS NOT NULL THEN 'Doctor'
            WHEN nurses.nurse_id IS NOT NULL THEN 'Nurse'
            ELSE 'Unknown'
        END AS staff_role,
        prices.price,
        a.status,
        a.type
    FROM appointments a
    JOIN patients ON a.patient_id = patients.patient_id
    LEFT JOIN doctors ON a.doctor_id = doctors.doctor_id
    LEFT JOIN nurses ON a.nurse_id = nurses.nurse_id
    JOIN prices ON a.price_id = prices.price_id
    LEFT JOIN invoices ON a.appt_id = invoices.appt_id
    ORDER BY a.status, a.date;
    '''
    connection.execute(query)
    appt_data = connection.fetchall()
    return render_template('reception/all_appt.html', role=role, appt_data=appt_data)


# Receptionist - view and create invoices for completed appointments and collect payment
@app.route('/home/reception/<int:user_id>/invoices/appointments')
def invoice_appt(user_id):

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Reception', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    # fetch a list of completed appointments with patient's name, and doctor's name or nurse's name, and charge, and invoice status.
    connection = getCursor()
    query = '''
    SELECT
        DATE_FORMAT(a.date, '%d/%m/%Y') as nz_date,
        DATE_FORMAT(a.time, '%H:%i') as nz_time,
        patients.fname AS patient_fname,
        patients.lname AS patient_lname,
        COALESCE(doctors.fname, nurses.fname) AS staff_fname,
        COALESCE(doctors.lname, nurses.lname) AS staff_lname,
        CASE
            WHEN doctors.doctor_id IS NOT NULL THEN 'Doctor'
            WHEN nurses.nurse_id IS NOT NULL THEN 'Nurse'
            ELSE 'Unknown'
        END AS staff_role,
        prices.price,
        COALESCE(invoices.status, 'Not Invoiced') AS invoice_status,
        a.appt_id
    FROM appointments a
    JOIN patients ON a.patient_id = patients.patient_id
    LEFT JOIN doctors ON a.doctor_id = doctors.doctor_id
    LEFT JOIN nurses ON a.nurse_id = nurses.nurse_id
    JOIN prices ON a.price_id = prices.price_id
    LEFT JOIN invoices ON a.appt_id = invoices.appt_id
    WHERE a.type = 'In-person' AND a.status = 'Completed'
    ORDER BY invoices.status, a.date;
    '''

    connection.execute(query)
    appt_data = connection.fetchall()
    return render_template('reception/invoice_appt.html', appt_data=appt_data)


# Receptionist - create invoices for appointments
@app.route('/home/reception/<int:user_id>/create_invoice', methods=['GET', 'POST'])
@app.route('/home/reception/<int:user_id>/<int:appt_id>/create_invoice', methods=['GET', 'POST'])
def create_appt_invoice(user_id, appt_id=None):
    
    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Reception', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403

    # get selected appt_id from the form
    selected_appt_id = appt_id if appt_id else request.form.get('appt_id')

    try:
        if selected_appt_id:
            # get the appointment data
            connection = getCursor()
            appt_data = get_appt_by_id(connection, selected_appt_id)

            # check if an invoice already exists
            connection.execute("SELECT invoice_id, status FROM invoices WHERE appt_id = %s", (selected_appt_id,))
            existing_invoice = connection.fetchone()

            # If no existing invoice, insert a new record into the invoices table
            if not existing_invoice:
                status = 'Unpaid'
                connection.execute('INSERT INTO invoices (appt_id, amount, status) VALUES (%s, %s, %s)', (selected_appt_id, appt_data[9], status))

            # get the invoice data
            invoice_data = {
                'invoice_id': existing_invoice[0] if existing_invoice else connection.lastrowid,
                'date': str(datetime.now().strftime('%d/%m/%Y')),
                'amount': appt_data[9],
                'status': existing_invoice[1] if existing_invoice else "Unpaid"
            }

        return render_template('reception/view_appt_invoice.html', invoice_data=invoice_data, appt_data=appt_data)
    
    except Exception as e:
        print(f"An error occurred: {e}")
        # Flash a message to the user
        flash('An error occurred while generating the invoice. Please try again.', 'danger')
        # Redirect to a safe page
        return redirect(url_for('invoice_appt', user_id=user_id))


# Receptionist - collection payment for an appt
@app.route('/home/reception/<int:user_id>/<int:invoice_id>/collect_payment', methods=['GET', 'POST'])
def collect_payment(user_id, invoice_id):
    
    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Reception', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    connection = getCursor()
    
    # Fetch invoice and appointment details
    connection.execute('SELECT invoice_id, amount, appt_id FROM invoices WHERE invoice_id=%s', (invoice_id,))
    invoice_data = connection.fetchone()
    connection.execute('SELECT patient_id FROM appointments WHERE appt_id=%s', (invoice_data[2],))
    patient_data = connection.fetchone()

    if request.method == 'POST':
        payment_method = request.form['payment_method']

        # Insert into payments table
        connection.execute('INSERT INTO payments (invoice_id, patient_id, amount, date, payment_method) VALUES (%s, %s, %s, %s, %s)',
                            (invoice_id, patient_data[0], invoice_data[1], datetime.now(), payment_method))
        
        # Update invoice status
        connection.execute('UPDATE invoices SET status=%s WHERE invoice_id=%s', ("Paid", invoice_id))

        flash('Payment successful', 'success')
        return redirect(url_for('invoice_appt', user_id=user_id))
    
    return render_template('reception/collect_payment.html', invoice_data=invoice_data, user_id=user_id)


# Admin - Manage all members
@app.route('/home/<string:role>/<int:user_id>/manage_users', methods=['GET', 'POST'])
def manage_users(role, user_id):

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised(role, user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    connection = getCursor()
    
    # Get the role that admin choose
    selected_role = request.args.get('target_role', 'All')  
    
    # Define a base query to join all tables
    base_query = '''
    SELECT u.user_id, u.role, u.username, COALESCE(p.fname, d.fname, n.fname, r.fname, a.fname) AS fname, COALESCE(p.lname, d.lname, n.lname, r.lname, a.lname) AS lname
    FROM users AS u
    LEFT JOIN patients AS p ON u.user_id = p.user_id
    LEFT JOIN doctors AS d ON u.user_id = d.user_id
    LEFT JOIN nurses AS n ON u.user_id = n.user_id
    LEFT JOIN receptions AS r ON u.user_id = r.user_id
    LEFT JOIN admins AS a ON u.user_id = a.user_id
    '''
    
    if selected_role != "All":
        # If a specific role is selected, modify the query accordingly
        query = f"{base_query} WHERE u.role = '{selected_role}'"
    else:
        # If 'All' is selected, use the base query
        query = base_query

    connection.execute(query)
    users = connection.fetchall()
    
    # Filter out users with the 'Patient' role
    if selected_role != "Patient":
        users = [user for user in users if user[1] != 'Patient']
    
    return render_template('admin/manage_users.html', users=users, role=role, user_id=user_id, selected_role=selected_role)


# Admin - Edit User
@app.route('/home/<string:role>/<int:user_id>/manage_users/edit', methods=['GET', 'POST'])
def edit_user(role, user_id):

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised(role, user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403

    target_id = request.args.get('target_id')
    target_role = request.args.get('target_role')
    
    connection = getCursor()
    query = ''
    
    if request.method == 'POST':

        first_name = request.form['first_name']
        last_name = request.form['last_name']

        if target_role == 'Doctor':
            gender = request.form['gender']
            specialty = request.form['specialty']
            language = request.form['language']
            photo = request.form['photo']
            connection.execute('UPDATE doctors SET fname = %s, lname = %s, gender = %s, specialty = %s, language = %s, photo = %s WHERE user_id = %s',
                              (first_name, last_name, gender, specialty, language, photo, target_id))
        elif target_role == 'Nurse':
            gender = request.form['gender']
            photo = request.form['photo']
            connection.execute('UPDATE nurses SET fname = %s, lname = %s, gender = %s, photo = %s WHERE user_id = %s',
                              (first_name, last_name, gender, photo, target_id))
        elif target_role == 'Reception':
            connection.execute('UPDATE receptions SET fname = %s, lname = %s WHERE user_id = %s', (first_name, last_name, target_id))       
        
        flash('Profile updated successfully', 'success')
        return redirect(url_for('manage_users', role=role, user_id=user_id, target_role=target_role))
    
    else:
        if target_role == 'Doctor':
            query = '''
                    SELECT u.user_id, d.fname, d.lname, d.gender, d.specialty, d.language, d.photo 
                    FROM users AS u JOIN doctors AS d ON u.user_id = d.user_id 
                    WHERE u.user_id = %s
                    '''       
        elif target_role == 'Nurse':
            query = '''
                    SELECT u.user_id, n.fname, n.lname, n.gender, n.photo 
                    FROM users AS u JOIN nurses AS n ON u.user_id = n.user_id 
                    WHERE u.user_id = %s
                    '''       
        elif target_role == 'Reception':
            query = '''
                    SELECT u.user_id, r.fname, r.lname 
                    FROM users AS u JOIN receptions AS r ON u.user_id = r.user_id 
                    WHERE u.user_id = %s
                    '''      
        
        connection.execute(query, (target_id,))
        user = connection.fetchone()
        
        return render_template('admin/edit_user.html', user=user, role=target_role)


# Admin - Add User
@app.route('/home/<string:role>/<int:user_id>/manage_users/add', methods=['GET', 'POST'])
def add_user(role, user_id):

    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised(role, user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403

    today = datetime.now().strftime('%Y-%m-d')
    connection = getCursor()
    
    if request.method == 'POST':
        form_data = request.form.to_dict()

        target_role = form_data['role']

        # check if username exists
        connection.execute("SELECT * FROM users WHERE username = %s", [form_data['username']])
        exist_user = connection.fetchone()
        if exist_user:
            flash('This username has already been used. ', 'warning')
            return render_template('/admin/add_user.html', form_data=form_data, today=today)

        # Determine which fields need to be checked based on the user's role
        fields_to_check = []

        if target_role == 'Doctor':
            fields_to_check = ['username', 'password']
        elif target_role == 'Nurse':
            fields_to_check = ['username', 'password']
        elif target_role == 'Receptionist':
            fields_to_check = ['username', 'password']
        else:
            flash('Invalid role. ', 'warning')
            return render_template('/admin/add_user.html', form_data=form_data, today=today)

        print("my role: ", target_role)
        # Perform field-specific checks for duplication
        for field in fields_to_check:
            if field in form_data:
                # Check if the field value already exists in the database for the specific role
                connection.execute(f"SELECT * FROM users WHERE role = %s AND {field} = %s", [target_role, form_data[field]])
                exist_duplicate = connection.fetchone()
                if exist_duplicate:
                    flash(f'The {field} is already in use.', 'warning')
                    return render_template('/admin/add_user.html', form_data=form_data, today=today)

        # Validate contact_number
        if 'contact_num' in fields_to_check and not form_data['contact_num'].isdigit():
            flash('Phone number should contain only digits.', 'warning')
            return render_template('/admin/add_user.html', form_data=form_data, today=today)

        # check password strength
        if 'password' in fields_to_check:
            strong_password, msg = is_password_strong(form_data['password'])
            if not strong_password:
                flash(msg, 'warning')
                return render_template('/admin/add_user.html', form_data=form_data, today=today)

        # Encrypt password
        hashed_password, salt = encrypt_password(form_data['password'])

        # Save User info to user table
        insert_query = "INSERT INTO users (username, password, role, salt) VALUES (%s, %s, %s, %s)"
        connection.execute(insert_query, (form_data['username'], hashed_password, target_role, salt))
        target_user_id = connection.lastrowid

        # Depending on the user role, insert data into the respective table
        if target_role == 'Doctor':
            # Insert Doctor-specific data
            insert_query = """INSERT INTO doctors (user_id, gender, fname, lname, specialty, language, photo) 
                              VALUES (%s, %s, %s, %s, %s, %s, %s)"""
            connection.execute(insert_query, (target_user_id, form_data['gender'], form_data['fname'], form_data['lname'], form_data['specialty'], form_data['language'], ''))
            session['doctor_id'] = connection.lastrowid
        elif target_role == 'Nurse':
            # Insert Nurse-specific data
            insert_query = """INSERT INTO nurses (user_id, gender, fname, lname, photo) VALUES (%s, %s, %s, %s, %s)"""
            connection.execute(insert_query, (target_user_id, form_data['gender'], form_data['fname'], form_data['lname'], ''))
            session['nurse_id'] = connection.lastrowid
        elif target_role == 'Receptionist':
            # Insert Receptionist-specific data
            insert_query = """INSERT INTO receptions (user_id, fname, lname) VALUES (%s, %s, %s)"""
            connection.execute(insert_query, (target_user_id, form_data['fname'], form_data['lname']))
            session['reception_id'] = connection.lastrowid
        
        flash('Your account has been created. ', 'success')
        return redirect(url_for('manage_users', role=role, user_id=user_id))

    return render_template('/admin/add_user.html')


# Admin - Reporting
@app.route('/home/admin/<int:user_id>/reports')
def reports(user_id):
    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Admin', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    return render_template('admin/reports.html', user_id=user_id)


# Admin - report, view appointments by type
@app.route('/home/admin/<int:user_id>/reports/appointments_by_type', methods=['GET'])
def appointments_by_type(user_id):
    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Admin', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    cursor = getCursor()
    cursor.execute('''
        SELECT type, COUNT(*) as count
        FROM appointments
        GROUP BY type
    ''')
    results = cursor.fetchall()
    total_appointments = sum(count for _, count in results)
    return render_template('admin/appointments_by_type.html', results=results, total_appointments=total_appointments, user_id=user_id)


# Admin - Financial report
@app.route('/home/admin/<int:user_id>/reports/financial_report', methods=['GET', 'POST'])
def financial_report(user_id):
    # auth checks
    if not is_logged_in():
        flash('You must log in to view the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if not is_authorised('Admin', user_id):
        flash('You are not authorised to access this page.', 'danger')
        return render_template('403.html'), 403
    
    cursor = getCursor()
    
    if request.method == 'POST':
        period = request.form.get('period')
        
        if period == 'month':
            query = """
            SELECT DATE_FORMAT(date, '%Y-%m') as period, SUM(amount)
            FROM payments
            GROUP BY period
            ORDER BY period;
            """
        elif period == 'financial_year':
            query = """
            SELECT CONCAT(YEAR(date - INTERVAL 3 MONTH), '-', YEAR(date - INTERVAL 3 MONTH) + 1) as period, SUM(amount)
            FROM payments
            GROUP BY period
            ORDER BY period;
            """
        
        cursor.execute(query)
        financial_data = cursor.fetchall()
        
        return render_template('admin/financial_report.html', user_id=user_id, financial_data=financial_data)
    return render_template('admin/financial_report.html', user_id=user_id)


if __name__ == '__main__':
    app.run(debug=True)