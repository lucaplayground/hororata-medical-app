# COMP639_group_4_project_2
## Test User Accounts (passwords are same as the usernames)
1. admin1
2. reception1
3. doctor1 - 5
4. nurse1 - 5
5. patient1 - 10 (patient10 is under 14)

## Assumptions
1. Patients are required to make payment immediately following their in-person appointments.
2. Patients need to pay for a virtual appointment upfront when they book the appointment. There's no need for receptionist to generate invoices for a virtual appointment.
3. Reception staff can collect the money from the patient or let the patient pay by card on a efpos machine and then finalize the invoice.
4. The default duaration for an appointment is 1 hour (both in-person and virtual).
5. The charge for an appointment is determined by the patient's age. There's no fee for patients under 14, which is why they can't alter their date of birth in the system.
6. An appointment can be made with a doctor or a nurse.
7. An invoice is created for an appointment.
8. Patient's health records can be viewed and edited by their assigned doctors.
9. Patient's test results can be viewed by their assigned doctors.

## Functions
1. is_logged_in() -> bool: True if logged-in, False otherwise.
2. is_authorised(role, user_id) -> - bool: True if authorised, False otherwise.
3. is_my_doctor() -> bool: True if authorised, False otherwise.
4. encrypt_password(password) -> hashed_password, salt
5. is_password_strong(password) -> Bool, msg
6. update_password(user_id, old_password, new_password) -> Boole, msg (compare the old_password with password stored in the database and update it with the new_password)
7. get_health_records(patient_id) -> return health_record_data (a dictionary)
8. get_test_results(patient_id) -> return test_result_data
9. calculate_age(dob) -> return age: int
10. calculate_appt_charge(appt_type, age) -> price: int or error message.
11. timedelta_to_normal_calculator(time) -> return time in format of "hours: minutes"
12. transfer_to_timedelta_calculator(time) -> return time in timedelta type for storing in the database

## Routes
1. '/login' - handles login requests and saves general session data.
2. '/logout' - handle logout requests and remote all saved session data.
3. '/home' - routes users to different dashboards based on their roles and saves role-specific session data.
4. '/profile/<string: role>/<int: user_id>' - general profile route for admins and receptions.
5. '/profile/patient/<int: user_id>' - patient profile route
6. '/profile/doctor/<int: user_id>' - doctor profile route, patients can see
7. '/profile/nurse/<int: user_id>' - nurse profile route, patient can see
8. '/home/<string: role>/<int: user_id>' - render different dashboards based on the user role. e.g. '/home/patient/<int:user_id>' for a patient.

## Saved Session Data
1. session['loggedin'] -> True or False
2. session['user_id]
3. session['username']
4. session['role']
5. session['patient_id']
6. session['doctor_id']
7. session['nurse_id']
8. session['reception_id']
9. session['admin_id']

