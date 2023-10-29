CREATE SCHEMA medicalapp;
USE medicalapp;

-- Create User table
CREATE TABLE users (
  user_id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(50) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  role ENUM('Patient', 'Doctor', 'Nurse', 'Reception', 'Admin') NOT NULL,
  salt VARCHAR(255) NOT NULL  
);

-- Create doctor table
CREATE TABLE doctors (
  doctor_id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  fname VARCHAR(50) NOT NULL,
  lname VARCHAR(50) NOT NULL,
  gender ENUM('Female', 'Male') NOT NULL,
  specialty VARCHAR(50),
  language VARCHAR(255),
  photo VARCHAR (255),
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Create Patient table
CREATE TABLE patients (
  patient_id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  fname VARCHAR(50) NOT NULL,
  lname VARCHAR(50) NOT NULL,
  gender ENUM('Female', 'Male') NOT NULL,
  dob DATE NOT NULL,
  contact_num VARCHAR(15) NOT NULL,
  address VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  doctor_id INT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(user_id),
  FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id)
);

-- Create nurse table
CREATE TABLE nurses (
  nurse_id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  fname VARCHAR(50) NOT NULL,
  lname VARCHAR(50) NOT NULL,
  gender ENUM('Female', 'Male') NOT NULL,
  photo VARCHAR (255),
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Create Receptionist table
CREATE TABLE receptions (
  reception_id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  fname VARCHAR(50) NOT NULL,
  lname VARCHAR(50) NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Create Administrator table
CREATE TABLE admins (
  admin_id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  fname VARCHAR(50) NOT NULL,
  lname VARCHAR(50) NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Create Slots table
CREATE TABLE slots (
    slot_id INT PRIMARY KEY AUTO_INCREMENT,
    slot_time TIME  NOT NULL
);

-- Bridge table for doctors and slots
CREATE TABLE doctor_slots (
  doctor_id INT NOT NULL,
  slot_id INT NOT NULL,
  available_date DATE,
  FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id),
  FOREIGN KEY (slot_id) REFERENCES slots(slot_id),
  PRIMARY KEY (doctor_id, slot_id, available_date)
);

-- Bridge table for nurses and slots
CREATE TABLE nurse_slots (
  nurse_id INT NOT NULL,
  slot_id INT NOT NULL,
  available_date DATE,
  FOREIGN KEY (nurse_id) REFERENCES nurses(nurse_id),
  FOREIGN KEY (slot_id) REFERENCES slots(slot_id),
  PRIMARY KEY (nurse_id, slot_id, available_date)
);

-- Create Prices table
CREATE TABLE prices (
  price_id INT PRIMARY KEY AUTO_INCREMENT,
  appt_type ENUM('In-person', 'Virtual') NOT NULL,
  age_group ENUM('Under 14', 'Over 14') NOT NULL, -- under 14 includes 14
  price DECIMAL(10, 2) NOT NULL
);

-- Create Appointment table
CREATE TABLE appointments (
  appt_id INT PRIMARY KEY AUTO_INCREMENT,
  patient_id INT NOT NULL,
  doctor_id INT,
  nurse_id INT,
  date DATE NOT NULL,
  time TIME NOT NULL,
  type ENUM('In-person', 'Virtual') NOT NULL,
  price_id INT NOT NULL,
  notes TEXT,
  status ENUM('Upcoming','Completed', 'Cancelled') NOT NULL,
  FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
  FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id),
  FOREIGN KEY (nurse_id) REFERENCES nurses(nurse_id),
  FOREIGN KEY (price_id) REFERENCES prices(price_id)
);

-- Create Prescription table
CREATE TABLE prescriptions (
  prescription_id INT PRIMARY KEY AUTO_INCREMENT,
  patient_id INT  NOT NULL,
  doctor_id INT  NOT NULL,
  medication VARCHAR(100) NOT NULL,
  date DATE NOT NULL,
  repeatable BOOLEAN,  -- easy to filter out repeatable prescriptions
  FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
  FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id)
);

-- Create HealthRecords table
CREATE TABLE health_records (
  record_id INT PRIMARY KEY AUTO_INCREMENT,
  patient_id INT NOT NULL,
  blood_type VARCHAR(50),
  allergies VARCHAR(255),
  medications VARCHAR(255),
  medical_conditions VARCHAR(255),
  surgeries VARCHAR(255),
  family_history VARCHAR(255),
  test_results TEXT, -- blood tests, x-rays, MRIs, etc
  notes TEXT,
  FOREIGN KEY (patient_id) REFERENCES patients(patient_id)
);

-- Create Invoice table
CREATE TABLE invoices (
  invoice_id INT PRIMARY KEY AUTO_INCREMENT,
  appt_id INT,
  amount DECIMAL(10, 2) NOT NULL,
  status ENUM('Paid', 'Unpaid') NOT NULL,
  FOREIGN KEY (appt_id) REFERENCES appointments(appt_id)
);

-- Create Payment table
CREATE TABLE payments (
  pay_id INT PRIMARY KEY AUTO_INCREMENT,
  invoice_id INT,
  patient_id INT NOT NULL,
  amount DECIMAL(10, 2) NOT NULL,
  date DATE NOT NULL,
  payment_method ENUM('Credit Card', 'Debit Card', 'Cash') NOT NULL,
  FOREIGN KEY (invoice_id) REFERENCES invoices(invoice_id),
  FOREIGN KEY (patient_id) REFERENCES patients(patient_id)
);

-- Insert dummy data into the users table
INSERT INTO users (username, password, role, salt) VALUES
    ('doctor1', '$2b$12$Ti2LB9ppat.03Lm36lN/8.LBgNul0iuf9h6FHC2BB67/YXUZ0oRWu', 'Doctor', '$2b$12$Ti2LB9ppat.03Lm36lN/8.'),
    ('doctor2', '$2b$12$rmPLodTK/muR/0YYxfn09eQ726jUYlk9FihKpiuyglbqRtZMyhZZO', 'Doctor', '$2b$12$rmPLodTK/muR/0YYxfn09e'),
    ('doctor3', '$2b$12$cIcp8ED17f2c.ApwwIQ2Gu73IaOBnAe1ZQgC5ZJWFQrHX1eS9/fZ6', 'Doctor', '$2b$12$cIcp8ED17f2c.ApwwIQ2Gu'),
    ('doctor4', '$2b$12$IFDNTvn4BbrNDceRW3EleucTh2SZ/PE3rlFnml2Wq2yx5WhafjQ8W', 'Doctor', '$2b$12$IFDNTvn4BbrNDceRW3Eleu'),
    ('doctor5', '$2b$12$spPH7WEc1M00eMrr2of6o.kyUrjTWUaPdrv5ADkPG93EMSdEJL0M6', 'Doctor', '$2b$12$spPH7WEc1M00eMrr2of6o.'),
    ('nurse1', '$2b$12$Rsa5ZS7ldkX0/l4LwNXgJ.9WqDtrxMhPPr7MbhmTN/FpNOMB4ceOe', 'Nurse', '$2b$12$Rsa5ZS7ldkX0/l4LwNXgJ.'),
    ('nurse2', '$2b$12$6lZz7VJP.HUknrUsvl9zQO8vvtzV/NPQGIv8yaouFvCnUPFi0b2gO', 'Nurse', '$2b$12$6lZz7VJP.HUknrUsvl9zQO'),
    ('nurse3', '$2b$12$u0oNx0rx2wEoBu.WhjDosOnZUVF0BFGlzdIVKDC7C0w71vbE0TeK.', 'Nurse', '$2b$12$u0oNx0rx2wEoBu.WhjDosO'),
    ('nurse4', '$2b$12$OujvPSiS690I9h6S1KGm6.i5HCP.5VUaLPXCC0xGU.rR8QQwZRG7a', 'Nurse', '$2b$12$OujvPSiS690I9h6S1KGm6.'),
    ('nurse5', '$2b$12$LP7ABhzOcCm6ZF6ZEdFVruF.HiAWbTqM/9F/U.EIyLYny/bqmZydK', 'Nurse', '$2b$12$LP7ABhzOcCm6ZF6ZEdFVru'),
    ('reception1', '$2b$12$fIIVcabi1ebnaawS8x9yzOA866ui0vZFAOczIYHIC6mRC4QJM8RQK', 'Reception', '$2b$12$fIIVcabi1ebnaawS8x9yzO'),
    ('admin1', '$2b$12$JdgVdUB.ciESFFuMZNrz.uRqd0m1qfPPvXhkiM/6oqEUMFOrrY6uS', 'Admin', '$2b$12$JdgVdUB.ciESFFuMZNrz.u'),
    ('patient1', '$2b$12$ZfSgaONYpzwMS8phJamPa.6lJzenpfsci/HsA0gAFbOPz0jPN7dKO', 'Patient', '$2b$12$ZfSgaONYpzwMS8phJamPa.'),
    ('patient2', '$2b$12$PF5x5z8j95ipzzL/DbJpyuGJlqsrtaFB8U48qOFug4aVBo76O/yei', 'Patient', '$2b$12$PF5x5z8j95ipzzL/DbJpyu'),
    ('patient3', '$2b$12$4gsNFd.41bgj6nDskwCj4uUtWXzirSGomFz/ymkgJMnlQr8y0F4Mq', 'Patient', '$2b$12$4gsNFd.41bgj6nDskwCj4u'),
    ('patient4', '$2b$12$yxvGSkin8YroY671TDYP8u6v4I.pa3fcDAGeS7BYCeTqcnX1nNE9e', 'Patient', '$2b$12$yxvGSkin8YroY671TDYP8u'),
    ('patient5', '$2b$12$l5CmkWZ9nj4R4z.ro1WSzuOqMbeaUofY3jN91nX2ecK/nTBwF6nDi', 'Patient', '$2b$12$l5CmkWZ9nj4R4z.ro1WSzu'),
    ('patient6', '$2b$12$nnvkPwqyle8d3zVrDEWU7e5.w/DJABJC6eYebMQe6grInwham15/O', 'Patient', '$2b$12$nnvkPwqyle8d3zVrDEWU7e'),
    ('patient7', '$2b$12$rpm7vSQYwpdk.rRPLk4m5.aw8aeR7w2SycXKnTs6sYRfGKkCeH.eu', 'Patient', '$2b$12$rpm7vSQYwpdk.rRPLk4m5.'),
    ('patient8', '$2b$12$xVKcEgJ7KkYn88N4FvBvm.Ik2YMn1L0VJXfdyP7Bqel64Rnfkbzj6', 'Patient', '$2b$12$xVKcEgJ7KkYn88N4FvBvm.'),
    ('patient9', '$2b$12$dcDI7mnIbkC.is5P13e9YuH5YjVVnw6l7HVqHwNTgs56f6zn0ERLy', 'Patient', '$2b$12$dcDI7mnIbkC.is5P13e9Yu'),
    ('patient10', '$2b$12$Yphcma8q/OqbG4zG5OMQPe0M9pTpn3UqTdWMrid7jl5r50.GCuy2a', 'Patient', '$2b$12$Yphcma8q/OqbG4zG5OMQPe'); -- teenager

-- Insert dummy data into doctors table
INSERT INTO doctors (user_id, fname, lname, gender, specialty, language, photo) VALUES
  (1, 'Alice', 'Lee', 'Female', 'Cardiology', 'English, Mandarin', 'doctor1.jpg'),
  (2, 'Bob', 'Johnson', 'Male', 'Neurology', 'English, Malaysian', 'doctor2.jpg'),
  (3, 'Charlie', 'Brown', 'Male', 'Orthopedics', 'English', 'doctor3.jpg'),
  (4, 'David', 'Williams', 'Male', 'Dermatology', 'English, Germany', 'doctor4.jpg'),
  (5, 'Eva', 'Davis', 'Female', 'Pediatrics', 'English', 'doctor5.jpg');

-- Insert dummy data into patients table
INSERT INTO patients (user_id, fname, lname, gender, dob, contact_num, address, email, doctor_id) VALUES
  (13, 'John', 'Doe', 'Male', '1985-12-01', '1234567890', '123 Main St', 'john.doe@example.com', 1),
  (14, 'Jane', 'Doe', 'Female', '1990-05-15', '0987654321', '456 Elm St', 'jane.doe@example.com', 2),
  (15, 'George', 'Harris', 'Male', '1995-06-15', '1234567890', '789 Oak St', 'george.harris@example.com', 3),
  (16, 'Helen', 'Clark', 'Female', '1987-09-25', '0987654321', '101 Maple St', 'helen.clark@example.com', 4),
  (17, 'Irene', 'Lewis', 'Female', '1992-03-30', '1234567890', '202 Pine St', 'irene.lewis@example.com', 5),
  (18, 'Jack', 'Wilson', 'Male', '1989-11-21', '0987654321', '303 Cedar St', 'jack.wilson@example.com', 1),
  (19, 'Karen', 'Lee', 'Female', '1996-04-17', '1234567890', '404 Birch St', 'karen.lee@example.com', 2),
  (20, 'Leo', 'King', 'Male', '1991-07-09', '0987654321', '505 Redwood St', 'leo.king@example.com', 3),
  (21, 'Mia', 'Scott', 'Female', '1993-10-03', '1234567890', '606 Willow St', 'mia.scott@example.com', 4),
  (22, 'Nina', 'Baker', 'Female', '2010-01-19', '0987654321', '707 Palm St', 'nina.baker@example.com', 5);

-- Insert dummy data into nurses table
INSERT INTO nurses (user_id, fname, lname, gender, photo) VALUES
  (6, 'Carol', 'Williams', 'Female', 'nurse1.jpg'),
  (7, 'Dave', 'Brown', 'Male', 'nurse2.jpg'),
  (8, 'Diana', 'Williams', 'Female', 'nurse3.jpg'),
  (9, 'Eva', 'Davis', 'Female', 'nurse4.jpg'),
  (10, 'Fiona', 'Garcia', 'Female', 'nurse5.jpg');

-- Insert dummy data into receptions table
INSERT INTO receptions (user_id, fname, lname) VALUES
  (11, 'Emily', 'Davis');

-- Insert dummy data into admins table
INSERT INTO admins (user_id, fname, lname) VALUES
  (12, 'Grace', 'Harris');
  
  -- Inserting dummy data into the slots table
INSERT INTO slots (slot_time) VALUES
('09:00:00'), -- 1
('10:00:00'),  -- 2
('11:00:00'),  -- 3
('12:00:00'),  -- 4
('13:00:00'),  -- 5
('14:00:00'),  -- 6
('15:00:00'), -- 7
('16:00:00');  -- 8

-- Inserting dummy data into the doctor_slots table
INSERT INTO doctor_slots (doctor_id, slot_id, available_date) VALUES
(1, 1, '2023-10-30'),
(1, 2, '2023-10-30'),
(1, 3, '2023-10-30'),
(2, 4, '2023-10-30'),
(2, 5, '2023-10-30'),
(2, 6, '2023-10-30'),
(3, 7, '2023-10-31'),
(3, 8, '2023-10-31'),
(4, 1, '2023-10-31'),
(4, 2, '2023-10-31'),
(4, 3, '2023-10-31'),
(5, 4, '2023-11-01'),
(5, 5, '2023-11-01'),
(5, 6, '2023-11-01'),
(1, 7, '2023-11-02'),
(1, 8, '2023-11-02'),
(2, 1, '2023-11-03'),
(2, 2, '2023-11-03'),
(3, 3, '2023-11-04'),
(3, 4, '2023-11-04');

-- Inserting dummy data into the nurse_slots table
INSERT INTO nurse_slots (nurse_id, slot_id, available_date) VALUES
(1, 1, '2023-10-30'),
(1, 2, '2023-10-30'),
(1, 3, '2023-10-30'),
(2, 4, '2023-10-30'),
(2, 5, '2023-10-30'),
(2, 6, '2023-10-30'),
(3, 7, '2023-10-31'),
(3, 8, '2023-10-31'),
(4, 1, '2023-10-31'),
(4, 2, '2023-10-31'),
(4, 3, '2023-10-31'),
(5, 4, '2023-11-01'),
(5, 5, '2023-11-01'),
(5, 6, '2023-11-01'),
(1, 7, '2023-11-02'),
(1, 8, '2023-11-02'),
(2, 1, '2023-11-03'),
(2, 2, '2023-11-03'),
(3, 3, '2023-11-04'),
(3, 4, '2023-11-04');

-- Insert data into Prices table
INSERT INTO prices (appt_type, age_group, price) VALUES
  ('In-person', 'Under 14', 0),
  ('Virtual', 'Under 14', 0),
  ('In-person', 'Over 14', 50.00),
  ('Virtual', 'Over 14', 40.00);

-- Insert dummy data Insert appointments table
INSERT INTO appointments (patient_id, doctor_id, nurse_id, date, time, type, price_id, status) VALUES
  (1, 1, NULL, '2023-10-28', '10:00:00', 'In-person', 3, 'Completed'),
  (2, 2, NULL, '2023-10-28', '11:00:00', 'Virtual', 4, 'Completed'),
  (3, 3, NULL, '2023-10-30', '12:00:00', 'In-person', 3, 'Completed'),
  (4, NULL, 1, '2023-10-31', '13:00:00', 'Virtual', 4, 'Cancelled'),
  (5, NULL, 2, '2023-10-31', '14:00:00', 'In-person', 3, 'Completed'),
  (6, NULL, 3, '2023-11-02', '15:00:00', 'Virtual', 4, 'Upcoming'),
  (7, 2, NULL, '2023-11-03', '16:00:00', 'In-person', 3, 'Upcoming'),
  (8, 3, NULL, '2023-11-03', '17:00:00', 'Virtual', 4, 'Upcoming'),
  (9, NULL, 4, '2023-11-04', '18:00:00', 'In-person', 3, 'Upcoming'),
  (10, NULL, 5, '2023-11-04', '19:00:00', 'Virtual', 2, 'Upcoming'),
  (10, NULL, 5, '2023-11-07', '14:00:00', 'In-person', 1, 'Upcoming'),
  (1, 1, NULL, '2023-11-07', '10:00:00', 'Virtual', 3, 'Upcoming'),
  (2, 2, NULL, '2023-11-10', '11:00:00', 'In-person', 4, 'Upcoming'),
  (3, 3, NULL, '2023-11-11', '12:00:00', 'Virtual', 3, 'Upcoming');

-- Insert dummy data into prescriptions table
INSERT INTO prescriptions (patient_id, doctor_id, medication, date, repeatable) VALUES
  (1, 1, 'Aspirin', '2023-10-11', TRUE),
  (2, 2, 'Ibuprofen', '2023-10-12', FALSE),
  (3, 3, 'Paracetamol', '2023-10-13', TRUE),
  (4, 4, 'Antibiotics', '2023-10-14', FALSE),
  (5, 5, 'Cough Syrup', '2023-10-15', TRUE),
  (6, 1, 'Insulin', '2023-10-16', FALSE),
  (7, 2, 'Vitamin C', '2023-10-17', TRUE),
  (8, 3, 'Painkiller', '2023-10-18',  FALSE),
  (9, 4, 'Antacid', '2023-10-19', TRUE),
  (10, 5, 'Allergy Medicine', '2023-10-20', FALSE);


-- Insert dummy data into health_records table
INSERT INTO health_records (patient_id, blood_type, allergies, medications, medical_conditions, surgeries, family_history, test_results, notes) VALUES
  (1, 'A+', 'Peanuts', 'Aspirin', 'Asthma', 'Appendectomy', 'Diabetes', 'Blood Test: Normal', 'Regular check-up needed'),
  (2, 'B+', 'None', 'Ibuprofen', 'Hypertension', 'None', 'Heart Disease', 'X-Ray: Normal', 'Follow-up in 6 months'),
  (3, 'O-', 'Seafood', 'Paracetamol', 'None', 'Gallbladder Removal', 'None', 'MRI: Normal', 'No issues'),
  (4, 'AB+', 'Dairy', 'Insulin', 'Diabetes', 'None', 'Diabetes', 'Blood Test: High sugar level', 'Needs to control sugar intake'),
  (5, 'A-', 'None', 'None', 'None', 'None', 'None', 'All Tests: Normal', 'Healthy'),
  (6, 'B-', 'Gluten', 'Antibiotics', 'Allergies', 'None', 'Allergies', 'Blood Test: Normal', 'Carry antihistamine'),
  (7, 'O+', 'None', 'Vitamin D supplements', 'Vitamin D Deficiency', 'None', 'None', 'Blood Test: Low Vitamin D', 'Take supplements'),
  (8, 'AB-', 'Nuts', 'Pain killers', 'Migraine', 'None', 'Migraine', 'MRI: Normal', 'Regular check-up needed'),
  (9, 'A+', 'None', 'Blood thinners', 'High Cholesterol', 'None', 'High Cholesterol', 'Blood Test: High LDL', 'Diet control'),
  (10, 'B+', 'Shellfish', 'Antihistamines', 'Allergies', 'None', 'None', 'All Tests: Normal', 'Avoid shellfish');

-- Insert dummy data into invoices table
INSERT INTO invoices (appt_id, amount, status) VALUES
  (1, 50.00, 'Paid'),
  (3, 50.00, 'Unpaid'),
  (5, 50.00, 'Unpaid');

-- Insert dummy data into payments table
INSERT INTO payments (invoice_id, patient_id, amount, date, payment_method) VALUES
  (1, 1, 50.00, '2023-10-10', 'Credit Card'),
  (2, 3, 40.00, '2023-10-11', 'Debit Card'),
  (3, 5, 50.00, '2023-10-11', 'Debit Card');
