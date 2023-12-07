from app import app, db
from models import User, Employer, Jobseeker, Admin
import datetime

with app.app_context():

    db.drop_all()
    db.create_all()

    employers = [
        Employer(username='mwithi', email='briankamau@gmail.com', firstname='Brian', secondname='Mwithi', surname='Kamau', 
                 address='Thika', phone_number='724777333', company_name="Coca-Cola", company_image="path_to_coca_cola_image", 
                 company_description="Coca-Cola Beverages Africa is the largest African Coca-Cola bottler.", 
                 gender='male', date_of_birth=datetime.date(1985, 5, 21)),
        Employer(username='mwende', email='mwendekanini@gmail.com', firstname='Elizabeth', secondname='Kanini', surname='Mwende', 
                 address='Nairobi', phone_number='726993377', company_name="Safaricom", company_image="path_to_safaricom_image", 
                 company_description="It is the largest telecommunications provider in Kenya.", 
                 gender='female', date_of_birth=datetime.date(1990, 3, 14)),
    ]

    for employer in employers:
        employer.set_password('Password@123')  
        db.session.add(employer)

    jobseekers = [
        Jobseeker(username='sally', email='atienosally@gmail.com', firstname='Sally', secondname='Amollo', surname='Atieno', 
                  address='Kisumu', phone_number='721839378', resume="path_to_resume", profile_status="Active", 
                  availability="Available", job_category="IT", salary_expectations="50000", 
                  file_approval_status="pending", is_verified=False, 
                  gender='female', date_of_birth=datetime.date(1995, 7, 22)),
    ]

    for jobseeker in jobseekers:
        jobseeker.set_password('Password@123')  
        db.session.add(jobseeker)

    admins = [
        Admin(username='gichachi', email='iangichachi@gmail.com', firstname='Ian', secondname='Mwaura', surname='Gichachi', 
              address='Nairobi', phone_number='720064950', gender='male', date_of_birth=datetime.date(1988, 12, 15)),
    ]

    for admin in admins:
        admin.set_password('Password@123')  
        db.session.add(admin)

    db.session.commit()

    print("Database seeded successfully!")