from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy_serializer import SerializerMixin
import re
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model, SerializerMixin):
    __tablename__= 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(256))
    firstname = db.Column(db.String(64))
    secondname = db.Column(db.String(64))
    surname = db.Column(db.String(64))
    address = db.Column(db.String(128))
    phone_number = db.Column(db.String(9))
    type = db.Column(db.String(50))
    gender = db.Column(db.String(50))  
    date_of_birth = db.Column(db.Date)  

    __mapper_args__ = {
        'polymorphic_identity': 'user',
        'polymorphic_on': type
    }

    def set_password(self, password):
        if not self.is_password_strong(password):
            raise ValueError("Password must contain lowercase, uppercase, special character, and number.")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def is_password_strong(password):
        """Check password complexity."""
        if (len(password) < 8 or not re.search("[a-z]", password) or 
            not re.search("[A-Z]", password) or not re.search("[0-9]", password) or 
            not re.search("[!@#\$%\^&\*]", password)):
            return False
        return True

    @staticmethod
    def is_email_valid(email):
        """Check if email is valid."""
        return "@" in email

class Admin(User):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)

    __mapper_args__ = {
        'polymorphic_identity': 'admin',
    }

class Jobseeker(User):
    __tablename__ = 'jobseekers'
    id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    resume = db.Column(db.String(255)) 
    profile_status = db.Column(db.String(120))
    availability = db.Column(db.String(120))
    job_category = db.Column(db.String(120))
    salary_expectations = db.Column(db.String(120))
    file_approval_status = db.Column(db.String(50), default="pending")
    is_verified = db.Column(db.Boolean, default=False) 

    __mapper_args__ = {
        'polymorphic_identity': 'jobseeker',
    }

    def serialize(self):
        return {
            'id': self.id,
            'resume': self.resume,
            'profile_status': self.profile_status,
            'availability': self.availability,
            'job_category': self.job_category,
            'salary_expectations': self.salary_expectations,
            'file_approval_status': self.file_approval_status,
            'is_verified': self.is_verified
        }

class Employer(User):
    __tablename__ = 'employers'
    id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    company_name = db.Column(db.String(120))
    company_image = db.Column(db.String(255))
    company_description = db.Column(db.String(1000))
    verified = db.Column(db.Boolean, default=False)

    __mapper_args__ = {
        'polymorphic_identity': 'employer',
    }

class JobPosting(db.Model, SerializerMixin):
    __tablename__ = 'jobpostings'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120))
    description = db.Column(db.String(1000))
    responsibilities = db.Column(db.String(1000))
    instructions = db.Column(db.String(1000))
    location = db.Column(db.String(255))
    salary_range = db.Column(db.String(255))
    qualifications = db.Column(db.String(1000))            
    job_type = db.Column(db.String(120))   

    employer_id = db.Column(db.Integer, db.ForeignKey('employers.id'))
    employer = db.relationship('Employer', backref=db.backref('postings', lazy='dynamic'))

    def serialize(self):
        employer_data = {
            'id': self.employer.id,
            'company_name': self.employer.company_name,
            'company_image': self.employer.company_image,
            } if self.employer else None
        
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'responsibilities': self.responsibilities,
            'instructions': self.instructions,
            'location': self.location,
            'salary_range': self.salary_range,
            'qualifications': self.qualifications,
            'job_type': self.job_type,
            'employer': employer_data
            }

class Notification(db.Model, SerializerMixin):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  
    message = db.Column(db.String(500))                         
    is_read = db.Column(db.Boolean, default=False)                

    user = db.relationship('User', backref=db.backref('notifications', lazy='dynamic'))

class ContactRequest(db.Model):
    __tablename__ = 'contact_requests'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    message = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])