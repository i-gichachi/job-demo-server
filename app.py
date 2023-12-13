from flask import Flask, request, jsonify
from flask_restful import Api, Resource, reqparse
from flask_cors import CORS
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, DateField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Regexp
from models import db, User, Jobseeker, Employer, JobPosting, Notification, ContactRequest, Admin
import requests
import base64
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = b'\x84^\xca\xaf\xca\x0e\xe6\xff\xbbw\x00\xfd\x8aN\xa6WS\x1d\x16`\xde\xb8W\xea'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://gichachi:CglpoGJbYJqDlYok1MnkfHS9U3FyRfzP@dpg-clor1ah46foc73a37ot0-a.oregon-postgres.render.com/testingdb_v4xf'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = b'\x84^\xca\xaf\xca\x0e\xe6\xff\xbbw\x00\xfd\x8aN\xa6WS\x1d\x16`\xde\xb8W\xea'

jwt = JWTManager(app)
CORS(app)
api = Api(app)
db.init_app(app)
migrate = Migrate(app, db)

CONSUMER_KEY = 'ksx4CGm3sjJFBVoWbEySqiuTAkjA1nr8'
CONSUMER_SECRET = 'JPplKP1go79NifUZ'
BUSINESS_SHORT_CODE = '174379'
LIPA_NA_MPESA_PASSKEY = 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919'  # Your passkey
CALLBACK_URL = 'https://test-server-6mxa.onrender.com/stk-callback'

def get_access_token():
    api_url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    credentials = base64.b64encode(f'{CONSUMER_KEY}:{CONSUMER_SECRET}'.encode()).decode('utf-8')
    headers = {'Authorization': f'Basic {credentials}'}
    response = requests.get(api_url, headers=headers)
    return response.json().get('access_token')

def stk_push(phone_number, amount=1):
    access_token = get_access_token()
    api_url = 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
    headers = {'Authorization': f'Bearer {access_token}'}

    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    password = base64.b64encode(f'{BUSINESS_SHORT_CODE}{LIPA_NA_MPESA_PASSKEY}{timestamp}'.encode()).decode('utf-8')

    payload = {
        'BusinessShortCode': BUSINESS_SHORT_CODE,
        'Password': password,
        'Timestamp': timestamp,
        'TransactionType': 'CustomerPayBillOnline',
        'Amount': amount,  # The amount to be paid
        'PartyA': phone_number,  # Employer's phone number
        'PartyB': BUSINESS_SHORT_CODE,
        'PhoneNumber': phone_number,  # Employer's phone number
        'CallBackURL': CALLBACK_URL,
        'AccountReference': 'UncleMaconnectionLTD',
        'TransactionDesc': 'Employer Verification Payment'
    }

    response = requests.post(api_url, json=payload, headers=headers)
    return response.json()

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    
    password = PasswordField('Password', validators=[
        DataRequired(),
        Regexp(regex='(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)', message="Password must contain at least one lowercase letter, one uppercase letter, one numeral, and one special character.")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

    first_name = StringField('First Name', validators=[DataRequired()])
    second_name = StringField('Second Name')
    surname = StringField('Surname', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('male', 'Male'), ('female', 'Female')], validators=[DataRequired()])
    date_of_birth = DateField('Date of Birth', format='%Y-%m-%d', validators=[DataRequired()])
    address = StringField('Address')
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    user_type = SelectField('User Type', choices=[('jobseeker', 'Jobseeker'), ('employer', 'Employer')], validators=[DataRequired()])
    agree_terms = BooleanField('I agree to the terms and conditions', validators=[DataRequired()])

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('This email is already in use. Please choose a different one.')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('This username is already taken. Please choose a different one.')

def create_user_notification(user):

    admin_users = User.query.filter_by(is_admin=True).all()

    for admin in admin_users:
        notification = Notification(
            user_id=admin.id,
            message=f"New user registered: {user.username}",
            is_read=False
        )
        db.session.add(notification)

    db.session.commit()

class HomePageResource(Resource):
    def get(self):
        return {
            'message': 'Welcome to the Job Seeking App API'
        }

api.add_resource(HomePageResource, '/')

class CheckUserResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if user:
            return jsonify({
                'logged_in': True,
                'user_id': user.id,
                'user_type': user.type,
                'username': user.username,
            })
        else:
            # This case might not be necessary since @jwt_required() ensures a valid user
            return jsonify({'logged_in': False})

# Add the CheckUser Resource to API
api.add_resource(CheckUserResource, '/check_user')

class LoginResource(Resource):
    def post(self):
        data = request.get_json()
        user_identifier = data.get('user_identifier')
        password = data.get('password')

        user = User.query.filter((User.email == user_identifier) |
                                 (User.username == user_identifier) |
                                 (User.phone_number == user_identifier)).first()

        if user and check_password_hash(user.password_hash, password):
            # Create JWT access token
            access_token = create_access_token(identity=user.id)
            return jsonify({
                'message': 'Logged in successfully',
                'access_token': access_token,  # Send the JWT token to the client
                'user_id': user.id,
                'user_type': user.type,
                'username': user.username
            })
        else:
            return {'message': 'Invalid credentials'}, 401

api.add_resource(LoginResource, '/login')

class LogoutResource(Resource):
    @jwt_required()
    def post(self):
        # JWT logout is handled client-side. Inform the client.
        return {'message': 'Please discard your access token.'}, 200

api.add_resource(LogoutResource, '/logout')

class SignupResource(Resource):
    def post(self):
        data = request.get_json()

        # Check for existing users
        if User.query.filter_by(email=data['email']).first():
            return {'message': 'Email already exists'}, 400

        if User.query.filter_by(username=data['username']).first():
            return {'message': 'Username already exists'}, 400

        hashed_password = generate_password_hash(data['password'])

        new_user = User(
            username=data['username'],
            email=data['email'],
            password_hash=hashed_password,
            firstname=data['first_name'],
            secondname=data.get('second_name', ''),
            surname=data['surname'],
            address=data.get('address', ''),
            phone_number=data['phone_number'],
            type=data['user_type'],  
            gender=data['gender'],  
            date_of_birth=data['date_of_birth']  
        )

        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User created successfully'}, 201

api.add_resource(SignupResource, '/signup')

class UserInfoResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return {'message': 'User not found'}, 404

        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'firstname': user.firstname,
            'secondname': user.secondname,
            'surname': user.surname,
            'address': user.address,
            'phone_number': user.phone_number,
            'gender': user.gender,
            'date_of_birth': user.date_of_birth.isoformat() if user.date_of_birth else None
        }

        return user_data, 200

api.add_resource(UserInfoResource, '/user/info')

class UpdateUserResource(Resource):
    @jwt_required()
    def put(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return {'message': 'User not found'}, 404

        form_data = request.get_json()

        user.username = form_data.get('username', user.username)
        user.email = form_data.get('email', user.email)
        user.firstname = form_data.get('first_name', user.firstname)
        user.secondname = form_data.get('second_name', user.secondname)
        user.surname = form_data.get('surname', user.surname)
        user.address = form_data.get('address', user.address)
        user.phone_number = form_data.get('phone_number', user.phone_number)
        user.gender = form_data.get('gender', user.gender)
        
        db.session.commit()

        return {'message': 'User information updated successfully'}, 200

api.add_resource(UpdateUserResource, '/user/update')

class JobseekerProfileResource(Resource):
    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return {'message': 'User not found'}, 404

        # Ensure the current user is a jobseeker
        if user.type != 'jobseeker':
            return {'message': 'Access denied. Only jobseekers can create a profile.'}, 403

        # Check if the jobseeker profile for the current user already exists
        jobseeker_profile = Jobseeker.query.filter_by(id=user.id).first()
        if jobseeker_profile:
            return {'message': 'Profile already exists. Use the update profile API to make changes.'}, 400

        form_data = request.get_json()

        # Validate the data
        if 'resume' not in form_data or not form_data['resume'].strip():
            return {'message': 'Resume is required.'}, 400
        # Add more validation checks here

        # Directly insert into the jobseekers table
        new_profile_data = {
            'id': user.id,
            'resume': form_data['resume'],
            'profile_status': "Active",
            'availability': "Available",
            'job_category': form_data.get('job_category', ''),
            'salary_expectations': form_data.get('salary_expectations', ''),
            'file_approval_status': "pending",
            'is_verified': False
        }
        db.session.execute(Jobseeker.__table__.insert().values(new_profile_data))
        db.session.commit()

        return {'message': 'Profile created successfully'}, 201

api.add_resource(JobseekerProfileResource, '/jobseeker/profile')

class GetJobseekerProfileResource(Resource):
    @jwt_required()
    def get(self, jobseeker_id):
        current_user_id = get_jwt_identity()
        
        # Check if the current user is requesting their own profile
        if current_user_id != jobseeker_id:
            return {'message': 'Unauthorized access'}, 401

        jobseeker = Jobseeker.query.get(jobseeker_id)
        if not jobseeker:
            return {'message': 'Jobseeker not found'}, 404

        profile_data = {
            'resume': jobseeker.resume,
            'profile_status': jobseeker.profile_status,
            'availability': jobseeker.availability,
            'job_category': jobseeker.job_category,
            'salary_expectations': jobseeker.salary_expectations,
            'file_approval_status': jobseeker.file_approval_status,
            'is_verified': jobseeker.is_verified
        }

        return profile_data, 200

api.add_resource(GetJobseekerProfileResource, '/jobseeker/profile/<int:jobseeker_id>')

class UpdateJobseekerProfileResource(Resource):
    @jwt_required()
    def put(self, jobseeker_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return {'message': 'User not found'}, 404

        # Check if the current user is the jobseeker or an admin
        if current_user_id != jobseeker_id and current_user.type != 'admin':
            return {'message': 'Unauthorized access'}, 401

        form_data = request.get_json()
        jobseeker = Jobseeker.query.get(jobseeker_id)

        if not jobseeker:
            return {'message': 'Jobseeker not found'}, 404

        jobseeker.resume = form_data.get('resume', jobseeker.resume)
        jobseeker.profile_status = form_data.get('profile_status', jobseeker.profile_status)
        jobseeker.availability = form_data.get('availability', jobseeker.availability)
        jobseeker.job_category = form_data.get('job_category', jobseeker.job_category)
        jobseeker.salary_expectations = form_data.get('salary_expectations', jobseeker.salary_expectations)

        db.session.commit()

        return {'message': 'Jobseeker profile updated successfully'}, 200

api.add_resource(UpdateJobseekerProfileResource, '/jobseeker/profile/update/<int:jobseeker_id>')

class EmployerProfileResource(Resource):
    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return {'message': 'User not found'}, 404

        # Ensure the current user is an employer
        if current_user.type != 'employer':
            return {'message': 'Unauthorized or invalid user'}, 401

        form_data = request.get_json()

        # Check if the employer profile for the current user already exists
        existing_profile = Employer.query.filter_by(id=current_user_id).first()
        if existing_profile:
            return {'message': 'Profile already exists'}, 400

        # Validate the data (add your own validations here)
        if not form_data.get('company_name'):
            return {'message': 'Company name is required.'}, 400
        # Add more validation checks here

        # Directly insert into the employers table
        new_profile_data = {
            'id': current_user_id,
            'company_name': form_data.get('company_name', ''),
            'company_image': form_data.get('company_image', ''),
            'company_description': form_data.get('company_description', ''),
            'verified': False
        }
        db.session.execute(Employer.__table__.insert().values(new_profile_data))
        db.session.commit()

        return {'message': 'Employer profile created successfully'}, 201

api.add_resource(EmployerProfileResource, '/employer/profile')

class GetEmployerProfileResource(Resource):
    @jwt_required()
    def get(self, employer_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return {'message': 'User not found'}, 404

        # Check if the current user is requesting their own profile
        if current_user_id != employer_id:
            return {'message': 'Unauthorized access'}, 401

        employer = Employer.query.get(employer_id)
        if not employer:
            return {'message': 'Employer not found'}, 404

        profile_data = {
            'company_name': employer.company_name,
            'company_image': employer.company_image,
            'company_description': employer.company_description,
            'verified': employer.verified
        }

        return profile_data, 200

api.add_resource(GetEmployerProfileResource, '/employer/profile/<int:employer_id>')

class UpdateEmployerProfileResource(Resource):
    @jwt_required()
    def put(self, employer_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return {'message': 'User not found'}, 404

        # Check if the current user is allowed to update this employer profile
        if current_user_id != employer_id:
            return {'message': 'Unauthorized access'}, 401

        form_data = request.get_json()
        employer = Employer.query.get(employer_id)

        if not employer:
            return {'message': 'Employer not found'}, 404

        employer.company_name = form_data.get('company_name', employer.company_name)
        employer.company_image = form_data.get('company_image', employer.company_image)
        employer.company_description = form_data.get('company_description', employer.company_description)

        db.session.commit()

        return {'message': 'Employer profile updated successfully'}, 200

api.add_resource(UpdateEmployerProfileResource, '/employer/profile/<int:employer_id>')

class CreateJobPostingResource(Resource):
    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return {'message': 'User not found'}, 404

        # Ensure the current user is an employer
        if current_user.type != 'employer':
            return {'message': 'Unauthorized access'}, 401

        form_data = request.get_json()

        # Create a new JobPosting object
        job_posting = JobPosting(
            title=form_data.get('title'),
            description=form_data.get('description'),
            responsibilities=form_data.get('responsibilities'),
            instructions=form_data.get('instructions'),
            location=form_data.get('location'),
            salary_range=form_data.get('salary_range'),
            qualifications=form_data.get('qualifications'),                           
            job_type=form_data.get('job_type'),             
            employer_id=current_user.id
        )

        # Add the new job posting to the database session and commit it
        db.session.add(job_posting)
        db.session.commit()

        # Send notification to admins and jobseekers
        self.send_new_posting_notifications(job_posting)

        return {'message': 'Job posting created successfully'}, 201

    def send_new_posting_notifications(self, job_posting):
        # Fetch all admins and jobseekers
        admins = Admin.query.all()
        jobseekers = Jobseeker.query.all()

        # Construct the notification title and message
        notification_title = "New job posting"
        notification_message = f"{job_posting.title} is now available."

        # Function to create notifications for each user
        def create_notification(user):
            notification = Notification(
                user_id=user.id, 
                title=notification_title,  # Set the title
                message=notification_message,  # Set the message
                is_read=False, 
            )
            db.session.add(notification)

        # Create notifications for each admin and jobseeker
        for admin in admins:
            create_notification(admin)
        for jobseeker in jobseekers:
            create_notification(jobseeker)

        # Commit the notifications to the database
        db.session.commit()

# Add the resource to the API
api.add_resource(CreateJobPostingResource, '/jobposting/create')

class JobPostingsResource(Resource):
    @jwt_required()
    def get(self):
        try:
            postings = JobPosting.query.all()
            postings_data = [posting.serialize() for posting in postings]
            return jsonify({'postings': postings_data})
        except Exception as e:
            print("Error: ", e)  # Log the exception for debugging
            return {"message": "An error occurred while fetching job postings"}, 500

api.add_resource(JobPostingsResource, '/jobpostings')

class JobPostingResource(Resource):
    @jwt_required()
    def get(self, jobposting_id):
        try:
            posting = JobPosting.query.get(jobposting_id)
            if posting:
                return jsonify(posting.serialize())
            else:
                return {"message": "Job posting not found"}, 404
        except Exception as e:
            print("Error: ", e)  # Log the exception for debugging
            return {"message": "An error occurred while fetching job posting"}, 500
        
api.add_resource(JobPostingResource, '/jobposting/<int:jobposting_id>')

class EmployerJobPostingsResource(Resource):
    @jwt_required()
    def get(self, employer_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return {'message': 'User not found'}, 404

        # Check if the current user is the employer making the request
        if current_user_id != employer_id:
            return {'message': 'Unauthorized access'}, 401

        postings = JobPosting.query.filter_by(employer_id=employer_id).all()
        postings_data = [{
            'id': posting.id,
            'title': posting.title,
            'description': posting.description,
            'responsibilities': posting.responsibilities,
            'instructions': posting.instructions,
            'location': posting.location,
            'salary_range': posting.salary_range,
            'qualifications': posting.qualifications,
            'job_type': posting.job_type
            # Add or remove fields based on your JobPosting model
        } for posting in postings]

        return jsonify({'postings': postings_data})

api.add_resource(EmployerJobPostingsResource, '/employer/<int:employer_id>/jobpostings')

class JobPostingDeleteResource(Resource):
    @jwt_required()
    def delete(self, jobposting_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return {'message': 'User not found'}, 404

        # Check if the current user is an employer and authorized to delete this posting
        if current_user.type != 'employer':
            return {'message': 'Unauthorized access'}, 401

        job_posting = JobPosting.query.get(jobposting_id)
        if not job_posting or job_posting.employer_id != current_user_id:
            return {'message': 'Job posting not found or unauthorized'}, 404

        db.session.delete(job_posting)
        db.session.commit()

        return {'message': 'Job posting deleted successfully'}, 200

api.add_resource(JobPostingDeleteResource, '/jobposting/delete/<int:jobposting_id>')

class JobPostingUpdateResource(Resource):
    @jwt_required()
    def put(self, jobposting_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return {'message': 'User not found'}, 404

        # Check if the current user is an employer and authorized to update this posting
        if current_user.type != 'employer':
            return {'message': 'Unauthorized access'}, 401

        job_posting = JobPosting.query.get(jobposting_id)
        if not job_posting or job_posting.employer_id != current_user_id:
            return {'message': 'Job posting not found or unauthorized'}, 404

        form_data = request.get_json()

        job_posting.title = form_data.get('title', job_posting.title)
        job_posting.description = form_data.get('description', job_posting.description)
        job_posting.responsibilities = form_data.get('responsibilities', job_posting.responsibilities)
        job_posting.instructions = form_data.get('instructions', job_posting.instructions)
        job_posting.location = form_data.get('location', job_posting.location)
        job_posting.salary_range = form_data.get('salary_range', job_posting.salary_range)
        job_posting.qualifications = form_data.get('qualifications', job_posting.qualifications)
        job_posting.job_type = form_data.get('job_type', job_posting.job_type)

        db.session.commit()

        return {'message': 'Job posting updated successfully'}, 200

api.add_resource(JobPostingUpdateResource, '/jobposting/update/<int:jobposting_id>')

class FileApprovalResource(Resource):
    @jwt_required()
    def put(self, jobseeker_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return {'message': 'User not found'}, 404

        if current_user.type != 'admin':
            return {'message': 'Unauthorized access'}, 401

        form_data = request.get_json()
        approval_status = form_data.get('approval_status')

        if approval_status not in ['approved', 'rejected']:
            return {'message': 'Invalid approval status'}, 400

        jobseeker = Jobseeker.query.get(jobseeker_id)
        if not jobseeker:
            return {'message': 'Jobseeker not found'}, 404

        jobseeker.file_approval_status = approval_status
        jobseeker.is_verified = approval_status == 'approved'

        db.session.commit()

        self.send_approval_notification(jobseeker, approval_status)

        return {'message': f'Jobseeker file status updated to {approval_status}'}, 200

    def send_approval_notification(self, jobseeker, approval_status):
        notification_title = "Profile Approval Status"
        notification_message = ("Congratulations! Your profile has been approved. You have been verified." 
                                if approval_status == 'approved' 
                                else "Your profile has not been approved. Please update your files for verification.")

        notification = Notification(
            user_id=jobseeker.id,
            title=notification_title,
            message=notification_message,
            is_read=False,
        )
        db.session.add(notification)
        db.session.commit()

api.add_resource(FileApprovalResource, '/jobseeker/file-approval/<int:jobseeker_id>')

class NotificationResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        notifications = Notification.query.filter_by(user_id=current_user_id).all()
        result = [{
            'id': notification.id,
            'type': notification.type,  # New field
            'title': notification.title,  # New field
            'message': notification.message,
            'is_read': notification.is_read,
        } for notification in notifications]

        return result, 200

api.add_resource(NotificationResource, '/notifications')

class NotificationReadResource(Resource):
    @jwt_required()
    def put(self, notification_id):
        current_user_id = get_jwt_identity()
        notification = Notification.query.get(notification_id)

        if not notification or notification.user_id != current_user_id:
            return {'message': 'Notification not found or unauthorized'}, 404

        notification.is_read = True
        db.session.commit()

        return {'message': 'Notification marked as read'}, 200

api.add_resource(NotificationReadResource, '/notifications/read/<int:notification_id>')

class ViewAllJobseekersResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return {'message': 'User not found'}, 404

        # Ensure the current user is an employer
        if current_user.type != 'employer':
            return {'message': 'Unauthorized access'}, 401

        jobseekers = Jobseeker.query.filter_by(profile_status='Active').all()
        jobseekers_data = [{
            'id': jobseeker.id,
            'username': jobseeker.username,  
            'resume': jobseeker.resume,
            'profile_status': jobseeker.profile_status,
            'availability': jobseeker.availability,
            'job_category': jobseeker.job_category,
            'salary_expectations': jobseeker.salary_expectations,
            'is_verified': jobseeker.is_verified
        } for jobseeker in jobseekers]

        return {'jobseekers': jobseekers_data}, 200

api.add_resource(ViewAllJobseekersResource, '/jobseekers/view')

class ContactJobseekerResource(Resource):
    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return {'message': 'User not found'}, 404

        # Check if current user is an employer
        if current_user.type != 'employer':
            return {'message': 'Unauthorized access'}, 401

        # Fetch the employer's company name
        employer = Employer.query.filter_by(id=current_user_id).first()
        if not employer:
            return {'message': 'Employer not found'}, 404
        company_name = employer.company_name

        # Parse the incoming data from the request
        form_data = request.get_json()
        jobseeker_id = form_data.get('jobseeker_id')
        contact_message = form_data.get('message')

        # Validate the message content
        if not contact_message:
            return {'message': 'Message is required'}, 400

        # Create a new contact request
        contact_request = ContactRequest(
            sender_id=current_user_id,
            receiver_id=jobseeker_id,
            message=contact_message,
        )

        # Add the contact request to the database
        db.session.add(contact_request)

        # Define the title and message for the notification
        notification_title = f"Message from {company_name}"
        notification_message = f"{company_name} sent you a message: '{contact_message}'"

        # Create a notification for the jobseeker including the employer's company name and message
        notification = Notification(
            user_id=jobseeker_id,
            title=notification_title,
            message=notification_message,
            is_read=False
        )

        # Add the notification to the database
        db.session.add(notification)
        db.session.commit()

        # Return a success message
        return {'message': 'Contact request sent successfully'}, 201

api.add_resource(ContactJobseekerResource, '/jobseeker/contact')

class ViewAllUsersResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return {'message': 'User not found'}, 404

        # Check if the current user is an admin
        if not current_user.is_admin:
            return {'message': 'Unauthorized access'}, 401

        users = User.query.all()
        users_data = [{
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'type': user.type,
            'phone_number': user.phone_number
        } for user in users]

        return users_data, 200

api.add_resource(ViewAllUsersResource, '/admin/users/view')

class EmployerSearchResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return {'message': 'User not found'}, 404

        # Check if the current user is an employer
        if current_user.type != 'employer':
            return {'message': 'Unauthorized access'}, 401

        query_params = request.args
        availability = query_params.get('availability')
        job_category = query_params.get('job_category')
        salary_expectations = query_params.get('salary_expectations')

        query = Jobseeker.query
        if availability:
            query = query.filter(Jobseeker.availability == availability)
        if job_category:
            query = query.filter(Jobseeker.job_category == job_category)
        if salary_expectations:
            query = query.filter(Jobseeker.salary_expectations == salary_expectations)

        jobseekers = query.all()
        result = [{
            'id': js.id,
            'username': js.username,
            'resume': js.resume,
            'availability': js.availability,
            'job_category': js.job_category,
            'salary_expectations': js.salary_expectations,
            'is_verified': js.is_verified  
        } for js in jobseekers]

        return result, 200

api.add_resource(EmployerSearchResource, '/employer/search')

class AdminUserManagementResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user or current_user.type != 'admin':
            return {'message': 'Unauthorized access'}, 401

        users = User.query.filter(User.type != 'admin').all()
        users_data = [
            {
                'id': user.id, 
                'username': user.username, 
                'email': user.email, 
                'type': user.type
            } 
            for user in users
        ]
        return {'users': users_data}, 200

    @jwt_required()
    def delete(self, user_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user or current_user.type != 'admin':
            return {'message': 'Unauthorized access'}, 401

        user = User.query.get(user_id)
        if not user:
            return {'message': 'User not found'}, 404

        db.session.delete(user)
        db.session.commit()
        return {'message': 'User deleted successfully'}, 200

api.add_resource(AdminUserManagementResource, '/admin/users', '/admin/users/<int:user_id>')

class AdminContentModerationResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user or current_user.type != 'admin':
            return {'message': 'Unauthorized access'}, 401

        postings = JobPosting.query.all()
        postings_data = [
            {
                'id': posting.id, 
                'title': posting.title, 
                'description': posting.description
            } 
            for posting in postings
        ]
        return {'postings': postings_data}, 200

    @jwt_required()
    def delete(self, posting_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user or current_user.type != 'admin':
            return {'message': 'Unauthorized access'}, 401

        posting = JobPosting.query.get(posting_id)
        if not posting:
            return {'message': 'Job posting not found'}, 404

        db.session.delete(posting)
        db.session.commit()
        return {'message': 'Job posting deleted successfully'}, 200

api.add_resource(AdminContentModerationResource, '/admin/content', '/admin/content/<int:posting_id>')

class AdminJobseekerProfileResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return {'message': 'User not found'}, 404

        # Check if the current user is an admin
        if current_user.type != 'admin':
            return {'message': 'Unauthorized access'}, 401

        jobseekers = Jobseeker.query.all()
        jobseeker_profiles = [{
            'id': jobseeker.id,
            'username': jobseeker.username,
            'resume': jobseeker.resume,
            'profile_status': jobseeker.profile_status,
            'availability': jobseeker.availability,
            'job_category': jobseeker.job_category,
            'salary_expectations': jobseeker.salary_expectations,
            'file_approval_status': jobseeker.file_approval_status,
            'is_verified': jobseeker.is_verified
        } for jobseeker in jobseekers]

        return {'jobseekers': jobseeker_profiles}, 200

api.add_resource(AdminJobseekerProfileResource, '/admin/jobseekers')

class STKPushResource(Resource):
    def post(self):
        data = request.get_json()
        phone_number = data.get('phone_number')
        amount = data.get('amount')
        response = stk_push(phone_number, amount)
        return response

api.add_resource(STKPushResource, '/stk-push')

class STKCallbackResource(Resource):
    def post(self):
        data = request.get_json()
        # Ensure you use the correct indexes to access phone number and other details based on the actual M-Pesa callback structure.
        phone_number = data['Body']['stkCallback']['CallbackMetadata']['Item'][4]['Value']

        employer = Employer.query.filter_by(phone_number=str(phone_number)).first()
        if employer:
            # Logic to check if the payment was successful and the amount is correct
            # should be implemented here, based on the actual M-Pesa callback structure.
            # Assuming you have verified the payment was successful:
            employer.verified = True
            db.session.commit()
            return {'status': 'success', 'message': 'Employer verified successfully.'}
        else:
            return {'status': 'failed', 'message': 'Employer not found.'}, 404

api.add_resource(STKCallbackResource, '/stk-callback')

class PaymentStatusResource(Resource):
    @jwt_required()
    def get(self, employer_id):
        employer = Employer.query.get(employer_id)
        if employer:
            return {'verified': employer.verified}
        else:
            return {'status': 'failed', 'message': 'Employer not found.'}, 404

api.add_resource(PaymentStatusResource, '/payment-status/<int:employer_id>')

if __name__ == '__main__':
    app.run(port=5555, debug=True)