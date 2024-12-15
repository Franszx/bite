from flask import request, make_response, url_for
from functools import wraps
import mysql.connector
import re
import os
import uuid

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from icecream import ic
ic.configureOutput(prefix=f'***** | ', includeContext=True)




UNSPLASH_ACCESS_KEY = '30f5d8eb-41ad-4dc1-8e95-36ab5e5e1009'
ADMIN_ROLE_PK = "16fd2706-8baf-433b-82eb-8c7fada847da"
CUSTOMER_ROLE_PK = "c56a4180-65aa-42ec-a945-5fd21dec0538"
PARTNER_ROLE_PK = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
RESTAURANT_ROLE_PK = "9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15"
SECRET_KEY = os.getenv('SECRET_KEY', '61dacde0-e6c2-4e31-b436-6f3e2ca4829109384')
DATABASE_PASSWORD = "a0b40581-8af6-4c98-bda0-b9b6df9688b2$kartofler" 

# This approach allows you to use a secure key in production while keeping a fallback for local development.


# form to get data from input fields
# args to get data from the url
# values to get data from the url and from the form

class CustomException(Exception):
    def __init__(self, message, code):
        super().__init__(message)  # Initialize the base class with the message
        self.message = message  # Store additional information (e.g., error code)
        self.code = code  # Store additional information (e.g., error code)

def raise_custom_exception(error, status_code):
    raise CustomException(error, status_code)

DATABASE = {
    'host': '2024lindberg.mysql.eu.pythonanywhere-services.com',
    'user': '2024lindberg',
    'password': "a0b40581-8af6-4c98-bda0-b9b6df9688b2",
    'database': '2024lindberg$company',
}


#############################
# def db():
#     db = mysql.connector.connect(
#         host="mysql",      # Replace with your MySQL server's address or docker service name "mysql"
#         user="root",  # Replace with your MySQL username
#         password="password",  # Replace with your MySQL password
#         database="company"   # Replace with your MySQL database name
#     )
#     cursor = db.cursor(dictionary=True)
#     return db, cursor

def db():
    """
    Establish a connection to the PythonAnywhere database using the DATABASE dictionary.
    """
    try:
        db = mysql.connector.connect(
            host=DATABASE['host'],
            user=DATABASE['user'],
            password=DATABASE['password'],
            database=DATABASE['database']
        )
        cursor = db.cursor(dictionary=True)
        return db, cursor
    except mysql.connector.Error as err:
        ic(f"Database connection error: {err}")
        raise


##############################
def no_cache(view):
    @wraps(view)
    def no_cache_view(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    return no_cache_view


##############################

def allow_origin(origin="*"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Call the wrapped function
            response = make_response(f(*args, **kwargs))
            # Add Access-Control-Allow-Origin header to the response
            response.headers["Access-Control-Allow-Origin"] = origin
            # Optionally allow other methods and headers for full CORS support
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            return response
        return decorated_function
    return decorator


##############################
USER_NAME_MIN = 2
USER_NAME_MAX = 20
USER_NAME_REGEX = f"^.{{{USER_NAME_MIN},{USER_NAME_MAX}}}$"
def validate_user_name():
    error = f"name {USER_NAME_MIN} to {USER_NAME_MAX} characters"
    user_name = request.form.get("user_name", "").strip()
    if not re.match(USER_NAME_REGEX, user_name): raise_custom_exception(error, 400)
    return user_name

##############################
USER_LAST_NAME_MIN = 2
USER_LAST_NAME_MAX = 20
USER_LAST_NAME_REGEX = f"^.{{{USER_LAST_NAME_MIN},{USER_LAST_NAME_MAX}}}$"
def validate_user_last_name():
    error = f"last name {USER_LAST_NAME_MIN} to {USER_LAST_NAME_MAX} characters"
    user_last_name = request.form.get("user_last_name", "").strip() # None
    if not re.match(USER_LAST_NAME_REGEX, user_last_name): raise_custom_exception(error, 400)
    return user_last_name

##############################
REGEX_EMAIL = "^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$"
def validate_user_email():
    error = "email invalid"
    user_email = request.form.get("user_email", "").strip()
    if not re.match(REGEX_EMAIL, user_email): raise_custom_exception(error, 400)
    return user_email

##############################
USER_PASSWORD_MIN = 8
USER_PASSWORD_MAX = 50
REGEX_USER_PASSWORD = f"^.{{{USER_PASSWORD_MIN},{USER_PASSWORD_MAX}}}$"
def validate_user_password():
    error = f"password {USER_PASSWORD_MIN} to {USER_PASSWORD_MAX} characters"
    user_password = request.form.get("user_password", "").strip()
    if not re.match(REGEX_USER_PASSWORD, user_password): raise_custom_exception(error, 400)
    return user_password

##############################
REGEX_UUID4 = "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
def validate_uuid4(uuid4 = ""):
    error = f"invalid uuid4"
    if not uuid4:
        uuid4 = request.values.get("uuid4", "").strip()
    if not re.match(REGEX_UUID4, uuid4): raise_custom_exception(error, 400)
    return uuid4

##############################
# Constants for page validation
PAGE_MIN = 1
PAGE_MAX = 1000  # You can adjust this to whatever the maximum number of pages should be

def validate_page_number(page=None):
    """
    Validates that the page number is an integer between PAGE_MIN and PAGE_MAX.
    If no page is provided, it checks the page from the request URL.
    """
    if page is None:
        # Get page from request arguments (URL query parameters)
        page = request.args.get("page", 1, type=int)

    # Ensure the page is within the defined range
    if page < PAGE_MIN or page > PAGE_MAX:
        raise_custom_exception(f"Page number must be between {PAGE_MIN} and {PAGE_MAX}", 400)

    return page

##############################
UPLOAD_ITEM_FOLDER = './images'
ALLOWED_ITEM_FILE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def validate_item_image():
    if 'item_file' not in request.files: raise_custom_exception("item_file missing", 400)
    file = request.files.get("item_file", "")
    if file.filename == "": raise_custom_exception("item_file name invalid", 400)

    if file:
        ic(file.filename)
        file_extension = os.path.splitext(file.filename)[1][1:]
        ic(file_extension)
        if file_extension not in ALLOWED_ITEM_FILE_EXTENSIONS: raise_custom_exception("item_file invalid extension", 400)
        filename = str(uuid.uuid4()) + file_extension
        return file, filename 


##############################





##############################
def send_verify_email(to_email, user_verification_key):
    try:
        # Create a gmail fullflaskdemomail
        # Enable (turn on) 2 step verification/factor in the google account manager
        # Visit: https://myaccount.google.com/apppasswords


        # Email and password of the sender's Gmail account
        sender_email = "anderslindberg999@gmail.com"
        password = "sxkqvqqwwztienky"  # If 2FA is on, use an App Password instead

        # Receiver email address
        receiver_email = "anderslindberg999@gmail.com"
        
        # Create the email message
        message = MIMEMultipart()
        message["From"] = "bite food inc."
        message["To"] = receiver_email
        message["Subject"] = "Please verify your account"

        # Body of the email
        body = f"""To verify your account, please <a href="{url_for('verify_user', verification_key=user_verification_key, _external=True)}">click here</a>"""
        message.attach(MIMEText(body, "html"))

        # Connect to Gmail's SMTP server and send the email
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Upgrade the connection to secure
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("Email sent successfully!")

        return "email sent"
       
    except Exception as ex:
        raise_custom_exception("cannot send email", 500)
    finally:
        pass

##############################


def send_reset_email(user_email, user_name, reset_link):
    try:
        sender_email = "anderslindberg999@gmail.com"
        password = "sxkqvqqwwztienky"

        receiver_email = "anderslindberg999@gmail.com"

        message = MIMEMultipart()
        message["From"] = "bite food inc."
        message["To"] = receiver_email
        message["Subject"] = "Password reset request"

        

        body = f"""
        Hello {user_name},
        
        <div class="">
        
        </div>

        We received a request to reset your password. Click the link to reset it:
        <a href="{reset_link}">click here</a>

        If you did not request this, please ignore this email.

        Best regards,
        Support Team
        
        """
        message.attach(MIMEText(body, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())

        # ic("Email sent successfully!")

        return "email sent"

    except Exception as ex:
        raise_custom_exception("cannot send email", 500)
    finally:
        pass


##############################

def send_user_info_email(user_email, user_info_link):
    try:
        sender_email = "anderslindberg999@gmail.com"
        password = "sxkqvqqwwztienky"

        receiver_email = user_email

        message = MIMEMultipart()
        message["From"] = "bite food inc."
        message["To"] = receiver_email
        message["Subject"] = "Your Account Information"
        
        # Email body with user info link
        body = f"""To view your account information, please <a href="{user_info_link}">click here</a>"""
        message.attach(MIMEText(body, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())

        print("Email sent successfully!")
        return "email sent"

    except Exception as ex:
        print("Failed to send email:", ex)
##############################


def send_password_update_confirmation(user_email, user_name):
    try:
        sender_email = "anderslindberg999@gmail.com"
        password = "sxkqvqqwwztienky"

        receiver_email = "anderslindberg999@gmail.com"

        message = MIMEMultipart()
        message["From"] = "bite food inc."
        message["To"] = receiver_email
        message["Subject"] = "Your Password Has Been Updated"

        body = f"""
        Hello {user_name}, 

        This is a confirmation that your password has been successfully updated.
        If you did not perform this change, please contact support immediately.

        Best regards,
        Support Team
        """
        message.attach(MIMEText(body, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, user_email, message.as_string())

    except Exception as ex:
        raise_custom_exception("cannot send email", 500)
    finally:
        pass

##############################

def send_block_notification(user_email):
    try:
        sender_email = "anderslindberg999@gmail.com"
        password = "sxkqvqqwwztienky"

        receiver_email = "anderslindberg999@gmail.com"

        message = MIMEMultipart()
        message["From"] = "bite support"
        message["To"] = receiver_email
        message["Subject"] = "Your Account Has Been Blocked"

        body = """
        Hello, 

        Your account has been blocked due to a violation of our policies. 
        If you believe this is a mistake, please contact support.

        Best regards, 
        Support Team
        """
        message.attach(MIMEText(body, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())

        print("Block notification email sent successfully!")

    except Exception as ex:
        print("Failed to send block notification email:", ex)

    finally:
        pass

##############################

def send_unblock_notification(user_email):
    try:
        sender_email = "anderslindberg999@gmail.com"
        password = "sxkqvqqwwztienky"

        receiver_email = "anderslindberg999@gmail.com"

        message = MIMEMultipart()
        message["From"] = "bite food inc."
        message["To"] = receiver_email
        message["Subject"] = "Your Account Has Been Unblocked"

        body = f"""
        Hello, 

        Your account has been unblocked, and you can now access our services again. 
        If you have any questions, feel free to contact support.

        Best regards, 
        Support Team
        """
        message.attach(MIMEText(body, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())

        print("Unblock notification email sent successfully!")

    except Exception as ex:
        print("Failed to send unblock notification email:", ex)

    finally:
        pass

##############################

def send_item_block_notification(partner_email, item_title):
    try:
        sender_email = "anderslindberg999@gmail.com"
        password = "sxkqvqqwwztienky"

        receiver_email = "anderslindberg999@gmail.com"

        message = MIMEMultipart()
        message["From"] = "bite food inc."
        message["To"] = receiver_email
        message["Subject"] = "Item Blocked Notification"

        body = f"""
        Hello, 

        Your item "{item_title}" has been blocked by the admin due to policy violations. 
        If you have any questions or believe this is a mistake, please contact support.

        Best regards, 
        Support Team
        """
        message.attach(MIMEText(body, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())

        print("Item block notification email sent successfully!")

    except Exception as ex:
        print("Failed to send item block notification email:", ex)

    finally:
        pass

##############################


def send_item_unblock_notification(partner_email, item_title):
    try:
        sender_email = "anderslindberg999@gmail.com"
        password = "sxkqvqqwwztienky"

        receiver_email = "anderslindberg999@gmail.com"

        message = MIMEMultipart()
        message["From"] = "bite food inc."
        message["To"] = receiver_email
        message["Subject"] = "Item Unblocked Notification"

        body = f"""
        Hello, 

        Your item "{item_title}" has been unblocked and is now visible to users. 
        If you have any questions, please contact support.

        Best regards, 
        Team bite support
        """
        message.attach(MIMEText(body, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())

        print("Item unblock notification email sent successfully!")

    except Exception as ex:
        print("Failed to send item unblock notification email:", ex)


##############################


def send_deleted_email_notification(to_email, user_name):
    try:
        if not user_name:
            user_name = "Unknown User"  # Default value if user_name is None or empty

        # Ensure it's a string
        user_name = str(user_name)

        sender_email = "anderslindberg999@gmail.com"
        password = "sxkqvqqwwztienky"

        to_email = "anderslindberg999@gmail.com"

        receiver_email = to_email

        message = MIMEMultipart()
        message["From"] = "bite food inc."
        message["To"] = receiver_email
        message["Subject"] = "Profile deleted Notification"

        body = f"""
        Hi {user_name},

        Your profile has been deleted by our administraion. If you believe this is a mistake, please contact bite support.

        Best regards,  
        Your bite Team
        """
        message.attach(MIMEText(body, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())

        print("Deletion email sent successfully!")

    except Exception as ex:
        print("Failed to send deletion email:", ex)

##############################

def send_undeleted_email_notification(to_email, user_name):
    try:
        sender_email = "anderslindberg999@gmail.com"
        password = "sxkqvqqwwztienky"

        receiver_email = "anderslindberg999@gmail.com"

        message = MIMEMultipart()
        message["From"] = "bite food inc."
        message["To"] = receiver_email
        message["Subject"] = "Profile available notification"

        body = f"""
        Hi {user_name},

        Your profile has been made available again by our administraion.

        Best regards,  
        Your bite Team
        """
        message.attach(MIMEText(body, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())

        print("Deletion email sent successfully!")

    except Exception as ex:
        print("Failed to send deletion email:", ex)

##############################

def send_deletion_confirmation_email(to_email, user_name):
    try:
        sender_email = "anderslindberg999@gmail.com"
        password = "sxkqvqqwwztienky"

        receiver_email = "anderslindberg999@gmail.com"

        message = MIMEMultipart()
        message["From"] = "bite food inc."
        message["To"] = receiver_email
        message["Subject"] = "Profile deleted notification"

        body = f"""
        Hi {user_name},

        Your profile has been successfully deleted. If you did not request this, please contact our support team immediately.

        Best regards,  
        Your bite Team
        """
        message.attach(MIMEText(body, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())

        print("Deletion email sent successfully!")

    except Exception as ex:
        print("Failed to send deletion email:", ex)


##############################

def send_item_purchase_confirmation_email(user_email, user_name, item_title, item_price, restaurant_name, quantity):
    try:
        sender_email = "anderslindberg999@gmail.com"
        password = "sxkqvqqwwztienky"
        receiver_email = "anderslindberg999@gmail.com"

        message = MIMEMultipart()
        message["From"] = "bite food inc."
        message["To"] = receiver_email
        message["Subject"] = "Order Confirmation - Bite"


        # Calculate the total price
        total_price = item_price * quantity

        # Email body with purchase details
        body = f"""
        Hi <h2 class="text-20px w-20">{user_name}</h2><br>
        

        Thank you for your order! Below are the details of your order:<br><br><br><br>
        - Item: {item_title}<br>
        - Pieces: {quantity} <br>
        - Price per dish: DKK {item_price:.2f}<br>
        - Total Price: DKK {total_price:.2f}<br>
        - Restaurant: {restaurant_name}<br><br>

        If you have any questions or issues, feel free to contact our support team.<br><br>

        Best regards,<br>
        bite Team
        """
        message.attach(MIMEText(body, "html"))

        # Connect to the SMTP server and send the email
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())

        print("Purchase confirmation email sent successfully!")
        return "email sent"

    except Exception as ex:
        print("Failed to send purchase confirmation email:", ex)
        raise_custom_exception("cannot send email", 500)


##############################
# Constants for Create Restaurant Form
RESTAURANT_NAME_MIN = 2
RESTAURANT_NAME_MAX = 50
RESTAURANT_NAME_REGEX = f"^.{{{RESTAURANT_NAME_MIN},{RESTAURANT_NAME_MAX}}}$"
def validate_restaurant_name():
    error = f"Restaurant name must be between {RESTAURANT_NAME_MIN} and {RESTAURANT_NAME_MAX} characters."
    restaurant_name = request.form.get("restaurant_name", "").strip()
    if not re.match(RESTAURANT_NAME_REGEX, restaurant_name): 
        raise_custom_exception(error, 400)
    return restaurant_name

##############################
STREET_NAME_MIN = 2
STREET_NAME_MAX = 50
STREET_NAME_REGEX = f"^.{{{STREET_NAME_MIN},{STREET_NAME_MAX}}}$"
def validate_street_name():
    error = f"Street name must be between {STREET_NAME_MIN} and {STREET_NAME_MAX} characters."
    street_name = request.form.get("street_name", "").strip()
    if not re.match(STREET_NAME_REGEX, street_name): 
        raise_custom_exception(error, 400)
    return street_name

##############################
STREET_NUMBER_REGEX = r"^\d{1,5}$"  # Allows numbers up to 5 digits
def validate_street_number():
    error = "Street number must be a number between 1 and 99999."
    street_number = request.form.get("street_number", "").strip()
    if not re.match(STREET_NUMBER_REGEX, street_number): 
        raise_custom_exception(error, 400)
    return street_number

##############################
CITY_NAME_MIN = 2
CITY_NAME_MAX = 50
CITY_NAME_REGEX = f"^.{{{CITY_NAME_MIN},{CITY_NAME_MAX}}}$"
def validate_city_name():
    error = f"City name must be between {CITY_NAME_MIN} and {CITY_NAME_MAX} characters."
    city_name = request.form.get("city", "").strip()
    if not re.match(CITY_NAME_REGEX, city_name): 
        raise_custom_exception(error, 400)
    return city_name

##############################
POSTAL_CODE_REGEX = r"^\d{2,6}$"  # Allows postal codes between 2 and 6 digits
def validate_postal_code():
    error = "Postal code must be a number between 4 and 6 digits."
    postal_code = request.form.get("postnummer", "").strip()
    if not re.match(POSTAL_CODE_REGEX, postal_code): 
        raise_custom_exception(error, 400)
    return postal_code







