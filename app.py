from flask import Flask, session, render_template, redirect, url_for, make_response, send_from_directory, request, jsonify
from flask_session import Session
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
import requests
import x
import uuid 
import time
import redis
import os
from datetime import datetime, timedelta
from mysql.connector.errors import IntegrityError
from functools import wraps
from werkzeug.utils import secure_filename
import random  

from icecream import ic
ic.configureOutput(prefix=f'***** | ', includeContext=True)



app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'  # or 'redis', etc.
Session(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}




# Ensure the UPLOAD_FOLDER exists
UPLOAD_FOLDER_AVATARS = 'static/avatars/'
if not os.path.exists(UPLOAD_FOLDER_AVATARS):
    os.makedirs(UPLOAD_FOLDER_AVATARS)

app.config['UPLOAD_FOLDER_AVATARS'] = UPLOAD_FOLDER_AVATARS

UPLOAD_FOLDER_ITEMS = 'static/uploads/items'
if not os.path.exists(UPLOAD_FOLDER_ITEMS):
    os.makedirs(UPLOAD_FOLDER_ITEMS)

app.config['UPLOAD_FOLDER_ITEMS'] = UPLOAD_FOLDER_ITEMS

UPLOAD_FOLDER_DISHES = os.path.join("static", "dishes")
if not os.path.exists(UPLOAD_FOLDER_DISHES):
    os.makedirs(UPLOAD_FOLDER_DISHES)

app.config['UPLOAD_FOLDER_DISHES'] = UPLOAD_FOLDER_DISHES



# Helper function to check if the file is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


UNSPLASH_ACCESS_KEY = os.getenv("UNSPLASH_ACCESS_KEY") or x.UNSPLASH_ACCESS_KEY
UNSPLASH_API_URL = "https://api.unsplash.com/search/photos"


def download_image(image_url, save_path):
    """Downloads an image from the given URL and saves it locally."""
    try:
        img_data = requests.get(image_url).content
        with open(save_path, "wb") as handler:
            handler.write(img_data)
        ic(f"Downloaded: {save_path}")
    except Exception as e:
        ic(f"Failed to download {image_url}: {e}")

def save_image(file, upload_folder):
    
    try:
        if file and allowed_file(file.filename):
            unique_filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
            file_path = os.path.join(upload_folder, unique_filename)
            file.save(file_path)
            # Return the relative path for use in templates or database
            return os.path.relpath(file_path, "static")
        return None
    except Exception as ex:
        ic(f"Error saving image: {ex}")
        return None
    


# Function to check allowed file extensions
# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_image(file):
    if file and allowed_file(file.filename):
        unique_filename = f"{uuid.uuid4()}.{file.filename.rsplit('.', 1)[1].lower()}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        return f"uploads/{unique_filename}"
    return None

def sanitize_json(data):
    """
    Recursively sanitize data for JSON serialization.
    Replace None with empty string or other default values as needed.
    """
    if isinstance(data, dict):
        return {key: sanitize_json(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [sanitize_json(item) for item in data]
    elif data is None:
        return ""  # Replace None with empty string
    elif isinstance(data, (int, float, str, bool)):
        return data
    else:
        return str(data)  # Convert unsupported types to string


def send_notification(email, subject, message):
    try:
        # Use a library like smtplib or any email API
        x.send_email(email, subject, message)
        return True
    except Exception as e:
        ic(f"Failed to send notification: {e}")
        return False    


# Helpers for session and role checking
def is_logged_in():
    return session.get("user") is not None

def has_role(role):
    return role in session.get("user", {}).get("roles", [])

# def admin_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if not is_logged_in() or not has_role("admin"):
#             return redirect(url_for("view_login"))
#         return f(*args, **kwargs)
#     return decorated_function

def role_redirect():
    roles = session.get("user", {}).get("roles", [])
    if len(roles) > 1:
        return redirect(url_for("view_choose_role"))
    if roles:
        return redirect(url_for(f"view_{roles[0]}"))
    return redirect(url_for("view_login"))


def has_required_role(role):
    return role in session.get("user", {}).get("roles", [])

def get_user_roles():
    return session.get("user", {}).get("roles", [])

def fetch_paginated_results(query, params, page, items_per_page, cursor):
    offset = (page - 1) * items_per_page
    paginated_query = f"{query} LIMIT %s OFFSET %s"
    cursor.execute(paginated_query, (*params, items_per_page, offset))
    return cursor.fetchall()

def fetch_total_count(table_name, cursor):
    cursor.execute(f"SELECT COUNT(*) AS total_items FROM {table_name}")
    return cursor.fetchone()["total_items"]




# app.secret_key = "your_secret_key"

##############################
##############################
##############################

def _________GET_________(): pass

##############################
##############################
##############################


# @app.get('/fetch-images')
# def fetch_images():
#     """Fetches and downloads images from Unsplash."""
#     search_params = {
#         "query": "food dishes",
#         "per_page": 10,  # Number of images per request
#         "page": 1,       # Start page
#     }
#     headers = {"Authorization": f"Client-ID {UNSPLASH_ACCESS_KEY}"}

#     try:
#         response = requests.get(UNSPLASH_API_URL, headers=headers, params=search_params)
#         if response.status_code != 200:
#             return jsonify({"error": "Failed to fetch images", "status": response.status_code}), 500

#         images = response.json().get("results", [])
#         if not images:
#             return jsonify({"error": "No images found"}), 404
#         for idx, img in enumerate(images):
#             img_url = img["urls"]["regular"]
#             img_name = f"dish_{idx + 1}.jpg"
#             save_path = os.path.join(UPLOAD_FOLDER_AVATARS, img_name)
#             download_image(img_url, save_path)

#         return jsonify({"message": "Images fetched and saved successfully."})

#     except Exception as e:
#         ic(e)
#         return jsonify({"error": "An error occurred while fetching images"}), 500

##############################

# @app.get('/images')
# def list_images():
#     """Lists all downloaded images."""
#     try:
#         images = os.listdir(UPLOAD_FOLDER_AVATARS)
#         images = [url_for('static', filename=f'uploads/images/{img}') for img in images if img]
#         return render_template("image_gallery.html", images=images)
#     except Exception as e:
#         return jsonify({"error": "Failed to list images", "details": str(e)}), 500


##############################

# @app.get('/images/<path:filename>')
# def serve_image(filename):
#     """Serves individual images."""
#     return send_from_directory(UPLOAD_FOLDER_AVATARS, filename)



##############################
# @app.get("/test-set-redis")
# def view_test_set_redis():
#     redis_host = "redis"
#     redis_port = 6379
#     redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)    
#     redis_client.set("name", "Anders", ex=10)
#     # name = redis_client.get("name")
#     return "name saved"

# @app.get("/test-get-redis")
# def view_test_get_redis():
#     redis_host = "redis"
#     redis_port = 6379
#     redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)    
#     name = redis_client.get("name")
#     if not name: name = "no name"
#     return name

##############################


##############################
@app.get("/")
@x.no_cache
def view_index():
    user = session.get("user", {})
    restaurants = []

    # Determine the active role
    active_role = None
    if user:
        roles = user.get("roles", [])
        role_from_query = request.args.get("role")  # Get role from query parameter

        # Validate role from query
        if role_from_query and role_from_query not in roles:
            return redirect(url_for("view_choose_role"))

        # Set active role from query or default to current_role/session
        active_role = role_from_query or user.get("current_role")
        if not active_role and roles:
            active_role = roles[0]
            session["user"]["current_role"] = active_role
            session.modified = True

    else:
        # Fetch restaurants for the public landing page
        db, cursor = x.db()
        cursor.execute("""
            SELECT 
                restaurant_name, 
                restaurant_latitude, 
                restaurant_longitude 
            FROM restaurants
            WHERE restaurant_latitude IS NOT NULL AND restaurant_longitude IS NOT NULL
        """)
        restaurants = cursor.fetchall() or []
        cursor.close()
        db.close()

        # Clean up the restaurant data
        restaurants = [
            {
                "restaurant_name": restaurant["restaurant_name"] or "Unnamed Restaurant",
                "restaurant_latitude": str(restaurant["restaurant_latitude"]) if restaurant["restaurant_latitude"] else None,
                "restaurant_longitude": str(restaurant["restaurant_longitude"]) if restaurant["restaurant_longitude"] else None,
            }
            for restaurant in restaurants
        ]

    # Render the template with a single `role` parameter
    return render_template(
        "view_index.html",
        is_index=True,
        user=user,
        role=active_role,  # Pass the determined role once
        roles=user.get("roles", []),
        is_logged_in=bool(user),
        restaurants=restaurants
    )


##############################

@app.get("/forgot-password")
@x.no_cache
def show_forgot_password_form():

    restaurants = []
    return render_template("__forgot_password.html", x=x, restaurants=restaurants)

##############################

@app.get("/reset-password/<reset_key>")
@x.no_cache
def show_reset_password(reset_key):
    try:
        # Step 1: Validate the reset_key format
        reset_key = x.validate_uuid4(reset_key)

        # Step 2: Connect to the database
        db, cursor = x.db()

        # Step 3: Check if the reset_key exists and is not expired
        cursor.execute("""
            SELECT user_pk FROM users 
            WHERE reset_key = %s AND token_expiry > NOW()
        """, (reset_key,))
        user = cursor.fetchone()

        restaurants = []

        if not user:
            # If the key is invalid or expired, show an error message
            toast = render_template(
                "___toast.html", message="Invalid or expired reset key. Please try again."
            )
            return f"""
                    <template mix-target="#toast" mix-bottom>{toast}</template>
                    <template mix-redirect="/forgot-password"></template>
                    """, 400

        # Step 4: Render the reset password form
        return render_template("__reset_link.html", x=x, reset_key=reset_key, restaurants=restaurants)

    except Exception as ex:
        ic(f"Error in show_reset_password: {ex}")
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return f"""<template mix-target="#toast" mix-bottom>Database error occurred.</template>""", 500
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################

@app.get("/signup")
@x.no_cache
def view_signup():  
    if session.get("user"):
        if len(session.get("user").get("roles")) > 1:
            return redirect(url_for("view_choose_role")) 
        if "admin" in session.get("user").get("roles"):
            return redirect(url_for("view_admin"))
        if "customer" in session.get("user").get("roles"):
            return redirect(url_for("view_customer")) 
        if "partner" in session.get("user").get("roles"):
            return redirect(url_for("view_partner"))         
        if "restaurant" in session.get("user").get("roles"):
            return redirect(url_for("view_restaurant"))         
    db, cursor = x.db()
    cursor.execute("SELECT role_pk, role_name FROM roles")
    roles = cursor.fetchall()
    cursor.close()
    db.close()

    return render_template(
    "view_signup.html", 
    roles=roles, 
    x=x, 
    title="Signup", 
    restaurants=[]  # Ensure restaurants is always defined
)

##############################
@app.get("/login")
@x.no_cache
def view_login():
    user = session.get("user")
    if user:
        # User is already logged in, so redirect them based on their role
        roles = user.get("roles", [])
        current_role = user.get("current_role")

        # Redirect to the appropriate role-specific page
        role_routes = {
            "admin": "view_admin",
            "customer": "view_customer",
            "partner": "view_partner",
            "restaurant": "view_restaurant",
        }
        if roles and current_role in role_routes:
            return redirect(url_for(role_routes[current_role]))

        return redirect(url_for("view_choose_role"))  # If role is invalid, ask the user to choose

    # Render login page for unauthenticated users
    return render_template(
        "view_login.html",
        x=x,
        title="Login",
        user=None,
        restaurants=[],
        message=request.args.get("message", "")
    )



##############################
@app.get("/customer")
@x.no_cache
def view_customer():
    user = session.get("user")
    if not user:
        return redirect(url_for("view_login"))
    
    roles = user.get("roles", [])
    current_role = user.get("current_role")

    # Validate current_role
    if not current_role or current_role != "customer":
        # Redirect to role selection if invalid role
        if "customer" in roles:
            current_role = "customer"
            session["user"]["current_role"] = current_role
            session.modified = True
        else:
            return redirect(url_for("view_choose_role"))

    # Ensure `restaurants` is defined
    restaurants = []

    return render_template(
        "view_index.html",
        user=user,
        role=current_role,
        restaurants=restaurants  # Pass an empty list
    )

##############################
@app.get("/partner")
@x.no_cache
def view_partner():
    # Ensure the user is logged in
    user = session.get("user")
    if not user:
        ic("User is not logged in. Redirecting to login.")
        return redirect(url_for("view_login"))
    else:
        ic(f"User session data: {user}")

    roles = user.get("roles", [])
    current_role = user.get("current_role")

    # Validate roles and current_role
    if "partner" not in roles:
        return redirect(url_for("view_login"))  # Redirect if user does not have 'partner' role

    if not current_role or current_role != "partner":
        # Assign 'partner' as the current role if valid
        if "partner" in roles:
            current_role = "partner"
            session["user"]["current_role"] = current_role
            session.modified = True
        else:
            return redirect(url_for("view_choose_role"))

    # Ensure restaurants is always a valid list
    restaurants = []

    # Rendering the partner-specific dashboard
    return render_template(
        "view_index.html",
        role=current_role,
        user=user,
        restaurants=restaurants,  # Pass an empty list if no restaurants are found
        is_logged_in=True  # Set is_logged_in to True
    )

##############################
@app.get("/restaurant")
@x.no_cache
def view_restaurant():
    user = session.get("user")
    if not user:
        return redirect(url_for("view_login"))

    roles = user.get("roles", [])
    current_role = user.get("current_role")

    # Validate or assign the current role
    if not current_role or current_role != "restaurant":
        if "restaurant" in roles:
            current_role = "restaurant"
            session["user"]["current_role"] = current_role
            session.modified = True
        else:
            return redirect(url_for("view_choose_role"))

    try:
        db, cursor = x.db()

        # Fetch restaurant-specific data
        cursor.execute("""
            SELECT * FROM restaurants WHERE restaurant_user_fk = %s
        """, (user["user_pk"],))
        restaurant_data = cursor.fetchone()

        # Debugging log
        ic(f"Current role: {current_role}, Restaurant data: {restaurant_data}")

        if not restaurant_data:
            # Handle case when no restaurant is found
            return render_template(
                "view_index.html",
                user=user,
                role=current_role,
                restaurant=None,
                message="No restaurant data found."
            )

        return render_template(
            "view_index.html",
            user=user,
            role=current_role,
            restaurant=restaurant_data
        )
    except Exception as ex:
        ic(f"Error loading restaurant page: {ex}")
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return f"""<template mix-target="#toast" mix-bottom>Database error occurred.</template>""", 500
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()


##############################

@app.get("/admin")
@x.no_cache
def view_admin():
    if not session.get("user", ""): 
        return redirect(url_for("view_login"))
    
    user = session.get("user")
    if not "admin" in user.get("roles", ""):
        return redirect(url_for("view_login"))
    
    try:
        db, cursor = x.db()

        # Fetch all users
        cursor.execute("""
            SELECT 
                u.user_pk, 
                u.user_name, 
                u.user_last_name, 
                u.user_avatar,
                u.user_email,
                u.user_blocked_at
            FROM users u
            LEFT JOIN users_roles ur ON u.user_pk = ur.user_role_user_fk
            LEFT JOIN roles r ON ur.user_role_role_fk = r.role_pk
            WHERE r.role_name != 'admin' OR r.role_name IS NULL
        """)
        users = cursor.fetchall()

        # Fetch total counts
        cursor.execute("SELECT COUNT(*) AS total_users FROM users")
        total_users = cursor.fetchone()["total_users"]

        # Fetch total items
        cursor.execute("SELECT COUNT(*) AS total_items FROM items")
        total_items = cursor.fetchone()["total_items"]

        # Fetch role counts in a single query
        cursor.execute("""
            SELECT 
                r.role_name, 
                COUNT(DISTINCT u.user_pk) AS total
            FROM users u
            JOIN users_roles ur ON u.user_pk = ur.user_role_user_fk
            JOIN roles r ON ur.user_role_role_fk = r.role_pk
            GROUP BY r.role_name
        """)
        role_counts = cursor.fetchall()
        role_summary = {row["role_name"]: row["total"] for row in role_counts}

        total_restaurants = role_summary.get("restaurant", 0)
        total_partners = role_summary.get("partner", 0)
        total_customers = role_summary.get("customer", 0)

        # Fetch all items
        cursor.execute("""
            SELECT 
                i.item_pk, 
                i.item_title, 
                i.item_price, 
                i.item_image, 
                i.item_user_fk, 
                i.item_blocked_at,
                u.user_name,
                u.user_last_name,
                u.user_email
            FROM items i
            LEFT JOIN users u ON i.item_user_fk = u.user_pk
        """)
        items = cursor.fetchall()

        # Add the role explicitly
        role = "admin"

        # Render the admin dashboard
        return render_template(
            "view_admin.html", 
            x=x, 
            user=user, 
            role=role,  # Pass the role to the template
            users=users, 
            items=items, 
            total_users=total_users,
            total_restaurants=total_restaurants,
            total_partners=total_partners,
            total_customers=total_customers,
            total_items=total_items,
            restaurants = []
        )
    except Exception as ex:
        ic(f"Error in view_admin: {ex}")
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error occurred</template>", 500
        return "<template>System under maintenance</template>", 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()
##############################

@app.get("/admin/users")
@x.no_cache
def view_edit_users():
    try:
        db, cursor = x.db()
        
        # Get the search query from the request
        query = request.args.get("query", "").strip()

        # Fetch users based on the query
        if query:
            cursor.execute("""
                SELECT 
                    u.user_pk, 
                    u.user_name, 
                    u.user_last_name, 
                    u.user_avatar, 
                    u.user_email, 
                    u.user_blocked_at, 
                    u.user_deleted_at,  
                    r.restaurant_name
                FROM users u
                LEFT JOIN restaurants r ON u.user_pk = r.restaurant_user_fk
                WHERE 
                    u.user_name LIKE %s OR 
                    u.user_last_name LIKE %s OR 
                    u.user_email LIKE %s
            """, (f"%{query}%", f"%{query}%", f"%{query}%"))
        else:
            # Fetch all users without a search query
            cursor.execute("""
                SELECT 
                    u.user_pk, 
                    u.user_name, 
                    u.user_last_name, 
                    u.user_avatar, 
                    u.user_email, 
                    u.user_blocked_at, 
                    u.user_deleted_at,  
                    r.restaurant_name
                FROM users u
                LEFT JOIN restaurants r ON u.user_pk = r.restaurant_user_fk
            """)
        
        users = cursor.fetchall()

        # Ensure all fields are defined and not None
        for user in users:
            user["user_pk"] = user.get("user_pk", "")
            user["user_name"] = user.get("user_name", "Unknown")
            user["user_last_name"] = user.get("user_last_name", "")
            user["user_avatar"] = user.get("user_avatar", "default.jpg")
            user["user_email"] = user.get("user_email", "no-email@example.com")
            user["user_blocked_at"] = user.get("user_blocked_at", None)
            user["restaurant_name"] = user.get("restaurant_name", "No Restaurant")

        return render_template(
            "__edit_user.html",
            x=x,
            users=users,
            restaurants=[],
            query=query  # Pass the query back to the template
        )
    except Exception as ex:
        ic(f"Error in view_edit_users: {ex}")
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error occurred.</template>", 500
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500
    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################



@app.get("/admin/items")
@x.no_cache
def view_edit_items():
    try:
        # Pagination parameters
        items_per_page = 8
        current_page = int(request.args.get("page", 1))
        offset = (current_page - 1) * items_per_page

        db, cursor = x.db()

        # Fetch items with LIMIT and OFFSET
        cursor.execute("""
            SELECT 
                i.item_pk, 
                i.item_title, 
                i.item_price, 
                i.item_image, 
                u.user_name AS user_name, 
                u.user_last_name AS user_last_name, 
                u.user_email AS user_email, 
                r.restaurant_name AS restaurant_name,  -- Get the restaurant name
                i.item_blocked_at
            FROM items i
            LEFT JOIN users u ON i.item_user_fk = u.user_pk
            LEFT JOIN restaurants r ON u.user_pk = r.restaurant_user_fk 
            LIMIT %s OFFSET %s
        """, (items_per_page, offset))
        items = cursor.fetchall()

        # Calculate total items for pagination
        cursor.execute("SELECT COUNT(*) AS total_items FROM items")
        total_items = cursor.fetchone()["total_items"]
        total_pages = (total_items + items_per_page - 1) // items_per_page
        has_more = current_page < total_pages

        # Prepare new button or empty if no more pages
        next_page = current_page + 1 if has_more else 0
        new_button = render_template("___btn_get_more_items.html", next_page=next_page) if has_more else ""

        return render_template(
            "__edit_items.html",
            x=x,
            items=items or [],  # Ensure items is never None
            next_page=next_page,
            new_button=new_button or "",
            restaurants=[]
        )
    except Exception as ex:
        ic(f"Error in view_edit_items: {ex}")
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error occurred.</template>", 500
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()


##############################
@app.get("/admin/items/page/<int:page>")
@x.no_cache
def get_more_items(page):
    try:
        items_per_page = 10
        offset = (page - 1) * items_per_page

        db, cursor = x.db()

        # Fetch items for the specific page
        cursor.execute("""
            SELECT 
                i.item_pk, 
                i.item_title, 
                i.item_price, 
                i.item_image, 
                u.user_name AS user_name, 
                u.user_last_name AS user_last_name, 
                u.user_email AS user_email, 
                i.item_blocked_at
            FROM items i
            LEFT JOIN users u ON i.item_user_fk = u.user_pk
            LIMIT %s OFFSET %s
        """, (items_per_page, offset))
        items = cursor.fetchall()

        html = ""
        for item in items:
            html_item = render_template("__edit_items_item_card.html", item=item)
            html += html_item
        ic(html)

        new_button = render_template("___btn_get_more_items.html", next_page=page + 1)

        return f"""
        <template mix-target="#items" mix-bottom>
            {html}
        </template>
        <template mix-target="#btn_next_page" mix-replace>
            {new_button}
        </template>
        """
    except Exception as ex:
        ic("Error in get_more_items:", ex)
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error occurred.</template>", 500
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################
@app.get("/profile")
@x.no_cache
def view_profile():
    user = session.get("user")
    if not user:
        return redirect(url_for("view_login"))

    # Get the current role from the session
    current_role = user.get("current_role")
    if not current_role:
        return redirect(url_for("view_choose_role"))

    restaurant = None
    restaurants = []  # Initialize as an empty list
    if current_role == "restaurant":
        try:
            db, cursor = x.db()
            # Fetch the first restaurant associated with the user
            cursor.execute("""
                SELECT restaurant_pk, restaurant_name 
                FROM restaurants 
                WHERE restaurant_user_fk = %s
            """, (user["user_pk"],))
            restaurant_row = cursor.fetchone()
            if restaurant_row:
                restaurant = {
                    "restaurant_pk": restaurant_row[0],
                    "restaurant_name": restaurant_row[1],
                }
                restaurants.append(restaurant)  # Add to the list for JSON rendering
        except Exception as ex:
            ic(f"Error fetching restaurant: {ex}")
        finally:
            if "cursor" in locals():
                cursor.close()
            if "db" in locals():
                db.close()

    return render_template(
        "view_profile.html",
        user=user,
        role=current_role,
        restaurant=restaurant,  # Pass the single restaurant dictionary
        restaurants=restaurants,  # Pass as a list for JSON rendering
    ), 200


##############################
@app.get("/profile/settings")
@x.no_cache
def view_profile_settings():
    try:
        user = session.get("user")
        if not user:
            return redirect(url_for("view_login"))

        # Ensure avatar exists
        if not user.get("user_avatar"):
            user["user_avatar"] = "profile_100.jpg"

        # Fetch roles and determine the current role
        roles = user.get("roles", [])
        user_role = user.get("current_role")

        # Ensure the current role is valid
        if user_role not in roles and roles:
            user_role = roles[0]  # Default to the first role if `current_role` is invalid or missing

        # Redirect to role selection if no valid role exists
        if not user_role:
            return redirect(url_for("view_choose_role"))

        # Fetch restaurant data for the logged-in user
        db, cursor = x.db()
        cursor.execute("SELECT * FROM restaurants WHERE restaurant_user_fk = %s", (user["user_pk"],))
        restaurant = cursor.fetchone()

        if restaurant:
            # Add restaurant details to the user object
            user["restaurant_name"] = restaurant["restaurant_name"]
            user["street_name"] = restaurant.get("restaurant_address", "").split(",")[0].split(" ")[1]
            user["street_number"] = restaurant.get("restaurant_address", "").split(",")[0].split(" ")[0]
            user["city"] = restaurant.get("restaurant_address", "").split(",")[1].strip().split(" ")[1]
            user["postnummer"] = restaurant.get("restaurant_address", "").split(",")[1].strip().split(" ")[0]

        # Pass all data to the template
        return render_template(
            "__profile_settings.html",
            x=x,
            user=user,
            role=user_role,
            restaurants=[restaurant] if restaurant else [],
        ), 200
    except Exception as ex:
        ic(f"Error in /profile/settings: {ex}")
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error occurred.</template>", 500
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################
@app.get("/choose-role")
@x.no_cache
def view_choose_role():
    user = session.get("user")
    
    # Redirect to login if the user is not logged in
    if not user:
        return redirect(url_for("view_login"))
    
    roles = user.get("roles", [])
    # Redirect to login if the user doesn't have multiple roles
    if len(user.get("roles", [])) < 2:
        return redirect(url_for("view_login"))


    # Render the template with the user, title, and restaurants
    return render_template(
        "view_choose_role.html", 
        user=user, 
        title="Choose Role", 
        x=x, 
        roles=roles,
        restaurants=[]
    )


##############################
##############################

@app.get("/select-role/<role>")
@x.no_cache
def select_role(role):
    user = session.get("user")
    if not user or "roles" not in user or role not in user["roles"]:
        return redirect(url_for("view_choose_role"))
    
    session["user"]["current_role"] = role
    session.modified = True 

    # Map roles to the correct route names
    role_routes = {
        "restaurant": "view_restaurant",
        "partner": "view_partner",
        "customer": "view_customer",
        "admin": "view_admin",
    }
 # Pass the role down to the target route
    if role in role_routes:
        return redirect(url_for("view_index", role=role))

    # Handle unknown roles gracefully
    return redirect(url_for("view_index"))

##############################


##############################
@app.get("/restaurants")
@x.no_cache
def view_restaurants():
    query = request.args.get("query", "").strip()
    db, cursor = x.db()
    user = session.get("user")
    restaurants = []

    try:
        if user and "restaurant" in user.get("roles", []):
            # Fetch only the restaurants owned by the logged-in user
            cursor.execute("""
                SELECT 
                    r.restaurant_pk, 
                    r.restaurant_name, 
                    r.restaurant_address, 
                    r.restaurant_latitude, 
                    r.restaurant_longitude
                FROM restaurants r
                WHERE r.restaurant_user_fk = %s
            """, (user["user_pk"],))
            restaurants = cursor.fetchall()
            if not restaurants:
                return render_template(
                    "view_index.html",
                    message="No associated restaurants found.",
                    restaurants=[],
                )
            return render_template("view_menu_management.html", restaurants=restaurants)

        if query:
            sql = f"""
                SELECT 
                    r.restaurant_pk, 
                    r.restaurant_name, 
                    r.restaurant_address, 
                    r.restaurant_latitude, 
                    r.restaurant_longitude,
                    i.item_title,
                    i.item_price,
                    i.item_image,
                    i.item_cuisine_type,
                    i.item_food_category
                FROM restaurants r
                LEFT JOIN items i ON r.restaurant_pk = i.item_user_fk
                WHERE 
                    MATCH(r.restaurant_name) AGAINST (%s IN NATURAL LANGUAGE MODE)
                    OR MATCH(i.item_title, i.item_cuisine_type, i.item_food_category) AGAINST (%s IN NATURAL LANGUAGE MODE)
            """
            cursor.execute(sql, (query, query))
            results = cursor.fetchall()

            # Group results by restaurant
            restaurants_dict = {}
            for row in results:
                restaurant_id = row["restaurant_pk"]
                if restaurant_id not in restaurants_dict:
                    restaurants_dict[restaurant_id] = {
                        "restaurant_name": row["restaurant_name"],
                        "restaurant_address": row["restaurant_address"],
                        "restaurant_latitude": row["restaurant_latitude"],
                        "restaurant_longitude": row["restaurant_longitude"],
                        "items": []
                    }
                if row["item_title"]:
                    restaurants_dict[restaurant_id]["items"].append({
                        "item_title": row["item_title"],
                        "item_price": row["item_price"],
                        "item_image": row["item_image"],
                        "item_cuisine_type": row["item_cuisine_type"],
                        "item_food_category": row["item_food_category"],
                    })

            restaurants = list(restaurants_dict.values())

        return render_template("view_index.html", restaurants=restaurants, query=query)
    except Exception as ex:
                ic(ex)
                if "db" in locals(): db.rollback()
                # My own exception
                if isinstance(ex, x.CustomException):
                    return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
                # Database exception
                if isinstance(ex, x.mysql.connector.Error):
                    ic(ex)
                    if "users.user_email" in str(ex):
                        return """<template mix-target="#toast" mix-bottom>Restaurants not available</template>""", 400
                    return "<template>System upgrading</template>", 500  
                # Any other exception
                return """<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500  
    finally:
                if "cursor" in locals(): cursor.close()
                if "db" in locals(): db.close()

##############################
# @app.get("/restaurant/manage")
# @x.no_cache
# def view_manage_restaurant():
#     db, cursor = x.db()
#     user = session.get("user")
#     restaurants = []

#     try:
#         if not user or "restaurant" not in user.get("roles", []):
#             return redirect(url_for("view_login"))  # Redirect if not logged in as a restaurant user

#         # Fetch restaurants for the logged-in user
#         cursor.execute("""
#             SELECT restaurant_pk, restaurant_name 
#             FROM restaurants 
#             WHERE restaurant_user_fk = %s
#         """, (user["user_pk"],))
#         restaurants = cursor.fetchall()

#         if not restaurants:  # No associated restaurants found
#             return render_template(
#                 "view_menu_management.html",
#                 message="No associated restaurants found.",
#                 restaurants=[],
#             )

#         # Map results to a list of dictionaries
#         restaurants = [
#             {"restaurant_pk": row[0], "restaurant_name": row[1]}
#             for row in restaurants
#         ]

#         # Render template with restaurant data
#         return render_template(
#             "view_menu_management.html",
#             restaurants=restaurants
#         )

#     except Exception as ex:
#         ic(f"Error fetching restaurants: {ex}")
#         return "<h1>System under maintenance</h1>", 500

#     finally:
#         if "cursor" in locals():
#             cursor.close()
#         if "db" in locals():
#             db.close()

##############################


##############################
@app.get("/items/<item_pk>/edit")
@x.no_cache
def view_item_edit_page(item_pk):
    try:
        # Validate item_pk
        item_pk = x.validate_uuid4(item_pk)
        db, cursor = x.db()
        # Ensure user session exists
        user = session.get("user")
        if not user:
            return redirect(url_for("view_login"))
        
        # Extract user_pk and role from the session
        user_pk = user.get("user_pk")
        role = user.get("current_role", "guest") 
        
        # Fetch the item's details
        cursor.execute("""
            SELECT 
                item_pk, 
                item_title, 
                item_price, 
                item_image, 
                item_cuisine_type, 
                item_food_category 
            FROM items 
            WHERE item_pk = %s
        """, (item_pk,))
        item = cursor.fetchone()

        if not item:
            raise ValueError(f"Item with ID {item_pk} not found")
        item['item_price'] = float(item['item_price'])
        
        ic("Fetched Item:", item)
        
        return render_template("__manage_item.html", item=item, role=role,  restaurants=[] )
    except Exception as ex:
        # Handle exceptions and rollback database changes
        ic("Error in view_item_edit_page:", ex)
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        elif isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error occurred.</template>", 500
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500

    finally:
        # Ensure resources are properly closed
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################
@app.get("/manage/items")
@x.no_cache
def view_manage_items():
    try:
        # Ensure user session exists
        user = session.get("user")
        if not user:
            return redirect(url_for("view_login"))

        # Extract user_pk and role from the session
        user_pk = user.get("user_pk")
        role = user.get("current_role", "guest")  # Default to "guest" if role is missing
        if not user_pk:
            return redirect(url_for("view_login"))  # Redirect if no user_pk is found

        # Validate user_pk using x.validate_uuid4
        user_pk = x.validate_uuid4(user_pk)

        # Query items and their additional images, including restaurant_fk
        db, cursor = x.db()
        cursor.execute("""
            SELECT 
                i.item_pk, 
                i.item_title, 
                i.item_price, 
                i.item_image,
                r.restaurant_pk
            FROM items i
            LEFT JOIN restaurants r ON i.item_user_fk = r.restaurant_user_fk
            WHERE i.item_user_fk = %s
        """, (user_pk,))
        items = cursor.fetchall()

        for item in items:
            # Resolve the main image path
            item["item_image_path"] = f"dishes/{item['item_image']}" if item["item_image"] else None

            # Fetch additional images uploaded by the user for the item
            cursor.execute("""
                SELECT image_path 
                FROM item_images 
                WHERE item_fk = %s
            """, (item["item_pk"],))
            additional_images = [row["image_path"] for row in cursor.fetchall()]

            # Ensure correct paths for additional images
            item["additional_images"] = [
                f"{image}" for image in additional_images if image.startswith("uploads/items/")
            ]

            # Debug to confirm additional images
            ic(f"Item PK: {item['item_pk']}, Additional Images: {item['additional_images']}")

        # Count items for display
        item_count = len(items)

        # Render template with fetched items and item count
        return render_template(
            "__menu_management.html",
            user=user,
            role=role,  # Pass the role to the template
            items=items,
            item_count=item_count,  # Pass the item count
            restaurants=[]  # Placeholder if needed
        )

    except Exception as ex:
        # Handle general exceptions
        ic("Error in view_manage_items:", ex)
        toast = render_template("___toast.html", message="An error occurred while loading items.")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 500

    finally:
        # Ensure resources are properly closed
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################
@app.get("/add_restaurant")
@x.no_cache
def add_restaurant():
    try:
        user = session.get("user")
        if not user:
            return redirect(url_for("view_login"))

        # Only allow users with the 'restaurant' role to access this page
        if "restaurant" not in user.get("roles", []):
            return "<h1>You are not allowed to create a restaurant.</h1>", 403

        # Fetch restaurants linked to the user
        db, cursor = x.db()
        cursor.execute("SELECT * FROM restaurants WHERE restaurant_user_fk = %s", (user["user_pk"],))
        restaurants = cursor.fetchall()  # Returns a list of dictionaries

        # Pass restaurants or default to an empty list
        return render_template("__create_restaurant.html", user=user, x=x, restaurants=restaurants or [])

    except Exception as ex:
        # Handle exceptions gracefully
        ic(f"Error in add_restaurant: {ex}")
        toast = render_template("___toast.html", message="System under maintenance.")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 500

    finally:
        # Ensure resources are properly closed
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################
@app.get("/search")
@x.no_cache
def view_search():
    try:
        query = request.args.get("query", "").strip()
        if not query:
            return redirect(url_for("view_index"))

        db, cursor = x.db()

        # Search restaurants using LIKE
        cursor.execute(
            """
            SELECT DISTINCT
                restaurant_pk, 
                restaurant_name, 
                restaurant_address, 
                restaurant_latitude, 
                restaurant_longitude 
            FROM restaurants 
            WHERE 
                restaurant_name LIKE %s OR 
                restaurant_item_title LIKE %s OR 
                restaurant_item_cuisine_type LIKE %s OR 
                restaurant_item_food_category LIKE %s
            """, (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%")
        )
        restaurant_results = cursor.fetchall()

        # Search items using LIKE and fetch associated restaurant details
        cursor.execute(
            """
            SELECT DISTINCT
                i.item_pk, 
                i.item_title, 
                i.item_price, 
                i.item_image, 
                r.restaurant_pk, 
                r.restaurant_name, 
                r.restaurant_address, 
                r.restaurant_latitude, 
                r.restaurant_longitude 
            FROM items i
            INNER JOIN restaurants r ON i.item_user_fk = r.restaurant_user_fk
            WHERE 
                i.item_title LIKE %s OR 
                i.item_cuisine_type LIKE %s OR 
                i.item_food_category LIKE %s
            """, (f"%{query}%", f"%{query}%", f"%{query}%")
        )
        item_results = cursor.fetchall()

        # Deduplicate restaurants
        restaurant_set = {
            r.get("restaurant_pk"): r
            for r in restaurant_results
            if r.get("restaurant_pk")  # Ensure no `None` keys
        }
        for item in item_results:
            restaurant_pk = item.get("restaurant_pk")
            if restaurant_pk:
                restaurant_set[restaurant_pk] = {
                    "restaurant_pk": restaurant_pk,
                    "restaurant_name": item.get("restaurant_name", "Unknown"),
                    "restaurant_address": item.get("restaurant_address", ""),
                    "restaurant_latitude": item.get("restaurant_latitude"),
                    "restaurant_longitude": item.get("restaurant_longitude"),
                }
        restaurants = list(restaurant_set.values())

        # Process items
        items = [
            {
                "item_pk": item["item_pk"],
                "item_title": item["item_title"],
                "item_price": item["item_price"],
                "item_image": item["item_image"],
                "restaurant_name": item["restaurant_name"],
            }
            for item in item_results
        ]

        # Check if the request is an XMLHttpRequest (AJAX)
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"restaurants": restaurants, "items": items})

        # Render the template for regular page load
        return render_template(
            "view_index.html",
            query=query,
            restaurants=restaurants,
            items=items,
            is_logged_in=session.get("user") is not None,
            user=session.get("user"),
            role=session.get("user", {}).get("current_role"),
            x=x
        )

    except Exception as ex:
        ic("Error in view_search:", ex)
        if "db" in locals():
            db.rollback()
        # Handle exceptions as per your existing logic
        if isinstance(ex, x.CustomException):
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>System upgrading</template>", 500  
        return """<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500  
    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################
@app.get("/restaurant/<restaurant_pk>")
@x.no_cache
def view_menu(restaurant_pk):
    try:
        # Get the search query from the URL parameters
        query = request.args.get("query", "").strip()
        cuisine_filter = request.args.get("cuisine", None)
        db, cursor = x.db()

        # Fetch restaurant details
        cursor.execute(
            """
            SELECT 
                restaurant_pk, 
                restaurant_name, 
                restaurant_address, 
                restaurant_item_cuisine_type 
            FROM restaurants
            WHERE restaurant_pk = %s
            """,
            (restaurant_pk,)
        )
        restaurant = cursor.fetchone()

        if not restaurant:
            ic(f"Restaurant not found for restaurant_pk: {restaurant_pk}")
            return "Restaurant not found", 404

        restaurant_data = {
            "restaurant_pk": restaurant.get("restaurant_pk", "N/A"),
            "restaurant_name": restaurant.get("restaurant_name", "Unknown"),
            "restaurant_address": restaurant.get("restaurant_address", "No Address"),
            "restaurant_item_cuisine_type": restaurant.get("restaurant_item_cuisine_type", "Unknown Cuisine"),
        }

        # Fetch menu items for the restaurant
        query = """
            SELECT 
                item_pk, 
                item_title, 
                item_price, 
                item_cuisine_type, 
                item_image
            FROM items
            WHERE item_user_fk = (
                SELECT restaurant_user_fk 
                FROM restaurants 
                WHERE restaurant_pk = %s
            )
        """
        params = [restaurant_pk]

        # Add cuisine filter if provided
        if cuisine_filter:
            query += " AND item_cuisine_type = %s"
            params.append(cuisine_filter)

        cursor.execute(query, tuple(params))
        items = cursor.fetchall()

        menu_items = [
            {
                "item_pk": item.get("item_pk", "N/A"),
                "item_title": item.get("item_title", "Unnamed Item"),
                "item_price": float(item.get("item_price") or 0.0),  # Default to 0.0
                "item_cuisine_type": item.get("item_cuisine_type", "Unknown"),
                "item_image": item["item_image"],
            }
            for item in items
        ]
            # Fetch unique cuisine types for filtering buttons
        cursor.execute(
            """
            SELECT DISTINCT item_cuisine_type
            FROM items
            WHERE item_user_fk = (
                SELECT restaurant_user_fk 
                FROM restaurants 
                WHERE restaurant_pk = %s
            )
            """,
            (restaurant_pk,)
        )
        cuisine_types = [row["item_cuisine_type"] for row in cursor.fetchall()]
        # Render the __view_menu.html template
        return render_template(
            "__view_menu.html",
            restaurant=restaurant_data,
            menu_items=menu_items,
            restaurants=[],  # Pass an empty list if `restaurants` is not used in this context
            cuisine_types=cuisine_types, 
            query=query  
        )

    except Exception as ex:
        ic(ex)
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>System upgrading</template>", 500        
        return "<template>System under maintenance</template>", 500  
    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()


##############################
# @app.get("/manage/menu/<item_pk>/images")
# @x.no_cache
# def view_add_item_images(item_pk):
#     try:
#         db, cursor = x.db()
#         cursor.execute(
#             """
#             SELECT item_title FROM items WHERE item_pk = %s
#             """,
#             (item_pk,),
#         )
#         item = cursor.fetchone()

#         cursor.execute(
#             """
#             SELECT image_path FROM item_images WHERE item_fk = %s
#             """,
#             (item_pk,),
#         )
#         images = cursor.fetchall()

#         return render_template("manage_images.html", item_title=item[0], item_pk=item_pk, images=images)

#     except Exception as ex:
#         ic(ex)
#         if "db" in locals():
#             db.rollback()
#         if isinstance(ex, x.CustomException):
#             toast = render_template("___toast.html", message=ex.message)
#             return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
#         if isinstance(ex, x.mysql.connector.Error):
#             ic(ex)
#             return "<template>System upgrading</template>", 500        
#         return "<template>System under maintenance</template>", 500  

#     finally:
#         if "cursor" in locals():
#             cursor.close()
#         if "db" in locals():
#             db.close()

##############################
##############################
##############################

def _________POST_________(): pass

##############################
##############################
##############################


##############################
@app.post('/manage/items/add-item')
@x.no_cache
def add_item():
    try:
        user_session = session.get("user", {})
        ic(user_session)  # Log the session to debug issues

        # Ensure the user is logged in and has the 'restaurant' role
        if not user_session or "restaurant" not in user_session.get("roles", []):
            return "Unauthorized action or role mismatch.", 403

        # Retrieve the correct user_pk for the logged-in restaurant
        user_pk = user_session.get("user_pk")
        if not user_pk:
            return "Unable to determine user. Please log in again.", 400
        
        db, cursor = x.db()
        cursor.execute("SELECT COUNT(*) AS count FROM users WHERE user_pk = %s", (user_pk,))
        result = cursor.fetchone()

        if not result or result["count"] == 0:
            return f"User with ID {user_pk} does not exist in the database.", 400

        # Retrieve form data
        item_title = request.form.get("item_title")
        item_price = request.form.get("item_price", type=float)
        item_cuisine_type = request.form.get("item_cuisine_type")
        item_food_category = request.form.get("item_food_category")
        item_created_at = int(time.time())  # Unix timestamp for creation time

        # Retrieve the image from the form
        item_image = request.files.get("item_image")

        # Check if the price exceeds the maximum allowed value
        if item_price > 999.99:
            toast = render_template("___toast.html", message="Price can only be a maximum of 999.99.")
            return f"""<template mix-target="#toast">{toast}</template>""", 400

        # Validate form fields (ensure all are provided)
        if not all([item_title, item_price, item_cuisine_type, item_food_category, item_image]):
            return "All fields are required, including the image.", 400

        # Validate the price
        try:
            if item_price <= 0:
                raise ValueError("Price must be a positive number.")
        except ValueError:
            return "Invalid price. Must be a positive number.", 400

        # Save the image to the 'dishes' folder
        if item_image:
            # Generate a unique filename
            filename = f"{uuid.uuid4().hex}_{secure_filename(item_image.filename)}"
            item_image.save(os.path.join(app.config['UPLOAD_FOLDER_DISHES'], filename))

        # Generate a unique item ID
        item_pk = str(uuid.uuid4())  # Generate a unique item ID

        # Insert item into the database with just the filename (not full path)
        cursor.execute("""
            INSERT INTO items (item_pk, item_title, item_price, item_user_fk, item_cuisine_type, item_food_category, item_created_at, item_image)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (item_pk, item_title, item_price, user_pk, item_cuisine_type, item_food_category, item_created_at, filename))
        db.commit()

        # Debugging: print the items to see if the new item was added
        ic("Item added successfully:", item_title)

        # Success toast message
        toast = render_template("___toast_success.html", message="Item has been added successfully.")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>
                   <template mix-redirect>{url_for("view_manage_items")}</template>""", 201

    except Exception as ex:
        ic(ex)
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast_error.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return f"""<template mix-target="#toast" mix-bottom>Database error occurred.</template>""", 500
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################
@app.post("/items/<item_pk>/update")
@x.no_cache
def update_item_details(item_pk):
    try:
        data = request.form  # Retrieve the form data
        files = request.files  # Retrieve uploaded files
        db, cursor = x.db()

         # Handle the main item_image upload
        main_image = files.get("item_image")  # Main item image
        main_image_filename = None
        if main_image and allowed_file(main_image.filename):  # Check file validity
            # Generate a UUID4 filename
            main_image_filename = f"{uuid.uuid4()}.{main_image.filename.rsplit('.', 1)[1].lower()}"
            main_upload_folder = os.path.join("static", "dishes")
            os.makedirs(main_upload_folder, exist_ok=True)  # Ensure directory exists
            main_filepath = os.path.join(main_upload_folder, main_image_filename)
            main_image.save(main_filepath)

        # Update the item details in the database
        cursor.execute("""
            UPDATE items
            SET item_title = %s, 
                item_price = %s, 
                item_cuisine_type = %s, 
                item_food_category = %s,
                item_image = COALESCE(%s, item_image)
            WHERE item_pk = %s
        """, (
            data.get("item_title"),
            data.get("item_price"),
            data.get("item_cuisine_type"),
            data.get("item_food_category"),
            main_image_filename,  # New image filename or None
            item_pk
        ))

        # Fetch restaurant_fk using the item_pk
        cursor.execute("""
            SELECT r.restaurant_pk
            FROM restaurants r
            INNER JOIN items i ON i.item_user_fk = r.restaurant_user_fk
            WHERE i.item_pk = %s
        """, (item_pk,))
        restaurant_fk_row = cursor.fetchone()

        if not restaurant_fk_row:
            raise ValueError("Restaurant not found for the given item.")
        
        restaurant_fk = restaurant_fk_row["restaurant_pk"]

        # Handle image uploads
        uploaded_images = []
        upload_folder = os.path.join("static", "uploads", "items")
        os.makedirs(upload_folder, exist_ok=True)  # Ensure directory exists

        for key in files:
            if key.startswith("item_image_"):  # Ensure it's one of the image inputs
                additional_image = files[key]
                if additional_image and allowed_file(additional_image.filename):  # Check file validity
                    # Generate a UUID4 filename
                    unique_filename = f"{uuid.uuid4()}.{additional_image.filename.rsplit('.', 1)[1].lower()}"
                    filepath = os.path.join(upload_folder, unique_filename)
                    additional_image.save(filepath)

                    # Insert the UUID4 filename into the database
                    cursor.execute("""
                        INSERT INTO item_images (image_pk, item_fk, image_path, restaurant_fk, created_at)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        str(uuid.uuid4()), 
                        item_pk, 
                        f"uploads/items/{unique_filename}", 
                        restaurant_fk, 
                        int(time.time())))
                    
                    uploaded_images.append(unique_filename)

        db.commit()

        # Generate a success toast message
        toast = render_template("___toast_success.html", message="Item successfully updated with images.")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 201
    except Exception as ex:
        # Log the exception for debugging
        ic("Error in update_item_details:", ex)
        
        # Rollback the database in case of an error
        if "db" in locals():
            db.rollback()

        # Handle specific exceptions with appropriate responses
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        elif isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error occurred.</template>", 500

        # Generic error response
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500

    finally:
        # Ensure database connections are closed
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################
@app.post('/manage/menu/<item_pk>/add-image')
@x.no_cache
def add_item_image(item_pk):
    try:
        # Retrieve uploaded file
        image = request.files.get("image")
        if not image or not allowed_file(image.filename):
            return jsonify({"error": "Invalid or no image uploaded"}), 400

        # Save the image
        filename = f"{uuid.uuid4().hex}_{secure_filename(image.filename)}"
        file_path = os.path.join(UPLOAD_FOLDER_ITEMS, filename)
        image.save(file_path)

        # Insert the image into the database
        db, cursor = x.db()
        cursor.execute(
            """
            INSERT INTO item_images (image_pk, item_fk, image_path)
            VALUES (%s, %s, %s)
            """,
            (str(uuid.uuid4()), item_pk, filename)
        )
        db.commit()
        ic("Image inserted into database")

        # Render a toast message template
        toast = render_template("___toast_success.html", message="Imagr has been added successfully.")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 201

    except Exception as ex:
        ic("Error in add_item_image:", ex)
        # Rollback the database in case of an error
        if "db" in locals():
            db.rollback()

        # Handle specific exceptions with appropriate responses
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        elif isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error occurred.</template>", 500

        # Generic error response
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500

    finally:
        # Ensure database connections are closed
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################
@app.post("/manage/edit/<item_pk>")
@x.no_cache
def edit_item(item_pk):
    user = session.get("user")
    if not user or "restaurant" not in user.get("roles", []):
        return redirect(url_for("view_login"))

    try:
        # Retrieve form data
        item_title = request.form.get("item_title", "").strip()
        item_description = request.form.get("item_description", "").strip()
        item_price = request.form.get("item_price", "").strip()
        item_image = request.files.get("item_image")

        # Validate fields
        if not item_title or not item_price:
            toast = render_template("___toast.html", message="Title and price are required!")
            return f"""<template mix-target="#toast">{toast}</template>""", 400

        # Save image if uploaded
        image_path = None
        if item_image and allowed_file(item_image.filename):
            filename = f"{uuid.uuid4().hex}_{secure_filename(item_image.filename)}"
            file_path = os.path.join(app.config["UPLOAD_FOLDER_ITEMS"], filename)
            item_image.save(file_path)
            image_path = f"uploads/images/{filename}"

        # Update item in database
        db, cursor = x.db()
        cursor.execute("""
            UPDATE items
            SET item_title = %s, item_description = %s, item_price = %s, item_image = COALESCE(%s, item_image)
            WHERE item_pk = %s AND item_user_fk = %s
        """, (item_title, item_description, item_price, image_path, item_pk, user["user_pk"]))
        db.commit()

        toast = render_template("___toast.html", message="Item updated successfully!")
        return f"""
            <template mix-target="#toast" mix-bottom>{toast}</template>
            <template mix-refresh></template>
        """

    except Exception as ex:
        ic("Error in edit_item:", ex)
        if "db" in locals():
            db.rollback()

        # Handle specific exceptions
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        elif isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error occurred.</template>", 500

        # Generic error response
        return f"""<template mix-target="#toast" mix-bottom>An error occurred while updating the item.</template>""", 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()



##############################
@app.post("/items/<item_pk>/buy")
@x.no_cache
def buy_item(item_pk):
    try:
        # Ensure the user is logged in
        user = session.get("user")
        if not user:
            raise x.CustomException("You must be logged in to buy items.", 401)
        
        item_pk = x.validate_uuid4(item_pk)
        # Get and validate the quantity from the request
        quantity = request.form.get("quantity", "").strip()
        
        if not quantity.isdigit() or int(quantity) < 1:
            raise x.CustomException("Invalid quantity. Please select a valid number.", 400)
        quantity = int(quantity)  # Safely convert to an integer

        # Fetch item and restaurant details
        db, cursor = x.db()
        query = """
            SELECT 
                i.item_title, 
                i.item_price, 
                r.restaurant_name
            FROM items i
            JOIN restaurants r ON i.item_user_fk = r.restaurant_user_fk
            WHERE i.item_pk = %s
        """
        cursor.execute(query, (item_pk,))
        item = cursor.fetchone()

        # Validate if the item exists
        if not item:
            raise x.CustomException("Item not found. Please try again.", 404)

        # Validate if the item exists
        if not item:
            raise x.CustomException("Item not found. Please try again.", 404)

        # Validate the price
        item_price = float(item.get("item_price", 0.0))  # Explicit conversion
        ic(f"Item price fetched from DB: {item_price}")  # Debugging the price

        if item_price <= 0:
            raise x.CustomException("Invalid item price. Please contact support.", 400)


        # Calculate the total price
        total_price = item["item_price"] * quantity

        
        # Send email
        x.send_item_purchase_confirmation_email(
            user_email=user["user_email"],
            user_name=user["user_name"],
            item_title=item["item_title"],
            item_price=item["item_price"],
            restaurant_name=item["restaurant_name"],
            quantity=quantity
        )
        # Render a success message
        toast = render_template(
            "___toast_success.html",
            message=f"{quantity} x {item['item_title']} bought successfully! Total: {total_price:.2f} DKK."
        )
        return f"""
            <template mix-target="#toast" mix-bottom>{toast}</template>
        """

    except Exception as ex:
        if "db" in locals():
            db.rollback()
        # Handle specific exceptions
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        elif isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error occurred.</template>", 500
        # Generic error response
        return f"""
            <template mix-target="#toast" mix-bottom>An error occurred while processing your request.</template>
        """, 500

    finally:
        # Ensure resources are closed
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################


@app.post("/logout")
def logout():
    session.clear() # Explicitly mark session as modified
    return redirect(url_for("view_index"))

##############################

@app.post("/users")
@x.no_cache
def signup():
    try:
        # Step 1: Validate user inputs
        user_name = x.validate_user_name()
        user_last_name = x.validate_user_last_name()
        user_email = x.validate_user_email()
        user_password = x.validate_user_password()
        hashed_password = generate_password_hash(user_password)

        # Step 2: Ensure user roles are selected
        selected_roles = request.form.getlist("roles")
        if not selected_roles:
            toast = render_template("___toast.html", message="Please select at least one role.")
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 400

        # Step 3: Prepare user data
        user_pk = str(uuid.uuid4())
        user_avatar = ""
        user_created_at = int(time.time())
        user_deleted_at = 0
        user_blocked_at = 0
        user_updated_at = 0
        user_verified_at = 0
        user_verification_key = str(uuid.uuid4())
        reset_key = str(uuid.uuid4())
        token_expiry = datetime.now() + timedelta(hours=2)

        db, cursor = x.db()

         # Step 3: Check if the email is already in use
        cursor.execute("SELECT user_pk FROM users WHERE user_email = %s", (user_email,))
        if cursor.fetchone():
            raise x.CustomException("Email is already registered.", 400)


        # Step 4: Insert user into the database
        q = 'INSERT INTO users VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'
        cursor.execute(q, (user_pk, user_name, user_last_name, user_email, 
                           hashed_password, user_avatar, user_created_at, user_deleted_at, user_blocked_at, 
                           user_updated_at, user_verified_at, user_verification_key, reset_key, token_expiry))

        # Step 5: Assign roles to the user
        for role_pk in selected_roles:
            cursor.execute("INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES (%s, %s)", 
                           (user_pk, role_pk))
            
        selected_roles = request.form.getlist("roles")
        ic("Roles received from form:", selected_roles)

        # Step 6: Send verification email
        x.send_verify_email(user_email, user_verification_key)
        db.commit()

        return """<template mix-redirect="/login"></template>""", 201

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code    
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            if "users.user_email" in str(ex): 
                toast = render_template("___toast.html", message="Email not available.")
                return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 400
            return f"""<template mix-target="#toast" mix-bottom>System upgrading</template>""", 500        
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500    
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################

@app.post("/restaurants/add")
@x.no_cache
def create_restaurant():
    try:
        # Validate inputs
        restaurant_name = x.validate_restaurant_name()
        street_name = x.validate_street_name()
        street_number = x.validate_street_number()
        city = x.validate_city_name()
        postal_code = x.validate_postal_code()

        # Fetch user session
        user = session.get("user")
        if not user:
            raise x.CustomException("User not logged in. Please log in to create a restaurant.", 401)

        user_pk = user.get("user_pk")

        # Combine address fields into one
        restaurant_address = f"{street_number} {street_name}, {postal_code} {city}"

        # Generate random latitude and longitude for Copenhagen
        latitude = round(random.uniform(55.5, 55.8), 8)
        longitude = round(random.uniform(12.4, 12.7), 8)

        # Insert into database
        db, cursor = x.db()
        restaurant_pk = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO restaurants (restaurant_pk, restaurant_user_fk, restaurant_name,
                                     restaurant_address, restaurant_latitude, restaurant_longitude)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (restaurant_pk, user_pk, restaurant_name, restaurant_address, latitude, longitude))
        db.commit()

        # Redirect to profile with a success message
        return """
            <template mix-redirect="{url}" mix-bottom>
                <div class="text-c-green:+9">Restaurant created successfully!</div>
            </template>
        """.format(url=url_for("view_profile")), 201

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code    
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            if "restaurants.restaurant_name" in str(ex): 
                toast = render_template("___toast.html", message="Restaurant name not available.")
                return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 400
            return f"""<template mix-target="#toast" mix-bottom>System upgrading</template>""", 500        
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500    

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()
##############################

@app.post("/login")
def login():
    try:
        # Validate inputs
        user_email = x.validate_user_email()
        user_password = x.validate_user_password()

        # Database connection
        db, cursor = x.db()

        # Get user data
        cursor.execute(
            "SELECT * FROM users WHERE user_email = %s", (user_email,)
        )
        user_row = cursor.fetchone()
        if not user_row:
            toast = render_template("___toast.html", message="user not registered")
            return f"""<template mix-target="#toast">{toast}</template>""", 400
        
        # Validate password
        if not check_password_hash(user_row["user_password"], user_password):
            toast = render_template("___toast.html", message="invalid credentials")
            return f"""<template mix-target="#toast">{toast}</template>""", 401
        
        # Get roles for the user
        cursor.execute(
            """
            SELECT roles.role_name
            FROM users
            LEFT JOIN users_roles ON users.user_pk = users_roles.user_role_user_fk
            LEFT JOIN roles ON users_roles.user_role_role_fk = roles.role_pk
            WHERE users.user_email = %s;
            """,
            (user_email,),
        )
        roles = [row.get("role_name", "") for row in cursor.fetchall() if row]

        # Determine active role with priority: customer > restaurant > partner
        priority = ["customer", "restaurant", "partner"]
        active_role = next((role for role in priority if role in roles), "customer")

        # Save user and roles in session
        session["user"] = {
            "user_pk": user_row["user_pk"],
            "user_name": user_row["user_name"],
            "user_last_name": user_row["user_last_name"],
            "user_email": user_row["user_email"],
            "user_avatar": user_row["user_avatar"] or "profile_100.jpg",
            "roles": roles,
            "active_role": active_role, 
        }


        # Directly redirect to the index page after login
        return f"""<template mix-redirect="/"></template>"""

    except Exception as ex:
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>System upgrading</template>", 500        
        return "<template>System under maintenance</template>", 500  
    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################
@app.post("/reset-password/<reset_key>")
def update_password(reset_key):
    try:
        # Validate and log the reset key
        reset_key = x.validate_uuid4(reset_key)

        # Retrieve the new password from the form
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Password validation
        if not new_password or not confirm_password:
            return render_template("view_reset_password.html", reset_key=reset_key, error="Password fields are required.")
        if new_password != confirm_password:
            return render_template("view_reset_password.html", reset_key=reset_key, error="Passwords do not match.")

        # Hash the new password
        hashed_password = generate_password_hash(new_password)

        # Connect to the database
        db, cursor = x.db()

        # Update the password if the reset key is valid and not expired
        new_reset_key = str(uuid.uuid4())
        q = """UPDATE users 
               SET user_password = %s, reset_key = %s, token_expiry = NOW() + INTERVAL 2 HOUR
               WHERE reset_key = %s AND token_expiry > NOW()"""
        cursor.execute(q, (hashed_password, new_reset_key, reset_key))
        ic("Executed update query")

        # Check if the update was successful
        if cursor.rowcount != 1:
            ic("Reset key invalid or expired")
            db.rollback()  # Roll back if update was not successful
            return render_template("view_reset_password.html", reset_key=reset_key, error="Invalid or expired reset key.")
        # Commit the transaction
        db.commit()
        ic("Committed changes to database")

        cursor.execute("SELECT user_email, user_name FROM users WHERE reset_key = %s", (new_reset_key,))
        user = cursor.fetchone()
        if user:
            user_email = user["user_email"]
            user_name = user["user_name"]
    

            # Send email notification that the password has been updated
            x.send_password_update_confirmation(user_email, user_name)

        # Redirect to login page with a success message
        return redirect(url_for("view_login", message="Password updated successfully, please login!"))

    except Exception as ex:
        ic(ex)
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>System upgrading</template>", 500
        return "<template>System under maintenance</template>", 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()


##############################
@app.post("/forgot-password")
def forgot_password():
    try:
# Step 1: Validate user email using your utility function
        user_email = x.validate_user_email()

        # Step 1: Retrieve and validate user email from form
        user_email = request.form.get("user_email")
        if not user_email:
            toast = render_template("___toast.html", message="Email is required.")
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 400

        # Validate email format

        # Step 2: Connect to the database
        db, cursor = x.db()

        # Step 3: Check if user exists
        cursor.execute("SELECT user_pk, user_name FROM users WHERE user_email = %s", (user_email,))
        user = cursor.fetchone()
        ic(user)
        if not user:
            toast = render_template("___toast.html", message="Email not found.")
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 404
        
        # Extract user details
        user_name = user["user_name"] 
        user_pk = user["user_pk"] # Second value is user_name

        # Step 4: Generate reset key and expiry
        reset_key = str(uuid.uuid4())
        token_expiry = datetime.now() + timedelta(hours=2)
        ic(reset_key, token_expiry)

        # Step 5: Update reset key and expiry in the database
        cursor.execute(
            "UPDATE users SET reset_key = %s, token_expiry = %s WHERE user_email = %s",
            (reset_key, token_expiry, user_email),
        )
        db.commit()
        ic("Database updated")

        # Step 6: Generate reset link and send email
        reset_link = url_for('show_reset_password', reset_key=reset_key, _external=True)
        x.send_reset_email(user_email, user_name, reset_link)
        ic("Email sent")

        # Redirect to login with a success message
        toast = render_template(
            "___toast_success.html", message="Reset link sent! Please check your email."
        )
        return f"""
                <template mix-target="#toast" mix-bottom>{toast}</template>
                <template mix-redirect="/login"></template>
                """, 200

    except Exception as ex:
        ic(f"Error in forgot_password: {str(ex)}")  # Use str() to ensure proper logging
        if "db" in locals():
            db.rollback()
        toast = render_template("___toast.html", message="System under maintenance.")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################
@app.post('/change-profile-picture')
def change_profile_picture():
    try:
        user = session.get("user")
        if not user:
            return redirect(url_for('view_login'))  # Redirect if the user is not logged in

        file = request.files.get('profile_picture')
        if not file:
            return "<h1>No file uploaded</h1>", 400  # Error if no file is uploaded

        # Validate the file format
        if file and allowed_file(file.filename):
            # Generate a unique filename for the image
            filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
            # Limit the filename length to 255 characters (or as per your column size)
            filename = filename[:255]

            file_path = os.path.join(UPLOAD_FOLDER_AVATARS, filename)

            # Save the file to the server
            file.save(file_path)

            # Update the user's profile picture in the database
            db, cursor = x.db() 

            cursor.execute("""
                UPDATE users
                SET user_avatar = %s
                WHERE user_pk = %s
            """, (filename, user['user_pk']))

            db.commit()

            # Update the session to reflect the new avatar
            user['user_avatar'] = filename
            session['user'] = user

            # Redirect back to the profile page to see the updated avatar
            return redirect(url_for('view_profile')) 

        return "<h1>Invalid file format or no file uploaded</h1>", 400  # Error if the file format is not allowed
    
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()

        # Handle custom exceptions
        if isinstance(ex, x.CustomException):
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
        
        # Handle database exceptions
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>System upgrading</template>", 500  # Database error handling  

        # Any other exceptions
        return """<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500  
    
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################



##############################
##############################
##############################

def _________PUT_________(): pass

##############################
##############################
##############################

# @app.put("/users/update-roles")
# def update_user_roles():
#     try:
#         if not session.get("user"): x.raise_custom_exception("Please log in", 401)

#         # Get data from the form
#         user_pk = request.form.get("user_pk")
#         selected_roles = request.form.getlist("roles")

#         if not user_pk or not selected_roles:
#             x.raise_custom_exception("User and roles are required", 400)

#         # Validate if the user can update roles (self or admin)
#         logged_in_user = session.get("user")
#         is_admin = "admin" in logged_in_user.get("roles")
#         if not is_admin and logged_in_user.get("user_pk") != user_pk:
#             x.raise_custom_exception("Unauthorized action", 403)

#         # Update roles in the database
#         db, cursor = x.db()

#         # Delete all current roles for the user
#         cursor.execute("DELETE FROM users_roles WHERE user_role_user_fk = %s", (user_pk,))

#         # Add the selected roles back
#         for role_pk in selected_roles:
#             cursor.execute(
#                 "INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES (%s, %s)",
#                 (user_pk, role_pk),
#             )

#         db.commit()

#         # Return success response
#         toast = render_template("___toast.html", message="Roles updated successfully.")
#         return f"""<template mix-target="#toast" mix-bottom>{toast}</template>"""

#     except Exception as ex:
#         ic(ex)
#         if "db" in locals():
#             db.rollback()
#         if isinstance(ex, x.CustomException):
#             toast = render_template("___toast.html", message=ex.message)
#             return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
#         if isinstance(ex, x.mysql.connector.Error):
#             ic(ex)
#             return "<template>Database error</template>", 500
#         return "<template>System under maintenance</template>", 500

#     finally:
#         if "cursor" in locals():
#             cursor.close()
#         if "db" in locals():
#             db.close()

##############################
# @app.put("/admin/edit")
# def update_admin_credentials():
#     try:
#         ic("Admin update request received")
        
#         # Ensure the user is logged in and is an admin
#         if not session.get("user", "") or "admin" not in session["user"].get("roles", []):
#             ic("User not admin or not logged in")
#             return redirect(url_for("view_login"))

#         # Get the admin's primary key from the session
#         user_pk = session["user"]["user_pk"]

#         # Fetch the data from the request
#         new_name = request.form.get("name")
#         new_email = request.form.get("email")
#         new_password = request.form.get("password")

#         # Input validation
#         if not new_name or not new_email or not new_password:
#             toast = render_template("___toast.html", message="All fields are required.")
#             return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 400

#         # Hash the new password
#         hashed_password = generate_password_hash(new_password)

#         # Update the admin's credentials in the database
#         db, cursor = x.db()
#         cursor.execute("""
#             UPDATE users
#             SET user_name = %s, user_email = %s, user_password = %s, user_updated_at = NOW()
#             WHERE user_pk = %s
#         """, (new_name, new_email, hashed_password, user_pk))
#         ic("Database rows affected:", cursor.rowcount)

#         if cursor.rowcount == 0:
#             raise x.CustomException("Unable to update admin credentials", 400)

#         # Commit the changes
#         db.commit()

#         # Success response
#         toast = render_template("___toast.html", message="Admin credentials updated successfully.")
#         return f"""<template mix-target="#toast" mix-bottom>{toast}</template>"""

#     except Exception as ex:
#         ic(ex)
#         if "db" in locals(): db.rollback()
#         if isinstance(ex, x.CustomException):
#             toast = render_template("___toast.html", message=ex.message)
#             return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
#         if isinstance(ex, x.mysql.connector.Error):
#             ic(ex)
#             if "users.user_email" in str(ex): 
#                 toast = render_template("___toast.html", message="Email not available.")
#                 return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 400
#             return f"""<template mix-target="#toast" mix-bottom>System upgrading</template>""", 500        
#         return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500    
#     finally:
#         if "cursor" in locals(): cursor.close()
#         if "db" in locals(): db.close()



##############################

@app.put("/users")
def user_update():
    try:
        # Check for user session
        if not session.get("user"): 
            x.raise_custom_exception("Please login", 401)

        # Fetch user details
        user_pk = session.get("user").get("user_pk")
        ic(f"User PK from session: {user_pk}")
        user_name = x.validate_user_name()
        user_last_name = x.validate_user_last_name()
        user_email = x.validate_user_email()

        # Fetch restaurant details from form
        restaurant_name = request.form.get("restaurant_name", "").strip()
        street_name = request.form.get("street_name", "").strip()
        street_number = request.form.get("street_number", "").strip()
        city = request.form.get("city", "").strip()
        postnummer = request.form.get("postnummer", "").strip()
        ic(f"Received restaurant details: {restaurant_name}, {street_name}, {street_number}, {city}, {postnummer}")

        # Timestamps
        user_updated_at = int(time.time())
        restaurant_updated_at = int(time.time())

        # Validate restaurant fields if restaurant_name is provided
        if restaurant_name and (not street_name or not street_number or not city or not postnummer):
            x.raise_custom_exception("All restaurant fields are required", 400)

        db, cursor = x.db()

        # Update user profile
        user_update_query = """
            UPDATE users
            SET user_name = %s, user_last_name = %s, user_email = %s, user_updated_at = %s
            WHERE user_pk = %s
        """
        cursor.execute(user_update_query, (user_name, user_last_name, user_email, user_updated_at, user_pk))
        ic(f"Rows affected for user update: {cursor.rowcount}")
        if cursor.rowcount != 1:
            x.raise_custom_exception("Cannot update user", 401)

        # Check if the user has a linked restaurant
        cursor.execute("SELECT * FROM restaurants WHERE restaurant_user_fk = %s", (user_pk,))
        linked_restaurant = cursor.fetchone()
        ic(f"Linked restaurant: {linked_restaurant}")

        # If the restaurant exists, update the details
        if linked_restaurant and restaurant_name:
            restaurant_address = f"{street_number} {street_name}, {postnummer} {city}"
            restaurant_update_query = """
                UPDATE restaurants
                SET restaurant_name = %s, restaurant_address = %s, restaurant_updated_at = %s
                WHERE restaurant_user_fk = %s
            """
            cursor.execute(restaurant_update_query, (restaurant_name, restaurant_address, restaurant_updated_at, user_pk))
            ic(f"Rows affected for restaurant update: {cursor.rowcount}")
            if cursor.rowcount != 1:
                x.raise_custom_exception("Cannot update restaurant", 401)

        # If no linked restaurant and restaurant_name is provided, redirect to create restaurant
        if not linked_restaurant and restaurant_name:
            return """
                <template mix-target="#toast" mix-bottom>
                    <a href="/create_restaurant" class="text-blue-500 underline">
                        You don't have a restaurant. Click here to create one.
                    </a>
                </template>
            """, 400

        # Commit changes
        db.commit()
        # Fetch the updated user data and update the session
        cursor.execute("SELECT * FROM users WHERE user_pk = %s", (user_pk,))
        updated_user = cursor.fetchone()
        ic(f"Updated user data: {updated_user}")
        session["user"].update({
            "user_name": updated_user["user_name"],
            "user_last_name": updated_user["user_last_name"],
            "user_email": updated_user["user_email"]
        })

        # Render success response
        toast = render_template("___toast_success.html", message="Profile updated successfully!")
        return f"""
            <template mix-target="#toast" mix-bottom>
                {toast}
            </template>
        """

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            if "users.user_email" in str(ex): 
                return "<template>email not available</template>", 400
            return "<template>System upgrading</template>", 500        
        return "<template>System under maintenance</template>", 500    
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


############################
@app.put("/users/block/<user_pk>")
def user_block(user_pk):
    try:
        user_email = request.form.get("user_email")
        if not "admin" in session.get("user").get("roles"): 
            ic("User not admin")
            return redirect(url_for("view_login"))

        user_pk = x.validate_uuid4(user_pk)
        db, cursor = x.db()

        # Block user
        user_blocked_at = int(time.time())
        cursor.execute("UPDATE users SET user_blocked_at = %s WHERE user_pk = %s", (user_blocked_at, user_pk))

        if cursor.rowcount == 0:
            raise x.CustomException("User not found or already blocked", 404)

        db.commit()
        x.send_block_notification(user_email)

        btn_unblock = render_template("___btn_unblock_user.html", user={"user_pk":user_pk})
        toast = render_template("___toast.html", message="User blocked")
        return f"""<template 
                mix-target='#block-{user_pk}' 
                mix-replace>
                    {btn_unblock}
                </template>
                <template mix-target="#toast" mix-bottom>
                    {toast}
                </template>
                """

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code        
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error</template>", 500        
        return "<template>System under maintenance</template>", 500  

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

#############################
@app.put("/users/unblock/<user_pk>")
def user_unblock(user_pk):
    try:
        user_email = request.form.get("user_email")

        if not "admin" in session.get("user").get("roles"): 
            ic("User not admin")
            return redirect(url_for("view_login"))

        user_pk = x.validate_uuid4(user_pk)

        db, cursor = x.db()

        cursor.execute("UPDATE users SET user_blocked_at = NULL WHERE user_pk = %s AND user_blocked_at IS NOT NULL", (user_pk,))

        if cursor.rowcount == 0:
            raise x.CustomException("User not found or already unblocked", 404)

        db.commit()
        x.send_unblock_notification(user_email)

        btn_block = render_template("___btn_block_user.html", user={"user_pk":user_pk})
        toast = render_template("___toast.html", message="User unblocked")
        return f"""
                <template 
                mix-target='#unblock-{user_pk}' 
                mix-replace>
                    {btn_block}
                </template>
                <template mix-target="#toast" mix-bottom>
                    {toast}
                </template>
                """

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code        
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error</template>", 500
        return "<template>System under maintenance</template>", 500  

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
@app.put("/users/delete/<user_pk>")
def user_delete(user_pk):
    try:
        # Fetch user_email from the form or database
        user_email = request.form.get("user_email")
        if not "admin" in session.get("user").get("roles"): 
            ic("User not admin")
            return redirect(url_for("view_login"))

        user_pk = x.validate_uuid4(user_pk)
        
        db, cursor = x.db()
        cursor.execute("SELECT user_email, user_name FROM users WHERE user_pk = %s", (user_pk,))
        user = cursor.fetchone()
        user_email, user_name = user
        if not user:
            raise x.CustomException("User not found", 404)

           # Delete user
        user_deleted_at = int(time.time())
        db, cursor = x.db()
        cursor.execute("UPDATE users SET user_deleted_at = %s WHERE user_pk = %s", (user_deleted_at, user_pk))

        if cursor.rowcount == 0:
            raise x.CustomException("User not found or already deleted", 404)
        
        user_email = request.args.get("user_email")
        user_name = request.args.get("user_name")

        db.commit()
        # Send email confirmation for user deletion
        x.send_deleted_email_notification(user_email, user_name)

        # Render the "undelete" button and toast message
        btn_undelete = render_template("___btn_undelete_user.html", user={"user_pk":user_pk})
        toast = render_template("___toast.html", message="User deleted")
        return f"""<template 
                mix-target='#delete-{user_pk}' 
                mix-replace>
                    {btn_undelete}
                </template>
                <template mix-target="#toast" mix-bottom>
                    {toast}
                </template>
                """

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code        
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error</template>", 500        
        return "<template>System under maintenance</template>", 500  

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

#############################
@app.put("/users/undelete/<user_pk>")
def user_undelete(user_pk):
    try:
        # Fetch user_email from the form or database
        user_email = request.form.get("user_email")
        if not "admin" in session.get("user").get("roles"): 
            ic("User not admin")
            return redirect(url_for("view_login"))

        user_pk = x.validate_uuid4(user_pk)
        ic("Validated user_pk:", user_pk)

        db, cursor = x.db()
        cursor.execute("SELECT user_email, user_name FROM users WHERE user_pk = %s", (user_pk,))
        user = cursor.fetchone()
        user_email, user_name = user
        if not user:
            raise x.CustomException("User not found", 404)

        # Perform undelete operation
        cursor.execute("UPDATE users SET user_deleted_at = NULL WHERE user_pk = %s AND user_deleted_at IS NOT NULL", (user_pk,))
        ic("Database rows affected:", cursor.rowcount)

        if cursor.rowcount == 0:
            raise x.CustomException("User not found or already made available", 404)

        db.commit()

        # Send email confirmation for undeleting the user
        x.send_undeleted_email_notification(user_email, user_name)

        # Render the "delete" button and toast message
        btn_delete = render_template("___btn_delete_user.html", user={"user_pk":user_pk})
        toast = render_template("___toast.html", message="User is available")
        return f"""<template 
                mix-target='#undelete-{user_pk}' 
                mix-replace>
                    {btn_delete}
                </template>
                <template mix-target="#toast" mix-bottom>
                    {toast}
                </template>
                """

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code        
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error</template>", 500
        return "<template>System under maintenance</template>", 500  

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################
##############################

@app.put("/items/block/<item_pk>")
def item_block(item_pk):
    try:
        
        if not "admin" in session.get("user").get("roles"): 
            ic("User not admin")
            return redirect(url_for("view_login"))
        
        item_pk = x.validate_uuid4(item_pk)
        
        db, cursor = x.db()

        item_blocked_at = int(time.time())
        cursor.execute("UPDATE items SET item_blocked_at = %s WHERE item_pk = %s", (item_blocked_at, item_pk))

        if cursor.rowcount == 0:
            raise x.CustomException("Item not found or already blocked", 404)
        

        cursor.execute("""
            SELECT u.user_email, i.item_title 
            FROM items i
            JOIN users u ON i.item_user_fk = u.user_pk
            WHERE i.item_pk = %s
        """, (item_pk,))
        item_data = cursor.fetchone()

        if not item_data:
            raise x.CustomException("Item not found or no associated partner", 404)
        
        user_email = request.form.get("user_email")
        item_title = item_data["item_title"]
        
        db.commit()
        x.send_item_block_notification(user_email, item_title)

        btn_unblock = render_template("___btn_unblock_item.html", item={"item_pk":item_pk})
        toast = render_template("___toast.html", message="Item blocked")
        return f"""<template 
                mix-target='#block-{item_pk}' 
                mix-replace>
                    {btn_unblock}
                </template>
                <template mix-target="#toast" mix-bottom>
                    {toast}
                </template>
                """

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error</template>", 500
        return "<template>System under maintenance</template>", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################

@app.put("/items/unblock/<item_pk>")
def item_unblock(item_pk):
    try:
        if not "admin" in session.get("user").get("roles"): 
            ic("User not admin")
            return redirect(url_for("view_login"))
        
        item_pk = x.validate_uuid4(item_pk)
        
        db, cursor = x.db()

        cursor.execute("UPDATE items SET item_blocked_at = NULL WHERE item_pk = %s AND item_blocked_at IS NOT NULL", (item_pk,))

        if cursor.rowcount == 0:
            raise x.CustomException("Item not found or already unblocked", 404)
        
        cursor.execute("""
            SELECT u.user_email, i.item_title 
            FROM items i
            JOIN users u ON i.item_user_fk = u.user_pk
            WHERE i.item_pk = %s
        """, (item_pk,))
        item_data = cursor.fetchone()

        if not item_data:
            raise x.CustomException("Item not found or no associated partner", 404)

        user_email = request.form.get("user_email")
        item_title = item_data["item_title"]

        db.commit()
        x.send_item_unblock_notification(user_email, item_title)

        btn_block = render_template("___btn_block_item.html", item={"item_pk":item_pk})
        toast = render_template("___toast.html", message="Item unblocked")
        return f"""<template 
                mix-target='#unblock-{item_pk}' 
                mix-replace>
                    {btn_block}
                </template>
                <template mix-target="#toast" mix-bottom>
                    {toast}
                </template>
                """
    
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error</template>", 500
        return "<template>System under maintenance</template>", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################
##############################
##############################

def _________DELETE_________(): pass

##############################
##############################
##############################

@app.delete('/items/<item_pk>/delete')
def delete_item(item_pk):
    try:
        db, cursor = x.db()

        # Delete the item from the database
        cursor.execute("DELETE FROM items WHERE item_pk = %s", (item_pk,))
        db.commit()

        # Generate a success toast and redirect
        toast = render_template("___toast_success.html", message="Item deleted successfully.")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>
                   <template mix-redirect="{url_for('view_manage_items')}"></template>""", 200

    except Exception as ex:
        # Handle exceptions and log for debugging
        ic("Error in delete_item:", ex)
        toast = render_template("___toast.html", message="System under maintenance.")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 500

    finally:
        # Ensure database resources are closed
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################





##############################
##############################
##############################

def _________BRIDGE_________(): pass

##############################
##############################
##############################
##############################
@app.post("/users/delete/<user_pk>")
def user_self_delete(user_pk):
    try:
        # Ensure the user is logged in
        if not session.get("user"):
            raise x.CustomException("You must be logged in to delete your account.", 401)

        logged_in_user = session["user"]
        logged_in_user_pk = logged_in_user["user_pk"]

        # Check if the logged-in user is trying to delete their own profile
        if logged_in_user_pk != user_pk:
            raise x.CustomException("Unauthorized action. You can only delete your own account.", 403)

        confirm_password = request.form.get("confirm_password", "").strip()
        ic(f"Received confirm_password: {confirm_password}")
        if not confirm_password:
            raise x.CustomException("Password is required to delete your profile.", 400)

        # Validate the password
        db, cursor = x.db()
        cursor.execute("SELECT user_password, user_deleted_at FROM users WHERE user_pk = %s", (user_pk,))
        user = cursor.fetchone()

        if not user or user["user_deleted_at"]:
            raise x.CustomException("Account not found or already deleted.", 404)

        stored_password_hash = user["user_password"]

        if not check_password_hash(stored_password_hash, confirm_password):
            raise x.CustomException("Incorrect password. Please try again.", 401)

        # Perform the soft delete (update `user_deleted_at`)
        user_deleted_at = int(time.time())
        cursor.execute("UPDATE users SET user_deleted_at = %s WHERE user_pk = %s", (user_deleted_at, user_pk))

        if cursor.rowcount != 1:
            return "Unable to delete account. Try again later.", 400

        # Commit changes to the database
        db.commit()

        # Log the user out after deletion
        session.pop("user", None)

        # Send confirmation email if necessary
        x.send_deletion_confirmation_email(logged_in_user['user_email'], logged_in_user['user_name'])

        toast = render_template("___toast.html", message="Roles updated successfully.")
        return f"""<template mix-redirect="/" mix-target="#toast" mix-bottom>{toast}</template>"""

    except Exception as ex:
        ic("Error in user_self_delete:", ex)
        if "db" in locals():
            db.rollback()
        # Handle specific exceptions
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        elif isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error occurred.</template>", 500
        # Generic error response
        return """
            <template mix-target="#toast" mix-bottom>
                <div class="text-c-red:-9">An error occurred while deleting your profile.</div>
            </template>
        """, 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################
@app.get("/verify/<verification_key>")
@x.no_cache
def verify_user(verification_key):
    try:
        ic(verification_key)
        verification_key = x.validate_uuid4(verification_key)
        user_verified_at = int(time.time())

        db, cursor = x.db()
        q = """ UPDATE users 
                SET user_verified_at = %s 
                WHERE user_verification_key = %s"""
        cursor.execute(q, (user_verified_at, verification_key))
        ic("Row count after update:", cursor.rowcount)

        if cursor.rowcount != 1:
            x.raise_custom_exception("cannot verify account", 400)

        db.commit()
        # return redirect(url_for("view_login", message="User verified, please login"))
        return redirect(f"/login?message=User verified, please login")

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): return ex.message, ex.code    
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "Database under maintenance", 500        
        return "System under maintenance", 500  
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()    








