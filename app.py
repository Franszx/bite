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

from icecream import ic
ic.configureOutput(prefix=f'***** | ', includeContext=True)

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'  # or 'redis', etc.
Session(app)


# Ensure the UPLOAD_FOLDER exists
UPLOAD_FOLDER = 'static/avatars/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Helper function to check if the file is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


UNSPLASH_ACCESS_KEY = os.getenv("UNSPLASH_ACCESS_KEY") or x.UNSPLASH_ACCESS_KEY
UNSPLASH_API_URL = "https://api.unsplash.com/search/photos"

# Helper function to download images
def download_image(image_url, save_path):
    """Downloads an image from the given URL and saves it locally."""
    try:
        img_data = requests.get(image_url).content
        with open(save_path, "wb") as handler:
            handler.write(img_data)
        ic(f"Downloaded: {save_path}")
    except Exception as e:
        ic(f"Failed to download {image_url}: {e}")

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max file size

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

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

# def update_block_status(table, pk_column, pk_value, blocked=True):
#     db, cursor = x.db()
#     timestamp = int(time.time()) if blocked else None
#     cursor.execute(
#         f"UPDATE {table} SET blocked_at = %s WHERE {pk_column} = %s",
#         (timestamp, pk_value),
#     )
#     if cursor.rowcount != 1:
#         raise x.CustomException(
#             f"{table} not found or already {'blocked' if blocked else 'unblocked'}",
#             404,
#         )
#     db.commit()

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


@app.get('/fetch-images')
def fetch_images():
    """Fetches and downloads images from Unsplash."""
    search_params = {
        "query": "food dishes",
        "per_page": 10,  # Number of images per request
        "page": 1,       # Start page
    }
    headers = {"Authorization": f"Client-ID {UNSPLASH_ACCESS_KEY}"}

    try:
        response = requests.get(UNSPLASH_API_URL, headers=headers, params=search_params)
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch images", "status": response.status_code}), 500

        images = response.json().get("results", [])
        for idx, img in enumerate(images):
            img_url = img["urls"]["regular"]
            img_name = f"dish_{idx + 1}.jpg"
            save_path = os.path.join(UPLOAD_FOLDER, img_name)
            download_image(img_url, save_path)

        return jsonify({"message": "Images fetched and saved successfully."})

    except Exception as e:
        ic(e)
        return jsonify({"error": "An error occurred while fetching images"}), 500

##############################

@app.get('/images')
def list_images():
    """Lists all downloaded images."""
    try:
        images = os.listdir(UPLOAD_FOLDER)
        images = [url_for('static', filename=f'uploads/images/{img}') for img in images]
        return render_template("image_gallery.html", images=images)
    except Exception as e:
        ic(e)
        return jsonify({"error": "Failed to list images"}), 500


##############################

@app.get('/images/<path:filename>')
def serve_image(filename):
    """Serves individual images."""
    return send_from_directory(UPLOAD_FOLDER, filename)

##############################
@app.get("/test-set-redis")
def view_test_set_redis():
    redis_host = "redis"
    redis_port = 6379
    redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)    
    redis_client.set("name", "Anders", ex=10)
    # name = redis_client.get("name")
    return "name saved"

@app.get("/test-get-redis")
def view_test_get_redis():
    redis_host = "redis"
    redis_port = 6379
    redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)    
    name = redis_client.get("name")
    if not name: name = "no name"
    return name

##############################

@app.get('/images/<path:filename>')
def serve_images(filename):
    return send_from_directory('images', filename)

##############################
@app.get("/")
def view_index():
    user = session.get("user")
    if user:
        # User is logged in: Fetch roles and current active role
        roles = user.get("roles", [])
        active_role = user.get("current_role") or (roles[0] if roles else None)

        # Debugging logs
        ic(user)
        ic(roles)
        ic(active_role)

        if not active_role:
            return redirect(url_for("view_choose_role"))

        # Render dynamic content for logged-in users
        return render_template(
            "view_index.html",
            user=user,
            role=active_role,
            roles=roles,
            is_logged_in=True,
        )

    # User is not logged in: Render the public landing page
    return render_template("view_index.html", is_logged_in=False)

##############################



##############################

# @app.get("/partner")
# def show_partner():
#     return render_template("_partner.html")

##############################

# @app.get("/restaurant")
# def show_restaurant():
#     return render_template("_restaurant.html")

##############################

@app.get("/forgot-password")
@x.no_cache
def show_forgot_password_form():
    return render_template("__forgot_password.html")

##############################

@app.get("/reset-password/<reset_key>")
@x.no_cache
def show_reset_password(reset_key):

    reset_key = x.validate_uuid4(reset_key)

    return render_template("__reset_link.html", x=x, reset_key=reset_key)

##############################

@app.get("/signup")
@x.no_cache
def view_signup():  
    ic(session)
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

    return render_template("view_signup.html", roles=roles, x=x, title="Signup")

##############################
@app.get("/login")
@x.no_cache
def view_login():  
    # ic("#"*20, "VIEW_LOGIN")
    ic(session)

    user = None
    # print(session, flush=True)  
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
  
        
    return render_template("view_login.html", x=x, title="Login", user=user, message=request.args.get("message", ""))


##############################

@app.get("/customer")
@x.no_cache
def view_customer():

    if not session.get("user", ""):
        return redirect(url_for("view_login"))
    user = session.get("user")
    if not "customer" in user.get("roles", ""):
        return redirect(url_for("view_login"))
    
    return render_template("view_index.html", user=user, role="customer")
    

##############################
@app.get("/partner")
@x.no_cache
def view_partner():

    if not session.get("user", ""): 
        return redirect(url_for("view_login"))
    
    user = session.get("user")
    if not "partner" in user.get("roles", ""):
        return redirect(url_for("view_login"))
    
    roles = user.get("roles", [])
    active_role = user.get("current_role") or (roles[0] if roles else None)
    
    try:
        db, cursor = x.db()

        if not active_role:
            return redirect(url_for("view_choose_role"))


        # Fetch additional data as needed
        return render_template(
            "view_index.html",
            role=active_role,
            user=user
        
        )
    except Exception as ex:
        print("Error loading partner page:", ex)
        return "<h1>System under maintenance</h1>", 500
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
@app.get("/restaurant")
@x.no_cache
def view_restaurant():
    if not session.get("user", ""): 
        return redirect(url_for("view_login"))
    user = session.get("user")
    if not "restaurant" in user.get("roles", ""):
        return redirect(url_for("view_login"))
    return render_template("view_index.html", user=user)


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
                user_pk, 
                user_name, 
                user_last_name, 
                user_avatar,
                user_email,
                user_blocked_at
            FROM users
        """)
        users = cursor.fetchall()

        # Fetch the total count of users
        cursor.execute("SELECT COUNT(*) AS total_users FROM users")
        total_users = cursor.fetchone()["total_users"]

        # Fetch total restaurants
        cursor.execute("""
            SELECT COUNT(DISTINCT u.user_pk) AS total_restaurants
            FROM users u
            JOIN users_roles ur ON u.user_pk = ur.user_role_user_fk
            JOIN roles r ON ur.user_role_role_fk = r.role_pk
            WHERE r.role_name = 'restaurant'
        """)
        total_restaurants = cursor.fetchone()["total_restaurants"]

        # Fetch total partners
        cursor.execute("""
            SELECT COUNT(DISTINCT u.user_pk) AS total_partners
            FROM users u
            JOIN users_roles ur ON u.user_pk = ur.user_role_user_fk
            JOIN roles r ON ur.user_role_role_fk = r.role_pk
            WHERE r.role_name = 'partner'
        """)
        total_partners = cursor.fetchone()["total_partners"]

        # Fetch total customers
        cursor.execute("""
            SELECT COUNT(DISTINCT u.user_pk) AS total_customers
            FROM users u
            JOIN users_roles ur ON u.user_pk = ur.user_role_user_fk
            JOIN roles r ON ur.user_role_role_fk = r.role_pk
            WHERE r.role_name = 'customer'
        """)
        total_customers = cursor.fetchone()["total_customers"]

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

        # Fetch the total count of items
        cursor.execute("SELECT COUNT(*) AS total_items FROM items")
        total_items = cursor.fetchone()["total_items"]

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
            total_items=total_items
        )
    except Exception as ex:
        ic("Error:", ex)
        if "db" in locals(): db.rollback()
        return "Error loading admin page", 500
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()



##############################

@app.get("/admin/users")
@x.no_cache
def view_edit_users():
    try:
        db, cursor = x.db()
        
        # Fetch all users without pagination
        cursor.execute("""
            SELECT 
                u.user_pk, 
                u.user_name, 
                u.user_last_name, 
                u.user_avatar, 
                u.user_email, 
                u.user_blocked_at, 
                r.restaurant_name  -- Get the restaurant name from the restaurants table
            FROM users u
            LEFT JOIN restaurants r ON u.user_pk = r.restaurant_user_fk
        """)
        users = cursor.fetchall()
        

        return render_template(
            "__edit_user.html",
            x=x,
            users=users
        )
    except Exception as ex:
        ic("Error:", ex)
        return "Error loading users page", 500
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
        next_page = current_page + 1 if has_more else None
        new_button = render_template("___btn_get_more_items.html", next_page=next_page) if has_more else ""

        return render_template(
            "__edit_items.html",
            items=items,
            next_page=next_page,
            new_button=new_button,
        )
    except Exception as ex:
        ic("Error:", ex)
        return "Error loading items page", 500
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
        ic("Error:", ex)
        return "<template>System under maintenance</template>", 500
    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()


##############################
@app.get("/overview")
def view_overview():
    # Ensure the user is logged in
    user = session.get("user")
    if not user:
        return redirect(url_for("view_login"))

    # Get the user's role
    roles = user.get("roles", [])
    if not roles:
        return "<h1>Access Denied: No roles assigned</h1>", 403

    role = roles[0]  # Assuming the primary role is the first role

    # Fetch stats specific to the role
    stats = {}
    if role == "partner":
        stats = {"total_revenue": "$4,320", "orders_fulfilled": 30}
    elif role == "restaurant":
        stats = {"menu_items": 15, "orders_in_progress": 5}
    elif role == "customer":
        stats = {"total_orders": 15, "favorite_items": 8}
    elif role == "admin":
        stats = {"total_users": 120, "active_restaurants": 45}

    # Render the overview page
    return render_template(
        "__view_overview.html",
        user=user,
        role=role,
        stats=stats)

##############################

@app.get("/admin/edit")
def view_edit_admin():
    # Ensure the user is logged in and is an admin
    if not session.get("user", "") or "admin" not in session["user"].get("roles", []):
        return redirect(url_for("view_login"))
    
    try:
        user = session.get("user")  # Get the logged-in admin's data
        return render_template("__edit_admin.html", user=user)  # Render the edit page with admin's current data
    except Exception as ex:
        print("Error loading admin edit page:", ex)
        return "Error loading admin edit page", 500


##############################

@app.get("/profile")
def view_profile():
    user = session.get("user")
    if not user:
        return redirect(url_for("view_login"))
    if not user.get("user_avatar"):
        user["user_avatar"] = "profile_100.jpg"
    
    # Fetch the user's roles from the session
    roles = user.get("roles", [])
    if len(roles) == 1:
        user_role = roles[0]  # Single role user
    else:
        user_role = session.get("user", {}).get("current_role", "Guest")

    restaurant_name = user.get("restaurant_name")

    return render_template("view_profile.html", user=user, role=user_role)

##############################
@app.get("/profile/settings")
def view_profile_settings():
    try:
        user = session.get("user")
        ic(f"User in session: {user}")  #
        
        # Ensure the user is logged in
        if not user:
            return redirect(url_for("view_login"))

        # Fetch the user's roles from the session
        roles = user.get("roles", [])
        if len(roles) == 1:
            user_role = roles[0]  # Single role user
        else:
            user_role = session.get("user", {}).get("current_role", "Guest")

        # Get the user_pk from session
        user_pk = user.get("user_pk")
        ic(f"Session User PK: {user_pk}")  # Debug log

        if not user_pk:
            return "<h1>User not found in session</h1>", 404

        # Fetch user details from the database
        db, cursor = x.db()

        cursor.execute("""
            SELECT 
                user_pk,
                user_name,
                user_last_name,
                user_email,
                user_avatar
            FROM users
            WHERE user_pk = %s
        """, (user_pk,))
        user = cursor.fetchone()
        
        if not user:
            ic(f"No user found with user_pk: {user_pk}")
            return "<h1>User not found</h1>", 404

        # Render the settings page with user and role information
        return render_template("__profile_settings.html", user=user, role=user_role)

    except Exception as ex:
        ic(ex)
        return "<h1>System under maintenance</h1>", 500

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
    if not session.get("user", ""): 
        return redirect(url_for("view_login"))
    if not len(session.get("user").get("roles")) >= 2:
        return redirect(url_for("view_login"))
    
    ic(user)
    ic(user.get("roles"))

    return render_template("view_choose_role.html", user=user, title="Choose role")


##############################
##############################

@app.get("/select-role/<role>")
def select_role(role):
    user = session.get("user")
    if not user or "roles" not in user or role not in user["roles"]:
        return redirect(url_for("view_choose_role"))
    
    session["user"]["current_role"] = role
    session.modified = True 

    # Debugging
    ic(f"User selected role: {role}")
    ic(session)

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


@app.get("/items")
def view_items():
    try:
        db, cursor = x.db()
        
        # Validate page number if pagination is added
        x.validate_page_number()

        # Fetch all items with their associated restaurants
        q = """
            SELECT 
                i.item_pk, 
                i.item_title, 
                i.item_price, 
                i.item_image, 
                r.restaurant_name 
            FROM items i
            JOIN restaurants r ON i.item_user_fk = r.restaurant_user_fk
        """
        cursor.execute(q)
        items = cursor.fetchall()

        return render_template("view_items.html", items=items)
    except Exception as ex:
        ic(ex)
        return "<h1>Error loading items</h1>", 500
    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################
@app.get("/restaurants")
def view_restaurants():
    query = request.args.get("query", "").strip()
    db, cursor = x.db()
    restaurants = []

    try:
        if query:
            # Perform FULLTEXT search
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
                    MATCH(r.restaurant_name, r.restaurant_item_title, r.restaurant_item_cuisine_type, r.restaurant_item_food_category) AGAINST (%s IN NATURAL LANGUAGE MODE)
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

        return render_template("view_restaurants.html", restaurants=restaurants, query=query)
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
                        return """<template mix-target="#toast" mix-bottom>restaurants not available</template>""", 400
                    return "<template>System upgrading</template>", 500  
              
                # Any other exception
                return """<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500  
            
    finally:
                if "cursor" in locals(): cursor.close()
                if "db" in locals(): db.close()

##############################
@app.get("/restaurants/<restaurant_pk>/items")
def view_restaurant_items(restaurant_pk):
    try:
        # Validate the UUID
        x.validate_uuid4(restaurant_pk)

        db, cursor = x.db()

        # Fetch items for the specific restaurant
        query = """
            SELECT 
                i.item_pk, 
                i.item_title, 
                i.item_price, 
                i.item_image 
            FROM items i
            WHERE i.item_user_fk = %s
        """
        cursor.execute(query, (restaurant_pk,))
        items = cursor.fetchall()

        return render_template("view_restaurant_items.html", items=items, restaurant_pk=restaurant_pk)
    

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
                        return """<template mix-target="#toast" mix-bottom>item not available</template>""", 400
                    return "<template>System upgrading</template>", 500  
              
                # Any other exception
                return """<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500  
            
    finally:
                if "cursor" in locals(): cursor.close()
                if "db" in locals(): db.close()


##############################
@app.get("/search")
def view_search():
    try:
        query = request.args.get("query", "").strip()
        if not query:
            return redirect(url_for("view_index"))

        db, cursor = x.db()

        # FULLTEXT search on restaurants
        cursor.execute(
            """
            SELECT restaurant_pk, restaurant_name, restaurant_address 
            FROM restaurants 
            WHERE MATCH(restaurant_name,restaurant_item_title, restaurant_item_cuisine_type, restaurant_item_food_category) 
            AGAINST (%s IN NATURAL LANGUAGE MODE)
            """, (query,)
        )
        restaurants = cursor.fetchall()

        # FULLTEXT search on items
        cursor.execute(
        """
        SELECT 
            items.item_pk, 
            items.item_title, 
            items.item_price, 
            items.item_cuisine_type, 
            items.item_food_category, 
            items.item_image,
            restaurants.restaurant_name
        FROM items 
        LEFT JOIN restaurants ON items.item_user_fk = restaurants.restaurant_user_fk
        WHERE MATCH(items.item_title, items.item_cuisine_type, items.item_food_category) 
        AGAINST (%s IN NATURAL LANGUAGE MODE)
        """, (query,)
        )
        items = cursor.fetchall()

        # Render the landing page with search results
        return render_template(
            "view_index.html",
            query=query,
            restaurants=restaurants,
            items=items,
            is_logged_in=session.get("user") is not None,
            user=session.get("user"),
            role=session.get("user", {}).get("current_role"),
        )

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()

        # Handle custom exceptions
        if isinstance(ex, x.CustomException):
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code

        # Handle database-related errors
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            if "users.user_email" in str(ex):
                return """<template mix-target="#toast" mix-bottom>email not available</template>""", 400
            return "<template>System upgrading</template>", 500  

        # Handle generic errors
        return """<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500  

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
# @app.get('/restaurants')
# def get_restaurants():
#     try:
#         # Connect to the database
#         db, cursor = x.db()

#         # Get search parameters
#         query_param = request.args.get('query', '')  # General search field for name, cuisine, or category

#         # Build SQL query
#         query = """
#             SELECT 
#                 r.restaurant_name, 
#                 r.restaurant_address, 
#                 r.restaurant_latitude, 
#                 r.restaurant_longitude,
#                 r.restaurant_item_title,
#                 r.restaurant_item_cuisine_type,
#                 r.restaurant_item_food_category
#             FROM restaurants r
#         """
#         params = []
#         where_clauses = []

#         # Add full-text search for the general search field
#         if query_param:
#             where_clauses.append("""
#                 MATCH(r.restaurant_name, r.restaurant_address, r.restaurant_item_title, 
#                       r.restaurant_item_cuisine_type, r.restaurant_item_food_category)
#                 AGAINST (%s WITH QUERY EXPANSION)
#             """)
#             params.append(query_param)

#         # Combine WHERE clauses
#         if where_clauses:
#             query += " WHERE " + " AND ".join(where_clauses)

#         # Execute the query
#         cursor.execute(query, params)
#         restaurants = cursor.fetchall()

#         # Format the results for JSON response
#         restaurant_data = [
#             {
#                 "name": r["restaurant_name"],
#                 "address": r["restaurant_address"],
#                 "latitude": float(r["restaurant_latitude"]),
#                 "longitude": float(r["restaurant_longitude"]),
#                 "cuisine": r["restaurant_item_cuisine_type"],
#                 "category": r["restaurant_item_food_category"],
#             }
#             for r in restaurants
#         ]

#         return jsonify(restaurant_data)
    
#     except Exception as ex:
        
#                 ic(ex)
#                 if "db" in locals(): db.rollback()
        
#                 # My own exception
#                 if isinstance(ex, x.CustomException):
#                     return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
                
#                 # Database exception
#                 if isinstance(ex, x.mysql.connector.Error):
#                     ic(ex)
#                     if "users.user_email" in str(ex):
#                         return """<template mix-target="#toast" mix-bottom>email not available</template>""", 400
#                     return "<template>System upgrading</template>", 500  
              
#                 # Any other exception
#                 return """<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500  
            
#     finally:
#                 if "cursor" in locals(): cursor.close()
#                 if "db" in locals(): db.close()



##############################
@app.get("/profile-deleted")
def view_profile_deleted():
    return render_template("profile_deleted.html")



##############################
##############################
##############################
##############################

def _________POST_________(): pass

##############################
##############################
##############################




##############################

@app.post("/add_item")
def add_item():
    item_image_path = None
    if 'item_image' in request.files:
        item_image_path = save_uploaded_image(request.files['item_image'])
    try:
        db, cursor = x.db()

        # Retrieve form data
        item_title = request.form.get("item_title")
        item_description = request.form.get("item_description")
        item_price = request.form.get("item_price")

        # Handle file upload and generate a UUID filename
        item_image_path = None
        if 'item_image' in request.files:
            file = request.files['item_image']
            if file and allowed_file(file.filename):
                # Generate a secure UUID filename
                unique_filename = f"{uuid.uuid4()}.{file.filename.rsplit('.', 1)[1].lower()}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                # Save the file in the uploads directory
                file.save(file_path)
                
                # Set the path to store in the database
                item_image_path = f"uploads/{unique_filename}"

        # Log for debugging
        ic(item_title, item_description, item_price, item_image_path)

        # Validation for required fields
        if not item_title or not item_price:
            return jsonify({"error": "Title and price are required"}), 400

        # Insert the new item into the database
        query = """
        INSERT INTO items (item_pk, item_title, item_description, item_image_path, item_price)
        VALUES (%s, %s, %s, %s, %s)
        """
        item_pk = str(uuid.uuid4())  # Generate UUID for item_pk
        cursor.execute(query, (item_pk, item_title, item_description, item_image_path, item_price))
        db.commit()

        return jsonify({"message": "Item added successfully", "item_id": item_pk}), 201

    except Exception as ex:
        ic("Error adding item:", ex)
        return jsonify({"error": "Failed to add item"}), 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################
@app.post("/items/<item_pk>/buy")
def buy_item(item_pk):
    try:
        # Validate the UUID
        x.validate_uuid4(item_pk)

        # Check if the user is logged in
        user = session.get("user")
        if not user:
            x.raise_custom_exception("You must be logged in to buy items.", 401)

        db, cursor = x.db()

        # Fetch item and restaurant details
        query = """
            SELECT 
                i.item_title, 
                i.item_price, 
                r.restaurant_name,
                r.restaurant_email  -- Ensure this column exists in your `restaurants` table
            FROM items i
            JOIN restaurants r ON i.item_user_fk = r.restaurant_user_fk
            WHERE i.item_pk = %s
        """
        cursor.execute(query, (item_pk,))
        item = cursor.fetchone()

        if not item:
            x.raise_custom_exception("Item not found.", 404)

        # Customer email
        customer_email = user.get("user_email")
        if not customer_email:
            x.raise_custom_exception("Your account email is missing.", 400)

        # Restaurant email
        restaurant_email = item.get("restaurant_email")
        if not restaurant_email:
            x.raise_custom_exception(f"Cannot contact the restaurant for {item['restaurant_name']}.", 400)


        x.send_item_purchase_confirmation_email(
            user_email=user["user_email"],
            user_name=user["user_name"],
            item_title=item["item_title"],
            item_price=item["item_price"],
            restaurant_name=item["restaurant_name"]
        )

        # Redirect to the items view
        return redirect(url_for("view_items"))

    except Exception as ex:
        ic(ex)
        if "db" in locals():
            db.rollback()

        # Custom exception handling
        if isinstance(ex, x.CustomException):
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code

        # Database-specific errors
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            if "users.user_email" in str(ex):
                return """<template mix-target="#toast" mix-bottom>Item not available</template>""", 400
            return "<template>System upgrading</template>", 500

        # Generic error handling
        return """<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################

# @app.post("/logout")
# def logout():
#     # ic("#"*30)
#     # ic(session)
#     session.pop("user", None)
#     # session.clear()
#     # session.modified = True
#     # ic("*"*30)
#     # ic(session)
#     return redirect(url_for("view_index"))

@app.post("/logout")
def logout():
    session.pop("user", None)
    session.modified = True  # Explicitly mark session as modified
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

        # Step 4: Insert user into the database
        db, cursor = x.db()
        q = 'INSERT INTO users VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'
        cursor.execute(q, (user_pk, user_name, user_last_name, user_email, 
                           hashed_password, user_avatar, user_created_at, user_deleted_at, user_blocked_at, 
                           user_updated_at, user_verified_at, user_verification_key, reset_key, token_expiry))

        # Step 5: Assign roles to the user
        for role_pk in selected_roles:
            cursor.execute("INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES (%s, %s)", 
                           (user_pk, role_pk))

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

# @app.post("/users")
# @x.no_cache
# def signup():
#     try:
#         user_name = x.validate_user_name()
#         user_last_name = x.validate_user_last_name()
#         user_email = x.validate_user_email()
#         user_password = x.validate_user_password()
#         hashed_password = generate_password_hash(user_password)

#         #   # Step 2: Ensure user roles are selected
#         # selected_roles = request.form.getlist("roles")  # Updated to match form's "name" attribute
#         # if not selected_roles:
#         #     toast = render_template("___toast.html", message="Please select a role")
#         #     return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 400
        
        
#         user_pk = str(uuid.uuid4())
#         user_avatar = ""
#         user_created_at = int(time.time())
#         user_deleted_at = 0
#         user_blocked_at = 0
#         user_updated_at = 0
#         user_verified_at = 0
#         user_verification_key = str(uuid.uuid4())
#         reset_key = str(uuid.uuid4())
#         token_expiry = datetime.now() + timedelta(hours=2)

#         db, cursor = x.db()

#         cursor.execute("SELECT role_pk FROM roles WHERE role_name = 'customer'")
#         result = cursor.fetchone()
#         ic(type(result))  # Check the type of result
#         ic(result) 
#         role_pk = result['role_pk']

#         # for role_pk in selected_roles:
#         #     cursor.execute("INSERT INTO users_roles (user_role_user_pk, user_role_role_fk) VALUES (%s, %s)", (user_pk, role_pk))
        
#         q = 'INSERT INTO users VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'
#         cursor.execute(q, (user_pk, user_name, user_last_name, user_email, 
#                            hashed_password, user_avatar, user_created_at, user_deleted_at, user_blocked_at, 
#                            user_updated_at, user_verified_at, user_verification_key, reset_key, token_expiry))
        
#         # Step 6: Assign the 'customer' role to the user
#         cursor.execute("INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES (%s, %s)", 
#                        (user_pk, role_pk))
#         db.commit()
        
#         # for role_pk in selected_roles:
#         #     try:
#         #         cursor.execute(
#         #             "INSERT IGNORE INTO users_roles (user_role_user_pk, user_role_role_fk) VALUES (%s, %s)", 
#         #             (user_pk, role_pk)
#         #         )
#         #     except IntegrityError as e:
#         #         ic("Skipping duplicate role insertion:", e)
#         #         # This ignores duplicate entries if they already exist
    

#         x.send_verify_email(user_email, user_verification_key)
#         db.commit()
    
#         return """<template mix-redirect="/login"></template>""", 201
    
#     except Exception as ex:
#         ic(ex)
#         if "db" in locals(): db.rollback()
#         if isinstance(ex, x.CustomException): 
#             toast = render_template("___toast.html", message=ex.message)
#             return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code    
#         if isinstance(ex, x.mysql.connector.Error):
#             ic(ex)
#             if "users.user_email" in str(ex): 
#                 toast = render_template("___toast.html", message="email not available")
#                 return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 400
#             return f"""<template mix-target="#toast" mix-bottom>System upgrating</template>""", 500        
#         return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500    
#     finally:
#         if "cursor" in locals(): cursor.close()
#         if "db" in locals(): db.close()


##############################
@app.post("/login")
def login():
    try:

        user_email = x.validate_user_email()
        user_password = x.validate_user_password()

        db, cursor = x.db()
        q = """ SELECT users.*, roles.role_name FROM users 
                LEFT JOIN users_roles ON users.user_pk = users_roles.user_role_user_fk 
                LEFT JOIN roles ON users_roles.user_role_role_fk = roles.role_pk
                WHERE users.user_email = %s"""
        cursor.execute(q, (user_email,))
        rows = cursor.fetchall()
        if not rows:
            toast = render_template("___toast.html", message="user not registered")
            return f"""<template mix-target="#toast">{toast}</template>""", 400     
        if not check_password_hash(rows[0]["user_password"], user_password):
            toast = render_template("___toast.html", message="invalid credentials")
            return f"""<template mix-target="#toast">{toast}</template>""", 401
        roles = []
        for row in rows:
            roles.append(row["role_name"])
        user = {
            "user_pk": rows[0]["user_pk"],
            "user_name": rows[0]["user_name"],
            "user_last_name": rows[0]["user_last_name"],
            "user_email": rows[0]["user_email"],
            "user_avatar": rows[0]["user_avatar"] or "profile_100.jpg",
            "roles": roles
        }
        ic(user)
        session["user"] = user
        if len(roles) == 1:
            return f"""<template mix-redirect="/{roles[0]}"></template>"""
        return f"""<template mix-redirect="/"></template>"""
      
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code    
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>System upgrating</template>", 500        
        return "<template>System under maintenance</template>", 500  
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()



# @app.post("/login")
# def login():
#     try:
#         user_email = x.validate_user_email()
#         user_password = x.validate_user_password()

#         db,cursor = x.db()
#         q = """
#             SELECT users.*, roles.role_name 
#             FROM users 
#             LEFT JOIN users_roles ON user_pk = user_role_user_pk 
#             LEFT JOIN roles ON role_pk = user_role_role_fk
#             WHERE user_email = %s
#             """
#         cursor.execute(q, (user_email,))
#         rows = cursor.fetchall()

#         if not rows:
#             toast = render_template("___toast.html", message="user not registered")
#             return f"""<template mix-target="#toast">{toast}</template>""", 400  
#         if rows[0]["user_verified_at"] is None:
#             ic("User verification status:", rows[0]["user_verified_at"])  # Log the verification status
#             toast = render_template("___toast.html", message="Please verify your email before logging in")
#             return f"""<template mix-target="#toast">{toast}</template> """, 403
#         if not check_password_hash(rows[0]["user_password"], user_password):
#             toast = render_template("___toast.html", message="invalid credentials")
#             return f"""<template mix-target="#toast">{toast}</template>""", 401
        
#         roles = [row["role_name"] for row in rows]
#         user = {
#             "user_pk": rows[0]["user_pk"],
#             "user_name": rows[0]["user_name"],
#             "user_last_name": rows[0]["user_last_name"],
#             "user_email": rows[0]["user_email"],
#             "roles": roles
#             }
#         ic(user)
#         session["user"] = user

#         # Redirect logic based on the number of roles
#         if len(roles) > 1:
#             # If the user has multiple roles, redirect to the choose-role page
#             return f"""<template mix-redirect="/choose-role"></template>"""
        
#         elif len(roles) == 1:
#             # If user has only one role, redirect to that specific role page
#             single_role = roles[0]
#             return f"""<template mix-redirect="/{single_role}"></template>"""
        
#         else:
#             # If no roles are assigned, display an error message
#             toast = render_template("___toast.html", message="No roles assigned to the user")
#             return f"""<template mix-target="#toast">{toast}</template>"""
        
#     except Exception as ex:
#         ic(ex)
#         if "db" in locals(): db.rollback()
#         if isinstance(ex, x.CustomException): 
#             toast = render_template("___toast.html", message=ex.message)
#             return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code    
#         if isinstance(ex, x.mysql.connector.Error):
#             ic(ex)
#             return "<template>System upgrading</template>", 500        
#         return "<template>System under maintenance</template>", 500  
#     finally:
#         if "cursor" in locals(): cursor.close()
#         if "db" in locals(): db.close()


##############################
# @app.post("/items")
# def create_item():
#     try:
#         # TODO: validate item_title, item_description, item_price
#         file, item_image_name = x.validate_item_image()

#         # Save the image
#         file.save(os.path.join(x.UPLOAD_ITEM_FOLDER, item_image_name))
#         # TODO: if saving the image went wrong, then rollback by going to the exception
#         # TODO: Success, commit
#         return item_image_name
#     except Exception as ex:
#         ic(ex)
#         if "db" in locals(): db.rollback()
#         if isinstance(ex, x.CustomException): 
#             toast = render_template("___toast.html", message=ex.message)
#             return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code    
#         if isinstance(ex, x.mysql.connector.Error):
#             ic(ex)
#             return "<template>System upgrating</template>", 500        
#         return "<template>System under maintenance</template>", 500  
#     finally:
#         if "cursor" in locals(): cursor.close()
#         if "db" in locals(): db.close()    


##############################
@app.post("/reset-password/<reset_key>")
def update_password(reset_key):
    try:
        # Validate and log the reset key
        ic("Received reset key:", reset_key)
        reset_key = x.validate_uuid4(reset_key)

        # Retrieve the new password from the form
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        
        ic("Received passwords:", new_password, confirm_password)

        # Password validation
        if not new_password or not confirm_password:
            ic("Password fields are missing")
            return render_template("view_reset_password.html", reset_key=reset_key, error="Password fields are required.")
        if new_password != confirm_password:
            ic("Passwords do not match")
            return render_template("view_reset_password.html", reset_key=reset_key, error="Passwords do not match.")

        # Hash the new password
        hashed_password = generate_password_hash(new_password)
        ic("Hashed password:", hashed_password)

        # Connect to the database
        db, cursor = x.db()
        ic("Connected to database")

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
        return redirect(url_for("view_login", message="Password updated successfully, please login"))

    except Exception as ex:
        ic("Database error:", ex)
        if "db" in locals():
            db.rollback()
        return "System under maintenance", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()




##############################
@app.post("/forgot-password")
def forgot_password():
    try:
        user_email = request.form.get("user_email")
        if not user_email:
            return render_template("forgot_password.html", error="Email is required.")

        # Step 1: Connect to the database
        db, cursor = x.db()
        
        # Step 2: Check if user exists
        cursor.execute("SELECT user_pk FROM users WHERE user_email = %s", (user_email,))
        user = cursor.fetchone()
        if not user:
            return render_template("forgot_password.html", error="Email not found.")

        # Step 3: Generate reset key and expiry
        reset_key = str(uuid.uuid4())
        token_expiry = datetime.now() + timedelta(hours=2)

        # Step 4: Store the reset key and expiry in the database
        cursor.execute("UPDATE users SET reset_key = %s, token_expiry = %s WHERE user_email = %s", 
                       (reset_key, token_expiry, user_email))
        db.commit()

        # Step 5: Generate reset link and send email
        reset_link = url_for('show_reset_password', reset_key=reset_key, _external=True)
        x.send_reset_email(user_email, reset_link)  # Function in `x` to send email with `reset_link`

        return redirect(url_for("view_login", message="Email sent successfully, please login"))
    
    except Exception as ex:
        if "db" in locals():
            db.rollback()
        return "<h1>System under maintenance</h1>", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

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

            file_path = os.path.join(UPLOAD_FOLDER, filename)

            # Save the file to the server
            file.save(file_path)

            # Update the user's profile picture in the database
            db, cursor = x.db()  # Assuming `x.db()` is your database connection function

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
@app.post("/users/delete/<user_pk>")
def user_self_delete(user_pk):
    try:
        # Ensure the user is logged in
        if not session.get("user"):
            return redirect(url_for("view_login"))

        logged_in_user = session["user"]
        logged_in_user_pk = logged_in_user["user_pk"]

        # Check if the logged-in user is trying to delete their own profile
        if logged_in_user_pk != user_pk:
            return "Unauthorized action", 403

        # Log the user_pk for debugging
        ic(f"User attempting to delete profile: {logged_in_user_pk}, Target user_pk: {user_pk}")

        confirm_password = request.form.get("confirm_password")
        if not confirm_password:
            return "Password is required to delete your profile.", 400

        # Validate the password
        db, cursor = x.db()
        cursor.execute("SELECT user_password, user_deleted_at FROM users WHERE user_pk = %s", (user_pk,))
        user = cursor.fetchone()

        # Debug: Check if the user is found
        ic(f"Fetched user from DB: {user}")

        if not user:
            return "Account not found or already deleted.", 404

        stored_password_hash = user["user_password"]
        ic(f"Stored password hash: {stored_password_hash}")
        ic(f"Entered password: {confirm_password}")

        if not check_password_hash(stored_password_hash, confirm_password):
            return "Incorrect password. Please try again.", 401 

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

        # Return the confirmation page after profile deletion
        return  redirect(url_for("view_profile_deleted", message="Profile is successfully deleted"))

    except Exception as ex:
        if "db" in locals():
            db.rollback()
        return "An error occurred while deleting your profile.", 500
    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()





##############################
##############################
##############################

def _________PUT_________(): pass

##############################
##############################
##############################

@app.put("/users/update-roles")
def update_user_roles():
    try:
        if not session.get("user"): x.raise_custom_exception("Please log in", 401)

        # Get data from the form
        user_pk = request.form.get("user_pk")
        selected_roles = request.form.getlist("roles")

        if not user_pk or not selected_roles:
            x.raise_custom_exception("User and roles are required", 400)

        # Validate if the user can update roles (self or admin)
        logged_in_user = session.get("user")
        is_admin = "admin" in logged_in_user.get("roles")
        if not is_admin and logged_in_user.get("user_pk") != user_pk:
            x.raise_custom_exception("Unauthorized action", 403)

        # Update roles in the database
        db, cursor = x.db()

        # Delete all current roles for the user
        cursor.execute("DELETE FROM users_roles WHERE user_role_user_fk = %s", (user_pk,))

        # Add the selected roles back
        for role_pk in selected_roles:
            cursor.execute(
                "INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES (%s, %s)",
                (user_pk, role_pk),
            )

        db.commit()

        # Return success response
        toast = render_template("___toast.html", message="Roles updated successfully.")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>"""

    except Exception as ex:
        ic(ex)
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error</template>", 500
        return "<template>System under maintenance</template>", 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()

##############################


@app.put("/admin/edit")
def update_admin_credentials():
    try:
        ic("Admin update request received")
        
        # Ensure the user is logged in and is an admin
        if not session.get("user", "") or "admin" not in session["user"].get("roles", []):
            ic("User not admin or not logged in")
            return redirect(url_for("view_login"))

        # Get the admin's primary key from the session
        user_pk = session["user"]["user_pk"]

        # Fetch the data from the request
        new_name = request.form.get("name")
        new_email = request.form.get("email")
        new_password = request.form.get("password")

        # Input validation
        if not new_name or not new_email or not new_password:
            toast = render_template("___toast.html", message="All fields are required.")
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 400

        # Hash the new password
        hashed_password = generate_password_hash(new_password)

        # Update the admin's credentials in the database
        db, cursor = x.db()
        cursor.execute("""
            UPDATE users
            SET user_name = %s, user_email = %s, user_password = %s, user_updated_at = NOW()
            WHERE user_pk = %s
        """, (new_name, new_email, hashed_password, user_pk))
        ic("Database rows affected:", cursor.rowcount)

        if cursor.rowcount == 0:
            raise x.CustomException("Unable to update admin credentials", 400)

        # Commit the changes
        db.commit()

        # Success response
        toast = render_template("___toast.html", message="Admin credentials updated successfully.")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>"""

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

@app.put("/users")
def user_update():
    try:
        if not session.get("user"): x.raise_custom_exception("please login", 401)

        user_pk = session.get("user").get("user_pk")
        user_name = x.validate_user_name()
        user_last_name = x.validate_user_last_name()
        user_email = x.validate_user_email()

        user_updated_at = int(time.time())

        db, cursor = x.db()
        q = """ UPDATE users
                SET user_name = %s, user_last_name = %s, user_email = %s, user_updated_at = %s
                WHERE user_pk = %s
            """
        cursor.execute(q, (user_name, user_last_name, user_email, user_updated_at, user_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot update user", 401)
        db.commit()

         # Render success response templates
        toast = render_template("___toast_success.html", message="Profile updated successfully!")
        return f"""<template mix-target="#toast" mix-bottom>
                        {toast}
                    </template>"""

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            if "users.user_email" in str(ex): return "<template>email not available</template>", 400
            return "<template>System upgrating</template>", 500        
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
        ic("Database rows affected:", cursor.rowcount)

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
        ic("Unblock request received")

        if not "admin" in session.get("user").get("roles"): 
            ic("User not admin")
            return redirect(url_for("view_login"))

        user_pk = x.validate_uuid4(user_pk)
        ic("Validated user_pk:", user_pk)

        db, cursor = x.db()

        cursor.execute("UPDATE users SET user_blocked_at = NULL WHERE user_pk = %s AND user_blocked_at IS NOT NULL", (user_pk,))
        ic("Database rows affected:", cursor.rowcount)

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
        ic("Executing query: UPDATE users SET user_deleted_at = %s WHERE user_pk = %s", (user_deleted_at, user_pk))
        db, cursor = x.db()
        cursor.execute("UPDATE users SET user_deleted_at = %s WHERE user_pk = %s", (user_deleted_at, user_pk))
        ic("Database rows affected:", cursor.rowcount)

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
        ic("Undelete request received")

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



# @app.delete("/users/delete/<user_pk>")
# def user_delete(user_pk):
#     try:
#         # Check if user is logged
#         if not session.get("user", ""): 
#             return redirect(url_for("view_login"))

#         # Check if it is an admin
#         if not "admin" in session.get("user").get("roles"): 
#             return redirect(url_for("view_login"))

#         user_pk = x.validate_uuid4(user_pk)

#         user_deleted_at = int(time.time())
#         db, cursor = x.db()
#         q = 'UPDATE users SET user_deleted_at = %s WHERE user_pk = %s'
#         cursor.execute(q, (user_deleted_at, user_pk))
        
#         if cursor.rowcount != 1: x.raise_custom_exception("cannot delete user", 400)

#         x.send_deletion_confirmation_email(user_pk)

#         db.commit()
#         return f"<template mix-target='#u{user_pk}' mix-replace>user deleted</template>"
    
#     except Exception as ex:

#         ic(ex)
#         if "db" in locals(): db.rollback()
#         if isinstance(ex, x.CustomException): 
#             return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code        
#         if isinstance(ex, x.mysql.connector.Error):
#             ic(ex)
#             return "<template>Database error</template>", 500        
#         return "<template>System under maintenance</template>", 500  
    
#     finally:
#         if "cursor" in locals(): cursor.close()
#         if "db" in locals(): db.close()

##############################






##############################





##############################
##############################
##############################

def _________BRIDGE_________(): pass

##############################
##############################
##############################


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
        if cursor.rowcount != 1: x.raise_custom_exception("cannot verify account", 400)
        db.commit()
        return redirect(url_for("view_login", message="User verified, please login"))

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






