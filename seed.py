import x
import uuid
import time
import random
from werkzeug.security import generate_password_hash
from faker import Faker
from shapely.geometry import Point, Polygon

fake = Faker()

from icecream import ic
ic.configureOutput(prefix=f'***** | ', includeContext=True)

db, cursor = x.db()

def insert_user(user):       
    q = f"""
    INSERT INTO users 
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)        
    """
    values = tuple(user.values())
    cursor.execute(q, values)

# Define Copenhagen's approximate boundary using latitude and longitude
copenhagen_boundary = Polygon([
    (12.45, 55.6), (12.65, 55.6), (12.65, 55.8), (12.45, 55.8), (12.45, 55.6)
])

def is_within_copenhagen(latitude, longitude):
    """Check if a given latitude and longitude point is within the boundary."""
    point = Point(longitude, latitude)  # Note: Longitude comes first in Point
    return copenhagen_boundary.contains(point)

def generate_coordinates_within_boundary():
    """Generate a random point within Copenhagen's boundary."""
    while True:
        latitude = round(random.uniform(55.6, 55.8), 8)
        longitude = round(random.uniform(12.45, 12.65), 8)
        if is_within_copenhagen(latitude, longitude):
            return latitude, longitude

try:


    
    ##############################
    cursor.execute("DROP TABLE IF EXISTS item_images")  # Drop `item_images` table first
    cursor.execute("DROP TABLE IF EXISTS items") 
    cursor.execute("DROP TABLE IF EXISTS users_roles") #  junction table
    cursor.execute("DROP TABLE IF EXISTS restaurants")
    cursor.execute("DROP TABLE IF EXISTS users")
    
    # Create `users` table
    cursor.execute("""
        CREATE TABLE users (
            user_pk CHAR(36),
            user_name VARCHAR(20) NOT NULL,
            user_last_name VARCHAR(20) NOT NULL,
            user_email VARCHAR(100) NOT NULL UNIQUE,
            user_password VARCHAR(255) NOT NULL,
            user_avatar VARCHAR(50),
            user_created_at INTEGER UNSIGNED,
            user_deleted_at INTEGER UNSIGNED,
            user_blocked_at INTEGER UNSIGNED,
            user_updated_at INTEGER UNSIGNED,
            user_verified_at INTEGER UNSIGNED,
            user_verification_key CHAR(36),
            reset_key CHAR(36),
            token_expiry DATETIME NULL,
            PRIMARY KEY(user_pk)
        )
    """)

    # Add FULLTEXT index for `users`
    cursor.execute("""
        ALTER TABLE users
        ADD FULLTEXT (user_name, user_last_name, user_email)
    """)


    ##############################


    # Create `restaurants` table
    cursor.execute("""
        CREATE TABLE restaurants (
            restaurant_pk CHAR(36),
            restaurant_user_fk CHAR(36),
            restaurant_name VARCHAR(50) NOT NULL,
            restaurant_address VARCHAR(255),
            restaurant_latitude DECIMAL(10, 8),
            restaurant_longitude DECIMAL(11, 8),
            restaurant_item_title TEXT,
            restaurant_item_cuisine_type TEXT,
            restaurant_item_food_category TEXT,
            PRIMARY KEY(restaurant_pk),
            FOREIGN KEY(restaurant_user_fk) REFERENCES users(user_pk) ON DELETE CASCADE
        )
    """)
    # Add FULLTEXT index for `restaurants`
    cursor.execute("""
        ALTER TABLE restaurants
        ADD FULLTEXT (restaurant_name, restaurant_item_title, restaurant_item_cuisine_type, restaurant_item_food_category)
    """)

    ##############################
    

    # Create `items` table
    cursor.execute("""
            CREATE TABLE items (
                item_pk CHAR(36),
                item_user_fk CHAR(36),
                item_title VARCHAR(50) NOT NULL,
                item_price DECIMAL(5,2) NOT NULL,
                item_image VARCHAR(255),
                item_cuisine_type VARCHAR(50),
                item_food_category VARCHAR(50),
                item_created_at INTEGER UNSIGNED,
                item_updated_at INTEGER UNSIGNED,
                item_blocked_at INTEGER UNSIGNED,
                PRIMARY KEY(item_pk)
                -- Note: item_restaurant_fk and its FOREIGN KEY line removed
            )
        """)

    cursor.execute("""
            ALTER TABLE items
            ADD FULLTEXT (item_title, item_cuisine_type, item_food_category)
        """)

    ##############################
    q = """
    CREATE TABLE item_images (
        image_pk CHAR(36) PRIMARY KEY,  
        item_fk CHAR(36),
        image_path VARCHAR(255) NOT NULL,
        restaurant_fk CHAR(36),
        created_at INTEGER UNSIGNED,
        FOREIGN KEY (item_fk) REFERENCES items(item_pk) ON DELETE CASCADE,
        FOREIGN KEY (restaurant_fk) REFERENCES restaurants(restaurant_pk) ON DELETE CASCADE
    )
    """
    cursor.execute(q)


    ##############################
    cursor.execute("DROP TABLE IF EXISTS roles")
    q = """
        CREATE TABLE roles (
            role_pk CHAR(36),
            role_name VARCHAR(10) NOT NULL UNIQUE,
            PRIMARY KEY(role_pk)
        );
        """        
    cursor.execute(q)


    ##############################  Users_roles Junction Table
    # q = """
    #     CREATE TABLE users_roles (
    #         user_role_user_fk CHAR(36),
    #         user_role_role_fk CHAR(36),
    #         PRIMARY KEY(user_role_user_fk, user_role_role_fk)
    #     );
    #     """        
    # cursor.execute(q)

    # Create `users_roles` table
    cursor.execute("""
        CREATE TABLE users_roles (
            user_role_user_fk CHAR(36),
            user_role_role_fk CHAR(36),
            PRIMARY KEY(user_role_user_fk, user_role_role_fk),
            FOREIGN KEY(user_role_user_fk) REFERENCES users(user_pk) ON DELETE CASCADE,
            FOREIGN KEY(user_role_role_fk) REFERENCES roles(role_pk) ON DELETE CASCADE
        )
    """)

    
    # Add foreign key constraints to `users_roles`
    cursor.execute("""
        ALTER TABLE users_roles ADD FOREIGN KEY (user_role_user_fk) REFERENCES users(user_pk) ON DELETE CASCADE ON UPDATE RESTRICT
    """)
    cursor.execute("""
        ALTER TABLE users_roles ADD FOREIGN KEY (user_role_role_fk) REFERENCES roles(role_pk) ON DELETE CASCADE ON UPDATE RESTRICT
    """)


    ############################## 
    # Create roles
    q = f"""
        INSERT INTO roles (role_pk, role_name)
        VALUES  ("{x.ADMIN_ROLE_PK}", "admin"), 
                ("{x.CUSTOMER_ROLE_PK}", "customer"), 
                ("{x.PARTNER_ROLE_PK}", "partner"), 
                ("{x.RESTAURANT_ROLE_PK}", "restaurant")
        """
    cursor.execute(q)


    ############################## 
    # Create admin user
    user_pk = str(uuid.uuid4())
    user = {
        "user_pk" : user_pk,
        "user_name" : "Anders",
        "user_last_name" : "Lindberg",
        "user_email" : "admin@fulldemo.com",
        "user_password" : generate_password_hash("password"),
        "user_avatar" : "profile_10.jpg",
        "user_created_at" : int(time.time()),
        "user_deleted_at" : 0,
        "user_blocked_at" : 0,
        "user_updated_at" : 0,
        "user_verified_at" : int(time.time()),
        "user_verification_key" : str(uuid.uuid4()),
        "reset_key" : str(uuid.uuid4()),
        "token_expiry" : None
    }            




    insert_user(user)
    # Assign role to admin user
    q = f"""
        INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES ("{user_pk}", 
        "{x.ADMIN_ROLE_PK}")        
        """    
    cursor.execute(q)    

    ############################## 
    # Create customer
    user_pk = "4218788d-03b7-4812-bd7d-31c8859e92d8"
    user = {
        "user_pk" : user_pk,
        "user_name" : "John",
        "user_last_name" : "Customer",
        "user_email" : "customer@fulldemo.com",
        "user_password" : generate_password_hash("password"),
        "user_avatar" : "profile_11.jpg",
        "user_created_at" : int(time.time()),
        "user_deleted_at" : 0,
        "user_blocked_at" : 0,
        "user_updated_at" : 0,
        "user_verified_at" : int(time.time()),
        "user_verification_key" : str(uuid.uuid4()),
        "reset_key" : str(uuid.uuid4()),
        "token_expiry" : None
    }
    insert_user(user)
   
    # Assign role to customer user
    q = f"""
        INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES ("{user_pk}", 
        "{x.CUSTOMER_ROLE_PK}")        
        """    
    cursor.execute(q)


    ############################## 
    # Create partner
    user_pk = str(uuid.uuid4())
    user = {
        "user_pk" : user_pk,
        "user_name" : "John",
        "user_last_name" : "Partner",
        "user_email" : "partner@fulldemo.com",
        "user_password" : generate_password_hash("password"),
        "user_avatar" : "profile_12.jpg",
        "user_created_at" : int(time.time()),
        "user_deleted_at" : 0,
        "user_blocked_at" : 0,
        "user_updated_at" : 0,
        "user_verified_at" : int(time.time()),
        "user_verification_key" : str(uuid.uuid4()),
        "reset_key" : str(uuid.uuid4()),
        "token_expiry" : None
    }
    insert_user(user)
    # Assign role to partner user
    q = f"""
        INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES ("{user_pk}", 
        "{x.PARTNER_ROLE_PK}")        
        """    
    cursor.execute(q)

    ############################## 
    ############################## 
    # Create restaurant
    user_pk = str(uuid.uuid4())
    restaurant_pk = str(uuid.uuid4())
    user = {
        "user_pk": user_pk,
        "user_name": "John",
        "user_last_name": "Restaurant",
        "user_email": "restaurant@fulldemo.com",
        "user_password": generate_password_hash("password"),
        "user_avatar": "profile_13.jpg",
        "user_created_at": int(time.time()),
        "user_deleted_at": 0,
        "user_blocked_at": 0,
        "user_updated_at": 0,
        "user_verified_at": int(time.time()),
        "user_verification_key": str(uuid.uuid4()),
        "reset_key": str(uuid.uuid4()),
        "token_expiry": None
    }
    insert_user(user)
    
    # Assign role to restaurant user
    q = f"""
        INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES ("{user_pk}", 
        "{x.RESTAURANT_ROLE_PK}")        
        """    
    cursor.execute(q)
    # Insert into the `restaurants` table
    cursor.execute("""
        INSERT INTO restaurants (restaurant_pk, restaurant_user_fk, restaurant_name,
                                restaurant_address, restaurant_latitude, restaurant_longitude, restaurant_item_title, restaurant_item_cuisine_type, restaurant_item_food_category)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (restaurant_pk, user_pk, "John's Fine Dining", "123 Gourmet Street, Food City",
        round(random.uniform(55.5, 55.8), 8),
        round(random.uniform(12.4, 12.7), 8),
        None,
        None,
        None   
    ))

    dishes = [
        # American
        ("Buffalo Wings", "American", "American"),
        ("Mac and Cheese", "American", "American"),
        ("Cornbread", "American", "American"),

        # Burger
        ("Classic Cheeseburger", "American", "Burger"),
        ("Vegan Black Bean Burger", "American", "Burger"),
        ("Chicken Burger", "American", "Burger"),

        ("Turkey Club Sandwich", "American", "Sandwich"),
        ("Pulled Pork Sandwich", "American", "Sandwich"),

        ]


    # Add random items to the restaurant
    item_titles = []
    item_cuisines = []
    item_categories = []

    for _ in range(random.randint(1, 2)):  # Random number of items
        dish = random.choice(dishes)
        item_pk = str(uuid.uuid4())
        item_title, item_cuisine_type, item_food_category = dish
        item_price = round(random.uniform(50, 150), 2)
        item_image = f"dish_{random.randint(1, 100)}.jpg"

        # Insert item into the items table
        cursor.execute("""
            INSERT INTO items (
                item_pk, item_user_fk, item_title, item_price, item_image, item_cuisine_type, item_food_category, item_created_at, item_updated_at, item_blocked_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (item_pk, user_pk, item_title, item_price, item_image, item_cuisine_type, item_food_category, int(time.time()), 0, 0))

        # Collect data for updating the restaurant
        item_titles.append(item_title)
        item_cuisines.append(item_cuisine_type)
        item_categories.append(item_food_category)

    # Update the restaurant with item details
    cursor.execute("""
        UPDATE restaurants
        SET 
            restaurant_item_title = %s,
            restaurant_item_cuisine_type = %s,
            restaurant_item_food_category = %s
        WHERE restaurant_pk = %s
    """, (
        ", ".join(item_titles),          # Concatenate all item titles
        ", ".join(set(item_cuisines)),   # Concatenate unique cuisine types
        ", ".join(set(item_categories)), # Concatenate unique food categories
        restaurant_pk                    # Restaurant primary key
    ))



    ############################## 
    # Create 50 customer

    domains = ["example.com", "testsite.org", "mydomain.net", "website.co", "fakemail.io", "gmail.com", "hotmail.com"]
    user_password = hashed_password = generate_password_hash("password")
    for _ in range(50):
        user_pk = str(uuid.uuid4())
        user_verified_at = random.choice([0,int(time.time())])
        user = {
            "user_pk" : user_pk,
            "user_name" : fake.first_name(),
            "user_last_name" : fake.last_name(),
            "user_email" : fake.unique.user_name() + "@" + random.choice(domains),
            "user_password" : user_password,
            # user_password = hashed_password = generate_password_hash(fake.password(length=20))
            "user_avatar" : "profile_"+ str(random.randint(1, 100)) +".jpg",
            "user_created_at" : int(time.time()),
            "user_deleted_at" : 0,
            "user_blocked_at" : 0,
            "user_updated_at" : 0,
            "user_verified_at" : user_verified_at,
            "user_verification_key" : str(uuid.uuid4()),
            "reset_key" : str(uuid.uuid4()),
            "token_expiry" : None
        }

        insert_user(user)
        cursor.execute("""INSERT INTO users_roles (
            user_role_user_fk,
            user_role_role_fk)
            VALUES (%s, %s)""", (user_pk, x.CUSTOMER_ROLE_PK))


    ############################## 
    # Create 50 partners

    user_password = hashed_password = generate_password_hash("password")
    for _ in range(50):
        user_pk = str(uuid.uuid4())
        user_verified_at = random.choice([0,int(time.time())])
        user = {
            "user_pk" : user_pk,
            "user_name" : fake.first_name(),
            "user_last_name" : fake.last_name(),
            "user_email" : fake.unique.email(),
            "user_password" : user_password,
            "user_avatar" : "profile_"+ str(random.randint(1, 100)) +".jpg",
            "user_created_at" : int(time.time()),
            "user_deleted_at" : 0,
            "user_blocked_at" : 0,
            "user_updated_at" : 0,
            "user_verified_at" : user_verified_at,
            "user_verification_key" : str(uuid.uuid4()),
            "reset_key" : str(uuid.uuid4()),
            "token_expiry" : None
        }

        insert_user(user)

        cursor.execute("""
        INSERT INTO users_roles (
            user_role_user_fk,
            user_role_role_fk)
            VALUES (%s, %s)
        """, (user_pk, x.PARTNER_ROLE_PK))

    ############################## 
    # Create 50 restaurants

    dishes = [
       # Burger
    ("Classic Cheeseburger", "American", "Burger"),
    ("Vegan Black Bean Burger", "American", "Burger"),
    ("Chicken Burger", "American", "Burger"),

    # Pizza
    ("Pepperoni Pizza", "Italian", "Pizza"),
    ("Four Cheese Pizza", "Italian", "Pizza"),
    ("Veggie Lover’s Pizza", "Italian", "Pizza"),

    # Kebab
    ("Lamb Doner Kebab", "Mediterranean", "Kebab"),
    ("Chicken Shish Kebab", "Mediterranean", "Kebab"),
    ("Vegan Seitan Kebab", "Mediterranean", "Kebab"),

    # Salad
    ("Caprese Salad", "Italian", "Salad"),
    ("Thai Green Papaya Salad", "Thai", "Salad"),
    ("Kale and Quinoa Salad", "Mediterranean", "Salad"),

    # Sandwich
    ("Turkey Club Sandwich", "American", "Sandwich"),
    ("Mediterranean Veggie Wrap", "Mediterranean", "Sandwich"),
    ("Pulled Pork Sandwich", "American", "Sandwich"),

    # Italian
    ("Risotto Milanese", "Italian", "Italian"),
    ("Osso Buco", "Italian", "Italian"),
    ("Pesto Gnocchi", "Italian", "Italian"),

    # Japanese
    ("Tonkotsu Ramen", "Japanese", "Japanese"),
    ("Yakitori Skewers", "Japanese", "Japanese"),
    ("Matcha Cheesecake", "Japanese", "Dessert"),

    # Thai
    ("Massaman Curry", "Thai", "Thai"),
    ("Pad See Ew", "Thai", "Thai"),
    ("Sticky Rice with Mango", "Thai", "Dessert"),

    # Sushi
    ("Dragon Roll", "Japanese", "Sushi"),
    ("Salmon Sashimi", "Japanese", "Sushi"),
    ("Vegetable Maki Roll", "Japanese", "Sushi"),

    # Breakfast
    ("Egg and Bacon Sandwich", "American", "Breakfast"),
    ("French Toast", "American", "Breakfast"),
    ("Chia Seed Pudding", "Mediterranean", "Breakfast"),

    # American
    ("Buffalo Wings", "American", "American"),
    ("Mac and Cheese", "American", "American"),
    ("Cornbread", "American", "American"),

    # Vegetarian
    ("Stuffed Bell Peppers", "Mediterranean", "Vegetarian"),
    ("Eggplant Rollatini", "Italian", "Vegetarian"),
    ("Vegetable Biryani", "Indian", "Vegetarian"),

    # Indian
    ("Dal Tadka", "Indian", "Indian"),
    ("Butter Paneer", "Indian", "Indian"),
    ("Roti with Sabzi", "Indian", "Indian"),

    # Bakery
    ("Blueberry Muffins", "American", "Bakery"),
    ("Banana Bread", "American", "Bakery"),
    ("Baklava", "Mediterranean", "Bakery"),

    # Chicken
    ("Honey Garlic Chicken", "Asian", "Chicken"),
    ("Butter Chicken", "Indian", "Chicken"),
    ("Grilled Lemon Chicken", "Mediterranean", "Chicken"),

    # Asian
    ("Kimchi Pancakes", "Korean", "Asian"),
    ("General Tso’s Tofu", "Asian", "Asian"),
    ("Coconut Curry Noodles", "Asian", "Asian"),

    # Vegan
    ("Vegan Chili", "American", "Vegan"),
    ("Spaghetti with Vegan Meatballs", "Italian", "Vegan"),
    ("Thai Peanut Stir-Fry", "Thai", "Vegan"),

    # Lunch
    ("Chicken Caesar Wrap", "American", "Lunch"),
    ("Mediterranean Grain Bowl", "Mediterranean", "Lunch"),
    ("Vegan Sushi Bowl", "Japanese", "Lunch"),

    # Pasta
    ("Linguine with Clam Sauce", "Italian", "Pasta"),
    ("Baked Macaroni and Cheese", "American", "Pasta"),
    ("Spinach and Ricotta Ravioli", "Italian", "Pasta"),

    # Mexican
    ("Chorizo Tacos", "Mexican", "Mexican"),
    ("Chicken Enchiladas", "Mexican", "Mexican"),
    ("Vegetarian Nachos", "Mexican", "Mexican"),

    # Bowl
    ("Acai Bowl", "American", "Bowl"),
    ("Bibimbap", "Korean", "Bowl"),
    ("Quinoa Buddha Bowl", "Mediterranean", "Bowl"),

    # Mediterranean
    ("Greek Moussaka", "Mediterranean", "Mediterranean"),
    ("Hummus with Pita", "Mediterranean", "Mediterranean"),
    ("Stuffed Grape Leaves", "Mediterranean", "Mediterranean"),

    # Dessert
    ("Crème Brûlée", "French", "Dessert"),
    ("New York Cheesecake", "American", "Dessert"),
    ("Tartufo", "Italian", "Dessert"),
]



    user_password = hashed_password = generate_password_hash("password")

    for _ in range(50):
        user_pk = str(uuid.uuid4())
        restaurant_pk = str(uuid.uuid4())
        user_verified_at = random.choice([0,int(time.time())])


        user = {
            "user_pk" : user_pk,
            "user_name" : fake.first_name(),
            "user_last_name" : "",
            "user_email" : fake.unique.email(),
            "user_password" : user_password,
            "user_avatar" : "profile_"+ str(random.randint(1, 100)) +".jpg",
            "user_created_at" : int(time.time()),
            "user_deleted_at" : 0,
            "user_blocked_at" : 0,
            "user_updated_at" : 0,
            "user_verified_at" : user_verified_at,
            "user_verification_key" : str(uuid.uuid4()),
            "reset_key" : str(uuid.uuid4()),
            "token_expiry" : None
        }
        insert_user(user)

        cursor.execute("""
        INSERT INTO users_roles (
            user_role_user_fk,
            user_role_role_fk)
            VALUES (%s, %s)
        """, (user_pk, x.RESTAURANT_ROLE_PK))

        def random_copenhagen_address():
            streets = [
                "Nørrebrogade", "Østerbrogade", "Vesterbrogade", 
                "Amagerbrogade", "Frederiksborggade", "Gammel Kongevej",
                "Strandvejen", "Torvegade", "Istedgade", "Enghavevej"
            ]
            neighborhoods = [
                "Nørrebro", "Østerbro", "Vesterbro", "Amager", 
                "Frederiksberg", "Indre By", "Christianshavn", "Valby"
            ]
            street = random.choice(streets)
            neighborhood = random.choice(neighborhoods)
            street_number = random.randint(1, 200)  # Random house number
            return f"{street} {street_number}, {neighborhood}, Copenhagen"
        
           # Generate valid latitude and longitude within Copenhagen boundary
        latitude, longitude = generate_coordinates_within_boundary()

        cursor.execute("""
            INSERT INTO restaurants (restaurant_pk, restaurant_user_fk, restaurant_name, restaurant_address, restaurant_latitude, restaurant_longitude, restaurant_item_title, restaurant_item_cuisine_type, restaurant_item_food_category)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
                restaurant_pk,
                user_pk,
                fake.company(),
                random_copenhagen_address(),
                latitude,  # Use the generated latitude
                longitude, # Use the generated longitude
                None,  # Placeholder for restaurant_item_title
                None,  # Placeholder for restaurant_item_cuisine_type
                None   # Placeholder for restaurant_item_food_category
    ))

        
        item_titles = []
        item_cuisines = []
        item_categories = []

        for _ in range(random.randint(1, 2)):  # Random number of items
            dish = random.choice(dishes)
            item_pk = str(uuid.uuid4())
            item_title, item_cuisine_type, item_food_category = dish
            item_price = round(random.uniform(50, 150), 2)
            item_image = f"dish_{random.randint(1, 100)}.jpg"

            # Insert item into the items table
            cursor.execute("""
                            INSERT INTO items (
                            item_pk, item_user_fk, item_title, item_price, item_image, item_cuisine_type, item_food_category, item_created_at, item_updated_at, item_blocked_at
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (item_pk, user_pk, item_title, item_price, item_image, item_cuisine_type, item_food_category, int(time.time()), 0, 0))

            # Collect data for updating the restaurant
            item_titles.append(item_title)
            item_cuisines.append(item_cuisine_type)
            item_categories.append(item_food_category)

            cursor.execute("""
                UPDATE restaurants
                SET 
                    restaurant_item_title = %s,
                    restaurant_item_cuisine_type = %s,
                    restaurant_item_food_category = %s
                WHERE restaurant_pk = %s
            """, (
                ", ".join(item_titles),          # Concatenate all item titles
                ", ".join(set(item_cuisines)),   # Concatenate unique cuisine types
                ", ".join(set(item_categories)), # Concatenate unique food categories
                restaurant_pk                    # Restaurant primary key
            ))

        
            # Fetch a list of existing user_pks from the users table
            cursor.execute("SELECT user_pk FROM users")
            existing_users = [row["user_pk"] for row in cursor.fetchall()]

            # Ensure there are users available before proceeding
            if not existing_users:
                raise Exception("No users available in the database to assign as foreign keys to items.")

            for dish in dishes:
                item_pk = str(uuid.uuid4())
                item_title, item_cuisine_type, item_food_category = dish
                item_price = round(random.uniform(50, 150), 2)
                item_image = f"dish_{random.randint(1, 100)}.jpg"

                # Randomly assign an existing user as the foreign key
                item_user_fk = random.choice(existing_users)

                cursor.execute("""
                    INSERT INTO items (item_pk, item_user_fk, item_title, item_price, item_image, item_cuisine_type, item_food_category)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (item_pk, item_user_fk, item_title, item_price, item_image, item_cuisine_type, item_food_category))

                # Insert additional images into `item_images`
                for _ in range(2):  # Adding two additional images per item
                    image_pk = str(uuid.uuid4())
                    image_path = f"alt_{random.randint(1, 100)}_{item_image}"
                    cursor.execute("""
                                        INSERT INTO item_images (image_pk, item_fk, image_path, restaurant_fk, created_at)
                                        VALUES (%s, %s, %s, %s, %s)
                    """, (image_pk, item_pk, image_path, restaurant_pk, int(time.time())))


    db.commit()

except Exception as ex:
    ic(ex)
    if "db" in locals(): db.rollback()

finally:
    if "cursor" in locals(): cursor.close()
    if "db" in locals(): db.close()


