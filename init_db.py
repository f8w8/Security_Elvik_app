# init_db.py

import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash

# connect to database file
connection = sqlite3.connect('database.db')

# read and execute schema file
with open('schema.sql') as f:
    connection.executescript(f.read())

# create cursor for executing commands
cur = connection.cursor()

# add default admin user
admin_password = generate_password_hash('admin123', method='pbkdf2:sha256')
current_time = datetime.now().isoformat()

cur.execute("INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            ('Admin', 'admin@admin.com', admin_password, 'admin', current_time)
            )

# add sample seller users
seller1_password = generate_password_hash('seller123', method='pbkdf2:sha256')
cur.execute("INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            ('John Electronics', 'john@sellers.com', seller1_password, 'seller', current_time)
            )

seller2_password = generate_password_hash('seller123', method='pbkdf2:sha256')
cur.execute("INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            ('Sarah Fashion', 'sarah@sellers.com', seller2_password, 'seller', current_time)
            )

seller3_password = generate_password_hash('seller123', method='pbkdf2:sha256')
cur.execute("INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            ('Mike Sports', 'mike@sellers.com', seller3_password, 'seller', current_time)
            )

# add sample customer user
customer_password = generate_password_hash('Turki123', method='pbkdf2:sha256')
cur.execute("INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            ('Turki', 'turki@gmail.com', customer_password, 'customer', current_time)
            )

# add sample products for seller 1 (John Electronics) - with local image paths
cur.execute("INSERT INTO products (seller_id, title, description, price, stock, image_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (2, 'Wireless Mouse', 'Ergonomic wireless mouse with USB receiver', 24.99, 45, 'uploads/20251126_172650_Screenshot_2025-11-26_172633.png', current_time)
            )

cur.execute("INSERT INTO products (seller_id, title, description, price, stock, image_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (2, 'Bluetooth Headphones', 'High-quality over-ear headphones with noise cancellation', 79.99, 30, 'uploads/20251126_172416_Screenshot_2025-11-26_172355.png', current_time)
            )

cur.execute("INSERT INTO products (seller_id, title, description, price, stock, image_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (2, 'USB-C Hub', '7-in-1 USB-C hub with HDMI and USB 3.0 ports', 39.99, 25, 'uploads/20251126_172759_Screenshot_2025-11-26_172747.png', current_time)
            )

# add sample products for seller 2 (Sarah Fashion) - with local image paths
cur.execute("INSERT INTO products (seller_id, title, description, price, stock, image_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (3, 'Classic T-Shirt', 'Comfortable 100% cotton t-shirt', 15.99, 100, 'uploads/20251126_173049_Screenshot_2025-11-26_173034.png', current_time)
            )

cur.execute("INSERT INTO products (seller_id, title, description, price, stock, image_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (3, 'Denim Jeans', 'Classic fit denim jeans, premium quality', 49.99, 60, 'uploads/20251126_173140_81mowFVrlRL._AC_SY606_.jpg', current_time)
            )

cur.execute("INSERT INTO products (seller_id, title, description, price, stock, image_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (3, 'Summer Dress', 'Elegant floral print summer dress', 59.99, 35, 'uploads/20251126_173420_Screenshot_2025-11-26_173413.png', current_time)
            )

# add sample products for seller 3 (Mike Sports) - with local image paths
cur.execute("INSERT INTO products (seller_id, title, description, price, stock, image_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (4, 'Yoga Mat', 'Non-slip yoga mat with carrying strap', 29.99, 50, 'uploads/20251126_173702_81geiKjPW6L._AC_SX679_.jpg', current_time)
            )

cur.execute("INSERT INTO products (seller_id, title, description, price, stock, image_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (4, 'Water Bottle', 'Insulated stainless steel water bottle, 750ml', 19.99, 80, 'uploads/20251126_174648_kx8390-water-bottle-750ml.jpg', current_time)
            )

cur.execute("INSERT INTO products (seller_id, title, description, price, stock, image_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (4, 'Resistance Bands Set', 'Set of 5 resistance bands with different strengths', 24.99, 40, 'uploads/20251126_173903_518DBe7OlrL._AC_SY300_SX300_QL70_ML2_.jpg', current_time)
            )

# save changes and close connection
connection.commit()
connection.close()

print("Database initialized successfully!")
print("Admin login: admin@admin.com / admin123")
print("Seller logins: john@sellers.com, sarah@sellers.com, mike@sellers.com / seller123")
print("Customer login: turki@gmail.com / Turki123")
