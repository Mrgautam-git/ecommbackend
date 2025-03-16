const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const app = express();
const port = 5000;
require('dotenv').config(); 
const firebaseAdmin = require("firebase-admin");
const bcrypt = require('bcrypt'); 
// Middleware
app.use(cors());
app.use(bodyParser.json()); // Parse JSON requests

const serviceAccount = {
  type: process.env.FIREBASE_TYPE,
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"), // Fix newline issue
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI,
  token_uri: process.env.FIREBASE_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER,
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT,
  universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN,
};

firebaseAdmin.initializeApp({
    credential: firebaseAdmin.credential.cert(serviceAccount),
});

// Create a connection to the database
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306, // Default MySQL port
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: true } : false 
});

// Connect to the database
db.connect((err) => {
  if (err) {
    console.error('Could not connect to the database:', err);
    process.exit(1);
  }
  console.log('Connected to the database');
});


// Fetch all categories for product selection
app.get('/categories', (req, res) => {
  const query = 'SELECT * FROM categories';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching categories:', err);
      return res.status(500).send('Error fetching categories');
    }
    res.json(results);
  });
});
app.get('/featured_product', (req, res) => {
  const query = 'SELECT * FROM featured_products;';  // Ensure SQL query has proper spacing

  // Execute the query on your database
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching featured products:', err);
      return res.status(500).send('Error fetching featured products');
    }
    res.json(results);
  });
});
// API to update search term count
app.post('/update-search', (req, res) => {
  const searchTerm = req.body.searchTerm;

  const query = `
      INSERT INTO popular_searches (search_term, search_count)
      VALUES (?, 1)
      ON DUPLICATE KEY UPDATE search_count = search_count + 1
  `;

  db.query(query, [searchTerm], (err) => {
      if (err) {
          return res.status(500).send('Error updating search count');
      }
      res.send('Search count updated successfully');
  });
});

// API to fetch popular search terms
app.get('/popular-searches', (req, res) => {
  const query = `
      SELECT search_term 
      FROM popular_searches 
      ORDER BY search_count DESC 
      LIMIT 5
  `;

  db.query(query, (err, results) => {
      if (err) {
          return res.status(500).send('Error fetching popular searches');
      }
      res.json(results);
  });
});


// Fetch all products (updated with category filtering)
app.get('/products', (req, res) => {
  const categoryId = req.query.category_id;
  const search = req.query.search ? req.query.search.toLowerCase() : ''; // Get the search term and convert to lowercase for case-insensitive search

  let query = `
    SELECT p.id, p.name, p.price, p.image_url
    FROM products p
    WHERE 1=1
  `;

  const queryParams = [];

  // If category_id is provided, add it to the query
  if (categoryId) {
      query += ` AND p.category_id = ?`;
      queryParams.push(categoryId);
  }

  // If search term is provided, add it to the query
  if (search) {
      query += ` AND (LOWER(p.name) LIKE ? OR LOWER(p.description) LIKE ?)`;
      queryParams.push(`%${search}%`, `%${search}%`);
  }

  // Execute the query with the constructed queryParams array
  db.query(query, queryParams, (err, results) => {
    if (err) {
      console.error('Error fetching products:', err);
      return res.status(500).send('Error fetching products');
    }
    res.json(results);
  });
})
//just for test>>>>***********************
app.get('/api/products/:productId', (req, res) => {
  const productId = req.params.productId; // Get the productId from the request parameters

  // SQL query to fetch the product details based on productId
  const query = 'SELECT * FROM products WHERE id = ?';

  db.query(query, [productId], (err, results) => {
    if (err) {
      console.error('Error fetching product details:', err);
      return res.status(500).json({ error: 'Failed to fetch product details' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const product = results[0]; // Assuming product exists
    res.status(200).json({
      name: product.name,
      price: product.price,
      description: product.description,
      category_id:product.category_id,
      image_url: product.image_url, // Assuming the product has an image_url field
    });
  });
});

// Add a new product
app.post('/products', (req, res) => {
  const { name, price, category_id } = req.body;
  const query = 'INSERT INTO products (name, price, category_id) VALUES (?, ?, ?)';
  
  db.query(query, [name, price, category_id], (err, result) => {
    if (err) {
      console.error('Error inserting product:', err);
      return res.status(500).send('Error inserting product');
    }
    res.json({ id: result.insertId, name, price, category_id });
  });
});

// Update a product
app.put('/products/:id', (req, res) => {
  const { name, price, category_id } = req.body;
  const query = 'UPDATE products SET name = ?, price = ?, category_id = ? WHERE id = ?';
  
  db.query(query, [name, price, category_id, req.params.id], (err, result) => {
    if (err) {
      console.error('Error updating product:', err);
      return res.status(500).send('Error updating product');
    }
    res.json({ id: req.params.id, name, price, category_id });
  });
});

// Delete a product
app.delete('/products/:id', (req, res) => {
  const query = 'DELETE FROM products WHERE id = ?';
  
  db.query(query, [req.params.id], (err, result) => {
    if (err) {
      console.error('Error deleting product:', err);
      return res.status(500).send('Error deleting product');
    }
    res.json({ message: 'Product deleted successfully' });
  });
});

// Remove an item from the cart
// Delete item from cart
app.get('/api/profiles', (req, res) => {
  const userId = 1;  // Replace with the logged-in user's ID
  db.query('SELECT name, email, address FROM users WHERE id = ?', [userId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Error fetching profile data' });
    }
    if (results.length > 0) {
      res.json(results[0]);
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  });
});
// PUT route to update user profile
app.put('/api/profiles', (req, res) => {
  const { name, email, address } = req.body;
  const userId = 1;  // Replace with the logged-in user's ID

  db.query(
    'UPDATE users SET name = ?, email = ?, address = ? WHERE id = ?',
    [name, email, address, userId],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: 'Error updating profile' });
      }
      res.json({ message: 'Profile updated successfully' });
    }
  );
});
app.post('/users', async (req, res) => {
  const { firebase_user_id, email } = req.body;

  // Add logic to check if user exists in the database
  const query = 'SELECT * FROM users WHERE firebase_user_id = ?';
  db.query(query, [firebase_user_id], (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Error fetching user data' });
    }

    if (results.length > 0) {
      return res.status(200).json({ message: 'User found' });
    } else {
      return res.status(404).json({ message: 'User not found' });
    }
  });
});

// Sign up (register new user)
app.get('/users', async (req, res) => {
  const firebaseToken = req.headers['firebase-token'];

  try {
    if (!firebaseToken) {
      return res.status(400).json({ message: 'Firebase token is required' });
    }

    // Verify Firebase Token
    const decodedToken = await admin.auth().verifyIdToken(firebaseToken);
    const firebaseUserId = decodedToken.uid;

    // Query to fetch user-related data
    const query = `
      SELECT 
        cart.product_id AS cart_product_id, 
        cart.quantity AS cart_quantity, 
        wishlist.product_id AS wishlist_product_id,
        payment_methods.card_number, 
        payment_methods.card_holder_name,
        addresses.address_line1, 
        addresses.city
      FROM users
      LEFT JOIN cart ON users.firebase_user_id = cart.firebase_user_id
      LEFT JOIN wishlist ON users.firebase_user_id = wishlist.firebase_user_id
      LEFT JOIN payment_methods ON users.firebase_user_id = payment_methods.firebase_user_id
      LEFT JOIN addresses ON users.firebase_user_id = addresses.firebase_user_id
      WHERE users.firebase_user_id = ?;
    `;

    db.query(query, [firebaseUserId], (err, results) => {
      if (err) {
        console.error('Database query error:', err);
        return res.status(500).json({ message: 'Error fetching user data' });
      }

      // If no results found for the user, return an empty data object
      if (results.length === 0) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Structure the response data for better readability
      const userData = {
        cart: results.filter(item => item.cart_product_id).map(item => ({
          product_id: item.cart_product_id,
          quantity: item.cart_quantity,
        })),
        wishlist: results.filter(item => item.wishlist_product_id).map(item => item.wishlist_product_id),
        payment_methods: results.filter(item => item.card_number).map(item => ({
          card_number: item.card_number,
          card_holder_name: item.card_holder_name,
        })),
        addresses: results.filter(item => item.address_line1).map(item => ({
          address_line1: item.address_line1,
          city: item.city,
        })),
      };

      res.status(200).json(userData);
    });
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(401).json({ message: 'Unauthorized' });
  }
});
app.get('/users', (req, res) => {
  const query = 'SELECT * FROM users';

  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching users data:', err);
      return res.status(500).json({ message: 'Error fetching users data' });
    }
    res.json(results);
  });
});

// 2. Create a new user (Create)
app.post('/users', (req, res) => {
  const { name, email, age, address } = req.body;
  const query = 'INSERT INTO users (name, email, age, address) VALUES (?, ?, ?, ?)';
  const values = [name, email, age, address];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Error creating user:', err);
      return res.status(500).json({ message: 'Error creating user' });
    }
    res.status(201).json({ message: 'User created successfully', userId: result.insertId });
  });
});

// 3. Update a user (Update)
app.put('/users/:id', (req, res) => {
  const userId = req.params.id;
  const { name, email, age, address } = req.body;
  const query = 'UPDATE users SET name = ?, email = ?, age = ?, address = ? WHERE id = ?';
  const values = [name, email, age, address, userId];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Error updating user:', err);
      return res.status(500).json({ message: 'Error updating user' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User updated successfully' });
  });
});

// 4. Delete a user (Delete)
app.delete('/users/:id', (req, res) => {
  const userId = req.params.id;
  const query = 'DELETE FROM users WHERE id = ?';

  db.query(query, [userId], (err, result) => {
    if (err) {
      console.error('Error deleting user:', err);
      return res.status(500).json({ message: 'Error deleting user' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  });
});

app.get('/cart', async (req, res) => {
  const userId = req.query.userId;
  if (!userId) {
    return res.status(400).json({ error: 'User ID is required' });
  }

  try {
    // Fetch cart items for the user
    const cartItems = await Cart.find({ userId });

    if (cartItems.length === 0) {
      return res.status(404).json({ message: 'No items found in cart' });
    }

    return res.json({ cart: cartItems });
  } catch (error) {
    console.error('Error fetching cart items:', error);
    return res.status(500).json({ error: 'Failed to fetch cart items' });
  }
});

app.get('/api/cart', (req, res) => {
  const userId = req.query.userId;
  console.log('Received userId:', userId);

  if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
  }

  const query = 'SELECT * FROM cart WHERE firebase_user_id = ?';
  db.query(query, [userId], (err, results) => {
      if (err) {
          console.error('Error fetching cart items:', err);
          return res.status(500).json({ error: 'Failed to fetch cart items' });
      }
      res.status(200).json(results);
  });
});


app.put('/cart/:id', (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;

  // Check if quantity is valid
  if (!quantity || quantity <= 0) {
    return res.status(400).json({ message: 'Invalid quantity' });
  }

  // Example: Update the item in the database (pseudo-code)
  db.query('UPDATE cart SET quantity = ? WHERE id = ?', [quantity, id], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Error updating quantity' });
    }

    res.json({ message: 'Quantity updated successfully', id, quantity });
  });
});

app.delete('/cart/:id', (req, res) => {
  const itemId = parseInt(req.params.id); // Convert id to integer
  console.log('Deleting item with ID:', itemId);

  const sqlQuery = 'DELETE FROM cart WHERE id = ?';

  db.query(sqlQuery, [itemId], (err, result) => {
      if (err) {
          console.error('Error deleting item:', err);
          res.status(500).send({ message: 'Failed to delete item from the cart' });
      } else {
          console.log('SQL Result:', result);
          if (result.affectedRows > 0) {
              res.send({ message: `Item with ID ${itemId} deleted successfully` });
          } else {
              res.status(404).send({ message: `Item with ID ${itemId} not found` });
          }
      }
  });
});

// Ensure you have the database connection set up in a `db` module
app.post('/api/cart', async (req, res) => {
  const { firebase_user_id, user_id, product_id, quantity } = req.body; // Extract data from the request body
  // Log the received data for debugging
  console.log("Received Data:", req.body);
  // Validate cart data from the body
  if (!user_id || !product_id || !quantity) {
    return res.status(400).json({ error: 'userId, productId, and quantity are required' });
  }
  // Check if quantity is a positive integer
  if (quantity <= 0 || !Number.isInteger(quantity)) {
    return res.status(400).json({ error: 'Quantity must be a positive integer' });
  }
  // Validate Firebase user ID
  if (!firebase_user_id) {
    return res.status(400).json({ error: 'Firebase user ID is required' });
  }
  try {
    // Check if the product already exists in the cart for the given user
    const checkQuery = `
      SELECT * FROM cart WHERE firebase_user_id = ? AND user_id = ? AND product_id = ?
    `;
    // Query to check if the product exists in the cart
    db.query(checkQuery, [firebase_user_id, user_id, product_id], (err, result) => {
      if (err) {
        console.error('Error checking if product exists in cart:', err);
        return res.status(500).json({ message: 'Failed to check product in cart' });
      }

      if (result.length > 0) {
        // Product exists in the cart, update the quantity
        const newQuantity = result[0].quantity + quantity;

        const updateQuery = `
          UPDATE cart SET quantity = ? WHERE firebase_user_id = ? AND user_id = ? AND product_id = ?
        `;

        db.query(updateQuery, [newQuantity, firebase_user_id, user_id, product_id], (updateErr, updateResult) => {
          if (updateErr) {
            console.error('Error updating cart quantity:', updateErr);
            return res.status(500).json({ message: 'Failed to update cart quantity' });
          }

          // Return the success response after updating the quantity
          res.status(200).json({
            message: 'Product quantity updated successfully',
            data: {
              cart_id: result[0].id,
              firebase_user_id,
              user_id,
              product_id,
              quantity: newQuantity,
            },
          });
        });
      } else {
        // Product doesn't exist in the cart, insert a new product
        const insertQuery = `
          INSERT INTO cart (firebase_user_id, user_id, product_id, quantity)
          VALUES (?, ?, ?, ?)
        `;

        db.query(insertQuery, [firebase_user_id, user_id, product_id, quantity], (insertErr, insertResult) => {
          if (insertErr) {
            console.error('Error inserting data into cart:', insertErr);
            return res.status(500).json({ message: 'Failed to add product to cart' });
          }

          // Return the success response after inserting the product
          res.status(200).json({
            message: 'Product added to cart successfully',
            data: {
              cart_id: insertResult.insertId,
              firebase_user_id,
              user_id,
              product_id,
              quantity,
            },
          });
        });
      }
    });
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({ message: 'An error occurred while adding the product to the cart' });
  }
});

app.post('/api/signup', async (req, res) => {
  // Destructuring fields from the request body
  const { firebase_user_id, username, email, password } = req.body;

  // Input validation
  if (!firebase_user_id || !username || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  // Check if email or firebase_user_id already exists in the database
  const checkQuery = 'SELECT * FROM users WHERE email = ? OR firebase_user_id = ?';
  db.query(checkQuery, [email, firebase_user_id], async (err, result) => {
    if (err) {
      console.error('Database error during check:', err.message);
      return res.status(500).json({ message: 'Server error' });
    }

    if (result.length > 0) {
      return res.status(409).json({ message: 'Email or Firebase ID already exists' });
    }

    try {
      // Hash the password before storing it in the database
      const hashedPassword = await bcrypt.hash(password, 10);

      // SQL query to insert new user
      const insertQuery = `
        INSERT INTO users (firebase_user_id, username, email, password)
        VALUES (?, ?, ?, ?)
      `;
      db.query(insertQuery, [firebase_user_id, username, email, hashedPassword], (err, result) => {
        if (err) {
          console.error('Error inserting user:', err.message); // Detailed error logging
          return res.status(500).json({ message: 'Server error' });
        }

        // Successful signup response
        res.status(201).json({ message: 'User signed up successfully' });
      });
    } catch (error) {
      console.error('Error during password hashing or user insertion:', error.message);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], async (err, results) => {
      if (results.length === 0) {
        return res.status(400).json({ error: 'User not found' });
      }
      
      const user = results[0];
      const passwordMatch = await bcrypt.compare(password, user.password);
      
      if (!passwordMatch) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }

      // Send user data along with a token
      return res.status(200).json({
        message: 'Login successful',
        user: { id: user.id, email: user.email, username: user.username }
      });
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});


app.put("/payment_methods", async (req, res) => {
  const { user_id, paymentMethods } = req.body;

  // Validate input
  if (!user_id || !paymentMethods) {
      return res.status(400).json({ message: 'User ID and payment methods are required.' });
  }

  try {
      // Update the payment methods in the payment_methods table
      db.query(
          "UPDATE payment_methods SET payment_methods = ? WHERE user_id = ?",
          [JSON.stringify(paymentMethods), user_id],
          (err, result) => {
              if (err) {
                  console.error(err);
                  return res.status(500).json({ message: 'Error updating payment methods.' });
              }
              if (result.affectedRows === 0) {
                  return res.status(404).json({ message: 'User not found.' });
              }
              res.status(200).json({ message: 'Payment methods updated successfully.' });
          }
      );
  } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Internal Server Error' });
  }
});
// POST: Add a new address

app.post('/api/addresses', async (req, res) => {
  const { user_id, firebase_user_id, address, city, state, zip_code, country, fullName } = req.body;

  console.log("Received address data:", req.body);

  // Validate required fields
  if (!user_id || !firebase_user_id || !address || !city || !state || !zip_code || !country || !fullName) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    // Insert the address into the database
    const insertQuery = `
      INSERT INTO addresses (user_id, firebase_user_id, address, city, state, zip_code, country, fullName)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(
      insertQuery,
      [user_id, firebase_user_id, address, city, state, zip_code, country, fullName],
      (insertErr, insertResult) => {
        if (insertErr) {
          console.error('Error inserting address:', insertErr);
          return res.status(500).json({ message: 'Failed to insert address' });
        }

        return res.status(200).json({
          message: 'Address added successfully',
          data: {
            user_id,
            firebase_user_id,
            address,
            city,
            state,
            zip_code,
            country,
            fullName,
          },
        });
      }
    );
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({ message: 'An error occurred while handling the address' });
  }
});


// Read Address (GET)
app.get('/api/addresses', (req, res) => {
  const { userId } = req.query;

  const query = 'SELECT * FROM addresses WHERE firebase_user_id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Failed to fetch address');
    }
    if (results.length === 0) {
      return res.status(404).send('No address found for this user');
    }
    res.status(200).json(results[0]);
  });
});

// Update Address (PUT)
app.put('/api/addresses/update', (req, res) => {
  const { user_id, fullName, streetAddress, city, state, zipCode, country } = req.body;

  const query = 'UPDATE addresses SET fullName = ?, streetAddress = ?, city = ?, state = ?, zipCode = ?, country = ? WHERE firebase_user_id = ?';
  db.query(query, [fullName, streetAddress, city, state, zipCode, country, user_id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Failed to update address');
    }
    if (results.affectedRows === 0) {
      return res.status(404).send('Address not found for this user');
    }
    res.status(200).send('Address updated successfully');
  });
});

// Delete Address (DELETE)
app.delete('api/addresses/:id', (req, res) => {
  const addressId = parseInt(req.params.id); // Convert id to integer
  console.log('Deleting address with ID:', addressId);

  const sqlQuery = 'DELETE FROM addresses WHERE id = ?';

  db.query(sqlQuery, [addressId], (err, result) => {
    if (err) {
      console.error('Error deleting address:', err);
      res.status(500).send({ message: 'Failed to delete address' });
    } else {
      console.log('SQL Result:', result);
      if (result.affectedRows > 0) {
        res.send({ message: `Address with ID ${addressId} deleted successfully` });
      } else {
        res.status(404).send({ message: `Address with ID ${addressId} not found` });
      }
    }
  });
});




// Create Order (POST)
app.post('/api/orders', async (req, res) => {
  const firebaseToken = req.body;
  const { shippingAddress, items } = req.body; // Items should include product IDs and quantities

  // Validate input
  if (!firebaseToken) {
    return res.status(401).json({ message: 'Firebase token is required.' });
  }
  if (!shippingAddress || !items || items.length === 0) {
    return res.status(400).json({ message: 'Shipping address and items are required.' });
  }

  for (let item of items) {
    if (!item.price || !item.quantity) {
      return res.status(400).json({ message: 'Each item must have a price and quantity.' });
    }
  }

  try {
    // Verify Firebase Token
    
    const firebaseUserId = req.body;

    // Calculate total price
    const totalPrice = items.reduce((sum, item) => sum + item.price * item.quantity, 0);

    // Insert order into 'orders' table
    const orderQuery = `
      INSERT INTO orders (firebase_user_id, total_price, order_status, shipping_address, payment_status)
      VALUES (?, ?, 'pending', ?, 'pending');
    `;

    db.query(orderQuery, [firebaseUserId, totalPrice, shippingAddress], (err, result) => {
      if (err) {
        console.error('Error inserting order:', err);
        return res.status(500).json({ message: 'Error creating order' });
      }

      const orderId = result.insertId;

      // Insert order items into 'order_items' table
      const orderItemsQuery = `
        INSERT INTO order_items (order_id, product_id, quantity, price)
        VALUES ?
      `;

      const values = items.map(item => [orderId, item.productId, item.quantity, item.price]);

      db.query(orderItemsQuery, [values], (err) => {
        if (err) {
          console.error('Error inserting order items:', err);
          return res.status(500).json({ message: 'Error adding order items' });
        }

        res.status(200).json({ message: 'Order created successfully', orderId });
      });
    });
  } catch (error) {
    console.error('Firebase token verification error:', error);
    res.status(401).json({ message: 'Unauthorized' });
  }
});

// Get Orders (GET)
app.get('/api/orders', async (req, res) => {
  const firebaseToken = req.body;

  // Validate Firebase token
  if (!firebaseToken) {
    return res.status(400).json({ message: 'Firebase token is required.' });
  }

  try {
    // Verify Firebase Token
   
    const firebaseUserId = req.body;

    // Query to fetch orders and associated items
    const orderQuery = `
      SELECT 
        orders.id AS order_id, 
        orders.order_date, 
        orders.total_price, 
        orders.order_status,
        orders.shipping_address, 
        orders.payment_status, 
        order_items.product_id, 
        order_items.quantity, 
        order_items.price
      FROM orders
      LEFT JOIN order_items ON orders.id = order_items.order_id
      WHERE orders.firebase_user_id = ?;
    `;

    db.query(orderQuery, [firebaseUserId], (err, results) => {
      if (err) {
        console.error('Error fetching orders:', err);
        return res.status(500).json({ message: 'Error fetching orders' });
      }

      res.status(200).json({ orders: results });
    });
  } catch (error) {
    console.error('Firebase token verification error:', error);
    res.status(401).json({ message: 'Unauthorized' });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
