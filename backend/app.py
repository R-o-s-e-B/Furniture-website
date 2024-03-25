import pyotp
from flask import Flask, request, session, jsonify, redirect, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from sqlalchemy import Column, Integer, ForeignKey
import stripe
import os
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_cors import CORS, cross_origin
import smtplib
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import time


stripe_keys = {
    "secret_key": "sk_test_51NJVpSSFpxiZ4LwaVAZ2B78eR4zcTloarIfPpZyCsOATjl07vRJ9gccbDp9fh7XuBF7N755DnbxfqXmw4QhoYSBA00vPMZKfVM",
    "publishable_key": "pk_test_51NJVpSSFpxiZ4LwaEkFCrzZUK5QnV0BnPyZWbFikuyZSQgF7cKMmIRO0Fs8Nv0P15tenpLgORJPg1oO96UUQBxh8006pudQNTr",
}

stripe.api_key = stripe_keys["secret_key"]
verification_code = None


def generate_otp():
    totp = pyotp.TOTP(pyotp.random_base32())
    otp = totp.now()
    print(otp)
    return otp


# secret_key = '\x03JH\xba\x0f\xf1\xe4\xc0\x86\xd7\xc8\xdd\xdb\x13\xd1Z[+\x10\xd5/{n\xd7'
my_email = "Rosebobbyofficial@gmail.com"
my_password = "ldjacsjrbaewfgla"

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://postgres:{'Zora123'}@localhost/furniture"

app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
app.config['SECRET_KEY'] = "my_secret_key_ig"


db = SQLAlchemy(app)
CORS(app, supports_credentials=True, origins=['http://localhost:3000'])

stripe.api_key = "sk_test_tR3PYbcVNZZ796tH88S4VQ2u"

GOOGLE_CLIENT_ID = "103595653306-rbb96utet96pjkvvlgc3vvo7jocfea7b.apps.googleusercontent.com"

flow = Flow.from_client_secrets_file(client_secrets_file="client_secret.json",
                                     scopes=["https://www.googleapis.com/auth/userinfo.profile",
                                             "https://www.googleapis.com/auth/userinfo.email", "openid"],
                                     redirect_uri="https://127.0.0.1:5000/login/google/authorized")


login_manager = LoginManager()
login_manager.init_app(app)


bcrypt = Bcrypt(app)


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(user_id)
    except:
        return None


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=True,
                         unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=True)
    google_identifier = db.Column(db.String(255), nullable=True, unique=True)
    facebook_identifier = db.Column(db.String(255), nullable=True, unique=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    order = relationship("User_order", back_populates="user")
    cart = relationship("Cart_item", back_populates="user")
    addresses = relationship("Address", back_populates="user")
    user_reviews = relationship("Review", back_populates="user")

    def get_id(self):
        return self.id

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def set_password(self, password):
        # Generate a salt and hash the password using bcrypt
        self.password_hash = bcrypt.generate_password_hash(
            password).decode('utf-8')

    def check_password(self, password):
        # Check if the provided password matches the stored password hash
        return bcrypt.check_password_hash(self.password_hash, password)


class Product(db.Model):
    __tablename__ = 'products'

    product_id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100))
    price = db.Column(db.Numeric(precision=10, scale=2), nullable=False)
    description = db.Column(db.Text)
    images = db.Column(db.ARRAY(db.String))  # Array of image URLs
    # Rating for the product
    times_bought = db.Column(db.Integer)
    category = db.Column(db.String(50))
    stripe_price_id = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    customization = relationship(
        "Product_Customization", back_populates="products")
    product_reviews = relationship("Review", back_populates="product")


class Product_Customization(db.Model):
    __tablename__ = 'customization'

    customization_id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, ForeignKey('products.product_id'))
    cstm_name = db.Column(db.String(50))  # color, size, material etc
    type = db.Column(db.String(50))  # select, radio or checkbox
    is_required = db.Column(db.Boolean)
    # choose from colors etc, mostly a list or an array
    options = db.Column(db.ARRAY(db.String))
    default_option = db.Column(db.String(50))
    images = db.Column(db.JSON)  # images available for option, in json format
    products = relationship("Product", back_populates="customization")


class User_order(db.Model):
    __tablename__ = 'user_order'
    order_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    order_date = db.Column(db.DateTime, default=datetime.utcnow)
    total_amount = db.Column(db.Numeric(precision=10, scale=2), nullable=False)
    status = db.Column(db.String(50))
    user = relationship("User", back_populates="order")
    cart = relationship("Cart_item", back_populates="user_order")


class Cart_item(db.Model):
    __tablename__ = 'cart'
    order_item_id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, ForeignKey('user_order.order_id'))
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    quantity = db.Column(db.Integer)
    # price_1NcoeLJAJfZb9HEBPQjbIQLF
    stripe_price_id = db.Column(db.String(50))
    customizations = db.Column(db.JSON)
    user_order = relationship("User_order", back_populates="cart")
    user = relationship("User", back_populates="cart")


class Verification_code(db.Model):
    __tablename__ = 'code'
    id = db.Column(db.Integer, primary_key=True)
    vrfctn_code = db.Column(db.String(20), nullable=True)


class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    full_name = db.Column(db.String(100))
    mobile_no = db.Column(db.String(20))
    pincode = db.Column(db.String(10))
    flat_house_no = db.Column(db.String(100))
    area_sector_village = db.Column(db.String(100))
    landmark = db.Column(db.String(100))
    town = db.Column(db.String(100))
    state = db.Column(db.String(100))
    user = relationship("User", back_populates="addresses")


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, ForeignKey('products.product_id'))
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    rating = db.Column(db.Float)
    review_text = db.Column(db.Text)
    review_date = db.Column(db.DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="user_reviews")
    product = relationship("Product", back_populates="product_reviews")


# with app.app_context():
#     db.create_all()


@app.route('/')
def hello():
    return 'hey'


@app.route('/addAddress', methods=['POST'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def add_address():
    new_address = Address()
    new_address.user_id = request.json['user_id']
    new_address.full_name = request.json['full_name']
    new_address.mobile_no = request.json['mobile_no']
    new_address.pincode = request.json['pincode']
    new_address.area_sector_village = request.json['area']
    new_address.flat_house_no = request.json['flat']
    new_address.landmark = request.json['landmark']
    new_address.town = request.json['town']
    new_address.state = request.json['state']
    db.session.add(new_address)

    try:
        db.session.commit()
        return jsonify({'message': "Address added successfully"}), 200
    except:
        return jsonify({'message': "Something went wrong"})


@app.route('/getAddress', methods=['GET'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def get_addresses():
    id = request.args.get('id')

    addresses = Address.query.filter_by(user_id=id).all()
    address_list = [
        {
            'id': i.id,
            'user_id': i.user_id,
            'full_name': i.full_name,
            'mobile_no': i.mobile_no,
            'pincode': i.pincode,
            'flat_house_no': i.flat_house_no,
            'area_sector_village': i.area_sector_village,
            'landmark': i.landmark,
            'town': i.town,
            'state': i.state,
        }
        for i in addresses
    ]

    print(address_list)
    if len(address_list) != 0:
        return address_list
    else:
        return {'message': 'You have no addresses'}


@app.route('/deleteCart', methods=['DELETE'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def delete_from_cart():
    id = request.args.get('id')
    item_to_del = Cart_item.query.get(id)
    if item_to_del:
        db.session.delete(item_to_del)
        db.session.commit()
        return jsonify({'status': 'success'})
    else:
        return jsonify({'status': 'failure'})


@app.route('/checkout', methods=['POST'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def create_checkout_session():
    total_amount = 0
    try:
        item_to_del = Cart_item.query.all()
        all_products = Product.query.all()  # Fetch all products

        checkout_line_items = []

        for cart_item in item_to_del:
            if cart_item.user_id == current_user.id:
                # Find the corresponding product for the cart item
                corresponding_product = next(
                    (product for product in all_products if product.stripe_price_id ==
                     cart_item.stripe_price_id), None
                )
                if corresponding_product:
                    checkout_line_items.append(
                        {
                            'price': corresponding_product.stripe_price_id,
                            'quantity': cart_item.quantity,
                        }
                    )
                    new_order = User_order()
                    new_order.user_id = current_user.id
                    total_amount += corresponding_product.price * cart_item.quantity
                    new_order.total_amount = total_amount
                    new_order.status = "Success"
                    db.session.add(new_order)
                else:
                    print(
                        f"Corresponding product not found for cart item: {cart_item.order_item_id}")

                db.session.delete(cart_item)

        db.session.commit()

        checkout_session = stripe.checkout.Session.create(
            line_items=checkout_line_items,
            mode='payment',
            success_url="http://localhost:3000/cart",
            cancel_url="http://localhost:3000/cart",
        )

    except Exception as e:
        return str(e)

    return jsonify({'url': checkout_session.url})


@app.route('/productToCart', methods=['POST'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def add_to_cart():
    if current_user.is_authenticated:
        count = 0
        add = 0
        quantity = 0
        new_cart_item = Cart_item()

        existing_product = Cart_item.query.filter_by(
            order_item_id=request.json.get("item_id")).first()
        if existing_product:
            count = existing_product.quantity
            add = request.json.get('quantity')
            quantity = count + add
            existing_product.quantity = quantity
        else:
            new_cart_item.order_item_id = request.json.get("item_id")
            new_cart_item.user_id = current_user.id
            new_cart_item.quantity = request.json.get('quantity')
            new_cart_item.customizations = request.json.get('customizations')

            new_cart_item.stripe_price_id = request.json.get('stripe_id')
            db.session.add(new_cart_item)
        db.session.commit()

        response = {
            "status": "success"
        }
    else:
        response = {
            "status": "failed",
            "message": "Not logged in"
        }
    return response


@app.route('/cart', methods=['GET'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def cart():
    if current_user.is_authenticated:
        user_id = current_user.id  # current_user.id
        my_items = []
        cart_items = Cart_item.query.all()

        # Convert the list of Cart_item objects to a JSON-serializable format
        my_items = [
            {
                "order_item_id": item.order_item_id,
                "user_id": item.user_id,
                "quantity": item.quantity,
                "customizations": item.customizations
            }
            for item in cart_items
        ]

        response = {
            "status": "success",
            "items": my_items
        }
    else:
        response = {
            "status": "failed"
        }

    return jsonify(response)  # Use jsonify to convert the response to JSON


@app.route('/login', methods=['POST'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def login():

    email = request.json['email']
    password = request.json['password']
    print(email, password)

    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):

        login_user(user)

        response_data = {
            'status': 'success',
            'message': 'Login successful',
        }
    elif not user:
        response_data = {
            'status': 'failed',
            'message': 'This account does not exist, register instead',
        }
    elif not user.check_password(password):
        response_data = {
            'status': 'failed',
            'message': 'Wrong password, try again',
        }

    return jsonify(response_data)


@app.route('/login/google')
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def google_login():
    authorization_url, state = flow.authorization_url()
    session['state'] = state

    return redirect(authorization_url)


@app.route("/login/google/authorized")
@cross_origin(supports_credentials=True)
def google_authorized():
    flow.fetch_token(authorization_response=request.url,
                     origins=['http://localhost:3000'])
    if not session['state'] == request.args['state']:
        abort(500)

    credentials = flow.credentials
    token_request = google_requests.Request()

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    print(id_info)
    email = id_info['email']
    print(email)
    first_name = id_info['given_name']
    last_name = id_info['family_name']
    print(first_name)
    id = id_info['sub']
    user_name = id_info['name']
    print(id)
    user = User.query.filter_by(email=email).first()
    if not user:
        new_user = User()
        new_user.first_name = first_name
        new_user.last_name = last_name
        new_user.email = email
        new_user.username = user_name
        new_user.google_identifier = id
        new_user.set_password(id)

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)

        print("new user logged in")

    else:

        login_user(user)

        print("existing user logged in")
    if current_user.is_authenticated:

        print("authenticated in login")

    return redirect("http://localhost:3000")


@app.route('/check_login_status', methods=['GET'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def check_login_status():
    # Check if the user is logged in

    if current_user.is_authenticated:
        print("is authenticated")
        return jsonify({'loggedIn': True, 'user': current_user.first_name, 'id': current_user.id})
    else:
        print('not authenticated')
        return jsonify({'loggedIn': False})


@app.route('/verify_mail', methods=['POST'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def verify_mail():

    if request.method == 'POST':
        email = request.json.get('email')
        code = Verification_code()
        code.vrfctn_code = generate_otp()
        print(code.vrfctn_code)

        connection = smtplib.SMTP("smtp.gmail.com")
        connection.starttls()
        connection.login(user=my_email, password=my_password)
        connection.sendmail(from_addr=my_email,
                            to_addrs=email,
                            msg=f"Your verification code is {code.vrfctn_code}")
        connection.close()

        db.session.add(code)
        db.session.commit()

        response_data = {
            'status': 'success',
            'message': 'Verification code sent successfully.',
        }

        return jsonify(response_data)


@app.route('/signup', methods=['POST'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def signup():
    code = request.json.get('code')

    verification_code = Verification_code.query.filter_by(
        vrfctn_code=code).first()

    print(verification_code)
    if verification_code:

        # The user has been verified, proceed with user registration
        new_user = User()
        new_user.email = request.json['email']
        new_user.first_name = request.json['firstName']
        new_user.last_name = request.json['lastName']
        new_user.username = request.json['username']

        new_user.set_password(request.json['password'])
        db.session.add(new_user)

        db.session.delete(verification_code)
        db.session.commit()

        # Remove the verification code from the session

        response_data = {
            'status': 'success',
            'message': 'User has been registered.',
        }
    else:
        response_data = {
            'status': 'error',
            'message': 'Verification failed.',
        }

    return jsonify(response_data)


@app.route('/product')
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def get_products():
    products = db.session.query(Product).all()
    print(products)
    product_details = []

    for i in products:
        print(i.stripe_price_id)
        product_details.append({
            "product_name": i.product_name,
            "price": i.price,
            "category": i.category,
            "description": i.description,
            "images": i.images,
            "id": i.product_id,
            "stripe_id": i.stripe_price_id
        })

    return product_details


@app.route('/productsCart')
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def get_product():
    id = request.args.get('id')
    product = db.session.query(Product).filter_by(product_id=id).first()

    if product is None:
        print("No product")
        return jsonify({"error": "Product not found"}), 404

    return jsonify({
        "id": product.product_id,
        "product_name": product.product_name,
        "price": product.price,
        "stripe_id": product.stripe_price_id,
        "category": product.category,
        "description": product.description,
        "image_url": product.images
    })


@app.route('/product', methods=['POST'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def add_product():
    try:
        new_product = Product()

        new_product.product_name = request.json['product_name']
        new_product.price = request.json['price']
        new_product.category = request.json['category']
        new_product.description = request.json['description']
        new_product.images = request.json['images']

        try:
            db.session.add(new_product)
            db.session.commit()
            print("item added successfully")
        except Exception as e:
            db.session.rollback()
            print(e)
            return {"status": "failed"}

        # stripe_product = stripe.Product.create(name="test product name",
        #                                        id=str(new_product.product_id))
        # stripe_price = stripe.Price.create(
        #     unit_amount=int(new_product.price),
        #     currency="inr",
        #     product=str(stripe_product.id),
        # )

        # print("Stripe Price ID:", stripe_price.id)

        # # Update the new_product with stripe_price_id and commit to database
        # new_product.stripe_price_id = stripe_price.id
        # db.session.commit()

        print("Product ID:", new_product.product_id)
        response_data = {
            "status": "Success"
        }
        return response_data
    except Exception as e:

        return {"status": "Failed"}


@app.route('/customization', methods=['POST'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def add_customizations():

    product_customization = Product_Customization()
    product_customization.product_id = request.json["product_id"]
    product_customization.cstm_name = request.json["customization_type"]
    product_customization.type = request.json["selection_type"]
    product_customization.options = request.json["options"]
    product_customization.default_option = request.json["default"]

    product_customization.images = request.json["images"]

    db.session.add(product_customization)
    print("item customization added")
    try:
        db.session.commit()
        response = {
            "status": "success"
        }
        print("success")
    except Exception as e:
        db.session.rollback()
        response = {
            "status": "failed",
            "error": str(e)
        }

    return response


@app.route('/customizationGet', methods=['GET'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def get_customization():
    custom_list = []
    product_id = request.args.get('id')
    customizations = Product_Customization.query.filter_by(
        product_id=product_id).all()
    for i in customizations:
        custom_list.append({
            "id": i.product_id,
            "custom_id": i.customization_id,
            "custom_type": i.cstm_name,
            "type": i.type,
            "options": i.options,
            "default": i.default_option,
            "is_required": i.is_required,
            "images": i.images
        })
    print(custom_list)
    return custom_list


@app.route('/logout', methods=['GET'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def logout():
    logout_user()
    response_data = {
        'status': 'success',
        'message': 'Logged out successfully',
    }
    return response_data


@app.route('/deleteAllProducts', methods=['DELETE'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def delete_all_products():
    print("function_started")
    try:
        # Delete all prices from Stripe
        products = stripe.Product.list()
        for product in products:
            print("product")
            prices = stripe.Price.list(product=product.id)
            print(price)
            for price in prices:
                price.delete()
                print("Price deleted")

        # Delete all products from your database
        products_to_delete = Product.query.all()
        for product in products_to_delete:
            db.session.delete(product)
            print(f"Deleted product: {product.product_name}")

        db.session.commit()

        return "Successfully deleted all products and prices"
    except Exception as e:
        return str(e)


@app.route("/delete", methods=['DELETE'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def delete():
    product_id = request.args.get('product_id')

    try:
        product_to_del = Product.query.get(product_id)

        if product_to_del:
            # Delete Stripe Price
            # if product_to_del.stripe_price_id:
            #     price = stripe.Price.modify(
            #         product_to_del.stripe_price_id,
            #         active=False
            #     )

            # # Delete Stripe Product
            # if product_to_del.product_id:
            #     stripe.Product.delete(product_to_del.product_id)

            # Delete product from database
            db.session.delete(product_to_del)
            db.session.commit()

            return jsonify({'message': 'Product and associated Stripe Price/Product deleted successfully'})
        else:
            return jsonify({'error': 'Product not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/delete_custom', methods=['DELETE'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def delete_customization():
    custom_id = request.args.get('custom_id')
    customization = Product_Customization.query.get(custom_id)
    if customization:
        db.session.delete(customization)
        db.session.commit()
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "failed"})


@app.route("/update", methods=['PUT'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def update():
    product_id = request.args.get('id')
    product = Product.query.get(product_id)

    if not product:
        return jsonify({"message": "Product not found"}), 404

    # Update fields from JSON data
    product.product_name = request.json.get(
        'product_name', product.product_name)
    product.price = request.json.get('price', product.price)
    product.description = request.json.get('description', product.description)
    product.image_url = request.json.get('image_url', product.image_url)
    product.category = request.json.get('category', product.category)

    # Fetch associated customizations
    customizations = Product_Customization.query.filter_by(
        product_id=product_id).all()

    for custom in customizations:
        custom.cstm_name = request.json.get('cstm_name', custom.cstm_name)
        custom.type = request.json.get('type', custom.type)
        custom.is_required = request.json.get(
            'is_required', custom.is_required)
        custom.options = request.json.get('options', custom.options)
        custom.default_option = request.json.get(
            'default_option', custom.default_option)
        custom.images = request.json.get('images', custom.images)

    try:
        db.session.commit()
        return jsonify({"message": "Product updated successfully", "status": "success"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Error updating product: {str(e)}", "status": "failed"}), 500


@app.route("/quantity", methods=['PUT'])
@cross_origin(supports_credentials=True, origins=['http://localhost:3000'])
def change_quantity():
    product_id = request.json.get('id')
    item = Cart_item.query.filter_by(order_item_id=product_id).first()
    item.quantity = request.json.get('quantity', item.quantity)

    try:
        db.session.commit()
        return jsonify({"message": "Product updated successfully", "status": "success"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Error updating product: {str(e)}", "status": "failed"}), 500


if __name__ == '__main__':
    app.run(ssl_context=('../certificates/localhost.crt',
            '../certificates/localhost.key'), debug=True)
