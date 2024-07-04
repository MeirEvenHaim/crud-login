from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, Date, Text, Boolean, ForeignKey, Enum
from sqlalchemy.orm import relationship
from flask_cors import CORS , cross_origin
import os
from werkzeug.utils import secure_filename



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'  # Adjust your database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
CORS(app)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'jfif', 'png', 'txt', 'py', 'js', 'gif'}
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit the maximum file size to 16MB

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)



UPLOAD_FOLDER = 'uploads'


class Register(db.Model):
    __tablename__ = 'register'

    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False)
    address = Column(String(100), nullable=False)
    role = Column(Enum('admin', 'client', name='role_enum'), nullable=False)
    password_hash = Column(String(128), nullable=False)
    email = Column(String(100), nullable=False, unique=True)
    image = Column(String(200), nullable=True)
    loans = relationship('Loan', backref='client', foreign_keys='Loan.client_id')
    admin_loans = relationship('Loan', backref='admin', foreign_keys='Loan.admin_id')

    def __init__(self, username, address, role, password, email, image=None):
        self.username = username
        self.address = address
        self.role = role
        self.set_password(password)
        self.email = email
        self.image = image

    def __repr__(self):
        return f"<Register(username='{self.username}', role='{self.role}', email='{self.email}')>"

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'address': self.address,
            'role': self.role,
            'email': self.email,
            'image': self.image
        }

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)


class Book(db.Model):
    __tablename__ = 'books'

    id = Column(Integer, primary_key=True)
    book_name = Column(String(100), nullable=False)
    author = Column(String(100), nullable=False)
    date_of_publish = Column(Date, nullable=False)
    summary = Column(Text, nullable=False)
    image = Column(String(200), nullable=True)
    series = Column(Boolean, nullable=False, default=False)
    loans = relationship('Loan', backref='book')

    def __init__(self, book_name, author, date_of_publish, summary, image=None, series=False):
        self.book_name = book_name
        self.author = author
        self.date_of_publish = date_of_publish
        self.summary = summary
        self.image = image
        self.series = series

    def __repr__(self):
        return f"<Book(book_name='{self.book_name}', author='{self.author}')>"

    def to_dict(self):
        return {
            'id': self.id,
            'book_name': self.book_name,
            'author': self.author,
            'date_of_publish': self.date_of_publish.isoformat(),
            'summary': self.summary,
            'image': self.image,
            'series': self.series
        }


class Loan(db.Model):
    __tablename__ = 'loans'

    id = Column(Integer, primary_key=True)
    book_id = Column(Integer, ForeignKey('books.id'), nullable=False)
    client_id = Column(Integer, ForeignKey('register.id'), nullable=False)
    admin_id = Column(Integer, ForeignKey('register.id'), nullable=False)
    loan_date = Column(Date, nullable=False, default=datetime.utcnow)
    return_date = Column(Date, nullable=False)

    def __init__(self, book_id, client_id, admin_id, return_date):
        self.book_id = book_id
        self.client_id = client_id
        self.admin_id = admin_id
        self.return_date = return_date

    def __repr__(self):
        return f"<Loan(book_id='{self.book_id}', client_id='{self.client_id}', admin_id='{self.admin_id}')>"

    def to_dict(self):
        return {
            'id': self.id,
            'book_name': self.book.book_name,
            'client_name': self.client.username,
            'client_address': self.client.address,
            'admin_name': self.admin.username,
            'admin_address': self.admin.address,
            'loan_date': self.loan_date.isoformat(),
            'return_date': self.return_date.isoformat()
        }


# Helper functions for role checks
def is_admin(current_user):
    current_user = get_jwt_identity()
    print(current_user)
    return current_user['role'] == 'admin'

def is_client():
    current_user = get_jwt_identity()
    return current_user['role'] == 'client'




def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# File upload route
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"msg": "No file part in the request"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"msg": "No file selected for uploading"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({"msg": "File successfully uploaded"}), 201
    else:
        return jsonify({"msg": "Allowed file types are pdf, jpg, jpeg, gif, png, txt, py, js"}), 400



# Endpoint to login and get a JWT token
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = Register.query.filter_by(username=username).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity={'username': user.username, 'role': user.role})
        return jsonify(access_token=access_token), 200

    return jsonify({"msg": "Bad username or password"}), 401


# Endpoint to create a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password_hash')
    address = data.get('address')
    role = data.get('role')

    if Register.query.filter_by(email=email).first():
        return jsonify({"msg": "Email already exists"}), 409

    new_user = Register(username=username, email=email, password=password, address=address, role=role)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify(new_user.to_dict()), 201


# Endpoint to get details of all users (protected)
@app.route('/register', methods=['GET'])
def get_all_users():
    users = Register.query.all()
    return jsonify([user.to_dict() for user in users]), 200


# Endpoint to get details of a specific user by ID (protected)
@app.route('/register/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = Register.query.get_or_404(user_id)
    return jsonify(user.to_dict()), 200


# Endpoint to update a user by ID (protected, admin only)
@app.route('/register/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    if not is_admin():
        return jsonify({"msg": "Admins only!"}), 403
    data = request.get_json()
    user = Register.query.get_or_404(user_id)

    user.username = data.get('username', user.username)
    user.email = data.get('email', user.email)
    if 'password' in data:
        user.set_password(data['password'])
    user.address = data.get('address', user.address)
    user.role = data.get('role', user.role)

    db.session.commit()
    return jsonify(user.to_dict()), 200


# Endpoint to delete a user by ID (protected, admin only)
@app.route('/register/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    if not is_admin():
        return jsonify({"msg": "Admins only!"}), 403
    user = Register.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"msg": "User deleted"}), 200



@app.route('/books', methods=['POST'])
@jwt_required()  
def create_book():
    current_user = get_jwt_identity()
    if not is_admin(current_user):  # Pass current_user to is_admin() for role check
        return jsonify({"msg": "Admins only!"}), 403
    data = request.form
    book_name = data['book_name']
    author = data['author']
    date_of_publish = datetime.strptime(data['date_of_publish'], '%Y-%m-%d').date()
    summary = data.get('summary')
    image = request.files['image'] if 'image' in request.files else None
    series = True if data.get('series') == 'on' else False  # Checkbox value

    new_book = Book(
        book_name=book_name,
        author=author,
        date_of_publish=date_of_publish,
        summary=summary,
        image=image.filename if image else None,
        series=series
    )

    db.session.add(new_book)
    db.session.commit()

    if image:
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(image.filename)))

    return jsonify(new_book.to_dict()), 201


# Endpoint to get details of a specific book by ID (public)
@app.route('/books/<int:id>', methods=['GET'])
def get_book(id):
    book = Book.query.get_or_404(id)
    return jsonify(book.to_dict()), 200


# Endpoint to update a book by ID (admin only)
@app.route('/books/<int:id>', methods=['PUT'])
@jwt_required()
def update_book(id):
    if not is_admin():
        return jsonify({"msg": "Admins only!"}), 403
    data = request.get_json()
    book = Book.query.get_or_404(id)

    book.book_name = data.get('book_name', book.book_name)
    book.author = data.get('author', book.author)
    book.date_of_publish = datetime.strptime(data.get('date_of_publish', book.date_of_publish.isoformat()), '%Y-%m-%d').date()
    book.summary = data.get('summary', book.summary)
    book.image = data.get('image', book.image)
    book.series = data.get('series', book.series)
    db.session.commit()
    return jsonify(book.to_dict()), 200


# Endpoint to delete a book by ID (admin only)
@app.route('/books/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_book(id):
    if not is_admin():
        return jsonify({"msg": "Admins only!"}), 403
    book = Book.query.get_or_404(id)
    db.session.delete(book)
    db.session.commit()
    return '', 204


# Endpoint to get details of all books (public)
@app.route('/books', methods=['GET'])
def get_books():
    books = Book.query.all()
    return jsonify([book.to_dict() for book in books]), 200


# Endpoint to create a new loan (admin only)
@app.route('/loans', methods=['POST'])
@jwt_required()
def create_loan():
    if not is_admin():
        return jsonify({"msg": "Admins only!"}), 403
    data = request.get_json()
    book_id = data['book_id']
    client_id = data['client_id']
    admin_id = get_jwt_identity()['id']
    return_date = datetime.strptime(data['return_date'], '%Y-%m-%d').date()

    new_loan = Loan(book_id=book_id, client_id=client_id, admin_id=admin_id, return_date=return_date)
    db.session.add(new_loan)
    db.session.commit()
    return jsonify(new_loan.to_dict()), 201


# Endpoint to get details of all loans (protected)
@app.route('/loans', methods=['GET'])
@jwt_required()
def get_loans():
    loans = Loan.query.all()
    return jsonify([loan.to_dict() for loan in loans]), 200


# Endpoint to delete a loan by ID (admin only)
@app.route('/loans/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_loan(id):
    if not is_admin():
        return jsonify({"msg": "Admins only!"}), 403
    loan = Loan.query.get_or_404(id)
    db.session.delete(loan)
    db.session.commit()
    return '', 204

# Endpoint to get details of a specific loan by ID (protected)
@app.route('/loans/<int:id>', methods=['GET'])
@jwt_required()
def get_loan(id):
    loan = Loan.query.get_or_404(id)
    return jsonify(loan.to_dict()), 200


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)