from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
from flask_migrate import Migrate # Import Migrate
import os
from datetime import datetime
import random
import traceback
import csv
from io import StringIO
import re # For item code validation
import click # Added for custom CLI command

# Flask app setup
app = Flask(__name__)

# Use DATABASE_URL from environment, with a local Postgres fallback for development
database_url = os.getenv("DATABASE_URL", "postgresql://postgres:password123@localhost:5432/sentinel_inventory")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")
app.config["JWT_HEADER_TYPE"] = "Bearer"
app.config["JWT_HEADER_NAME"] = "Authorization"

db = SQLAlchemy(app)
migrate = Migrate(app, db) # Initialize Flask-Migrate

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app, resources={r"/*": {"origins": ["http://localhost:3000", "https://sentinel-inventory-frontend-f89591a6b344.herokuapp.com"]}}, supports_credentials=True)

@jwt.invalid_token_loader
def invalid_token_callback(error):
    print(f"Invalid token error: {error}")
    return jsonify({"error": "Invalid token"}), 401

@jwt.unauthorized_loader
def unauthorized_callback(error):
    print(f"Unauthorized error: {error}")
    return jsonify({"error": "Missing or invalid Authorization header"}), 401

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default="Staff")
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100))
    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode("utf-8")
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class Item(db.Model):
    __tablename__ = "item"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    barcode = db.Column(db.String(20), unique=True, nullable=False)
    vendor = db.Column(db.String(100))
    cost = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default="In Stock")
    condition = db.Column(db.String(20), default="New")
    notes = db.Column(db.Text)
    item_group = db.Column(db.String(50), nullable=True, default="Misc.")

class Inmate(db.Model):
    __tablename__ = "inmate"
    id = db.Column(db.String(20), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    housing_unit = db.Column(db.String(50), default="Unknown")
    fees_paid = db.Column(db.Float, default=0.0) # This will be re-evaluated for "Fees Owed"
    notes = db.Column(db.Text)

class InmateItem(db.Model):
    __tablename__ = "inmate_item"
    id = db.Column(db.Integer, primary_key=True)
    inmate_id = db.Column(db.String(20), db.ForeignKey("inmate.id"), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey("item.id"), nullable=False)
    assigned_date = db.Column(db.DateTime, default=datetime.utcnow)
    return_status = db.Column(db.String(20))
    condition = db.Column(db.String(20))
    item = db.relationship("Item", backref="inmate_items")
    inmate = db.relationship("Inmate", backref="inmate_items")

class Fee(db.Model):
    __tablename__ = "fee"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    inmate_id = db.Column(db.String(20), db.ForeignKey("inmate.id"), nullable=True)
    item_barcodes = db.Column(db.String(200))
    date_applied = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)

class ActionLog(db.Model):
    __tablename__ = "action_log"
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)

class RecycledBarcodes(db.Model):
    __tablename__ = "recycled_barcodes"
    id = db.Column(db.Integer, primary_key=True)
    barcode = db.Column(db.String(20), unique=True, nullable=False)

class ItemCode(db.Model):
    __tablename__ = "item_code"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    code = db.Column(db.String(2), unique=True, nullable=False)

# Custom CLI command for diagnostics
@app.cli.command("test-cli")
def test_cli_command():
    """A simple test command for CLI diagnostics."""
    print("Custom CLI command \"test-cli\" executed successfully!")

def generate_barcode(item_code, size_code):
    size_map = {
        "SM": "01", "MD": "02", "LG": "03", "XL": "04", "2XL": "05", "3XL": "06",
        "4XL": "07", "5XL": "08", "6XL": "09", "7XL": "10", "8XL": "11", "9XL": "12", "10XL": "13"
    }
    size_numeric = size_map.get(size_code.upper(), "01")
    serial = str(random.randint(1, 999999)).zfill(6)
    barcode = f"{item_code}{size_numeric}{serial}"
    while Item.query.filter_by(barcode=barcode).first() or RecycledBarcodes.query.filter_by(barcode=barcode).first():
        serial = str(random.randint(1, 999999)).zfill(6)
        barcode = f"{item_code}{size_numeric}{serial}"
    return barcode

@app.route("/login", methods=["OPTIONS"])
def login_options():
    response = jsonify({"message": "Preflight OK"})
    response.headers.add("Access-Control-Allow-Origin", "https://sentinel-inventory-frontend-f89591a6b344.herokuapp.com")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
    response.headers.add("Access-Control-Allow-Methods", "POST")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response, 200

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        if not data or "username" not in data or "password" not in data:
            return jsonify({"error": "Username and password are required"}), 400
        user = User.query.filter_by(username=data["username"]).first()
        if user and user.check_password(data["password"]):
            token = create_access_token(identity=str(user.id), additional_claims={"role": user.role})
            return jsonify({"token": token})
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        print(f"Login error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route("/inmates", methods=["GET"])
@jwt_required()
def get_inmates():
    try:
        search_term = request.args.get("search", None)
        query = Inmate.query
        if search_term:
            search_ilike = f"%{search_term}%"
            query = query.filter(
                db.or_(
                    Inmate.id.ilike(search_ilike),
                    Inmate.name.ilike(search_ilike)
                )
            )
        inmates = query.all()
        result = []
        for inmate in inmates:
            total_fees_applied = db.session.query(db.func.sum(Fee.amount)).filter(Fee.inmate_id == inmate.id).scalar() or 0.0
            fees_owed = total_fees_applied 
            result.append({
                "id": str(inmate.id),
                "name": inmate.name or "",
                "housing_unit": inmate.housing_unit or "Unknown",
                "fees_owed": float(fees_owed),
                "notes": inmate.notes or ""
            })
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_inmates: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inmates", methods=["POST"])
@jwt_required()
def add_inmate():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "id" not in data or "name" not in data:
        return jsonify({"error": "Inmate ID and Name are required"}), 400
    if Inmate.query.get(data["id"]):
        return jsonify({"error": "Inmate ID already exists"}), 400
    try:
        inmate = Inmate(
            id=data["id"],
            name=data["name"],
            housing_unit=data.get("housing_unit", "Unknown"),
            notes=data.get("notes", "")
        )
        db.session.add(inmate)
        db.session.commit()
        log = ActionLog(action="Inmate Added", user_id=int(identity), details=f"Inmate {inmate.id} added")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Inmate added successfully"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in add_inmate: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inmates/import_csv", methods=["POST"])
@jwt_required()
def import_inmates_csv():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file and file.filename.endswith('.csv'):
        try:
            csv_file = StringIO(file.read().decode('utf-8'))
            csv_reader = csv.DictReader(csv_file)
            expected_headers = ['last name', 'first name', 'housing unit', 'notes', 'ID']
            
            reader_fieldnames_normalized = [h.lower().strip() for h in csv_reader.fieldnames] if csv_reader.fieldnames else []

            if not all(header.lower() in reader_fieldnames_normalized for header in expected_headers):
                return jsonify({"error": f"CSV headers do not match expected format. Expected: {', '.join(expected_headers)}. Found: {', '.join(csv_reader.fieldnames or [])}"}), 400

            inmates_added = 0
            inmates_skipped = 0
            errors = []

            for row_num, row_data in enumerate(csv_reader, start=2):
                row = {k.lower().strip(): v for k, v in row_data.items()}
                try:
                    inmate_id = row.get('id', '').strip()
                    last_name = row.get('last name', '').strip()
                    first_name = row.get('first name', '').strip()
                    housing_unit = row.get('housing unit', '').strip() or "Unknown"
                    notes = row.get('notes', '').strip()

                    if not inmate_id or not last_name or not first_name:
                        errors.append(f"Row {row_num}: Missing required fields (ID, Last Name, First Name).")
                        continue
                    
                    full_name = f"{first_name} {last_name}"

                    if Inmate.query.get(inmate_id):
                        errors.append(f"Row {row_num}: Inmate ID {inmate_id} already exists. Skipping.")
                        inmates_skipped += 1
                        continue
                    
                    new_inmate = Inmate(
                        id=inmate_id,
                        name=full_name,
                        housing_unit=housing_unit,
                        notes=notes
                    )
                    db.session.add(new_inmate)
                    inmates_added += 1
                except Exception as row_e:
                    errors.append(f"Row {row_num}: Error processing row - {str(row_e)}")
            
            if inmates_added > 0:
                db.session.commit()
                log = ActionLog(action="Inmates CSV Imported", user_id=int(identity), details=f"{inmates_added} inmates imported. {inmates_skipped} skipped. Errors: {len(errors)}")
                db.session.add(log)
                db.session.commit()
            else:
                db.session.rollback()

            response_message = f"{inmates_added} inmates imported successfully."
            if inmates_skipped > 0:
                response_message += f" {inmates_skipped} inmates were skipped (already exist)."
            if errors:
                return jsonify({"message": response_message, "errors": errors}), 207
            return jsonify({"message": response_message}), 201

        except Exception as e:
            db.session.rollback()
            print(f"Error in import_inmates_csv: {str(e)}\n{traceback.format_exc()}")
            return jsonify({"error": f"Failed to process CSV file: {str(e)}"}), 500
    else:
        return jsonify({"error": "Invalid file type. Please upload a CSV file."}), 400

@app.route("/inmates/<string:id>", methods=["PUT"])
@jwt_required()
def update_inmate(id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    inmate = Inmate.query.get_or_404(id)
    if "housing_unit" in data:
        inmate.housing_unit = data["housing_unit"]
    if "notes" in data:
        inmate.notes = data["notes"]
    try:
        db.session.commit()
        log_details = f"Inmate {inmate.id} details updated. "
        if "housing_unit" in data: log_details += f"Housing Unit: {data['housing_unit']}. "
        if "notes" in data: log_details += f"Notes: {data['notes']}. "
        log = ActionLog(action="Inmate Updated", user_id=int(identity), details=log_details.strip())
        db.session.add(log)
        db.session.commit()
        
        total_fees_applied = db.session.query(db.func.sum(Fee.amount)).filter(Fee.inmate_id == inmate.id).scalar() or 0.0
        fees_owed = total_fees_applied
        return jsonify({
            "message": "Inmate updated successfully",
            "inmate": {
                "id": str(inmate.id),
                "name": inmate.name or "",
                "housing_unit": inmate.housing_unit or "Unknown",
                "fees_owed": float(fees_owed),
                "notes": inmate.notes or ""
            }
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_inmate: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory", methods=["GET"])
@jwt_required()
def get_inventory():
    try:
        search_term = request.args.get("search", None)
        query = Item.query.filter(Item.status != "Removed")
        if search_term:
            search_ilike = f"%{search_term}%"
            query = query.filter(
                db.or_(
                    Item.name.ilike(search_ilike),
                    Item.barcode.ilike(search_ilike),
                    Item.status.ilike(search_ilike),
                    Item.vendor.ilike(search_ilike),
                    Item.item_group.ilike(search_ilike) # Added item_group to search
                )
            )
        items = query.all()
        result = []
        for item in items:
            result.append({
                "id": item.id,
                "name": item.name,
                "barcode": item.barcode,
                "vendor": item.vendor,
                "cost": item.cost,
                "status": item.status,
                "condition": item.condition,
                "notes": item.notes,
                "item_group": item.item_group
            })
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_inventory: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory", methods=["POST"])
@jwt_required()
def add_item():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "name" not in data or "cost" not in data or "item_code" not in data or "size_code" not in data:
        return jsonify({"error": "Name, cost, item_code, and size_code are required"}), 400
    
    # Validate item_code and size_code format
    if not re.match(r"^[A-Z0-9]{2}$", data["item_code"]):
        return jsonify({"error": "Invalid item_code format. Must be 2 uppercase alphanumeric characters."}), 400
    # Allow more flexible size codes based on generate_barcode function
    # if not re.match(r"^[A-Z0-9]{2,4}$", data["size_code"]):
    #     return jsonify({"error": "Invalid size_code format. Must be 2-4 uppercase alphanumeric characters."}), 400

    barcode = generate_barcode(data["item_code"], data["size_code"])
    try:
        item = Item(
            name=data["name"],
            barcode=barcode,
            vendor=data.get("vendor", ""),
            cost=data["cost"],
            status=data.get("status", "In Stock"),
            condition=data.get("condition", "New"),
            notes=data.get("notes", ""),
            item_group=data.get("item_group", "Misc.") # Added item_group
        )
        db.session.add(item)
        db.session.commit()
        log = ActionLog(action="Item Added", user_id=int(identity), details=f"Item {item.barcode} ({item.name}) added")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item added successfully", "item": {"id": item.id, "name": item.name, "barcode": item.barcode, "vendor": item.vendor, "cost": item.cost, "status": item.status, "condition": item.condition, "notes": item.notes, "item_group": item.item_group}}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in add_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/<int:id>", methods=["PUT"])
@jwt_required()
def update_item(id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    item = Item.query.get_or_404(id)
    if "name" in data: item.name = data["name"]
    if "vendor" in data: item.vendor = data["vendor"]
    if "cost" in data: item.cost = data["cost"]
    if "status" in data: item.status = data["status"]
    if "condition" in data: item.condition = data["condition"]
    if "notes" in data: item.notes = data["notes"]
    if "item_group" in data: item.item_group = data["item_group"] # Added item_group
    try:
        db.session.commit()
        log_details = f"Item {item.barcode} ({item.name}) updated. "
        for key, value in data.items():
            if key in ["name", "vendor", "cost", "status", "condition", "notes", "item_group"]:
                log_details += f"{key.capitalize()}: {value}. "
        log = ActionLog(action="Item Updated", user_id=int(identity), details=log_details.strip())
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item updated successfully", "item": {"id": item.id, "name": item.name, "barcode": item.barcode, "vendor": item.vendor, "cost": item.cost, "status": item.status, "condition": item.condition, "notes": item.notes, "item_group": item.item_group}})
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/codes", methods=["GET"])
@jwt_required()
def get_item_codes():
    try:
        item_codes = ItemCode.query.all()
        return jsonify([{"id": ic.id, "name": ic.name, "type": ic.type, "code": ic.code} for ic in item_codes])
    except Exception as e:
        print(f"Error in get_item_codes: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/assign", methods=["POST"])
@jwt_required()
def assign_item():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "inmate_id" not in data or "item_barcode" not in data:
        return jsonify({"error": "Inmate ID and Item Barcode are required"}), 400
    item = Item.query.filter_by(barcode=data["item_barcode"]).first()
    if not item:
        return jsonify({"error": "Item not found"}), 404
    if item.status != "In Stock":
        return jsonify({"error": "Item is not in stock"}), 400
    inmate = Inmate.query.get(data["inmate_id"])
    if not inmate:
        return jsonify({"error": "Inmate not found"}), 404
    try:
        inmate_item = InmateItem(inmate_id=inmate.id, item_id=item.id)
        item.status = "Assigned"
        db.session.add(inmate_item)
        db.session.commit()
        log = ActionLog(action="Item Assigned", user_id=int(identity), details=f"Item {item.barcode} assigned to Inmate {inmate.id}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item assigned successfully"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in assign_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/return", methods=["POST"])
@jwt_required()
def return_item():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "item_barcode" not in data or "condition" not in data:
        return jsonify({"error": "Item Barcode and Condition are required"}), 400
    item = Item.query.filter_by(barcode=data["item_barcode"]).first()
    if not item:
        return jsonify({"error": "Item not found"}), 404
    if item.status != "Assigned":
        return jsonify({"error": "Item is not currently assigned"}), 400
    inmate_item = InmateItem.query.filter_by(item_id=item.id, return_status=None).order_by(InmateItem.assigned_date.desc()).first()
    if not inmate_item:
        return jsonify({"error": "No active assignment found for this item"}), 400
    try:
        inmate_item.return_status = "Returned"
        inmate_item.condition = data["condition"]
        item.status = "In Stock"
        item.condition = data["condition"]
        db.session.commit()
        log = ActionLog(action="Item Returned", user_id=int(identity), details=f"Item {item.barcode} returned from Inmate {inmate_item.inmate_id}. Condition: {data['condition']}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item returned successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in return_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/release", methods=["POST"])
@jwt_required()
def release_items():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "inmate_id" not in data or "item_barcodes" not in data or not isinstance(data["item_barcodes"], list):
        return jsonify({"error": "Inmate ID and a list of Item Barcodes are required"}), 400
    inmate = Inmate.query.get(data["inmate_id"])
    if not inmate:
        return jsonify({"error": "Inmate not found"}), 404
    released_items_details = []
    try:
        for barcode in data["item_barcodes"]:
            item = Item.query.filter_by(barcode=barcode).first()
            if not item or item.status != "Assigned":
                return jsonify({"error": f"Item {barcode} not found or not assigned"}), 400
            inmate_item = InmateItem.query.filter_by(item_id=item.id, inmate_id=inmate.id, return_status=None).first()
            if not inmate_item:
                return jsonify({"error": f"Item {barcode} not assigned to this inmate"}), 400
            item.status = "Removed"
            inmate_item.return_status = "Released"
            released_items_details.append(f"{item.barcode} ({item.name})")
        db.session.commit()
        log = ActionLog(action="Items Released", user_id=int(identity), details=f"Items released for Inmate {inmate.id}: {', '.join(released_items_details)}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Items released successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in release_items: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/fees", methods=["POST"])
@jwt_required()
def add_fee():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "name" not in data or "amount" not in data or "inmate_id" not in data:
        return jsonify({"error": "Fee name, amount, and inmate ID are required"}), 400
    try:
        fee = Fee(
            name=data["name"],
            amount=data["amount"],
            inmate_id=data["inmate_id"],
            item_barcodes=data.get("item_barcodes", ""),
            notes=data.get("notes", "")
        )
        db.session.add(fee)
        db.session.commit()
        log = ActionLog(action="Fee Added", user_id=int(identity), details=f"Fee '{fee.name}' ({fee.amount}) added for Inmate {fee.inmate_id}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Fee added successfully"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in add_fee: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports/action_log", methods=["GET"])
@jwt_required()
def get_action_log():
    try:
        logs = ActionLog.query.order_by(ActionLog.timestamp.desc()).all()
        result = []
        for log in logs:
            user = User.query.get(log.user_id) if log.user_id else None
            result.append({
                "id": log.id,
                "action": log.action,
                "user": user.username if user else "System",
                "timestamp": log.timestamp.isoformat(),
                "details": log.details
            })
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_action_log: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports/inventory_status", methods=["GET"])
@jwt_required()
def get_inventory_status_report():
    try:
        items = Item.query.all()
        status_counts = {}
        for item in items:
            status_counts[item.status] = status_counts.get(item.status, 0) + 1
        return jsonify(status_counts)
    except Exception as e:
        print(f"Error in get_inventory_status_report: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports/inmate_inventory/<string:inmate_id>", methods=["GET"])
@jwt_required()
def get_inmate_inventory_report(inmate_id):
    try:
        inmate = Inmate.query.get_or_404(inmate_id)
        assigned_items = InmateItem.query.filter_by(inmate_id=inmate.id, return_status=None).all()
        result = {
            "inmate_id": inmate.id,
            "inmate_name": inmate.name,
            "items": [
                {
                    "item_id": ai.item.id,
                    "item_name": ai.item.name,
                    "barcode": ai.item.barcode,
                    "assigned_date": ai.assigned_date.isoformat()
                } for ai in assigned_items
            ]
        }
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_inmate_inventory_report: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/users", methods=["GET"])
@jwt_required()
def get_users():
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    try:
        users = User.query.all()
        return jsonify([{"id": u.id, "username": u.username, "role": u.role, "first_name": u.first_name, "last_name": u.last_name, "email": u.email} for u in users])
    except Exception as e:
        print(f"Error in get_users: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/users", methods=["POST"])
@jwt_required()
def add_user():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "username" not in data or "password" not in data or "role" not in data or "first_name" not in data or "last_name" not in data:
        return jsonify({"error": "Username, password, role, first_name, and last_name are required"}), 400
    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "Username already exists"}), 400
    try:
        user = User(
            username=data["username"],
            role=data["role"],
            first_name=data["first_name"],
            last_name=data["last_name"],
            email=data.get("email", "")
        )
        user.set_password(data["password"])
        db.session.add(user)
        db.session.commit()
        log = ActionLog(action="User Added", user_id=int(identity), details=f"User {user.username} added with role {user.role}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "User added successfully"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in add_user: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/users/<int:id>", methods=["PUT"])
@jwt_required()
def update_user(id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    user = User.query.get_or_404(id)
    if "username" in data and data["username"] != user.username:
        if User.query.filter_by(username=data["username"]).first():
            return jsonify({"error": "Username already exists"}), 400
        user.username = data["username"]
    if "role" in data: user.role = data["role"]
    if "first_name" in data: user.first_name = data["first_name"]
    if "last_name" in data: user.last_name = data["last_name"]
    if "email" in data: user.email = data["email"]
    if "password" in data and data["password"]:
        user.set_password(data["password"])
    try:
        db.session.commit()
        log_details = f"User {user.username} (ID: {user.id}) updated. "
        for key, value in data.items():
            if key in ["username", "role", "first_name", "last_name", "email"]:
                log_details += f"{key.capitalize()}: {value}. "
            elif key == "password" and value: 
                log_details += "Password changed. "
        log = ActionLog(action="User Updated", user_id=int(identity), details=log_details.strip())
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "User updated successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_user: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/users/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_user(id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    user = User.query.get_or_404(id)
    try:
        db.session.delete(user)
        db.session.commit()
        log = ActionLog(action="User Deleted", user_id=int(identity), details=f"User {user.username} (ID: {user.id}) deleted")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in delete_user: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all() # Creates tables if they don't exist
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5001)))



@app.route("/inmates/<string:inmate_id>/items", methods=["GET"])
@jwt_required()
def get_inmate_assigned_items(inmate_id):
    try:
        inmate = Inmate.query.get_or_404(inmate_id)
        assigned_items = InmateItem.query.filter_by(inmate_id=inmate.id, return_status=None).all()
        result = []
        for ai in assigned_items:
            item = Item.query.get(ai.item_id)
            if item:
                result.append({
                    "id": item.id,
                    "name": item.name,
                    "barcode": item.barcode,
                    "vendor": item.vendor,
                    "cost": item.cost,
                    "status": item.status,
                    "condition": item.condition,
                    "notes": item.notes,
                    "item_group": item.item_group,
                    "assigned_date": ai.assigned_date.isoformat() if ai.assigned_date else None
                })
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_inmate_assigned_items for inmate {inmate_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all() # Creates tables if they don't exist
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5001)))



@app.route("/inmates/<string:inmate_id>/items", methods=["OPTIONS"])
@jwt_required() # Keep JWT for consistency, though OPTIONS might not always need it depending on server/CORS library behavior
def get_inmate_assigned_items_options(inmate_id):
    # Preflight requests don't need a body, just the right headers
    response = jsonify({"message": "Preflight OK for inmate items"})
    # Ensure these headers are consistent with your global CORS config or specific needs
    # The global CORS(app, ...) should handle most of this, but explicit can help for debugging
    # response.headers.add("Access-Control-Allow-Origin", "https://sentinel-inventory-frontend-f89591a6b344.herokuapp.com") # Handled by global CORS
    # response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization") # Handled by global CORS
    # response.headers.add("Access-Control-Allow-Methods", "GET, OPTIONS") # Handled by global CORS
    # response.headers.add("Access-Control-Allow-Credentials", "true") # Handled by global CORS
    return response, 200

@app.route("/inmates/<string:inmate_id>/items", methods=["GET"])
@jwt_required()
def get_inmate_assigned_items(inmate_id):
    try:
        inmate = Inmate.query.get_or_404(inmate_id)
        assigned_items = InmateItem.query.filter_by(inmate_id=inmate.id, return_status=None).all()
        result = []
        for ai in assigned_items:
            item = Item.query.get(ai.item_id)
            if item:
                result.append({
                    "id": item.id,
                    "name": item.name,
                    "barcode": item.barcode,
                    "vendor": item.vendor,
                    "cost": item.cost,
                    "status": item.status,
                    "condition": item.condition,
                    "notes": item.notes,
                    "item_group": item.item_group,
                    "assigned_date": ai.assigned_date.isoformat() if ai.assigned_date else None
                })
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_inmate_assigned_items for inmate {inmate_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all() # Creates tables if they don't exist
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5001)))

