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
database_url = os.getenv("DATABASE_URL", "postgresql+psycopg2://postgres:password123@localhost:5432/sentinel_inventory")
if database_url.startswith("postgres://"):
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
    print("Custom CLI command \'test-cli\' executed successfully!")

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
        result = [{
            "id": item.id,
            "name": item.name,
            "barcode": item.barcode,
            "vendor": item.vendor,
            "cost": item.cost,
            "status": item.status,
            "condition": item.condition,
            "notes": item.notes,
            "item_group": item.item_group or "Misc." # Ensure item_group is returned
        } for item in items]
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
    
    item_code_str = data["item_code"].strip()
    size_code_str = data["size_code"].strip()

    # Validate item_code and size_code format (e.g., 2 alphanumeric for item_code)
    if not re.match(r"^[a-zA-Z0-9]{2}$", item_code_str):
        return jsonify({"error": "Item code must be 2 alphanumeric characters."}), 400

    barcode = generate_barcode(item_code_str, size_code_str)
    
    try:
        item = Item(
            name=data["name"],
            barcode=barcode,
            vendor=data.get("vendor", ""),
            cost=data["cost"],
            status=data.get("status", "In Stock"),
            condition=data.get("condition", "New"),
            notes=data.get("notes", ""),
            item_group=data.get("item_group", "Misc.")
        )
        db.session.add(item)
        db.session.commit()
        log = ActionLog(action="Item Added", user_id=int(identity), details=f"Item {item.name} ({item.barcode}) added")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item added successfully", "barcode": barcode}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in add_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/<string:barcode>", methods=["PUT"])
@jwt_required()
def update_item(barcode):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    item = Item.query.filter_by(barcode=barcode).first_or_404()
    
    log_details_parts = [f"Item {item.name} ({item.barcode}) updated."]

    if "name" in data:
        item.name = data["name"]
        log_details_parts.append(f"Name: {data['name']}.")
    if "vendor" in data:
        item.vendor = data["vendor"]
        log_details_parts.append(f"Vendor: {data['vendor']}.")
    if "cost" in data:
        item.cost = data["cost"]
        log_details_parts.append(f"Cost: {data['cost']}.")
    if "status" in data:
        item.status = data["status"]
        log_details_parts.append(f"Status: {data['status']}.")
    if "condition" in data:
        item.condition = data["condition"]
        log_details_parts.append(f"Condition: {data['condition']}.")
    if "notes" in data:
        item.notes = data["notes"]
        log_details_parts.append(f"Notes: {data['notes']}.")
    if "item_group" in data:
        item.item_group = data["item_group"]
        log_details_parts.append(f"Item Group: {data['item_group']}.")

    try:
        db.session.commit()
        log = ActionLog(action="Item Updated", user_id=int(identity), details=" ".join(log_details_parts))
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item updated successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/<string:barcode>", methods=["DELETE"])
@jwt_required()
def delete_item(barcode):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied. Admin role required."}), 403
    item = Item.query.filter_by(barcode=barcode).first_or_404()
    try:
        # Instead of deleting, mark as 'Removed'
        item.status = "Removed"
        # Add barcode to recycled list if not already there
        if not RecycledBarcodes.query.filter_by(barcode=item.barcode).first():
            recycled = RecycledBarcodes(barcode=item.barcode)
            db.session.add(recycled)
        db.session.commit()
        log = ActionLog(action="Item Marked as Removed", user_id=int(identity), details=f"Item {item.name} ({item.barcode}) marked as Removed")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item marked as Removed successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in delete_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/item_codes", methods=["GET"])
@jwt_required()
def get_item_codes():
    try:
        item_codes = ItemCode.query.all()
        return jsonify([{"id": ic.id, "name": ic.name, "type": ic.type, "code": ic.code} for ic in item_codes])
    except Exception as e:
        print(f"Error in get_item_codes: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/item_codes", methods=["POST"])
@jwt_required()
def add_item_code():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied. Admin role required."}), 403
    data = request.get_json()
    if not data or "name" not in data or "type" not in data or "code" not in data:
        return jsonify({"error": "Name, type, and code are required for item code"}), 400
    
    code_str = data["code"].strip()
    if not re.match(r"^[a-zA-Z0-9]{2}$", code_str):
        return jsonify({"error": "Item code must be 2 alphanumeric characters."}), 400
    if ItemCode.query.filter_by(code=code_str).first():
        return jsonify({"error": "This 2-character code already exists."}), 400

    try:
        item_code = ItemCode(name=data["name"], type=data["type"], code=code_str)
        db.session.add(item_code)
        db.session.commit()
        log = ActionLog(action="Item Code Added", user_id=int(identity), details=f"Item Code {item_code.name} ({item_code.code}) added")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item code added successfully"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in add_item_code: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/item_codes/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_item_code(id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied. Admin role required."}), 403
    item_code = ItemCode.query.get_or_404(id)
    try:
        db.session.delete(item_code)
        db.session.commit()
        log = ActionLog(action="Item Code Deleted", user_id=int(identity), details=f"Item Code {item_code.name} ({item_code.code}) deleted")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item code deleted successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in delete_item_code: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/assign_item", methods=["POST"])
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
    inmate = Inmate.query.get(data["inmate_id"])
    item = Item.query.filter_by(barcode=data["item_barcode"]).first()
    if not inmate or not item:
        return jsonify({"error": "Inmate or Item not found"}), 404
    if item.status != "In Stock":
        return jsonify({"error": "Item is not in stock"}), 400
    try:
        inmate_item = InmateItem(inmate_id=inmate.id, item_id=item.id, condition=item.condition)
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

@app.route("/release_item", methods=["POST"])
@jwt_required()
def release_item():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "inmate_id" not in data or "item_barcode" not in data or "return_status" not in data:
        return jsonify({"error": "Inmate ID, Item Barcode, and Return Status are required"}), 400
    
    inmate_id = data["inmate_id"]
    item_barcode = data["item_barcode"]
    return_status = data["return_status"]
    condition = data.get("condition", "Used") # Default to Used if not provided
    notes = data.get("notes", "")

    inmate_item = InmateItem.query.join(Item).filter(InmateItem.inmate_id == inmate_id, Item.barcode == item_barcode, InmateItem.return_status == None).first()
    if not inmate_item:
        return jsonify({"error": "Assigned item not found for this inmate or already processed"}), 404
    
    item = Item.query.get(inmate_item.item_id)
    if not item:
         return jsonify({"error": "Item associated with assignment not found"}), 404 # Should not happen

    try:
        inmate_item.return_status = return_status
        inmate_item.condition = condition
        
        if return_status == "Returned":
            item.status = "In Stock"
            item.condition = condition # Update item's main condition
        elif return_status == "Damaged" or return_status == "Lost":
            item.status = return_status # Mark item as Damaged or Lost
            # Create a fee for damaged or lost item
            fee_name = f"{return_status} Item - {item.name}"
            fee_amount = item.cost # Charge full cost for damaged/lost
            fee = Fee(name=fee_name, amount=fee_amount, inmate_id=inmate_id, item_barcodes=item.barcode, notes=notes)
            db.session.add(fee)
        
        db.session.commit()
        log = ActionLog(action="Item Released/Processed", user_id=int(identity), details=f"Item {item.barcode} from Inmate {inmate_id} processed as {return_status}. Condition: {condition}. Notes: {notes}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": f"Item processed as {return_status} successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in release_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inmate_inventory/<string:inmate_id>", methods=["GET"])
@jwt_required()
def get_inmate_inventory(inmate_id):
    try:
        inmate = Inmate.query.get_or_404(inmate_id)
        assigned_items = InmateItem.query.filter_by(inmate_id=inmate_id, return_status=None).all()
        items_details = []
        for ai in assigned_items:
            item = Item.query.get(ai.item_id)
            if item:
                items_details.append({
                    "item_id": item.id,
                    "name": item.name,
                    "barcode": item.barcode,
                    "assigned_date": ai.assigned_date.isoformat(),
                    "condition": ai.condition
                })
        
        # Calculate total fees owed
        total_fees_applied = db.session.query(db.func.sum(Fee.amount)).filter(Fee.inmate_id == inmate_id).scalar() or 0.0
        fees_owed = total_fees_applied

        return jsonify({
            "inmate_id": inmate.id,
            "inmate_name": inmate.name,
            "housing_unit": inmate.housing_unit,
            "fees_owed": float(fees_owed),
            "notes": inmate.notes,
            "assigned_items": items_details
        })
    except Exception as e:
        print(f"Error in get_inmate_inventory: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/fees/<string:inmate_id>", methods=["GET"])
@jwt_required()
def get_inmate_fees(inmate_id):
    try:
        fees = Fee.query.filter_by(inmate_id=inmate_id).all()
        return jsonify([{
            "id": fee.id,
            "name": fee.name,
            "amount": fee.amount,
            "item_barcodes": fee.item_barcodes,
            "date_applied": fee.date_applied.isoformat(),
            "notes": fee.notes
        } for fee in fees])
    except Exception as e:
        print(f"Error in get_inmate_fees: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/logs", methods=["GET"])
@jwt_required()
def get_logs():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied. Admin role required."}), 403
    try:
        logs = ActionLog.query.order_by(ActionLog.timestamp.desc()).limit(100).all()
        result = []
        for log_entry in logs:
            user = User.query.get(log_entry.user_id) if log_entry.user_id else None
            result.append({
                "id": log_entry.id,
                "action": log_entry.action,
                "user": f"{user.first_name} {user.last_name} ({user.username})" if user else "System",
                "timestamp": log_entry.timestamp.isoformat(),
                "details": log_entry.details
            })
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_logs: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/users", methods=["GET"])
@jwt_required()
def get_users():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied. Admin role required."}), 403
    try:
        users = User.query.all()
        return jsonify([{
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email
        } for user in users])
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
        return jsonify({"error": "Permission denied. Admin role required."}), 403
    data = request.get_json()
    if not data or "username" not in data or "password" not in data or "first_name" not in data or "last_name" not in data:
        return jsonify({"error": "Username, password, first name, and last name are required"}), 400
    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "Username already exists"}), 400
    try:
        user = User(
            username=data["username"],
            role=data.get("role", "Staff"),
            first_name=data["first_name"],
            last_name=data["last_name"],
            email=data.get("email", "")
        )
        user.set_password(data["password"])
        db.session.add(user)
        db.session.commit()
        log = ActionLog(action="User Added", user_id=int(identity), details=f"User {user.username} added")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "User added successfully"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in add_user: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/users/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied. Admin role required."}), 403
    user_to_update = User.query.get_or_404(user_id)
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    log_details_parts = [f"User {user_to_update.username} updated."]

    if "username" in data and data["username"] != user_to_update.username:
        if User.query.filter_by(username=data["username"]).first():
            return jsonify({"error": "New username already exists"}), 400
        user_to_update.username = data["username"]
        log_details_parts.append(f"Username: {data['username']}.")
    if "role" in data:
        user_to_update.role = data["role"]
        log_details_parts.append(f"Role: {data['role']}.")
    if "first_name" in data:
        user_to_update.first_name = data["first_name"]
        log_details_parts.append(f"First Name: {data['first_name']}.")
    if "last_name" in data:
        user_to_update.last_name = data["last_name"]
        log_details_parts.append(f"Last Name: {data['last_name']}.")
    if "email" in data:
        user_to_update.email = data["email"]
        log_details_parts.append(f"Email: {data['email']}.")
    if "password" in data and data["password"]:
        user_to_update.set_password(data["password"])
        log_details_parts.append("Password updated.")
    
    try:
        db.session.commit()
        log = ActionLog(action="User Updated", user_id=int(identity), details=" ".join(log_details_parts))
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "User updated successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_user: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied. Admin role required."}), 403
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == int(identity):
        return jsonify({"error": "Cannot delete your own account."}), 403
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        log = ActionLog(action="User Deleted", user_id=int(identity), details=f"User {user_to_delete.username} deleted")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in delete_user: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/profile", methods=["GET"])
@jwt_required()
def get_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email
    })

@app.route("/profile", methods=["PUT"])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    log_details_parts = [f"User {user.username} updated their profile."]

    if "first_name" in data:
        user.first_name = data["first_name"]
        log_details_parts.append(f"First Name: {data['first_name']}.")
    if "last_name" in data:
        user.last_name = data["last_name"]
        log_details_parts.append(f"Last Name: {data['last_name']}.")
    if "email" in data:
        user.email = data["email"]
        log_details_parts.append(f"Email: {data['email']}.")
    if "password" in data and data["password"]:
        user.set_password(data["password"])
        log_details_parts.append("Password updated.")
    
    try:
        db.session.commit()
        log = ActionLog(action="Profile Updated", user_id=int(user_id), details=" ".join(log_details_parts))
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Profile updated successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_profile: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=False)

