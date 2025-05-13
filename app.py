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
            
            # Normalize reader fieldnames for comparison
            reader_fieldnames_normalized = [h.lower().strip() for h in csv_reader.fieldnames] if csv_reader.fieldnames else []

            if not all(header.lower() in reader_fieldnames_normalized for header in expected_headers):
                return jsonify({"error": f"CSV headers do not match expected format. Expected: {', '.join(expected_headers)}. Found: {', '.join(csv_reader.fieldnames or [])}"}), 400

            inmates_added = 0
            inmates_skipped = 0
            errors = []

            for row_num, row_data in enumerate(csv_reader, start=2): # Start at 2 because header is row 1
                # Normalize keys from the row for consistent access
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

@app.route("/inventory/codes", methods=["GET"])
@jwt_required()
def get_item_codes():
    try:
        codes = ItemCode.query.all()
        return jsonify([{"id": code.id, "name": code.name, "type": code.type, "code": code.code} for code in codes])
    except Exception as e:
        print(f"Error in get_item_codes: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/codes", methods=["POST"])
@jwt_required()
def create_item_code():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "name" not in data or "type" not in data or "code" not in data:
        return jsonify({"error": "Name, type, and code are required"}), 400
    if not re.match(r"^[A-Za-z0-9]{2}$", data["code"]):
         return jsonify({"error": "Item code must be exactly 2 alphanumeric characters."}), 400
    if ItemCode.query.filter_by(code=data["code"].upper()).first():
        return jsonify({"error": "Item code already exists"}), 400
    try:
        item_code = ItemCode(name=data["name"], type=data["type"], code=data["code"].upper())
        db.session.add(item_code)
        db.session.commit()
        log = ActionLog(action="Item Code Created", user_id=int(identity), details=f"Item code {item_code.code} created")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item code created successfully"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in create_item_code: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/bulk", methods=["POST"])
@jwt_required()
def receive_bulk_items():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    required_fields = ["item_code", "size_code", "quantity", "name", "cost"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields for bulk item creation"}), 400
    try:
        quantity = int(data["quantity"])
        cost = float(data["cost"])
        if quantity <= 0 or cost <= 0:
            return jsonify({"error": "Quantity and cost must be positive values"}), 400
        
        item_code_obj = ItemCode.query.filter_by(code=data["item_code"]).first()
        if not item_code_obj:
            return jsonify({"error": f"Item code {data['item_code']} not found."}), 404

        items_created = []
        for _ in range(quantity):
            barcode = generate_barcode(data["item_code"], data["size_code"])
            new_item = Item(
                name=data["name"],
                barcode=barcode,
                vendor=data.get("vendor", ""),
                cost=cost,
                status="In Stock",
                condition="New",
                notes=data.get("notes", ""),
                item_group=data.get("item_group", "Misc.") # Use provided item_group or default
            )
            db.session.add(new_item)
            items_created.append(new_item.barcode)
        
        db.session.commit()
        log = ActionLog(action="Bulk Items Received", user_id=int(identity), details=f"{quantity} items of {data['name']} received. Barcodes: {', '.join(items_created)}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": f"{quantity} items received successfully", "barcodes": items_created}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in receive_bulk_items: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/remove", methods=["POST"])
@jwt_required()
def remove_item():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if "barcode" not in data or "condition" not in data:
        return jsonify({"error": "Barcode and condition are required"}), 400
    item = Item.query.filter_by(barcode=data["barcode"]).first()
    if not item:
        return jsonify({"error": "Item not found"}), 404
    if item.status == "Removed":
        return jsonify({"error": "Item already marked as removed"}), 400
    try:
        item.status = "Removed"
        item.condition = data["condition"]
        if "notes" in data:
            item.notes = data["notes"]
        
        # Add barcode to recycled barcodes table
        recycled_barcode = RecycledBarcodes(barcode=item.barcode)
        db.session.add(recycled_barcode)
        
        db.session.commit()
        log = ActionLog(action="Item Removed", user_id=int(identity), details=f"Item {item.barcode} removed. Condition: {item.condition}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item removed successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in remove_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/<string:barcode>", methods=["PUT"])
@jwt_required()
def update_inventory_item(barcode):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    item = Item.query.filter_by(barcode=barcode).first_or_404()
    
    updated_fields = []
    if "name" in data and data["name"] != item.name:
        item.name = data["name"]
        updated_fields.append(f"Name to '{data['name']}'")
    if "vendor" in data and data["vendor"] != item.vendor:
        item.vendor = data["vendor"]
        updated_fields.append(f"Vendor to '{data['vendor']}'")
    if "cost" in data and float(data["cost"]) != item.cost:
        item.cost = float(data["cost"])
        updated_fields.append(f"Cost to {data['cost']}")
    if "condition" in data and data["condition"] != item.condition:
        item.condition = data["condition"]
        updated_fields.append(f"Condition to '{data['condition']}'")
    if "notes" in data and data["notes"] != item.notes:
        item.notes = data["notes"]
        updated_fields.append(f"Notes to '{data['notes']}'")
    if "item_group" in data and data["item_group"] != item.item_group:
        item.item_group = data["item_group"]
        updated_fields.append(f"Item Group to '{data['item_group']}'")

    if not updated_fields:
        return jsonify({"message": "No changes detected for item"}), 200

    try:
        db.session.commit()
        log_details = f"Item {barcode} updated: {', '.join(updated_fields)}."
        log = ActionLog(action="Item Updated", user_id=int(identity), details=log_details)
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item updated successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_inventory_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/assign", methods=["POST"])
@jwt_required()
def assign_item():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if "inmate_id" not in data or "barcode" not in data:
        return jsonify({"error": "Inmate ID and item barcode are required"}), 400
    inmate = Inmate.query.get(data["inmate_id"])
    item = Item.query.filter_by(barcode=data["barcode"]).first()
    if not inmate or not item:
        return jsonify({"error": "Inmate or item not found"}), 404
    if item.status != "In Stock":
        return jsonify({"error": "Item is not in stock"}), 400
    try:
        item.status = "Assigned"
        inmate_item = InmateItem(inmate_id=inmate.id, item_id=item.id)
        db.session.add(inmate_item)
        db.session.commit()
        log = ActionLog(action="Item Assigned", user_id=int(identity), details=f"Item {item.barcode} assigned to inmate {inmate.id}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item assigned successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in assign_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/release", methods=["POST"])
@jwt_required()
def release_item():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if "inmate_id" not in data or "barcode" not in data or "condition" not in data:
        return jsonify({"error": "Inmate ID, item barcode, and condition are required"}), 400
    inmate = Inmate.query.get(data["inmate_id"])
    item = Item.query.filter_by(barcode=data["barcode"]).first()
    if not inmate or not item:
        return jsonify({"error": "Inmate or item not found"}), 404
    inmate_item = InmateItem.query.filter_by(inmate_id=inmate.id, item_id=item.id, return_status=None).order_by(InmateItem.assigned_date.desc()).first()
    if not inmate_item:
        return jsonify({"error": "Item not currently assigned to this inmate or already processed"}), 400
    try:
        item.status = "In Stock" # Or another status like "Returned", "Needs Cleaning" etc.
        item.condition = data["condition"] # Update main item condition upon return
        inmate_item.return_status = "Returned"
        inmate_item.condition = data["condition"]
        
        # Fee logic based on condition
        fee_amount = 0
        fee_name = ""
        if data["condition"] == "Damaged":
            fee_amount = item.cost # Example: full cost for damaged
            fee_name = "Damaged Item Fee"
        elif data["condition"] == "Altered":
            fee_amount = item.cost * 0.5 # Example: half cost for altered
            fee_name = "Altered Item Fee"
        elif data["condition"] == "Lost": # This might be handled differently, e.g. not via release
            fee_amount = item.cost
            fee_name = "Lost Item Fee"
        
        if fee_amount > 0:
            fee = Fee(
                name=fee_name,
                amount=fee_amount,
                inmate_id=inmate.id,
                item_barcodes=item.barcode,
                notes=f"Fee for item {item.barcode} returned in {data['condition']} condition."
            )
            db.session.add(fee)
            # inmate.fees_paid += fee_amount # This logic is now handled by total fees owed

        db.session.commit()
        log_details = f"Item {item.barcode} released from inmate {inmate.id}. Condition: {data['condition']}."
        if fee_amount > 0: log_details += f" Fee of ${fee_amount:.2f} ({fee_name}) applied."
        log = ActionLog(action="Item Released", user_id=int(identity), details=log_details)
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item released successfully" + (f" and fee of ${fee_amount:.2f} applied." if fee_amount > 0 else "")})
    except Exception as e:
        db.session.rollback()
        print(f"Error in release_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inmates/<string:inmate_id>/items", methods=["GET"])
@jwt_required()
def get_inmate_items(inmate_id):
    try:
        inmate = Inmate.query.get_or_404(inmate_id)
        assigned_items = InmateItem.query.filter_by(inmate_id=inmate.id, return_status=None).all()
        result = [{
            "id": ii.item.id,
            "name": ii.item.name,
            "barcode": ii.item.barcode,
            "assigned_date": ii.assigned_date.isoformat()
        } for ii in assigned_items]
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_inmate_items: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports/inventory", methods=["GET"])
@jwt_required()
def inventory_report():
    try:
        items = Item.query.all()
        report_data = [{
            "name": item.name,
            "barcode": item.barcode,
            "vendor": item.vendor,
            "cost": item.cost,
            "status": item.status,
            "condition": item.condition,
            "item_group": item.item_group or "Misc."
        } for item in items]
        return jsonify(report_data)
    except Exception as e:
        print(f"Error in inventory_report: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports/fees", methods=["GET"])
@jwt_required()
def fees_report():
    try:
        fees = Fee.query.join(Inmate, Fee.inmate_id == Inmate.id).all()
        report_data = [{
            "fee_id": fee.id,
            "fee_name": fee.name,
            "amount": fee.amount,
            "inmate_id": fee.inmate_id,
            "inmate_name": fee.inmate.name if fee.inmate else "N/A",
            "item_barcodes": fee.item_barcodes,
            "date_applied": fee.date_applied.isoformat(),
            "notes": fee.notes
        } for fee in fees]
        return jsonify(report_data)
    except Exception as e:
        print(f"Error in fees_report: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports/action_logs", methods=["GET"])
@jwt_required()
def action_logs_report():
    try:
        logs = ActionLog.query.join(User, ActionLog.user_id == User.id, isouter=True).order_by(ActionLog.timestamp.desc()).all()
        report_data = [{
            "log_id": log.id,
            "action": log.action,
            "user_id": log.user_id,
            "username": log.user.username if log.user else "System",
            "timestamp": log.timestamp.isoformat(),
            "details": log.details
        } for log in logs]
        return jsonify(report_data)
    except Exception as e:
        print(f"Error in action_logs_report: {str(e)}\n{traceback.format_exc()}")
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
def create_user():
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    required_fields = ["username", "password", "first_name", "last_name"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Username, password, first name, and last name are required"}), 400
    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "Username already exists"}), 400
    try:
        new_user = User(
            username=data["username"],
            role=data.get("role", "Staff"),
            first_name=data["first_name"],
            last_name=data["last_name"],
            email=data.get("email")
        )
        new_user.set_password(data["password"])
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User created successfully"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in create_user: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/users/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    user = User.query.get_or_404(user_id)
    try:
        if "username" in data and data["username"] != user.username:
            if User.query.filter_by(username=data["username"]).first():
                return jsonify({"error": "Username already exists"}), 400
            user.username = data["username"]
        if "password" in data and data["password"]:
            user.set_password(data["password"])
        if "role" in data:
            user.role = data["role"]
        if "first_name" in data:
            user.first_name = data["first_name"]
        if "last_name" in data:
            user.last_name = data["last_name"]
        if "email" in data:
            user.email = data["email"]
        db.session.commit()
        return jsonify({"message": "User updated successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_user: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    user = User.query.get_or_404(user_id)
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in delete_user: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

# Create tables if they don't exist (primarily for local dev, migrations handle prod)
# This line is usually removed or commented out when using Flask-Migrate for production
# as migrations will handle schema creation and updates.
# However, for initial setup or simple dev, it can be useful.
# For this exercise, we will keep it to ensure local dev works, but migrations are key for Heroku.
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=True)

