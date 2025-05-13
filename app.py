from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
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
            # Calculate total fees owed
            total_fees_applied = db.session.query(db.func.sum(Fee.amount)).filter(Fee.inmate_id == inmate.id).scalar() or 0.0
            # The field `fees_paid` in Inmate model might be used differently or deprecated based on user's clarification.
            # For now, "fees_owed" will be total_fees_applied. If `fees_paid` is meant to be subtracted, adjust here.
            fees_owed = total_fees_applied 
            result.append({
                "id": str(inmate.id),
                "name": inmate.name or "",
                "housing_unit": inmate.housing_unit or "Unknown",
                "fees_owed": float(fees_owed), # Changed from fees_paid
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
            # fees_paid will default to 0.0 as per model, not set during manual add here
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
            # Expected header: last name, first name, housing unit, notes, ID
            # Adjust mapping based on actual CSV header if present, or assume order if no header
            csv_reader = csv.DictReader(csv_file) 
            # Ensure the DictReader uses the correct fieldnames if the CSV doesn't have a header
            # or if the header names are different from what's expected by the model.
            # For now, assuming CSV has headers: 'last name', 'first name', 'housing unit', 'notes', 'ID'
            
            expected_headers = ['last name', 'first name', 'housing unit', 'notes', 'ID']
            if not csv_reader.fieldnames or not all(header.lower() in [h.lower().strip() for h in csv_reader.fieldnames] for header in expected_headers):
                 # Try to read based on order if headers are missing or don't match
                csv_file.seek(0) # Reset file pointer
                sniffer = csv.Sniffer()
                has_header = sniffer.has_header(csv_file.read(1024))
                csv_file.seek(0)
                if has_header:
                    # If it has a header but it's not what we expect, it's an error
                    return jsonify({"error": f"CSV headers do not match expected format. Expected: {', '.join(expected_headers)}. Found: {', '.join(csv_reader.fieldnames or [])}"}), 400
                else:
                    # No header, read by order
                    csv_reader = csv.reader(csv_file)
                    # Skip header row if it was just column numbers from a previous DictReader attempt
                    # This part is tricky without knowing the exact CSV structure. Assuming DictReader is preferred.
                    # For simplicity, let's stick to requiring headers for now.
                    return jsonify({"error": "CSV file must contain headers: last name, first name, housing unit, notes, ID"}), 400

            inmates_added = 0
            inmates_skipped = 0
            errors = []

            for row_num, row in enumerate(csv_reader, start=1): # start=1 for header, start=2 if skipping manual header
                try:
                    inmate_id = row.get('ID', '').strip()
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
                        # fees_paid defaults to 0.0
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
                db.session.rollback() # Rollback if no inmates were actually added

            response_message = f"{inmates_added} inmates imported successfully."
            if inmates_skipped > 0:
                response_message += f" {inmates_skipped} inmates were skipped (already exist)."
            if errors:
                return jsonify({"message": response_message, "errors": errors}), 207 # Multi-Status
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
    # Name update is not part of this specific request, but could be added if needed
    try:
        db.session.commit()
        log_details = f"Inmate {inmate.id} details updated. "
        if "housing_unit" in data: log_details += f"Housing Unit: {data['housing_unit']}. "
        if "notes" in data: log_details += f"Notes: {data['notes']}. "
        log = ActionLog(action="Inmate Updated", user_id=int(identity), details=log_details.strip())
        db.session.add(log)
        db.session.commit()
        
        # Recalculate fees_owed for the response
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
        }), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_inmate: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inmates/<id>/items", methods=["GET"])
@jwt_required()
def get_inmate_items(id):
    try:
        inmate = Inmate.query.get_or_404(id)
        items = Item.query.join(InmateItem).filter(InmateItem.inmate_id == inmate.id, Item.status == "Assigned").all()
        result = [{
            "id": item.id,
            "name": item.name or "",
            "barcode": item.barcode,
            "size": item.barcode[2:4] if len(item.barcode) >= 4 else "N/A",
            "status": item.status or "Assigned",
            "item_group": item.item_group or "Misc."
        } for item in items]
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_inmate_items: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inmates/<id>", methods=["GET"])
@jwt_required()
def get_inmate(id):
    try:
        inmate = Inmate.query.get_or_404(id)
        total_fees_applied = db.session.query(db.func.sum(Fee.amount)).filter(Fee.inmate_id == inmate.id).scalar() or 0.0
        fees_owed = total_fees_applied
        return jsonify({
            "id": str(inmate.id),
            "name": inmate.name or "",
            "housing_unit": inmate.housing_unit or "Unknown",
            "fees_owed": float(fees_owed),
            "notes": inmate.notes or ""
        })
    except Exception as e:
        print(f"Error in get_inmate: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inmates/<id>/items", methods=["POST"])
@jwt_required()
def assign_item(id):
    identity = get_jwt_identity()
    try:
        data = request.get_json()
        inmate = Inmate.query.get_or_404(id)
        item = Item.query.filter_by(barcode=data["barcode"]).first()
        if not item:
            return jsonify({"error": "Item not found"}), 404
        if item.status != "In Stock":
            return jsonify({"error": f"Item {item.barcode} is not In Stock. Current status: {item.status}"}), 400

        inmate_item = InmateItem(
            inmate_id=inmate.id,
            item_id=item.id,
            condition=item.condition
        )
        item.status = "Assigned"
        db.session.add(inmate_item)
        db.session.commit()
        log = ActionLog(action="Item Assigned", user_id=int(identity), details=f"Item {item.barcode} assigned to inmate {inmate.id}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item assigned to inmate"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in assign_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inmates/<id>/fees", methods=["GET"])
@jwt_required()
def get_inmate_fees(id):
    try:
        fees = Fee.query.filter_by(inmate_id=id).all()
        result = [{
            "id": fee.id,
            "name": fee.name,
            "amount": float(fee.amount),
            "date_applied": fee.date_applied.isoformat(),
            "notes": fee.notes
        } for fee in fees]
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_inmate_fees: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory", methods=["GET"])
@jwt_required()
def get_inventory():
    try:
        search_term = request.args.get("search", None)
        query = Item.query
        if search_term:
            search_ilike = f"%{search_term}%"
            query = query.filter(
                db.or_(
                    Item.name.ilike(search_ilike),
                    Item.barcode.ilike(search_ilike),
                    Item.status.ilike(search_ilike),
                    Item.vendor.ilike(search_ilike),
                    Item.item_group.ilike(search_ilike)
                )
            )
        items = query.all()
        result = [{
            "id": item.id,
            "name": item.name or "",
            "barcode": item.barcode,
            "size": item.barcode[2:4] if len(item.barcode) >= 4 else "N/A",
            "vendor": item.vendor or "",
            "cost": float(item.cost) if item.cost is not None else 0.0,
            "status": item.status or "In Stock",
            "condition": item.condition or "New",
            "notes": item.notes or "",
            "item_group": item.item_group or "Misc."
        } for item in items]
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_inventory: {str(e)}\n{traceback.format_exc()}")
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

    if "name" in data: item.name = data["name"]
    if "vendor" in data: item.vendor = data["vendor"]
    if "cost" in data:
        try: item.cost = float(data["cost"])
        except ValueError: return jsonify({"error": "Invalid cost format"}), 400
    if "condition" in data:
        allowed_conditions = ["New", "Used", "Altered", "Damaged"]
        if data["condition"] not in allowed_conditions:
            return jsonify({"error": f"Invalid condition. Must be one of {", ".join(allowed_conditions)}"}), 400
        item.condition = data["condition"]
    if "notes" in data: item.notes = data["notes"]
    if "item_group" in data: item.item_group = data["item_group"]
    
    try:
        db.session.commit()
        log = ActionLog(action="Inventory Item Updated", user_id=int(identity), details=f"Item {barcode} updated: {data}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item updated successfully", "item": {
            "id": item.id, "name": item.name, "barcode": item.barcode, "vendor": item.vendor,
            "cost": item.cost, "status": item.status, "condition": item.condition, "notes": item.notes,
            "item_group": item.item_group
        }}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_inventory_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/bulk", methods=["POST"])
@jwt_required()
def add_bulk_items():
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
            return jsonify({"error": "Quantity and cost must be positive"}), 400
        
        item_code_obj = ItemCode.query.filter_by(code=data["item_code"]).first()
        if not item_code_obj:
            return jsonify({"error": f"Item code {data['item_code']} not found."}), 404

        created_barcodes = []
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
                item_group=data.get("item_group", "Misc.")
            )
            db.session.add(new_item)
            created_barcodes.append(barcode)
        
        db.session.commit()
        log = ActionLog(action="Bulk Items Added", user_id=int(identity), details=f"{quantity} of item {data['name']} added. Barcodes: {', '.join(created_barcodes)}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": f"{quantity} items created successfully", "barcodes": created_barcodes}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in add_bulk_items: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/codes", methods=["GET"])
@jwt_required()
def get_item_codes():
    try:
        codes = ItemCode.query.all()
        return jsonify([{"id": c.id, "name": c.name, "type": c.type, "code": c.code} for c in codes])
    except Exception as e:
        print(f"Error in get_item_codes: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/codes", methods=["POST"])
@jwt_required()
def create_item_code():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin"]:
        return jsonify({"error": "Permission denied. Admin role required."}), 403
    data = request.get_json()
    if not data or "name" not in data or "type" not in data or "code" not in data:
        return jsonify({"error": "Name, type, and code are required"}), 400
    if not re.match(r"^[a-zA-Z0-9]{2}$", data["code"]):
         return jsonify({"error": "Code must be exactly 2 alphanumeric characters."}), 400
    if ItemCode.query.filter_by(code=data["code"].upper()).first():
        return jsonify({"error": "Item code already exists"}), 400
    try:
        item_code = ItemCode(name=data["name"], type=data["type"], code=data["code"].upper())
        db.session.add(item_code)
        db.session.commit()
        log = ActionLog(action="Item Code Created", user_id=int(identity), details=f"Item code {item_code.code} created for {item_code.name}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item code created successfully"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in create_item_code: {str(e)}\n{traceback.format_exc()}")
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
    if not data or "barcode" not in data or "condition" not in data:
        return jsonify({"error": "Barcode and condition are required to remove an item"}), 400
    item = Item.query.filter_by(barcode=data["barcode"]).first()
    if not item:
        return jsonify({"error": "Item not found"}), 404
    if item.status == "Assigned":
        return jsonify({"error": "Cannot remove an item that is currently assigned to an inmate."}), 400
    try:
        item.status = "Removed"
        item.condition = data["condition"]
        if "notes" in data: item.notes = data["notes"]
        recycled_barcode = RecycledBarcodes(barcode=item.barcode)
        db.session.add(recycled_barcode)
        db.session.commit()
        log = ActionLog(action="Item Removed", user_id=int(identity), details=f"Item {item.barcode} removed. Condition: {data['condition']}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item removed successfully"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error in remove_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/laundry/send", methods=["POST"])
@jwt_required()
def send_to_laundry():
    identity = get_jwt_identity()
    data = request.get_json()
    if not data or "barcodes" not in data or not isinstance(data["barcodes"], list):
        return jsonify({"error": "List of barcodes is required"}), 400
    updated_items = []
    errors = []
    for barcode in data["barcodes"]:
        item = Item.query.filter_by(barcode=barcode).first()
        if not item:
            errors.append(f"Item {barcode} not found.")
            continue
        if item.status != "In Stock" and item.status != "Used":
            errors.append(f"Item {barcode} cannot be sent to laundry. Status: {item.status}")
            continue
        item.status = "In Laundry"
        updated_items.append(barcode)
    try:
        db.session.commit()
        if updated_items:
            log = ActionLog(action="Items Sent to Laundry", user_id=int(identity), details=f"Items sent to laundry: {', '.join(updated_items)}")
            db.session.add(log)
            db.session.commit()
        if errors:
            return jsonify({"message": f"Partial success. {len(updated_items)} items sent to laundry.", "errors": errors}), 207 if updated_items else 400
        return jsonify({"message": "Items sent to laundry successfully"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error in send_to_laundry: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/laundry/return-inventory", methods=["POST"])
@jwt_required()
def return_from_laundry():
    identity = get_jwt_identity()
    data = request.get_json()
    if not data or "barcode" not in data or "condition" not in data:
        return jsonify({"error": "Barcode and condition are required"}), 400
    item = Item.query.filter_by(barcode=data["barcode"]).first()
    if not item:
        return jsonify({"error": "Item not found"}), 404
    if item.status != "In Laundry":
         return jsonify({"error": f"Item {item.barcode} is not in laundry. Status: {item.status}"}), 400
    try:
        item.status = "In Stock"
        item.condition = data["condition"]
        db.session.commit()
        log = ActionLog(action="Item Returned from Laundry", user_id=int(identity), details=f"Item {item.barcode} returned from laundry. Condition: {data['condition']}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item returned to inventory"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error in return_from_laundry: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports/inventory", methods=["GET"])
@jwt_required()
def inventory_report():
    try:
        items = Item.query.all()
        report_data = [{
            "barcode": item.barcode, "name": item.name, "status": item.status,
            "condition": item.condition, "cost": item.cost, "vendor": item.vendor,
            "item_group": item.item_group
        } for item in items]
        return jsonify(report_data)
    except Exception as e:
        print(f"Error in inventory_report: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports/inmate_items/<inmate_id>", methods=["GET"])
@jwt_required()
def inmate_items_report(inmate_id):
    try:
        inmate = Inmate.query.get_or_404(inmate_id)
        assigned_items = Item.query.join(InmateItem).filter(InmateItem.inmate_id == inmate.id, Item.status == "Assigned").all()
        report_data = {
            "inmate_id": inmate.id,
            "inmate_name": inmate.name,
            "items": [{
                "barcode": item.barcode, "name": item.name, "condition": item.condition,
                "assigned_date": InmateItem.query.filter_by(item_id=item.id, inmate_id=inmate.id).first().assigned_date.isoformat()
            } for item in assigned_items]
        }
        return jsonify(report_data)
    except Exception as e:
        print(f"Error in inmate_items_report: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.before_request
def create_tables_if_not_exist():
    if not hasattr(app, 'tables_created'):
        with app.app_context():
            db.create_all()
            if not User.query.filter_by(username="admin").first():
                admin_user = User(username="admin", role="Admin", first_name="Admin", last_name="User", email="admin@example.com")
                admin_user.set_password("password123")
                db.session.add(admin_user)
                db.session.commit()
                print("Default admin user created with password 'password123'")
        app.tables_created = True

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5001)))

