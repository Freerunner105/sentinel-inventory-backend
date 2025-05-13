from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
import os
from datetime import datetime
import random
import traceback

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
    status = db.Column(db.String(50), default="In Stock") # e.g., In Stock, Assigned, In Laundry, Removed
    condition = db.Column(db.String(20), default="New") # e.g., New, Used, Altered, Damaged
    notes = db.Column(db.Text)

class Inmate(db.Model):
    __tablename__ = "inmate"
    id = db.Column(db.String(20), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    housing_unit = db.Column(db.String(50), default="Unknown")
    fees_paid = db.Column(db.Float, default=0.0)
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
    size_numeric = size_map.get(size_code, "01")
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
        inmates = Inmate.query.all()
        result = [{
            "id": str(inmate.id),
            "name": inmate.name or "",
            "housing_unit": inmate.housing_unit or "Unknown",
            "fees_paid": float(inmate.fees_paid) if inmate.fees_paid is not None else 0.0,
            "notes": inmate.notes or ""
        } for inmate in inmates]
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
            fees_paid=float(data.get("fees_paid", 0.0)),
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
        if "housing_unit" in data:
            log_details += f"Housing Unit: {data["housing_unit"]}. "
        if "notes" in data:
            log_details += f"Notes: {data["notes"]}. "
        log = ActionLog(action="Inmate Updated", user_id=int(identity), details=log_details.strip())
        db.session.add(log)
        db.session.commit()
        return jsonify({
            "message": "Inmate updated successfully",
            "inmate": {
                "id": str(inmate.id),
                "name": inmate.name or "",
                "housing_unit": inmate.housing_unit or "Unknown",
                "fees_paid": float(inmate.fees_paid) if inmate.fees_paid is not None else 0.0,
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
            "status": item.status or "Assigned"
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
        return jsonify({
            "id": str(inmate.id),
            "name": inmate.name or "",
            "housing_unit": inmate.housing_unit or "Unknown",
            "fees_paid": float(inmate.fees_paid) if inmate.fees_paid is not None else 0.0,
            "notes": inmate.notes or ""
        })
    except Exception as e:
        print(f"Error in get_inmate: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inmates/<id>/items", methods=["POST"])
@jwt_required()
def assign_item(id):
    try:
        data = request.get_json()
        inmate = Inmate.query.get_or_404(id)
        item = Item.query.filter_by(barcode=data["barcode"]).first()
        if not item:
            return jsonify({"error": "Item not found"}), 404
        # Ensure item is in stock before assigning
        if item.status != "In Stock":
            return jsonify({"error": f"Item {item.barcode} is not In Stock. Current status: {item.status}"}), 400

        inmate_item = InmateItem(
            inmate_id=inmate.id,
            item_id=item.id,
            condition=item.condition # Assigns the current condition of the item
        )
        item.status = "Assigned"
        db.session.add(inmate_item)
        db.session.commit()
        identity = get_jwt_identity()
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
                    Item.vendor.ilike(search_ilike)
                )
            )
        items = query.all()
        result = [{
            "id": item.id,
            "name": item.name or "",
            "barcode": item.barcode,
            "size": item.barcode[2:4] if len(item.barcode) >= 4 else "N/A", # Assuming size is encoded in barcode
            "vendor": item.vendor or "",
            "cost": float(item.cost) if item.cost is not None else 0.0,
            "status": item.status or "In Stock",
            "condition": item.condition or "New",
            "notes": item.notes or ""
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

    # Fields that can be updated (excluding status, which has specific workflows)
    if "name" in data:
        item.name = data["name"]
    if "vendor" in data:
        item.vendor = data["vendor"]
    if "cost" in data:
        try:
            item.cost = float(data["cost"])
        except ValueError:
            return jsonify({"error": "Invalid cost format"}), 400
    if "condition" in data:
        # Ensure condition is one of the allowed values if you have a predefined list
        allowed_conditions = ["New", "Used", "Altered", "Damaged"]
        if data["condition"] not in allowed_conditions:
            return jsonify({"error": f"Invalid condition. Must be one of {', '.join(allowed_conditions)}"}), 400
        item.condition = data["condition"]
    if "notes" in data:
        item.notes = data["notes"]
    
    # Barcode and Status are generally not directly editable via a generic update
    # Barcode is a unique identifier. Status changes via specific actions (assign, laundry, remove).

    try:
        db.session.commit()
        log_details = f"Inventory item {item.barcode} updated. "
        updated_fields = []
        if "name" in data: updated_fields.append(f"Name: {data['name']}")
        if "vendor" in data: updated_fields.append(f"Vendor: {data['vendor']}")
        if "cost" in data: updated_fields.append(f"Cost: {data['cost']}")
        if "condition" in data: updated_fields.append(f"Condition: {data['condition']}")
        if "notes" in data: updated_fields.append(f"Notes: {data['notes']}")
        log_details += ", ".join(updated_fields)

        log = ActionLog(action="Inventory Item Updated", user_id=int(identity), details=log_details)
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            "message": "Inventory item updated successfully",
            "item": {
                "id": item.id,
                "name": item.name or "",
                "barcode": item.barcode,
                "size": item.barcode[2:4] if len(item.barcode) >= 4 else "N/A",
                "vendor": item.vendor or "",
                "cost": float(item.cost) if item.cost is not None else 0.0,
                "status": item.status or "In Stock",
                "condition": item.condition or "New",
                "notes": item.notes or ""
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_inventory_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/bulk", methods=["POST"])
@jwt_required()
def bulk_receive():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    required_fields = ["item_code", "size_code", "quantity", "name", "cost"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Item Code, Size Code, Quantity, Name, and Cost are required"}), 400
    try:
        item_code = data["item_code"]
        size_code = data["size_code"]
        quantity = int(data["quantity"])
        name = data["name"]
        cost = float(data["cost"])
        items_added = []
        for _ in range(quantity):
            barcode = generate_barcode(item_code, size_code)
            item = Item(
                name=name,
                barcode=barcode,
                vendor=data.get("vendor", ""),
                cost=cost,
                status="In Stock",
                condition="New" # Default condition for new items
            )
            db.session.add(item)
            items_added.append(barcode)
        db.session.commit()
        log = ActionLog(action="Bulk Items Received", user_id=int(identity), details=f"{quantity} items added: {", ".join(items_added)}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": f"{quantity} items received", "barcodes": items_added}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in bulk_receive: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inventory/codes", methods=["GET"])
@jwt_required()
def get_item_codes():
    try:
        codes = ItemCode.query.all()
        result = [{
            "id": code.id,
            "name": code.name,
            "type": code.type,
            "code": code.code
        } for code in codes]
        return jsonify(result)
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
        return jsonify({"error": "Item Name, Item Type, and Code are required"}), 400
    if not isinstance(data["code"], str) or len(data["code"]) != 2:
        return jsonify({"error": "Code must be a 2-character string"}), 400
    if ItemCode.query.filter_by(code=data["code"].upper()).first():
        return jsonify({"error": "Item code already exists"}), 400
    try:
        item_code = ItemCode(
            name=data["name"],
            type=data["type"],
            code=data["code"].upper()
        )
        db.session.add(item_code)
        db.session.commit()
        log = ActionLog(action="Item Code Created", user_id=int(identity), details=f"Code {item_code.code} for {item_code.name}")
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
        return jsonify({"error": "Barcode and Condition are required"}), 400
    barcode = data["barcode"]
    condition = data["condition"]
    notes = data.get("notes", "")
    if condition not in ["Used", "Altered", "Damaged"]:
        return jsonify({"error": "Condition must be Used, Altered, or Damaged"}), 400
    try:
        item = Item.query.filter_by(barcode=barcode).first()
        if not item:
            return jsonify({"error": "Item not found"}), 404
        if item.status == "Assigned":
            return jsonify({"error": "Cannot remove assigned item. Unassign it first."}), 400
        
        log_details = f"Item {barcode} removed. Condition: {condition}."
        if notes: log_details += f" Notes: {notes}"

        log = ActionLog(
            action="Item Removed",
            user_id=int(identity),
            details=log_details
        )
        db.session.add(log)
        # Instead of deleting, mark as 'Removed' and recycle barcode
        item.status = "Removed"
        item.condition = condition # Update condition upon removal
        item.notes = notes if notes else item.notes # Update notes if provided

        recycled = RecycledBarcodes(barcode=barcode)
        db.session.add(recycled)
        # db.session.delete(item) # Do not delete, mark as Removed
        db.session.commit()
        return jsonify({"message": "Item marked as removed and barcode recycled successfully"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error in remove_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/laundry", methods=["GET"])
@jwt_required()
def get_laundry_items():
    try:
        items = Item.query.filter_by(status="In Laundry").all()
        result = [{
            "id": item.id,
            "name": item.name or "",
            "barcode": item.barcode,
            "size": item.barcode[2:4] if len(item.barcode) >= 4 else "N/A",
            "status": item.status or "In Laundry"
        } for item in items]
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_laundry_items: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/laundry/send", methods=["POST"])
@jwt_required()
def send_to_laundry():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "barcode" not in data:
        return jsonify({"error": "Barcode is required"}), 400
    barcode = data["barcode"]
    try:
        item = Item.query.filter_by(barcode=barcode).first()
        if not item:
            return jsonify({"error": "Item not found"}), 404
        if item.status != "Assigned": # Only assigned items can be sent to laundry
            return jsonify({"error": f"Item must be Assigned to send to laundry. Current status: {item.status}"}), 400
        
        # Find the InmateItem record to update its return_status if needed, or just log
        inmate_item_link = InmateItem.query.filter_by(item_id=item.id, inmate_id=Inmate.query.join(InmateItem, InmateItem.inmate_id == Inmate.id).filter(InmateItem.item_id == item.id).order_by(InmateItem.assigned_date.desc()).first().inmate_id).order_by(InmateItem.assigned_date.desc()).first()
        if inmate_item_link:
            inmate_item_link.return_status = "Sent to Laundry" # Optional: track this on the link

        item.status = "In Laundry"
        db.session.commit()
        log = ActionLog(action="Item Sent to Laundry", user_id=int(identity), details=f"Item {barcode} from inmate {inmate_item_link.inmate_id if inmate_item_link else 'Unknown'}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item sent to laundry"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error in send_to_laundry: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/laundry/return-inmate", methods=["POST"])
@jwt_required()
def return_to_inmate():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "barcode" not in data:
        return jsonify({"error": "Barcode is required"}), 400
    barcode = data["barcode"]
    try:
        item = Item.query.filter_by(barcode=barcode).first()
        if not item:
            return jsonify({"error": "Item not found"}), 404
        if item.status != "In Laundry":
            return jsonify({"error": f"Item must be In Laundry to return to inmate. Current status: {item.status}"}), 400
        
        # Find the most recent InmateItem link to associate the return
        inmate_item_link = InmateItem.query.filter_by(item_id=item.id).order_by(InmateItem.assigned_date.desc()).first()
        if not inmate_item_link:
             # This case should ideally not happen if item was properly assigned before laundry
            return jsonify({"error": "No previous inmate assignment found for this item. Cannot return to inmate."}), 400

        item.status = "Assigned"
        # Optionally update condition if it changed in laundry, or keep as is
        # item.condition = data.get("condition", item.condition) 
        inmate_item_link.return_status = "Returned to Inmate" # Optional: track this on the link

        db.session.commit()
        log = ActionLog(action="Item Returned to Inmate from Laundry", user_id=int(identity), details=f"Item {barcode} to inmate {inmate_item_link.inmate_id}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item returned to inmate from laundry"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error in return_to_inmate: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/laundry/return-inventory", methods=["POST"])
@jwt_required()
def return_to_inventory():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "barcode" not in data or "condition" not in data:
        return jsonify({"error": "Barcode and Condition are required"}), 400
    barcode = data["barcode"]
    condition = data["condition"]
    if condition not in ["New", "Used", "Altered", "Damaged"]:
        return jsonify({"error": "Condition must be New, Used, Altered, or Damaged"}), 400
    try:
        item = Item.query.filter_by(barcode=barcode).first()
        if not item:
            return jsonify({"error": "Item not found"}), 404
        if item.status != "In Laundry":
            return jsonify({"error": f"Item must be In Laundry to return to inventory. Current status: {item.status}"}), 400
        
        # Find the most recent InmateItem link and update its return_status
        inmate_item_link = InmateItem.query.filter_by(item_id=item.id).order_by(InmateItem.assigned_date.desc()).first()
        if inmate_item_link:
            inmate_item_link.return_status = "Returned to Inventory" # Optional: track this on the link

        item.status = "In Stock"
        item.condition = condition
        db.session.commit()
        log = ActionLog(action="Item Returned to Inventory from Laundry", user_id=int(identity), details=f"Item {barcode} with condition {condition}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item returned to inventory from laundry"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error in return_to_inventory: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/release/<id>", methods=["POST"])
@jwt_required()
def release_inmate(id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    try:
        inmate = Inmate.query.get_or_404(id)
        # Check for items currently assigned to the inmate
        assigned_items_count = Item.query.join(InmateItem).filter(InmateItem.inmate_id == inmate.id, Item.status == "Assigned").count()
        if assigned_items_count > 0:
            return jsonify({"error": f"Cannot release inmate. {assigned_items_count} item(s) still assigned. Please unassign or process items first."}), 400
        
        # Optional: Handle fees. For now, just releasing.
        # Consider if fees need to be zeroed or archived.

        # Remove InmateItem links for this inmate (for items not currently 'Assigned' but previously linked)
        InmateItem.query.filter_by(inmate_id=inmate.id).delete()

        db.session.delete(inmate)
        db.session.commit()
        log = ActionLog(action="Inmate Released", user_id=int(identity), details=f"Inmate {id} released from system.")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Inmate released successfully"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error in release_inmate: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/settings/users", methods=["GET"])
@jwt_required()
def get_users():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    try:
        users = User.query.all()
        result = [{
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email
        } for user in users]
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_users: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/settings/users", methods=["POST"])
@jwt_required()
def add_user():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    required_fields = ["username", "password", "first_name", "last_name"]
    if not data or not all(field in data for field in required_fields):
        return jsonify({"error": "Username, Password, First Name, and Last Name are required"}), 400
    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "Username already exists"}), 400
    try:
        user = User(
            username=data["username"],
            role=data.get("role", "Staff"), # Default role to Staff if not provided
            first_name=data["first_name"],
            last_name=data["last_name"],
            email=data.get("email", "")
        )
        user.set_password(data["password"])
        db.session.add(user)
        db.session.commit()
        log = ActionLog(action="User Added", user_id=int(identity), details=f"User {user.username} with role {user.role}")
        db.session.add(log)
        db.session.commit()
        return jsonify({
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email
        }), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in add_user: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/settings/fees", methods=["GET"])
@jwt_required()
def get_fees():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    try:
        fees = Fee.query.all()
        result = []
        for fee in fees:
            inmate_name = None
            if fee.inmate_id:
                inmate = Inmate.query.get(fee.inmate_id)
                if inmate: inmate_name = inmate.name
            result.append({
                "id": fee.id,
                "name": fee.name,
                "amount": float(fee.amount),
                "inmate_id": fee.inmate_id,
                "inmate_name": inmate_name,
                "item_barcodes": fee.item_barcodes,
                "date_applied": fee.date_applied.isoformat(),
                "notes": fee.notes
            })
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_fees: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/settings/fees", methods=["POST"])
@jwt_required()
def add_fee():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "name" not in data or "amount" not in data:
        return jsonify({"error": "Name and Amount are required"}), 400
    try:
        fee = Fee(
            name=data["name"],
            amount=float(data["amount"]),
            inmate_id=data.get("inmate_id"),
            item_barcodes=data.get("item_barcodes"),
            notes=data.get("notes")
        )
        db.session.add(fee)
        db.session.commit()
        log = ActionLog(action="Fee Added", user_id=int(identity), details=f"Fee {fee.name} of ${fee.amount} added. Inmate: {fee.inmate_id if fee.inmate_id else 'N/A'}")
        db.session.add(log)
        db.session.commit()
        inmate_name = None
        if fee.inmate_id:
            inmate = Inmate.query.get(fee.inmate_id)
            if inmate: inmate_name = inmate.name
        return jsonify({
            "id": fee.id,
            "name": fee.name,
            "amount": float(fee.amount),
            "inmate_id": fee.inmate_id,
            "inmate_name": inmate_name,
            "item_barcodes": fee.item_barcodes,
            "date_applied": fee.date_applied.isoformat(),
            "notes": fee.notes
        }), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in add_fee: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports/items", methods=["GET"])
@jwt_required()
def get_item_report():
    try:
        barcode = request.args.get("barcode")
        start_date_str = request.args.get("start_date")
        end_date_str = request.args.get("end_date")
        
        query = Item.query
        if barcode:
            query = query.filter(Item.barcode == barcode)
        
        # Join with InmateItem only if date filters are present to avoid issues with items never assigned
        if start_date_str or end_date_str:
            query = query.outerjoin(InmateItem) # Use outerjoin to include items not in InmateItem
            if start_date_str:
                start_date = datetime.fromisoformat(start_date_str.split("T")[0] + "T00:00:00")
                query = query.filter(InmateItem.assigned_date >= start_date)
            if end_date_str:
                end_date = datetime.fromisoformat(end_date_str.split("T")[0] + "T23:59:59")
                query = query.filter(InmateItem.assigned_date <= end_date)
        
        items = query.all()
        result = []
        for item in items:
            last_assigned_date = None
            # Get the most recent assignment date if the item has been assigned
            if item.inmate_items:
                last_assignment = sorted(item.inmate_items, key=lambda x: x.assigned_date, reverse=True)[0]
                last_assigned_date = last_assignment.assigned_date.isoformat()

            result.append({
                "barcode": item.barcode,
                "name": item.name,
                "status": item.status,
                "condition": item.condition,
                "cost": float(item.cost),
                "assigned_date": last_assigned_date
            })
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_item_report: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports/inmates", methods=["GET"])
@jwt_required()
def get_inmate_report():
    try:
        inmate_id = request.args.get("inmate_id")
        start_date_str = request.args.get("start_date")
        end_date_str = request.args.get("end_date")

        query = Inmate.query
        if inmate_id:
            query = query.filter(Inmate.id == inmate_id)
        
        inmates = query.all()
        result = []
        for inmate in inmates:
            items_query = InmateItem.query.filter_by(inmate_id=inmate.id)
            fees_query = Fee.query.filter_by(inmate_id=inmate.id)

            if start_date_str:
                start_date = datetime.fromisoformat(start_date_str.split("T")[0] + "T00:00:00")
                items_query = items_query.filter(InmateItem.assigned_date >= start_date)
                fees_query = fees_query.filter(Fee.date_applied >= start_date)
            if end_date_str:
                end_date = datetime.fromisoformat(end_date_str.split("T")[0] + "T23:59:59")
                items_query = items_query.filter(InmateItem.assigned_date <= end_date)
                fees_query = fees_query.filter(Fee.date_applied <= end_date)
            
            current_items = items_query.all()
            current_fees = fees_query.all()

            result.append({
                "id": inmate.id,
                "name": inmate.name,
                "housing_unit": inmate.housing_unit,
                "fees_paid": float(inmate.fees_paid),
                "total_fees_in_period": sum(float(fee.amount) for fee in current_fees),
                "items_assigned_in_period": [{
                    "barcode": item_link.item.barcode, 
                    "name": item_link.item.name, 
                    "assigned_date": item_link.assigned_date.isoformat()
                } for item_link in current_items]
            })
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_inmate_report: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/action_logs", methods=["GET"])
@jwt_required()
def get_action_logs():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    try:
        start_date_str = request.args.get("start_date")
        end_date_str = request.args.get("end_date")
        user_filter = request.args.get("user") # Optional filter by username

        query = ActionLog.query.join(User, ActionLog.user_id == User.id, isouter=True).add_columns(User.username)

        if start_date_str:
            start_date = datetime.fromisoformat(start_date_str.split("T")[0] + "T00:00:00")
            query = query.filter(ActionLog.timestamp >= start_date)
        if end_date_str:
            end_date = datetime.fromisoformat(end_date_str.split("T")[0] + "T23:59:59")
            query = query.filter(ActionLog.timestamp <= end_date)
        if user_filter:
            query = query.filter(User.username.ilike(f"%{user_filter}%"))
            
        logs_with_users = query.order_by(ActionLog.timestamp.desc()).all()
        
        result = []
        for log, username in logs_with_users:
            result.append({
                "id": log.id,
                "action": log.action,
                "user": username if username else "System",
                "timestamp": log.timestamp.isoformat(),
                "details": log.details
            })
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_action_logs: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/settings/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    
    # Prevent deleting oneself
    if str(user_id) == identity:
        return jsonify({"error": "Cannot delete your own account."}), 400

    user = User.query.get_or_404(user_id)
    # Prevent deleting the last admin user if it is the case
    if user.role == "Admin":
        admin_users_count = User.query.filter_by(role="Admin").count()
        if admin_users_count <= 1:
            return jsonify({"error": "Cannot delete the last admin user."}), 400
            
    db.session.delete(user)
    db.session.commit()
    log = ActionLog(action="User Deleted", user_id=int(identity), details=f"User {user.username} deleted")
    db.session.add(log)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"}), 200

# Initialize DB and default users (ensure this is safe for production)
def initialize_database():
    with app.app_context():
        try:
            db.create_all()
            # Check if default admin user exists, if not create it
            if not User.query.filter_by(username="admin").first():
                admin = User(username="admin", role="Admin", first_name="Admin", last_name="User", email="admin@example.com")
                admin.set_password(os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")) # Use env var for default password
                db.session.add(admin)
                print("Default admin user created.")
            
            # Check for other default users like staff, trustee if needed
            if not User.query.filter_by(username="staff").first():
                staff = User(username="staff", role="Staff", first_name="Staff", last_name="One", email="staff@example.com")
                staff.set_password(os.getenv("DEFAULT_STAFF_PASSWORD", "staff123"))
                db.session.add(staff)
                print("Default staff user created.")

            if not User.query.filter_by(username="trustee").first():
                trustee = User(username="trustee", role="Trustee", first_name="Trustee", last_name="Two", email="trustee@example.com")
                trustee.set_password(os.getenv("DEFAULT_TRUSTEE_PASSWORD", "trustee123"))
                db.session.add(trustee)
                print("Default trustee user created.")

            db.session.commit()
            print("Database initialized successfully.")
        except Exception as e:
            print(f"Error initializing database: {str(e)}\n{traceback.format_exc()}")
            db.session.rollback()

if __name__ == "__main__":
    initialize_database() # Call initialization function
    app.run(debug=True, port=os.environ.get("PORT", 5000))

