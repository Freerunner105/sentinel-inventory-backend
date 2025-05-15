from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
from flask_migrate import Migrate
import os
from datetime import datetime
import random
import traceback
import csv
from io import StringIO
import re
import click
from werkzeug.exceptions import NotFound # Import NotFound

# --- Sentinel Backend App Starting - Version: 20250515-1526 ---
print("--- Sentinel Backend App Starting - Version: 20250515-1920 ---")

app = Flask(__name__)

database_url = os.getenv("DATABASE_URL", "postgresql://postgres:password123@localhost:5432/sentinel_inventory")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")
app.config["JWT_HEADER_TYPE"] = "Bearer"
app.config["JWT_HEADER_NAME"] = "Authorization"

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app, resources={r"/*": {"origins": ["http://localhost:3000", "https://sentinel-inventory-frontend-f89591a6b344.herokuapp.com"]}}, supports_credentials=True)

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "version": "20250515-1445"}), 200

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

@app.cli.command("test-cli")
def test_cli_command():
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
                "fees_paid": float(inmate.fees_paid or 0.0),
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
    file = request.files["file"]
    if file.filename == "": # Fixed SyntaxError here
        return jsonify({"error": "No selected file"}), 400
    if file and file.filename.endswith(".csv"):
        try:
            stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.DictReader(stream)
            added_count = 0
            skipped_count = 0
            skipped_ids = []
            for row in csv_input:
                inmate_id = row.get("id")
                name = row.get("name")
                if not inmate_id or not name:
                    skipped_count += 1
                    skipped_ids.append(f"{inmate_id or 'MISSING_ID'} ({name or 'MISSING_NAME'}) - Missing ID or Name")
                    continue
                if Inmate.query.get(inmate_id):
                    skipped_count += 1
                    skipped_ids.append(f"{inmate_id} ({name}) - Already Exists")
                    continue
                inmate = Inmate(
                    id=inmate_id,
                    name=name,
                    housing_unit=row.get("housing_unit", "Unknown"),
                    fees_paid=float(row.get("fees_paid", 0.0)),
                    notes=row.get("notes", "")
                )
                db.session.add(inmate)
                added_count += 1
            db.session.commit()
            log_details = f"CSV Import: Added {added_count} inmates."
            if skipped_count > 0:
                log_details += f" Skipped {skipped_count} inmates: {', '.join(skipped_ids[:5])}{'...' if skipped_count > 5 else ''}."
            log = ActionLog(action="Inmates CSV Imported", user_id=int(identity), details=log_details)
            db.session.add(log)
            db.session.commit()
            return jsonify({"message": f"Successfully added {added_count} inmates. Skipped {skipped_count} inmates.", "skipped_ids": skipped_ids}), 201
        except Exception as e:
            db.session.rollback()
            print(f"Error in import_inmates_csv: {str(e)}\n{traceback.format_exc()}")
            return jsonify({"error": f"Error processing CSV: {str(e)}"}), 500
    else:
        return jsonify({"error": "Invalid file type. Please upload a CSV file."}), 400

@app.route("/inmates/<string:inmate_id>", methods=["GET"])
@jwt_required()
def get_inmate_by_id(inmate_id):
    print(f"--- DEBUG v20250514-2137: Fetching details for inmate_id: {inmate_id} ---")
    try:
        inmate = Inmate.query.get(inmate_id)
        if not inmate:
            print(f"--- DEBUG v20250514-2137: Inmate {inmate_id} not found ---")
            return jsonify({"error": "Inmate not found"}), 404
        
        print(f"--- DEBUG v20250514-2137: Found inmate: {inmate.name} ---")
        total_fees_applied = db.session.query(db.func.sum(Fee.amount)).filter(Fee.inmate_id == inmate.id).scalar() or 0.0
        fees_owed = total_fees_applied

        result = {
            "id": str(inmate.id),
            "name": inmate.name or "",
            "housing_unit": inmate.housing_unit or "Unknown",
            "fees_owed": float(fees_owed),
            "fees_paid": float(inmate.fees_paid or 0.0),
            "notes": inmate.notes or ""
        }
        print(f"--- DEBUG v20250514-2137: Successfully processed details for inmate {inmate_id}. Returning data. ---")
        return jsonify(result)
    except Exception as e:
        print(f"--- DEBUG v20250514-2137: Error in get_inmate_by_id for {inmate_id}: {str(e)}\n{traceback.format_exc()} ---")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route("/inmates/<string:inmate_id>", methods=["PUT"])
@jwt_required()
def update_inmate(inmate_id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    inmate = Inmate.query.get(inmate_id)
    if not inmate:
        return jsonify({"error": "Inmate not found"}), 404
    data = request.get_json()
    try:
        if "name" in data:
            inmate.name = data["name"]
        if "housing_unit" in data:
            inmate.housing_unit = data["housing_unit"]
        if "fees_paid" in data:
            inmate.fees_paid = float(data["fees_paid"])
        if "notes" in data:
            inmate.notes = data["notes"]
        db.session.commit()
        log = ActionLog(action="Inmate Updated", user_id=int(identity), details=f"Inmate {inmate.id} updated")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Inmate updated successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_inmate: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inmates/<string:inmate_id>", methods=["DELETE"])
@jwt_required()
def delete_inmate(inmate_id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    inmate = Inmate.query.get(inmate_id)
    if not inmate:
        return jsonify({"error": "Inmate not found"}), 404
    try:
        # Consider implications: what happens to assigned items, fees etc.?
        # For now, we will delete the inmate and cascade deletes should handle related records if set up in models.
        # If not, manual deletion of related records might be needed.
        InmateItem.query.filter_by(inmate_id=inmate_id).delete()
        Fee.query.filter_by(inmate_id=inmate_id).delete()
        db.session.delete(inmate)
        db.session.commit()
        log = ActionLog(action="Inmate Deleted", user_id=int(identity), details=f"Inmate {inmate_id} deleted")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Inmate deleted successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in delete_inmate: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inmates/<string:inmate_id>/items", methods=["GET"])
@jwt_required()
def get_inmate_items(inmate_id):
    print(f"--- DEBUG v20250515-1417: Fetching items for inmate_id: {inmate_id} ---")
    try:
        inmate = Inmate.query.get(inmate_id)
        if not inmate:
            print(f"--- DEBUG v20250515-1417: Inmate {inmate_id} not found in get_inmate_items. ---")
            return jsonify({"error": "Inmate not found"}), 404
        print(f"--- DEBUG v20250515-1417: Found inmate: {inmate.name} ---")
        assigned_items = InmateItem.query.filter_by(inmate_id=inmate_id).all()
        print(f"--- DEBUG v20250515-1417: Found {len(assigned_items)} assigned items records for inmate {inmate_id} ---")
        result = []
        for i, assigned_item_record in enumerate(assigned_items):
            print(f"--- DEBUG v20250515-1417: Processing assigned item record {i+1}/{len(assigned_items)}, item_id: {assigned_item_record.item_id} ---")
            item_details = Item.query.get(assigned_item_record.item_id)
            if item_details:
                print(f"--- DEBUG v20250515-1417: Found item details for item_id {assigned_item_record.item_id}: {item_details.name} ---")
                result.append({
                    "id": item_details.id,
                    "name": item_details.name,
                    "barcode": item_details.barcode,
                    "assigned_date": assigned_item_record.assigned_date.isoformat() if assigned_item_record.assigned_date else None,
                    "return_status": assigned_item_record.return_status,
                    "condition": assigned_item_record.condition
                })
            else:
                print(f"--- DEBUG v20250515-1417: Item details not found for item_id {assigned_item_record.item_id} (associated with InmateItem id {assigned_item_record.id}) ---")
        print(f"--- DEBUG v20250515-1417: Successfully processed items for inmate {inmate_id}. Returning {len(result)} items. ---")
        return jsonify(result)
    except Exception as e:
        print(f"--- DEBUG v20250515-1417: Error in get_inmate_items for {inmate_id}: {str(e)}\n{traceback.format_exc()} ---")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route("/inmates/<string:inmate_id>/items", methods=["POST"])
@jwt_required()
def assign_item_to_inmate(inmate_id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    inmate = Inmate.query.get(inmate_id)
    if not inmate:
        return jsonify({"error": "Inmate not found"}), 404
    data = request.get_json()
    if not data or "item_barcode" not in data:
        return jsonify({"error": "Item barcode is required"}), 400
    item = Item.query.filter_by(barcode=data["item_barcode"]).first()
    if not item:
        return jsonify({"error": "Item not found"}), 404
    if item.status != "In Stock":
        return jsonify({"error": f"Item {item.name} is not In Stock. Current status: {item.status}"}), 400
    try:
        inmate_item = InmateItem(
            inmate_id=inmate_id,
            item_id=item.id,
            condition=item.condition # Assign current item condition
        )
        item.status = "Assigned"
        db.session.add(inmate_item)
        db.session.commit()
        log = ActionLog(action="Item Assigned", user_id=int(identity), details=f"Item {item.barcode} assigned to inmate {inmate_id}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item assigned successfully"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in assign_item_to_inmate: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inmates/<string:inmate_id>/items/<int:item_id>/return", methods=["PUT"])
@jwt_required()
def return_inmate_item(inmate_id, item_id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    
    inmate_item_record = InmateItem.query.filter_by(inmate_id=inmate_id, item_id=item_id).first()
    if not inmate_item_record:
        return jsonify({"error": "Item not assigned to this inmate or item does not exist"}), 404

    item_details = Item.query.get(item_id)
    if not item_details:
        return jsonify({"error": "Item details not found"}), 404 # Should not happen if inmate_item_record exists

    data = request.get_json()
    return_status = data.get("return_status") # e.g., "Returned", "Damaged", "Lost"
    new_condition = data.get("condition") # e.g., "Used", "Damaged"

    if not return_status:
        return jsonify({"error": "Return status is required"}), 400
    if not new_condition and return_status in ["Returned", "Damaged"]:
         return jsonify({"error": "New condition is required if status is Returned or Damaged"}), 400

    try:
        inmate_item_record.return_status = return_status
        if new_condition:
            inmate_item_record.condition = new_condition
            item_details.condition = new_condition # Update the main item's condition

        if return_status == "Returned":
            item_details.status = "In Stock"
        elif return_status == "Damaged":
            item_details.status = "Damaged"
        elif return_status == "Lost":
            item_details.status = "Lost"
        # Potentially other statuses for the item itself

        db.session.commit()
        log_details = f"Item {item_details.barcode} returned by inmate {inmate_id}. Status: {return_status}, Condition: {new_condition or 'N/A'}."
        log = ActionLog(action="Item Returned", user_id=int(identity), details=log_details)
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item return status updated successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in return_inmate_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inmates/<string:inmate_id>/fees", methods=["GET"])
@jwt_required()
def get_inmate_fees(inmate_id):
    print(f"--- DEBUG v20250514-2137: Fetching fees for inmate_id: {inmate_id} ---")
    try:
        inmate = Inmate.query.get(inmate_id)
        if not inmate:
            print(f"--- DEBUG v20250514-2137: Inmate {inmate_id} not found in get_inmate_fees. ---")
            return jsonify({"error": "Inmate not found"}), 404
        print(f"--- DEBUG v20250514-2137: Found inmate: {inmate.name} for fees ---")
        fees = Fee.query.filter_by(inmate_id=inmate_id).all()
        print(f"--- DEBUG v20250514-2137: Found {len(fees)} fee records for inmate {inmate_id} ---")
        result = []
        for fee in fees:
            result.append({
                "id": fee.id,
                "name": fee.name,
                "amount": float(fee.amount),
                "date_applied": fee.date_applied.isoformat() if fee.date_applied else None,
                "item_barcodes": fee.item_barcodes,
                "notes": fee.notes
            })
        print(f"--- DEBUG v20250514-2137: Successfully processed fees for inmate {inmate_id}. Returning {len(result)} fees. ---")
        return jsonify(result)
    except Exception as e:
        print(f"--- DEBUG v20250514-2137: Error in get_inmate_fees for {inmate_id}: {str(e)}\n{traceback.format_exc()} ---")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route("/inmates/<string:inmate_id>/fees", methods=["POST"])
@jwt_required()
def add_fee_to_inmate(inmate_id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    inmate = Inmate.query.get(inmate_id)
    if not inmate:
        return jsonify({"error": "Inmate not found"}), 404
    data = request.get_json()
    if not data or "name" not in data or "amount" not in data:
        return jsonify({"error": "Fee name and amount are required"}), 400
    try:
        fee = Fee(
            inmate_id=inmate_id,
            name=data["name"],
            amount=float(data["amount"]),
            item_barcodes=data.get("item_barcodes", ""),
            notes=data.get("notes", "")
        )
        db.session.add(fee)
        db.session.commit()
        log = ActionLog(action="Fee Added", user_id=int(identity), details=f"Fee '{fee.name}' for {fee.amount} added to inmate {inmate_id}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Fee added successfully"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in add_fee_to_inmate: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/inmates/<string:inmate_id>/pay_fees", methods=["POST"])
@jwt_required()
def pay_inmate_fees(inmate_id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    inmate = Inmate.query.get(inmate_id)
    if not inmate:
        return jsonify({"error": "Inmate not found"}), 404
    data = request.get_json()
    if "amount_paid" not in data:
        return jsonify({"error": "Amount paid is required"}), 400
    try:
        amount_paid = float(data["amount_paid"])
        if amount_paid <= 0:
            return jsonify({"error": "Amount paid must be positive"}), 400
        inmate.fees_paid = (inmate.fees_paid or 0.0) + amount_paid
        db.session.commit()
        log = ActionLog(action="Fees Paid", user_id=int(identity), details=f"Payment of {amount_paid} applied to inmate {inmate_id}. New fees_paid: {inmate.fees_paid}")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Fees paid successfully", "new_fees_paid": inmate.fees_paid})
    except ValueError:
        return jsonify({"error": "Invalid amount_paid format"}), 400
    except Exception as e:
        db.session.rollback()
        print(f"Error in pay_inmate_fees: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/items", methods=["GET"])
@jwt_required()
def get_items():
    try:
        search_term = request.args.get("search", None)
        query = Item.query
        if search_term:
            search_ilike = f"%{search_term}%"
            query = query.filter(
                db.or_(
                    Item.name.ilike(search_ilike),
                    Item.barcode.ilike(search_ilike),
                    Item.vendor.ilike(search_ilike),
                    Item.item_group.ilike(search_ilike)
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
            "item_group": item.item_group
        } for item in items]
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_items: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/items", methods=["POST"])
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
    
    item_code_entry = ItemCode.query.filter_by(code=data["item_code"]).first()
    if not item_code_entry:
        return jsonify({"error": f"Invalid item_code: {data['item_code']}"}), 400

    barcode = generate_barcode(data["item_code"], data["size_code"])
    
    try:
        item = Item(
            name=data["name"],
            barcode=barcode,
            vendor=data.get("vendor", ""),
            cost=float(data["cost"]),
            status=data.get("status", "In Stock"),
            condition=data.get("condition", "New"),
            notes=data.get("notes", ""),
            item_group=data.get("item_group", item_code_entry.type) # Default to item_code type if not provided
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

@app.route("/items/import_csv", methods=["POST"])
@jwt_required()
def import_items_csv():
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
    if file and file.filename.endswith(".csv"):
        try:
            stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.DictReader(stream)
            added_count = 0
            skipped_count = 0
            skipped_items = []
            for row in csv_input:
                name = row.get("name")
                cost_str = row.get("cost")
                item_code_val = row.get("item_code")
                size_code_val = row.get("size_code")

                if not all([name, cost_str, item_code_val, size_code_val]):
                    skipped_count += 1
                    skipped_items.append(f"{name or 'MISSING_NAME'} - Missing required fields")
                    continue
                try:
                    cost = float(cost_str)
                except ValueError:
                    skipped_count += 1
                    skipped_items.append(f"{name} - Invalid cost format: {cost_str}")
                    continue
                
                item_code_entry = ItemCode.query.filter_by(code=item_code_val).first()
                if not item_code_entry:
                    skipped_count += 1
                    skipped_items.append(f"{name} - Invalid item_code: {item_code_val}")
                    continue

                barcode = generate_barcode(item_code_val, size_code_val)
                item = Item(
                    name=name,
                    barcode=barcode,
                    vendor=row.get("vendor", ""),
                    cost=cost,
                    status=row.get("status", "In Stock"),
                    condition=row.get("condition", "New"),
                    notes=row.get("notes", ""),
                    item_group=row.get("item_group", item_code_entry.type)
                )
                db.session.add(item)
                added_count += 1
            db.session.commit()
            log_details = f"Item CSV Import: Added {added_count} items."
            if skipped_count > 0:
                log_details += f" Skipped {skipped_count} items: {', '.join(skipped_items[:5])}{'...' if skipped_count > 5 else ''}."
            log = ActionLog(action="Items CSV Imported", user_id=int(identity), details=log_details)
            db.session.add(log)
            db.session.commit()
            return jsonify({"message": f"Successfully added {added_count} items. Skipped {skipped_count} items.", "skipped_items": skipped_items}), 201
        except Exception as e:
            db.session.rollback()
            print(f"Error in import_items_csv: {str(e)}\n{traceback.format_exc()}")
            return jsonify({"error": f"Error processing CSV: {str(e)}"}), 500
    else:
        return jsonify({"error": "Invalid file type. Please upload a CSV file."}), 400

@app.route("/items/<int:item_id>", methods=["PUT"])
@jwt_required()
def update_item(item_id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role not in ["Admin", "Staff"]:
        return jsonify({"error": "Permission denied"}), 403
    item = Item.query.get(item_id)
    if not item:
        return jsonify({"error": "Item not found"}), 404
    data = request.get_json()
    try:
        if "name" in data: item.name = data["name"]
        if "vendor" in data: item.vendor = data["vendor"]
        if "cost" in data: item.cost = float(data["cost"])
        if "status" in data: item.status = data["status"]
        if "condition" in data: item.condition = data["condition"]
        if "notes" in data: item.notes = data["notes"]
        if "item_group" in data: item.item_group = data["item_group"]
        # Barcode is not updatable by design after generation
        db.session.commit()
        log = ActionLog(action="Item Updated", user_id=int(identity), details=f"Item {item.barcode} updated")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item updated successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/items/<int:item_id>", methods=["DELETE"])
@jwt_required()
def delete_item(item_id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    item = Item.query.get(item_id)
    if not item:
        return jsonify({"error": "Item not found"}), 404
    if InmateItem.query.filter_by(item_id=item_id).first():
        return jsonify({"error": "Cannot delete item. It is currently assigned to an inmate or has assignment history."}), 400
    try:
        # Add barcode to recycled barcodes before deleting
        recycled_barcode = RecycledBarcodes(barcode=item.barcode)
        db.session.add(recycled_barcode)
        db.session.delete(item)
        db.session.commit()
        log = ActionLog(action="Item Deleted", user_id=int(identity), details=f"Item {item.barcode} deleted and barcode recycled")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item deleted successfully and barcode recycled"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in delete_item: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/item_codes", methods=["GET"])
@jwt_required()
def get_item_codes():
    try:
        item_codes = ItemCode.query.all()
        result = [{
            "id": ic.id,
            "name": ic.name,
            "type": ic.type,
            "code": ic.code
        } for ic in item_codes]
        return jsonify(result)
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
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "name" not in data or "type" not in data or "code" not in data:
        return jsonify({"error": "Name, type, and code are required"}), 400
    if not re.match(r"^[A-Z0-9]{2}$", data["code"]):
         return jsonify({"error": "Code must be 2 uppercase alphanumeric characters"}), 400
    if ItemCode.query.filter_by(code=data["code"]).first():
        return jsonify({"error": "Item code already exists"}), 400
    try:
        item_code = ItemCode(name=data["name"], type=data["type"], code=data["code"])
        db.session.add(item_code)
        db.session.commit()
        log = ActionLog(action="Item Code Added", user_id=int(identity), details=f"Item Code {item_code.code} ({item_code.name}) added")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item code added successfully"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in add_item_code: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/item_codes/<int:code_id>", methods=["PUT"])
@jwt_required()
def update_item_code(code_id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    item_code = ItemCode.query.get(code_id)
    if not item_code:
        return jsonify({"error": "Item code not found"}), 404
    data = request.get_json()
    try:
        if "name" in data: item_code.name = data["name"]
        if "type" in data: item_code.type = data["type"]
        # Code itself is not updatable to maintain integrity with barcodes
        db.session.commit()
        log = ActionLog(action="Item Code Updated", user_id=int(identity), details=f"Item Code {item_code.code} updated")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item code updated successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in update_item_code: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/item_codes/<int:code_id>", methods=["DELETE"])
@jwt_required()
def delete_item_code(code_id):
    identity = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    if role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    item_code = ItemCode.query.get(code_id)
    if not item_code:
        return jsonify({"error": "Item code not found"}), 404
    # Check if any items use this code before deleting - might be complex if barcodes are already generated
    # For now, allow deletion. Consider implications for existing items if this is a live system.
    try:
        db.session.delete(item_code)
        db.session.commit()
        log = ActionLog(action="Item Code Deleted", user_id=int(identity), details=f"Item Code {item_code.code} deleted")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Item code deleted successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in delete_item_code: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports/inventory", methods=["GET"])
@jwt_required()
def inventory_report():
    try:
        items = Item.query.order_by(Item.name).all()
        report_data = []
        for item in items:
            report_data.append({
                "Name": item.name,
                "Barcode": item.barcode,
                "Vendor": item.vendor,
                "Cost": item.cost,
                "Status": item.status,
                "Condition": item.condition,
                "Item Group": item.item_group,
                "Notes": item.notes
            })
        return jsonify(report_data)
    except Exception as e:
        print(f"Error in inventory_report: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports/inmate_items", methods=["GET"])
@jwt_required()
def inmate_items_report():
    try:
        assigned_items = db.session.query(
                Inmate.name.label("inmate_name"),
                Inmate.id.label("inmate_id_val"), # aliasing Inmate.id to avoid conflict
                Item.name.label("item_name"),
                Item.barcode,
                InmateItem.assigned_date,
                InmateItem.return_status,
                InmateItem.condition
            ).\
            join(InmateItem, Inmate.id == InmateItem.inmate_id).\
            join(Item, Item.id == InmateItem.item_id).\
            order_by(Inmate.name, Item.name).all()
        
        report_data = []
        for row in assigned_items:
            report_data.append({
                "Inmate Name": row.inmate_name,
                "Inmate ID": str(row.inmate_id_val),
                "Item Name": row.item_name,
                "Item Barcode": row.barcode,
                "Assigned Date": row.assigned_date.isoformat() if row.assigned_date else None,
                "Return Status": row.return_status,
                "Condition": row.condition
            })
        return jsonify(report_data)
    except Exception as e:
        print(f"Error in inmate_items_report: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports/fees", methods=["GET"])
@jwt_required()
def fees_report():
    try:
        fees_data = db.session.query(
                Inmate.name.label("inmate_name"),
                Inmate.id.label("inmate_id_val"),
                Fee.name.label("fee_name"),
                Fee.amount,
                Fee.date_applied,
                Fee.item_barcodes,
                Fee.notes
            ).select_from(Fee).outerjoin(Inmate, Fee.inmate_id == Inmate.id). \
            order_by(Inmate.name, Fee.date_applied.desc()).all()

        report_data = []
        for row in fees_data:
            report_data.append({
                "Inmate Name": row.inmate_name or "N/A (Fee not tied to specific inmate)",
                "Inmate ID": str(row.inmate_id_val) if row.inmate_id_val else "N/A",
                "Fee Name": row.fee_name,
                "Amount": row.amount,
                "Date Applied": row.date_applied.isoformat() if row.date_applied else None,
                "Item Barcodes": row.item_barcodes,
                "Notes": row.notes
            })
        return jsonify(report_data)
    except Exception as e:
        print(f"Error in fees_report: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports/action_logs", methods=["GET"])
@jwt_required()
def action_logs_report():
    try:
        logs = db.session.query(
                ActionLog.action,
                User.username.label("user_username"),
                ActionLog.timestamp,
                ActionLog.details
            ).
            outerjoin(User, User.id == ActionLog.user_id).
            order_by(ActionLog.timestamp.desc()).all()
        
        report_data = []
        for log_entry in logs:
            report_data.append({
                "Action": log_entry.action,
                "User": log_entry.user_username or "System/Unknown",
                "Timestamp": log_entry.timestamp.isoformat() if log_entry.timestamp else None,
                "Details": log_entry.details
            })
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

@app.route("/users", methods=["POST"])
@jwt_required()
def add_user():
    identity = get_jwt_identity() # Current user performing action
    claims = get_jwt()
    current_user_role = claims.get("role")
    if current_user_role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    data = request.get_json()
    if not data or "username" not in data or "password" not in data or "first_name" not in data or "last_name" not in data:
        return jsonify({"error": "Username, password, first_name, and last_name are required"}), 400
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
    current_user_role = claims.get("role")
    if current_user_role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    data = request.get_json()
    try:
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
        db.session.commit()
        log = ActionLog(action="User Updated", user_id=int(identity), details=f"User {user.username} (ID: {user_id}) updated")
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
    current_user_role = claims.get("role")
    if current_user_role != "Admin":
        return jsonify({"error": "Permission denied"}), 403
    if int(identity) == user_id:
        return jsonify({"error": "Admin users cannot delete themselves"}), 400
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    try:
        db.session.delete(user)
        db.session.commit()
        log = ActionLog(action="User Deleted", user_id=int(identity), details=f"User {user.username} (ID: {user_id}) deleted")
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        db.session.rollback()
        print(f"Error in delete_user: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all() # Ensure tables are created if they don't exist
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5001)))

