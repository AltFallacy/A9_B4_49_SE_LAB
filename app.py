"""
app.py - Main Flask Application for Sports Management System (SPMS)
-------------------------------------------------------------------
This module contains the Flask application instance, route controllers,
authentication middleware, session management, CSRF validation,
and input validation logic.

Academic Context:
Designed for a Software Engineering PBL assignment demonstrating:
- Role-based staff authentication
- Inventory CRUD operations
- Parameterized SQLite access
- Defensive server-side input validation
"""

import os
import secrets
from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
)
from dotenv import load_dotenv

from database import (
    get_db_connection,
    init_db,
    verify_user,
    get_db_path,
)

# Load environment variables from .env file if present
load_dotenv()

# Initialize Flask application
app = Flask(__name__)

# Application Configuration
app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY", "spms-default-fallback-dev-key-change-in-production"
)
app.config["DATABASE_PATH"] = os.environ.get("DATABASE_PATH", "spms.db")

# Ensure secure cookie configurations
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Valid domain values for equipment condition
ALLOWED_CONDITIONS = ("Good", "Needs Repair", "Damaged")


# ==============================================================================
# Helper Functions & Middleware
# ==============================================================================


def login_required(view_func):
    """
    Decorator to ensure route is only accessible by authenticated users.
    If the user is unauthenticated, redirects to login page with a flash message.
    """

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)

    return wrapped_view


def generate_csrf_token():
    """
    Generates and stores a unique CSRF token in the session if not present.
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.context_processor
def inject_template_globals():
    """
    Injects useful helper variables into all Jinja2 templates automatically.
    - csrf_token: accessible in every form
    - current_user: username of logged-in staff member
    """
    return {
        "csrf_token": generate_csrf_token(),
        "current_user": session.get("username"),
        "is_authenticated": "user_id" in session,
        "allowed_conditions": ALLOWED_CONDITIONS,
    }


@app.before_request
def csrf_protect():
    """
    Validates CSRF token on all state-mutating requests (POST).
    Can be bypassed in automated tests by setting app.config['TESTING'] = True.
    """
    if request.method == "POST":
        if app.config.get("TESTING"):
            # Allow tests to bypass CSRF if explicitly disabled in test configuration
            if app.config.get("WTF_CSRF_ENABLED") is False:
                return

        token = request.form.get("csrf_token")
        expected_token = session.get("csrf_token")

        if not expected_token or not token or not secrets.compare_digest(token, expected_token):
            flash("Security check failed: Invalid or expired session token. Please try again.", "danger")
            abort(400, description="CSRF token validation failed.")


@app.after_request
def add_security_headers(response):
    """
    Appends security and cache-control headers to prevent browsers from
    caching protected pages (prevents viewing dashboard via back button after logout).
    """
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def validate_equipment_payload(name, category, quantity_str, condition, description):
    """
    Performs comprehensive server-side validation for equipment forms.
    Returns: (is_valid, cleaned_data, list_of_error_messages)
    """
    errors = []

    # 1. Validate Name
    cleaned_name = name.strip() if name else ""
    if not cleaned_name:
        errors.append("Equipment Name is required and cannot be empty or whitespace only.")

    # 2. Validate Category
    cleaned_category = category.strip() if category else ""
    if not cleaned_category:
        errors.append("Category is required and cannot be empty.")

    # 3. Validate Quantity
    cleaned_quantity = None
    if quantity_str is None or str(quantity_str).strip() == "":
        errors.append("Quantity is required.")
    else:
        try:
            cleaned_quantity = int(str(quantity_str).strip())
            if cleaned_quantity < 0:
                errors.append("Quantity must be a non-negative whole number (0 or higher).")
        except ValueError:
            errors.append("Quantity must be a valid whole number (integer).")

    # 4. Validate Condition
    cleaned_condition = condition.strip() if condition else ""
    if cleaned_condition not in ALLOWED_CONDITIONS:
        errors.append(
            f"Condition must be one of: {', '.join(ALLOWED_CONDITIONS)}."
        )

    # 5. Clean Description (optional)
    cleaned_description = description.strip() if description else ""

    cleaned_data = {
        "name": cleaned_name,
        "category": cleaned_category,
        "quantity": cleaned_quantity,
        "condition": cleaned_condition,
        "description": cleaned_description,
    }

    return (len(errors) == 0), cleaned_data, errors


# ==============================================================================
# Authentication Routes (Module 1)
# ==============================================================================


@app.route("/")
def index():
    """
    Root route: redirects authenticated users to Dashboard,
    or unauthenticated visitors to Login page.
    """
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    User login controller.
    Validates credentials against SQLite database and sets up session.
    """
    # If already logged in, redirect straight to dashboard
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Server-side validation for required fields
        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template("login.html", username=username)

        # Verify against database
        db_path = app.config.get("DATABASE_PATH")
        user = verify_user(username, password, db_path=db_path)

        if user:
            # Clear any prior session data to prevent session fixation
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            generate_csrf_token()

            flash(f"Welcome back, {user['username']}! Login successful.", "success")

            # Handle safe redirection to the requested 'next' URL
            next_page = request.args.get("next")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password. Please try again.", "danger")
            return render_template("login.html", username=username)

    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """
    Terminates the user session and redirects to the login screen.
    """
    session.clear()
    flash("You have been successfully logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    """
    Administrative Dashboard.
    Presents summary statistics and quick links to equipment management.
    """
    db_path = app.config.get("DATABASE_PATH")
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()

        # Total distinct equipment items
        cursor.execute("SELECT COUNT(*) AS total_items FROM equipment")
        total_items = cursor.fetchone()["total_items"]

        # Total inventory stock units
        cursor.execute("SELECT COALESCE(SUM(quantity), 0) AS total_units FROM equipment")
        total_units = cursor.fetchone()["total_units"]

        # Condition counts
        cursor.execute(
            """
            SELECT condition, COUNT(*) as count
            FROM equipment
            GROUP BY condition
            """
        )
        condition_rows = cursor.fetchall()
        condition_stats = {"Good": 0, "Needs Repair": 0, "Damaged": 0}
        for row in condition_rows:
            if row["condition"] in condition_stats:
                condition_stats[row["condition"]] = row["count"]

        # 5 most recently updated / added equipment records
        cursor.execute(
            "SELECT * FROM equipment ORDER BY id DESC LIMIT 5"
        )
        recent_items = cursor.fetchall()

        return render_template(
            "dashboard.html",
            total_items=total_items,
            total_units=total_units,
            condition_stats=condition_stats,
            recent_items=recent_items,
        )
    finally:
        conn.close()


# ==============================================================================
# Sports Equipment Management Routes (Module 2)
# ==============================================================================


@app.route("/equipment")
@login_required
def equipment_list():
    """
    Displays the catalog of sports equipment with search capability.
    Supports search across Name, Category, and ID.
    """
    search_query = request.args.get("search", "").strip()
    db_path = app.config.get("DATABASE_PATH")
    conn = get_db_connection(db_path)

    try:
        cursor = conn.cursor()
        if search_query:
            # Check if search query is a specific integer ID
            is_numeric = search_query.isdigit()
            if is_numeric:
                sql = """
                    SELECT * FROM equipment
                    WHERE id = ? OR name LIKE ? OR category LIKE ?
                    ORDER BY id DESC
                """
                like_param = f"%{search_query}%"
                cursor.execute(sql, (int(search_query), like_param, like_param))
            else:
                sql = """
                    SELECT * FROM equipment
                    WHERE name LIKE ? OR category LIKE ?
                    ORDER BY id DESC
                """
                like_param = f"%{search_query}%"
                cursor.execute(sql, (like_param, like_param))
        else:
            cursor.execute("SELECT * FROM equipment ORDER BY id DESC")

        items = cursor.fetchall()
        return render_template(
            "equipment.html",
            items=items,
            search_query=search_query,
            total_count=len(items),
        )
    finally:
        conn.close()


@app.route("/equipment/add", methods=["GET", "POST"])
@login_required
def add_equipment():
    """
    Renders equipment insertion form and handles record creation.
    """
    if request.method == "POST":
        name = request.form.get("name")
        category = request.form.get("category")
        quantity = request.form.get("quantity")
        condition = request.form.get("condition")
        description = request.form.get("description")

        is_valid, cleaned, errors = validate_equipment_payload(
            name, category, quantity, condition, description
        )

        if not is_valid:
            for err in errors:
                flash(err, "danger")
            # Preserve form inputs on failure so user doesn't lose work
            return render_template(
                "add_equipment.html",
                form_data=request.form,
            )

        db_path = app.config.get("DATABASE_PATH")
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO equipment (name, category, quantity, condition, description)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    cleaned["name"],
                    cleaned["category"],
                    cleaned["quantity"],
                    cleaned["condition"],
                    cleaned["description"],
                ),
            )
            conn.commit()
            flash(
                f"Equipment '{cleaned['name']}' has been added successfully!",
                "success",
            )
            return redirect(url_for("equipment_list"))
        except Exception as e:
            conn.rollback()
            flash("Database error occurred while adding equipment. Please try again.", "danger")
            return render_template("add_equipment.html", form_data=request.form)
        finally:
            conn.close()

    return render_template("add_equipment.html", form_data={})


@app.route("/equipment/edit/<int:item_id>", methods=["GET", "POST"])
@login_required
def edit_equipment(item_id):
    """
    Retrieves and updates an existing equipment record.
    Rejects nonexistent record modifications with clear messaging.
    """
    db_path = app.config.get("DATABASE_PATH")
    conn = get_db_connection(db_path)

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM equipment WHERE id = ?", (item_id,))
        item = cursor.fetchone()

        if item is None:
            flash(f"Equipment record #{item_id} does not exist.", "danger")
            return redirect(url_for("equipment_list"))

        if request.method == "POST":
            name = request.form.get("name")
            category = request.form.get("category")
            quantity = request.form.get("quantity")
            condition = request.form.get("condition")
            description = request.form.get("description")

            is_valid, cleaned, errors = validate_equipment_payload(
                name, category, quantity, condition, description
            )

            if not is_valid:
                for err in errors:
                    flash(err, "danger")
                return render_template(
                    "edit_equipment.html",
                    item=request.form,
                    item_id=item_id,
                )

            cursor.execute(
                """
                UPDATE equipment
                SET name = ?, category = ?, quantity = ?, condition = ?,
                    description = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    cleaned["name"],
                    cleaned["category"],
                    cleaned["quantity"],
                    cleaned["condition"],
                    cleaned["description"],
                    item_id,
                ),
            )
            conn.commit()
            flash(
                f"Equipment #{item_id} ('{cleaned['name']}') was successfully updated.",
                "success",
            )
            return redirect(url_for("equipment_list"))

        return render_template("edit_equipment.html", item=item, item_id=item_id)
    finally:
        conn.close()


@app.route("/equipment/delete/<int:item_id>", methods=["POST"])
@login_required
def delete_equipment(item_id):
    """
    Deletes an existing equipment record.
    Requires POST method to prevent accidental or CSRF-based deletions.
    """
    db_path = app.config.get("DATABASE_PATH")
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM equipment WHERE id = ?", (item_id,))
        item = cursor.fetchone()

        if item is None:
            flash(f"Cannot delete: Equipment record #{item_id} was not found.", "danger")
            return redirect(url_for("equipment_list"))

        cursor.execute("DELETE FROM equipment WHERE id = ?", (item_id,))
        conn.commit()
        flash(f"Equipment #{item_id} ('{item['name']}') has been removed.", "success")
        return redirect(url_for("equipment_list"))
    finally:
        conn.close()


# ==============================================================================
# Error Handlers
# ==============================================================================


@app.errorhandler(400)
def bad_request(error):
    description = getattr(error, "description", "Bad Request")
    return (
        render_template(
            "base.html",
            error_code=400,
            error_title="Bad Request",
            error_message=description,
        ),
        400,
    )


@app.errorhandler(404)
def not_found(error):
    return (
        render_template(
            "base.html",
            error_code=404,
            error_title="Page Not Found",
            error_message="The requested resource could not be found.",
        ),
        404,
    )


@app.errorhandler(500)
def internal_error(error):
    return (
        render_template(
            "base.html",
            error_code=500,
            error_title="Server Error",
            error_message="An unexpected server error occurred. Please contact the administrator.",
        ),
        500,
    )


# ==============================================================================
# Application Entry Point
# ==============================================================================

if __name__ == "__main__":
    # Ensure database schema is present before running
    init_db(get_db_path())
    print("\n" + "=" * 60)
    print(" Sports Management System (SPMS) is running!")
    print(" Access URL: http://127.0.0.1:5000")
    print(" Default Login -> Username: admin | Password: admin123")
    print("=" * 60 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
