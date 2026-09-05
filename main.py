import os
import sqlite3
from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)
app = Flask(__name__)
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "change-this-secret"
)
DATABASE = "mt_characters.db"
# =========================================================
# الصلاحيات
# =========================================================
PERMISSIONS = {
    # الشخصيات
    "characters_view_all": "عرض جميع الشخصيات",
    "characters_view_details": "عرض تفاصيل الشخصيات",
    "characters_search": "البحث عن الشخصيات",
    "characters_edit_all": "تعديل جميع الشخصيات",
    "characters_delete_all": "حذف جميع الشخصيات",
    "characters_hide": "إخفاء شخصية",
    "characters_show": "إظهار شخصية",
    "characters_transfer": "نقل شخصية بين الحسابات",
    "characters_reset": "إعادة تعيين بيانات الشخصية",
    # الشرطة
    "police_manage": "إدارة الشرطة",
    "police_view": "عرض أفراد الشرطة",
    "police_add": "إضافة أفراد الشرطة",
    "police_edit": "تعديل أفراد الشرطة",
    "police_delete": "حذف أفراد الشرطة",
    "police_assign_rank": "تعيين رتبة شرطة",
    "police_change_rank": "تغيير رتبة شرطة",
    "police_remove": "إزالة فرد من الشرطة",
    # العدل
    "justice_manage": "إدارة وزارة العدل",
    "justice_view": "عرض أفراد العدل",
    "justice_add": "إضافة أفراد العدل",
    "justice_edit": "تعديل أفراد العدل",
    "justice_delete": "حذف أفراد العدل",
    "justice_assign_rank": "تعيين رتبة عدل",
    "justice_change_rank": "تغيير رتبة عدل",
    "justice_remove": "إزالة فرد من العدل",
    # الصحة
    "health_manage": "إدارة الصحة",
    "health_view": "عرض أفراد الصحة",
    "health_add": "إضافة أفراد الصحة",
    "health_edit": "تعديل أفراد الصحة",
    "health_delete": "حذف أفراد الصحة",
    "health_assign_rank": "تعيين رتبة صحية",
    "health_change_rank": "تغيير رتبة صحية",
    "health_remove": "إزالة فرد من الصحة",
    # العصابات
    "gangs_manage": "إدارة العصابات",
    "gangs_view": "عرض العصابات",
    "gangs_add": "إنشاء عصابة",
    "gangs_edit": "تعديل العصابات",
    "gangs_delete": "حذف العصابات",
    "gangs_add_members": "إضافة أعضاء",
    "gangs_remove_members": "إزالة أعضاء",
    "gangs_change_leader": "تغيير قائد العصابة",
    # المستخدمون
    "users_view": "عرض المستخدمين",
    "users_edit": "تعديل المستخدمين",
    "users_ban": "حظر المستخدمين",
    "users_unban": "فك حظر المستخدمين",
    "users_delete": "حذف المستخدمين",
    "users_disable": "تعطيل الحسابات",
    "users_enable": "تفعيل الحسابات",
    # الصلاحيات
    "permissions_view": "عرض صلاحيات المستخدمين",
    "permissions_give": "إعطاء الصلاحيات",
    "permissions_remove": "سحب الصلاحيات",
    "permissions_edit": "تعديل صلاحيات المستخدم",
    # الموقع
    "site_settings": "تعديل إعدادات الموقع",
    "site_sections": "إدارة الأقسام",
    "site_home": "إدارة الصفحة الرئيسية",
    "site_maintenance": "صيانة الموقع",
    # السجلات
    "logs_view": "عرض سجل العمليات",
    "logs_search": "البحث في السجلات",
    "logs_export": "تصدير السجلات",
    # الإدارة العليا
    "admins_manage": "إدارة المدراء",
    "admins_add": "تعيين مدير",
    "admins_remove": "إزالة مدير",
    "admins_all_permissions": "التحكم بجميع الصلاحيات",
    "admins_all_sections": "التحكم بجميع الأقسام",
}
DEPARTMENTS = {
    "police": "الشرطة",
    "justice": "وزارة العدل",
    "health": "الصحة",
    "gangs": "العصابات",
}
# =========================================================
# قاعدة البيانات
# =========================================================
def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db
def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_banned INTEGER DEFAULT 0,
            is_disabled INTEGER DEFAULT 0,
            is_owner INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS characters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            first_name TEXT NOT NULL,
            second_name TEXT NOT NULL,
            full_name TEXT NOT NULL,
            full_name_key TEXT UNIQUE NOT NULL,
            country TEXT NOT NULL,
            nationality TEXT NOT NULL,
            birth_date TEXT NOT NULL,
            hidden INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS user_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            permission TEXT NOT NULL,
            UNIQUE(user_id, permission),
            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS character_departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            character_id INTEGER NOT NULL,
            department TEXT NOT NULL,
            UNIQUE(character_id, department),
            FOREIGN KEY (character_id)
            REFERENCES characters(id)
            ON DELETE CASCADE
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS character_ranks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            character_id INTEGER NOT NULL,
            department TEXT NOT NULL,
            rank_name TEXT NOT NULL,
            UNIQUE(character_id, department),
            FOREIGN KEY (character_id)
            REFERENCES characters(id)
            ON DELETE CASCADE
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS gangs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            leader TEXT,
            status TEXT DEFAULT 'نشطة',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS gang_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gang_id INTEGER NOT NULL,
            character_id INTEGER NOT NULL,
            UNIQUE(gang_id, character_id),
            FOREIGN KEY (gang_id)
            REFERENCES gangs(id)
            ON DELETE CASCADE,
            FOREIGN KEY (character_id)
            REFERENCES characters(id)
            ON DELETE CASCADE
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE SET NULL
        )
    """)
    db.commit()
    db.close()
# =========================================================
# الإدارة الرئيسية
# =========================================================
def create_owner():
    username = os.environ.get(
        "MT_ADMIN_USERNAME",
        "admin"
    )
    password = os.environ.get(
        "MT_ADMIN_PASSWORD",
        "CHANGE_THIS_PASSWORD"
    )
    db = get_db()
    owner = db.execute("""
        SELECT id
        FROM users
        WHERE is_owner = 1
        LIMIT 1
    """).fetchone()
    if not owner:
        db.execute("""
            INSERT INTO users (
                username,
                password_hash,
                is_owner
            )
            VALUES (?, ?, 1)
        """, (
            username,
            generate_password_hash(password)
        ))
        db.commit()
    db.close()
# =========================================================
# المستخدم الحالي
# =========================================================
def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    user = db.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        user_id,
    )).fetchone()
    db.close()
    return user
# =========================================================
# الصلاحيات
# =========================================================
def has_permission(permission):
    user = current_user()
    if not user:
        return False
    if user["is_owner"]:
        return True
    db = get_db()
    result = db.execute("""
        SELECT id
        FROM user_permissions
        WHERE user_id = ?
        AND permission = ?
        LIMIT 1
    """, (
        user["id"],
        permission
    )).fetchone()
    db.close()
    return result is not None
def permission_required(permission):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(
                    url_for("login")
                )
            if not has_permission(permission):
                flash(
                    "ليس لديك صلاحية لهذا الإجراء."
                )
                return redirect(
                    url_for("home")
                )
            return function(*args, **kwargs)
        return wrapper
    return decorator
# =========================================================
# سجل العمليات
# =========================================================
def log_action(action):
    user = current_user()
    if not user:
        return
    db = get_db()
    db.execute("""
        INSERT INTO activity_logs (
            user_id,
            action
        )
        VALUES (?, ?)
    """, (
        user["id"],
        action
    ))
    db.commit()
    db.close()
# =========================================================
# توحيد الأسماء
# =========================================================
def normalize_name(name):
    replacements = {
        "أ": "ا",
        "إ": "ا",
        "آ": "ا",
        "ة": "ه",
        "ى": "ي"
    }
    name = name.strip()
    for old, new in replacements.items():
        name = name.replace(old, new)
    name = name.replace("ـ", "")
    name = " ".join(
        name.split()
    )
    return name.casefold()
# =========================================================
# الصفحة الرئيسية
# =========================================================
@app.route("/")
def home():
    user = current_user()
    return render_template(
        "index.html",
        user=user,
        has_permission=has_permission
    )
# =========================================================
# التسجيل
# =========================================================
@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():
    if request.method == "POST":
        username = request.form.get(
            "username",
            ""
        ).strip()
        password = request.form.get(
            "password",
            ""
        )
        confirm_password = request.form.get(
            "confirm_password",
            ""
        )
        if len(username) < 3:
            flash(
                "اسم المستخدم يجب أن يكون 3 أحرف على الأقل."
            )
            return redirect(
                url_for("register")
            )
        if len(password) < 6:
            flash(
                "كلمة المرور يجب أن تكون 6 أحرف على الأقل."
            )
            return redirect(
                url_for("register")
            )
        if password != confirm_password:
            flash(
                "كلمتا المرور غير متطابقتين."
            )
            return redirect(
                url_for("register")
            )
        db = get_db()
        exists = db.execute("""
            SELECT id
            FROM users
            WHERE username = ?
        """, (
            username,
        )).fetchone()
        if exists:
            db.close()
            flash(
                "اسم المستخدم مستخدم مسبقًا."
            )
            return redirect(
                url_for("register")
            )
        db.execute("""
            INSERT INTO users (
                username,
                password_hash
            )
            VALUES (?, ?)
        """, (
            username,
            generate_password_hash(password)
        ))
        db.commit()
        db.close()
        flash(
            "تم إنشاء الحساب بنجاح."
        )
        return redirect(
            url_for("login")
        )
    return render_template(
        "register.html"
    )
# =========================================================
# تسجيل الدخول
# =========================================================
@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():
    if request.method == "POST":
        username = request.form.get(
            "username",
            ""
        ).strip()
        password = request.form.get(
            "password",
            ""
        )
        db = get_db()
        user = db.execute("""
            SELECT *
            FROM users
            WHERE username = ?
        """, (
            username,
        )).fetchone()
        db.close()
        if not user:
            flash(
                "اسم المستخدم أو كلمة المرور غير صحيحة."
            )
            return redirect(
                url_for("login")
            )
        if user["is_banned"]:
            flash(
                "الحساب محظور."
            )
            return redirect(
                url_for("login")
            )
        if user["is_disabled"]:
            flash(
                "الحساب معطل."
            )
            return redirect(
                url_for("login")
            )
        if not check_password_hash(
            user["password_hash"],
            password
        ):
            flash(
                "اسم المستخدم أو كلمة المرور غير صحيحة."
            )
            return redirect(
                url_for("login")
            )
        session.clear()
        session["user_id"] = user["id"]
        log_action(
            "تسجيل الدخول"
        )
        return redirect(
            url_for("home")
        )
    return render_template(
        "login.html"
    )
# =========================================================
# تسجيل الخروج
# =========================================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        url_for("home")
    )
# =========================================================
# الشخصيات
# =========================================================
@app.route("/characters")
def characters():
    user = current_user()
    if not user:
        return redirect(
            url_for("login")
        )
    db = get_db()
    if has_permission(
        "characters_view_all"
    ):
        rows = db.execute("""
            SELECT
                characters.*,
                users.username
            FROM characters
            JOIN users
            ON users.id = characters.user_id
            ORDER BY characters.id DESC
        """).fetchall()
        admin_view = True
    else:
        rows = db.execute("""
            SELECT *
            FROM characters
            WHERE user_id = ?
            AND hidden = 0
            ORDER BY id DESC
        """, (
            user["id"],
        )).fetchall()
        admin_view = False
    characters_data = []
    for character in rows:
        ranks = db.execute("""
            SELECT
                department,
                rank_name
            FROM character_ranks
            WHERE character_id = ?
        """, (
            character["id"],
        )).fetchall()
        departments = db.execute("""
            SELECT department
            FROM character_departments
            WHERE character_id = ?
        """, (
            character["id"],
        )).fetchall()
        characters_data.append({
            "character": character,
            "ranks": ranks,
            "departments": departments
        })
    db.close()
    return render_template(
        "characters.html",
        characters=characters_data,
        admin_view=admin_view,
        can_edit_all=has_permission(
            "characters_edit_all"
        ),
        can_delete_all=has_permission(
            "characters_delete_all"
        ),
        can_manage_sections=has_permission(
            "site_sections"
        )
    )
# =========================================================
# إنشاء شخصية
# =========================================================
@app.route(
    "/characters/register",
    methods=["GET", "POST"]
)
def register_character():
    user = current_user()
    if not user:
        return redirect(
            url_for("login")
        )
    db = get_db()
    count = db.execute("""
        SELECT COUNT(*)
        FROM characters
        WHERE user_id = ?
    """, (
        user["id"],
    )).fetchone()[0]
    if count >= 3:
        db.close()
        flash(
            "وصلت للحد الأقصى: 3 شخصيات."
        )
        return redirect(
            url_for("characters")
        )
    if request.method == "POST":
        first_name = request.form.get(
            "first_name",
            ""
        ).strip()
        second_name = request.form.get(
            "second_name",
            ""
        ).strip()
        country = request.form.get(
            "country",
            ""
        ).strip()
        nationality = request.form.get(
            "nationality",
            ""
        ).strip()
        birth_date = request.form.get(
            "birth_date",
            ""
        ).strip()
        if not all([
            first_name,
            second_name,
            country,
            nationality,
            birth_date
        ]):
            db.close()
            flash(
                "فضلاً عب جميع البيانات."
            )
            return redirect(
                url_for("register_character")
            )
        full_name = (
            f"{first_name} {second_name}"
        )
        full_name_key = normalize_name(
            full_name
        )
        exists = db.execute("""
            SELECT id
            FROM characters
            WHERE full_name_key = ?
        """, (
            full_name_key,
        )).fetchone()
        if exists:
            db.close()
            flash(
                "اسم الشخصية مستخدم مسبقًا."
            )
            return redirect(
                url_for("register_character")
            )
        cursor = db.execute("""
            INSERT INTO characters (
                user_id,
                first_name,
                second_name,
                full_name,
                full_name_key,
                country,
                nationality,
                birth_date
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user["id"],
            first_name,
            second_name,
            full_name,
            full_name_key,
            country,
            nationality,
            birth_date
        ))
        character_id = cursor.lastrowid
        # الرتبة العامة التلقائية
        db.execute("""
            INSERT INTO character_ranks (
                character_id,
                department,
                rank_name
            )
            VALUES (?, ?, ?)
        """, (
            character_id,
            "general",
            "يوجد شخصية"
        ))
        db.commit()
        db.close()
        log_action(
            f"إنشاء شخصية: {full_name}"
        )
        flash(
            "تم إنشاء الشخصية بنجاح."
        )
        return redirect(
            url_for("characters")
        )
    db.close()
    return render_template(
        "register_character.html"
    )
# =========================================================
# حذف شخصية المستخدم
# =========================================================
@app.route(
    "/characters/<int:character_id>/delete",
    methods=["POST"]
)
def delete_own_character(
    character_id
):
    user = current_user()
    if not user:
        return redirect(
            url_for("login")
        )
    db = get_db()
    character = db.execute("""
        SELECT *
        FROM characters
        WHERE id = ?
        AND user_id = ?
    """, (
        character_id,
        user["id"]
    )).fetchone()
    if not character:
        db.close()
        flash(
            "لا يمكنك حذف هذه الشخصية."
        )
        return redirect(
            url_for("characters")
        )
    db.execute("""
        DELETE FROM characters
        WHERE id = ?
    """, (
        character_id,
    ))
    db.commit()
    db.close()
    log_action(
        f"حذف الشخصية: {character['full_name']}"
    )
    flash(
        "تم حذف الشخصية."
    )
    return redirect(
        url_for("characters")
    )
# =========================================================
# حذف شخصية إداري
# =========================================================
@app.route(
    "/admin/characters/<int:character_id>/delete",
    methods=["POST"]
)
@permission_required(
    "characters_delete_all"
)
def admin_delete_character(
    character_id
):
    db = get_db()
    character = db.execute("""
        SELECT *
        FROM characters
        WHERE id = ?
    """, (
        character_id,
    )).fetchone()
    if not character:
        db.close()
        flash(
            "الشخصية غير موجودة."
        )
        return redirect(
            url_for("characters")
        )
    db.execute("""
        DELETE FROM characters
        WHERE id = ?
    """, (
        character_id,
    ))
    db.commit()
    db.close()
    log_action(
        f"حذف شخصية إداريًا: {character['full_name']}"
    )
    flash(
        "تم حذف الشخصية."
    )
    return redirect(
        url_for("characters")
    )
# =========================================================
# تعديل شخصية إداري
# =========================================================
@app.route(
    "/admin/characters/<int:character_id>/edit",
    methods=["POST"]
)
@permission_required(
    "characters_edit_all"
)
def admin_edit_character(
    character_id
):
    first_name = request.form.get(
        "first_name",
        ""
    ).strip()
    second_name = request.form.get(
        "second_name",
        ""
    ).strip()
    country = request.form.get(
        "country",
        ""
    ).strip()
    nationality = request.form.get(
        "nationality",
        ""
    ).strip()
    birth_date = request.form.get(
        "birth_date",
        ""
    ).strip()
    if not all([
        first_name,
        second_name,
        country,
        nationality,
        birth_date
    ]):
        flash(
            "جميع البيانات مطلوبة."
        )
        return redirect(
            url_for("characters")
        )
    full_name = (
        f"{first_name} {second_name}"
    )
    full_name_key = normalize_name(
        full_name
    )
    db = get_db()
    exists = db.execute("""
        SELECT id
        FROM characters
        WHERE full_name_key = ?
        AND id != ?
    """, (
        full_name_key,
        character_id
    )).fetchone()
    if exists:
        db.close()
        flash(
            "اسم الشخصية مستخدم مسبقًا."
        )
        return redirect(
            url_for("characters")
        )
    db.execute("""
        UPDATE characters
        SET
            first_name = ?,
            second_name = ?,
            full_name = ?,
            full_name_key = ?,
            country = ?,
            nationality = ?,
            birth_date = ?
        WHERE id = ?
    """, (
        first_name,
        second_name,
        full_name,
        full_name_key,
        country,
        nationality,
        birth_date,
        character_id
    ))
    db.commit()
    db.close()
    log_action(
        f"تعديل شخصية: {full_name}"
    )
    flash(
        "تم تعديل الشخصية."
    )
    return redirect(
        url_for("characters")
    )
# =========================================================
# تحديد صلاحية إدارة القسم
# =========================================================
def department_manage_permission(
    department
):
    return f"{department}_manage"
def department_view_permission(
    department
):
    return f"{department}_view"
# =========================================================
# تعيين قسم للشخصية
# =========================================================
@app.route(
    "/admin/characters/<int:character_id>/department",
    methods=["POST"]
)
def assign_department(
    character_id
):
    user = current_user()
    if not user:
        return redirect(
            url_for("login")
        )
    department = request.form.get(
        "department",
        ""
    ).strip()
    if department not in DEPARTMENTS:
        flash(
            "القسم غير صحيح."
        )
        return redirect(
            url_for("characters")
        )
    permission = department_manage_permission(
        department
    )
    if not has_permission(permission):
        flash(
            "ليس لديك صلاحية إدارة هذا القسم."
        )
        return redirect(
            url_for("characters")
        )
    db = get_db()
    character = db.execute("""
        SELECT *
        FROM characters
        WHERE id = ?
    """, (
        character_id,
    )).fetchone()
    if not character:
        db.close()
        flash(
            "الشخصية غير موجودة."
        )
        return redirect(
            url_for("characters")
        )
    db.execute("""
        INSERT OR IGNORE INTO character_departments (
            character_id,
            department
        )
        VALUES (?, ?)
    """, (
        character_id,
        department
    ))
    db.execute("""
        INSERT OR IGNORE INTO character_ranks (
            character_id,
            department,
            rank_name
        )
        VALUES (?, ?, ?)
    """, (
        character_id,
        department,
        "عضو"
    ))
    db.commit()
    db.close()
    log_action(
        f"تعيين {character['full_name']} إلى {DEPARTMENTS[department]}"
    )
    flash(
        f"تم تعيين الشخصية إلى {DEPARTMENTS[department]}."
    )
    return redirect(
        url_for("characters")
    )
# =========================================================
# إزالة شخصية من قسم
# =========================================================
@app.route(
    "/admin/characters/<int:character_id>/department/remove",
    methods=["POST"]
)
def remove_department(
    character_id
):
    user = current_user()
    if not user:
        return redirect(
            url_for("login")
        )
    department = request.form.get(
        "department",
        ""
    ).strip()
    if department not in DEPARTMENTS:
        flash(
            "القسم غير صحيح."
        )
        return redirect(
            url_for("characters")
        )
    permission = department_manage_permission(
        department
    )
    if not has_permission(permission):
        flash(
            "ليس لديك صلاحية إدارة هذا القسم."
        )
        return redirect(
            url_for("characters")
        )
    db = get_db()
    db.execute("""
        DELETE FROM character_departments
        WHERE character_id = ?
        AND department = ?
    """, (
        character_id,
        department
    ))
    db.execute("""
        DELETE FROM character_ranks
        WHERE character_id = ?
        AND department = ?
    """, (
        character_id,
        department
    ))
    db.commit()
    db.close()
    log_action(
        f"إزالة الشخصية من {DEPARTMENTS[department]}"
    )
    flash(
        "تمت إزالة الشخصية من القسم."
    )
    return redirect(
        url_for("characters")
    )
# =========================================================
# تغيير رتبة داخل القسم
# =========================================================
@app.route(
    "/admin/characters/<int:character_id>/rank",
    methods=["POST"]
)
def assign_rank(
    character_id
):
    user = current_user()
    if not user:
        return redirect(
            url_for("login")
        )
    department = request.form.get(
        "department",
        ""
    ).strip()
    rank = request.form.get(
        "rank",
        ""
    ).strip()
    if department not in DEPARTMENTS:
        flash(
            "القسم غير صحيح."
        )
        return redirect(
            url_for("characters")
        )
    if not rank:
        flash(
            "الرتبة مطلوبة."
        )
        return redirect(
            url_for("characters")
        )
    permission = department_manage_permission(
        department
    )
    if not has_permission(permission):
        flash(
            "ليس لديك صلاحية إدارة هذا القسم."
        )
        return redirect(
            url_for("characters")
        )
    db = get_db()
    exists = db.execute("""
        SELECT id
        FROM character_departments
        WHERE character_id = ?
        AND department = ?
    """, (
        character_id,
        department
    )).fetchone()
    if not exists:
        db.close()
        flash(
            "الشخصية ليست في هذا القسم."
        )
        return redirect(
            url_for("characters")
        )
    db.execute("""
        INSERT OR REPLACE INTO character_ranks (
            character_id,
            department,
            rank_name
        )
        VALUES (?, ?, ?)
    """, (
        character_id,
        department,
        rank
    ))
    db.commit()
    db.close()
    log_action(
        f"تغيير رتبة شخصية داخل {DEPARTMENTS[department]}"
    )
    flash(
        "تم تحديث الرتبة."
    )
    return redirect(
        url_for("characters")
    )
# =========================================================
# الصلاحيات
# =========================================================
@app.route("/admin/permissions")
@permission_required(
    "permissions_view"
)
def permissions():
    db = get_db()
    users = db.execute("""
        SELECT
            id,
            username,
            is_owner
        FROM users
        ORDER BY username
    """).fetchall()
    user_permissions = {}
    for user in users:
        rows = db.execute("""
            SELECT permission
            FROM user_permissions
            WHERE user_id = ?
        """, (
            user["id"],
        )).fetchall()
        user_permissions[user["id"]] = {
            row["permission"]
            for row in rows
        }
    db.close()
    return render_template(
        "permissions.html",
        users=users,
        permissions=PERMISSIONS,
        user_permissions=user_permissions
    )
@app.route(
    "/admin/permissions/<int:user_id>",
    methods=["POST"]
)
@permission_required(
    "permissions_give"
)
def update_permissions(
    user_id
):
    db = get_db()
    user = db.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        user_id,
    )).fetchone()
    if not user:
        db.close()
        flash(
            "المستخدم غير موجود."
        )
        return redirect(
            url_for("permissions")
        )
    if user["is_owner"]:
        db.close()
        flash(
            "لا يمكن تعديل مالك الموقع."
        )
        return redirect(
            url_for("permissions")
        )
    selected = request.form.getlist(
        "permissions"
    )
    db.execute("""
        DELETE FROM user_permissions
        WHERE user_id = ?
    """, (
        user_id,
    ))
    for permission in selected:
        if permission not in PERMISSIONS:
            continue
        db.execute("""
            INSERT OR IGNORE INTO user_permissions (
                user_id,
                permission
            )
            VALUES (?, ?)
        """, (
            user_id,
            permission
        ))
    db.commit()
    db.close()
    log_action(
        f"تحديث صلاحيات المستخدم: {user['username']}"
    )
    flash(
        "تم تحديث الصلاحيات."
    )
    return redirect(
        url_for("permissions")
    )
# =========================================================
# المستخدمون
# =========================================================
@app.route("/admin/users")
@permission_required(
    "users_view"
)
def users():
    db = get_db()
    users_list = db.execute("""
        SELECT
            id,
            username,
            is_banned,
            is_disabled,
            is_owner,
            created_at
        FROM users
        ORDER BY id DESC
    """).fetchall()
    db.close()
    return render_template(
        "users.html",
        users=users_list
    )
# =========================================================
# حظر
# =========================================================
@app.route(
    "/admin/users/<int:user_id>/ban",
    methods=["POST"]
)
@permission_required(
    "users_ban"
)
def ban_user(user_id):
    db = get_db()
    user = db.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        user_id,
    )).fetchone()
    if user and user["is_owner"]:
        db.close()
        flash(
            "لا يمكن حظر مالك الموقع."
        )
        return redirect(
            url_for("users")
        )
    db.execute("""
        UPDATE users
        SET is_banned = 1
        WHERE id = ?
    """, (
        user_id,
    ))
    db.commit()
    db.close()
    log_action(
        f"حظر المستخدم رقم {user_id}"
    )
    return redirect(
        url_for("users")
    )
# =========================================================
# فك الحظر
# =========================================================
@app.route(
    "/admin/users/<int:user_id>/unban",
    methods=["POST"]
)
@permission_required(
    "users_unban"
)
def unban_user(user_id):
    db = get_db()
    db.execute("""
        UPDATE users
        SET is_banned = 0
        WHERE id = ?
    """, (
        user_id,
    ))
    db.commit()
    db.close()
    log_action(
        f"فك حظر المستخدم رقم {user_id}"
    )
    return redirect(
        url_for("users")
    )
# =========================================================
# تعطيل
# =========================================================
@app.route(
    "/admin/users/<int:user_id>/disable",
    methods=["POST"]
)
@permission_required(
    "users_disable"
)
def disable_user(user_id):
    db = get_db()
    user = db.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        user_id,
    )).fetchone()
    if user and user["is_owner"]:
        db.close()
        flash(
            "لا يمكن تعطيل مالك الموقع."
        )
        return redirect(
            url_for("users")
        )
    db.execute("""
        UPDATE users
        SET is_disabled = 1
        WHERE id = ?
    """, (
        user_id,
    ))
    db.commit()
    db.close()
    log_action(
        f"تعطيل المستخدم رقم {user_id}"
    )
    return redirect(
        url_for("users")
    )
# =========================================================
# تفعيل
# =========================================================
@app.route(
    "/admin/users/<int:user_id>/enable",
    methods=["POST"]
)
@permission_required(
    "users_enable"
)
def enable_user(user_id):
    db = get_db()
    db.execute("""
        UPDATE users
        SET is_disabled = 0
        WHERE id = ?
    """, (
        user_id,
    ))
    db.commit()
    db.close()
    log_action(
        f"تفعيل المستخدم رقم {user_id}"
    )
    return redirect(
        url_for("users")
    )
# =========================================================
# حذف المستخدم
# =========================================================
@app.route(
    "/admin/users/<int:user_id>/delete",
    methods=["POST"]
)
@permission_required(
    "users_delete"
)
def delete_user(user_id):
    db = get_db()
    user = db.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        user_id,
    )).fetchone()
    if user and user["is_owner"]:
        db.close()
        flash(
            "لا يمكن حذف مالك الموقع."
        )
        return redirect(
            url_for("users")
        )
    db.execute("""
        DELETE FROM users
        WHERE id = ?
    """, (
        user_id,
    ))
    db.commit()
    db.close()
    log_action(
        f"حذف المستخدم رقم {user_id}"
    )
    return redirect(
        url_for("users")
    )
# =========================================================
# شخصيات القسم
# =========================================================
def get_department_characters(
    department
):
    db = get_db()
    characters = db.execute("""
        SELECT
            characters.*,
            users.username,
            character_ranks.rank_name
        FROM characters
        JOIN character_departments
        ON character_departments.character_id =
           characters.id
        JOIN users
        ON users.id = characters.user_id
        LEFT JOIN character_ranks
        ON character_ranks.character_id =
           characters.id
        AND character_ranks.department = ?
        WHERE character_departments.department = ?
        AND characters.hidden = 0
        ORDER BY characters.id DESC
    """, (
        department,
        department
    )).fetchall()
    db.close()
    return characters
def get_user_department_characters(
    user_id,
    department
):
    db = get_db()
    characters = db.execute("""
        SELECT
            characters.*,
            character_ranks.rank_name
        FROM characters
        JOIN character_departments
        ON character_departments.character_id =
           characters.id
        LEFT JOIN character_ranks
        ON character_ranks.character_id =
           characters.id
        AND character_ranks.department = ?
        WHERE character_departments.department = ?
        AND characters.user_id = ?
        AND characters.hidden = 0
        ORDER BY characters.id DESC
    """, (
        department,
        department,
        user_id
    )).fetchall()
    db.close()
    return characters
# =========================================================
# صفحة القسم
# =========================================================
def department_page(
    department,
    template
):
    user = current_user()
    if not user:
        return redirect(
            url_for("login")
        )
    view_permission = (
        f"{department}_view"
    )
    manage_permission = (
        f"{department}_manage"
    )
    if (
        has_permission(view_permission)
        or
        has_permission(manage_permission)
    ):
        characters = get_department_characters(
            department
        )
    else:
        characters = get_user_department_characters(
            user["id"],
            department
        )
        if not characters:
            flash(
                "لا تملك صلاحية دخول هذا القسم."
            )
            return redirect(
                url_for("home")
            )
    return render_template(
        template,
        characters=characters,
        department_name=DEPARTMENTS[department]
    )
# =========================================================
# الشرطة
# =========================================================
@app.route("/police")
def police():
    return department_page(
        "police",
        "police.html"
    )
# =========================================================
# العدل
# =========================================================
@app.route("/justice")
def justice():
    return department_page(
        "justice",
        "justice.html"
    )
# =========================================================
# الصحة
# =========================================================
@app.route("/health")
def health():
    return department_page(
        "health",
        "health.html"
    )
# =========================================================
# العصابات
# =========================================================
@app.route("/gangs")
def gangs():
    user = current_user()
    if not user:
        return redirect(
            url_for("login")
        )
    if not (
        has_permission("gangs_view")
        or
        has_permission("gangs_manage")
    ):
        flash(
            "ليس لديك صلاحية دخول قسم العصابات."
        )
        return redirect(
            url_for("home")
        )
    db = get_db()
    gangs_list = db.execute("""
        SELECT
            gangs.*,
            (
                SELECT COUNT(*)
                FROM gang_members
                WHERE gang_members.gang_id = gangs.id
            ) AS members_count
        FROM gangs
        ORDER BY gangs.id DESC
    """).fetchall()
    db.close()
    return render_template(
        "gangs.html",
        gangs=gangs_list,
        has_gang_create=has_permission(
            "gangs_add"
        ),
        has_gang_edit=has_permission(
            "gangs_edit"
        ),
        has_gang_delete=has_permission(
            "gangs_delete"
        )
    )
# =========================================================
# إنشاء عصابة
# =========================================================
@app.route(
    "/admin/gangs/create",
    methods=["GET", "POST"]
)
@permission_required(
    "gangs_add"
)
def create_gang():
    if request.method == "POST":
        name = request.form.get(
            "name",
            ""
        ).strip()
        leader = request.form.get(
            "leader",
            ""
        ).strip()
        if not name:
            flash(
                "اسم العصابة مطلوب."
            )
            return redirect(
                url_for("create_gang")
            )
        db = get_db()
        try:
            db.execute("""
                INSERT INTO gangs (
                    name,
                    leader
                )
                VALUES (?, ?)
            """, (
                name,
                leader or None
            ))
            db.commit()
        except sqlite3.IntegrityError:
            db.close()
            flash(
                "اسم العصابة مستخدم مسبقًا."
            )
            return redirect(
                url_for("create_gang")
            )
        db.close()
        log_action(
            f"إنشاء عصابة: {name}"
        )
        flash(
            "تم إنشاء العصابة."
        )
        return redirect(
            url_for("gangs")
        )
    return render_template(
        "gangs.html",
        gangs=[],
        has_gang_create=True,
        has_gang_edit=False,
        has_gang_delete=False
    )
# =========================================================
# تعديل عصابة
# =========================================================
@app.route(
    "/admin/gangs/<int:gang_id>/edit",
    methods=["GET", "POST"]
)
@permission_required(
    "gangs_edit"
)
def edit_gang(gang_id):
    db = get_db()
    gang = db.execute("""
        SELECT *
        FROM gangs
        WHERE id = ?
    """, (
        gang_id,
    )).fetchone()
    if not gang:
        db.close()
        flash(
            "العصابة غير موجودة."
        )
        return redirect(
            url_for("gangs")
        )
    if request.method == "POST":
        name = request.form.get(
            "name",
            ""
        ).strip()
        leader = request.form.get(
            "leader",
            ""
        ).strip()
        status = request.form.get(
            "status",
            "نشطة"
        ).strip()
        if not name:
            db.close()
            flash(
                "اسم العصابة مطلوب."
            )
            return redirect(
                url_for(
                    "edit_gang",
                    gang_id=gang_id
                )
            )
        try:
            db.execute("""
                UPDATE gangs
                SET
                    name = ?,
                    leader = ?,
                    status = ?
                WHERE id = ?
            """, (
                name,
                leader or None,
                status or "نشطة",
                gang_id
            ))
            db.commit()
        except sqlite3.IntegrityError:
            db.close()
            flash(
                "اسم العصابة مستخدم مسبقًا."
            )
            return redirect(
                url_for(
                    "edit_gang",
                    gang_id=gang_id
                )
            )
        db.close()
        log_action(
            f"تعديل العصابة: {name}"
        )
        flash(
            "تم تعديل العصابة."
        )
        return redirect(
            url_for("gangs")
        )
    db.close()
    return render_template(
        "edit_gang.html",
        gang=gang
    )
# =========================================================
# حذف عصابة
# =========================================================
@app.route(
    "/admin/gangs/<int:gang_id>/delete",
    methods=["POST"]
)
@permission_required(
    "gangs_delete"
)
def delete_gang(gang_id):
    db = get_db()
    gang = db.execute("""
        SELECT *
        FROM gangs
        WHERE id = ?
    """, (
        gang_id,
    )).fetchone()
    if gang:
        db.execute("""
            DELETE FROM gangs
            WHERE id = ?
        """, (
            gang_id,
        ))
        db.commit()
    db.close()
    if gang:
        log_action(
            f"حذف العصابة: {gang['name']}"
        )
        flash(
            "تم حذف العصابة."
        )
    return redirect(
        url_for("gangs")
    )
# =========================================================
# السجلات
# =========================================================
@app.route("/admin/logs")
@permission_required(
    "logs_view"
)
def logs():
    db = get_db()
    logs_list = db.execute("""
        SELECT
            activity_logs.*,
            users.username
        FROM activity_logs
        LEFT JOIN users
        ON users.id = activity_logs.user_id
        ORDER BY activity_logs.id DESC
    """).fetchall()
    db.close()
    return render_template(
        "logs.html",
        logs=logs_list
    )
# =========================================================
# تشغيل قاعدة البيانات
# =========================================================
init_db()
create_owner()
# =========================================================
# تشغيل Flask
# =========================================================
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        )
    )
