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


# =========================================================
# إعداد التطبيق
# =========================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "mt-character-system-secret"
)

DATABASE = "mt_characters.db"


# =========================================================
# الصلاحيات
# =========================================================

PERMISSIONS = {

    # =====================================================
    # الشخصيات
    # =====================================================

    "characters_view_all": "عرض جميع الشخصيات",
    "characters_view_details": "عرض تفاصيل الشخصيات",
    "characters_search": "البحث عن الشخصيات",
    "characters_edit_all": "تعديل جميع الشخصيات",
    "characters_delete_all": "حذف جميع الشخصيات",
    "characters_hide": "إخفاء شخصية",
    "characters_show": "إظهار شخصية",
    "characters_transfer": "نقل شخصية بين الحسابات",
    "characters_reset": "إعادة تعيين بيانات الشخصية",


    # =====================================================
    # الشرطة
    # =====================================================

    "police_manage": "إدارة الشرطة",
    "police_view": "عرض أفراد الشرطة",
    "police_add": "إضافة أفراد الشرطة",
    "police_edit": "تعديل أفراد الشرطة",
    "police_delete": "حذف أفراد الشرطة",
    "police_assign_rank": "تعيين رتبة شرطة",
    "police_change_rank": "تغيير رتبة شرطة",
    "police_remove": "إزالة فرد من الشرطة",


    # =====================================================
    # العدل
    # =====================================================

    "justice_manage": "إدارة وزارة العدل",
    "justice_view": "عرض أفراد العدل",
    "justice_add": "إضافة أفراد العدل",
    "justice_edit": "تعديل أفراد العدل",
    "justice_delete": "حذف أفراد العدل",
    "justice_assign_rank": "تعيين رتبة عدل",
    "justice_change_rank": "تغيير رتبة عدل",
    "justice_remove": "إزالة فرد من العدل",


    # =====================================================
    # الصحة
    # =====================================================

    "health_manage": "إدارة الصحة",
    "health_view": "عرض أفراد الصحة",
    "health_add": "إضافة أفراد الصحة",
    "health_edit": "تعديل أفراد الصحة",
    "health_delete": "حذف أفراد الصحة",
    "health_assign_rank": "تعيين رتبة صحية",
    "health_change_rank": "تغيير رتبة صحية",
    "health_remove": "إزالة فرد من الصحة",


    # =====================================================
    # العصابات
    # =====================================================

    "gangs_manage": "إدارة العصابات",
    "gangs_view": "عرض العصابات",
    "gangs_add": "إنشاء عصابة",
    "gangs_edit": "تعديل العصابات",
    "gangs_delete": "حذف العصابات",
    "gangs_add_members": "إضافة أعضاء",
    "gangs_remove_members": "إزالة أعضاء",
    "gangs_change_leader": "تغيير قائد العصابة",


    # =====================================================
    # المستخدمون
    # =====================================================

    "users_view": "عرض المستخدمين",
    "users_edit": "تعديل المستخدمين",
    "users_ban": "حظر المستخدمين",
    "users_unban": "فك حظر المستخدمين",
    "users_delete": "حذف المستخدمين",
    "users_disable": "تعطيل الحسابات",
    "users_enable": "تفعيل الحسابات",


    # =====================================================
    # الصلاحيات
    # =====================================================

    "permissions_view": "عرض صلاحيات المستخدمين",
    "permissions_give": "إعطاء الصلاحيات",
    "permissions_remove": "سحب الصلاحيات",
    "permissions_edit": "تعديل صلاحيات المستخدم",


    # =====================================================
    # الموقع
    # =====================================================

    "site_settings": "تعديل إعدادات الموقع",
    "site_sections": "إدارة الأقسام",
    "site_home": "إدارة الصفحة الرئيسية",
    "site_maintenance": "صيانة الموقع",


    # =====================================================
    # السجلات
    # =====================================================

    "logs_view": "عرض سجل العمليات",
    "logs_search": "البحث في السجلات",
    "logs_export": "تصدير السجلات",


    # =====================================================
    # الإدارة العليا
    # =====================================================

    "admins_manage": "إدارة المدراء",
    "admins_add": "تعيين مدير",
    "admins_remove": "إزالة مدير",
    "admins_all_permissions": "التحكم بجميع الصلاحيات",
    "admins_all_sections": "التحكم بجميع الأقسام",
}


# =========================================================
# الرتب الإدارية - 20 رتبة
# =========================================================

ROLES = {

    # 1
    "owner": {
        "name": "Owner",
        "permissions": set(PERMISSIONS.keys())
    },

    # 2
    "co_owner": {
        "name": "Co-Owner",
        "permissions": set(PERMISSIONS.keys())
        - {
            "admins_remove"
        }
    },

    # 3
    "founder": {
        "name": "Founder",
        "permissions": set(PERMISSIONS.keys())
        - {
            "admins_remove",
            "admins_manage"
        }
    },

    # 4
    "super_admin": {
        "name": "Super Admin",
        "permissions": set(PERMISSIONS.keys())
        - {
            "admins_remove",
            "admins_manage"
        }
    },

    # 5
    "admin": {
        "name": "Admin",
        "permissions": {

            # الشخصيات
            "characters_view_all",
            "characters_view_details",
            "characters_search",
            "characters_edit_all",
            "characters_delete_all",
            "characters_hide",
            "characters_show",

            # الشرطة
            "police_manage",
            "police_view",
            "police_add",
            "police_edit",
            "police_delete",
            "police_assign_rank",
            "police_change_rank",
            "police_remove",

            # العدل
            "justice_manage",
            "justice_view",
            "justice_add",
            "justice_edit",
            "justice_delete",
            "justice_assign_rank",
            "justice_change_rank",
            "justice_remove",

            # الصحة
            "health_manage",
            "health_view",
            "health_add",
            "health_edit",
            "health_delete",
            "health_assign_rank",
            "health_change_rank",
            "health_remove",

            # العصابات
            "gangs_manage",
            "gangs_view",
            "gangs_add",
            "gangs_edit",
            "gangs_delete",
            "gangs_add_members",
            "gangs_remove_members",
            "gangs_change_leader",

            # المستخدمون
            "users_view",
            "users_edit",
            "users_ban",
            "users_unban",
            "users_disable",
            "users_enable",

            # الصلاحيات
            "permissions_view",
            "permissions_give",
            "permissions_remove",
            "permissions_edit",

            # الموقع
            "site_sections",

            # السجلات
            "logs_view",
            "logs_search"
        }
    },

    # 6
    "moderator": {
        "name": "Moderator",
        "permissions": {
            "characters_view_all",
            "characters_view_details",
            "characters_search",
            "characters_hide",
            "characters_show",
            "users_view",
            "logs_view"
        }
    },

    # 7
    "supervisor": {
        "name": "Supervisor",
        "permissions": {
            "characters_view_all",
            "characters_view_details",
            "characters_search",
            "characters_edit_all",
            "characters_hide",
            "characters_show",
            "users_view",
            "users_edit",
            "logs_view",
            "logs_search"
        }
    },

    # 8
    "manager": {
        "name": "Manager",
        "permissions": {
            "characters_view_all",
            "characters_view_details",
            "characters_search",
            "characters_edit_all",
            "characters_hide",
            "characters_show",
            "users_view"
        }
    },

    # 9
    "department_manager": {
        "name": "Department Manager",
        "permissions": {
            "characters_view_all",
            "characters_view_details",
            "police_manage",
            "justice_manage",
            "health_manage",
            "gangs_manage",
            "users_view"
        }
    },

    # 10
    "police_director": {
        "name": "Police Director",
        "permissions": {
            "police_manage",
            "police_view",
            "police_add",
            "police_edit",
            "police_delete",
            "police_assign_rank",
            "police_change_rank",
            "police_remove"
        }
    },

    # 11
    "justice_director": {
        "name": "Justice Director",
        "permissions": {
            "justice_manage",
            "justice_view",
            "justice_add",
            "justice_edit",
            "justice_delete",
            "justice_assign_rank",
            "justice_change_rank",
            "justice_remove"
        }
    },

    # 12
    "health_director": {
        "name": "Health Director",
        "permissions": {
            "health_manage",
            "health_view",
            "health_add",
            "health_edit",
            "health_delete",
            "health_assign_rank",
            "health_change_rank",
            "health_remove"
        }
    },

    # 13
    "gang_manager": {
        "name": "Gang Manager",
        "permissions": {
            "gangs_manage",
            "gangs_view",
            "gangs_add",
            "gangs_edit",
            "gangs_delete",
            "gangs_add_members",
            "gangs_remove_members",
            "gangs_change_leader"
        }
    },

    # 14
    "police_supervisor": {
        "name": "Police Supervisor",
        "permissions": {
            "police_manage",
            "police_view",
            "police_edit",
            "police_assign_rank",
            "police_change_rank",
            "police_remove"
        }
    },

    # 15
    "justice_supervisor": {
        "name": "Justice Supervisor",
        "permissions": {
            "justice_manage",
            "justice_view",
            "justice_edit",
            "justice_assign_rank",
            "justice_change_rank",
            "justice_remove"
        }
    },

    # 16
    "health_supervisor": {
        "name": "Health Supervisor",
        "permissions": {
            "health_manage",
            "health_view",
            "health_edit",
            "health_assign_rank",
            "health_change_rank",
            "health_remove"
        }
    },

    # 17
    "gang_supervisor": {
        "name": "Gang Supervisor",
        "permissions": {
            "gangs_manage",
            "gangs_view",
            "gangs_edit",
            "gangs_add_members",
            "gangs_remove_members",
            "gangs_change_leader"
        }
    },

    # 18
    "senior_staff": {
        "name": "Senior Staff",
        "permissions": {
            "characters_view_all",
            "characters_view_details",
            "characters_search",
            "characters_edit_all",
            "characters_hide",
            "characters_show",
            "users_view",
            "logs_view"
        }
    },

    # 19
    "staff": {
        "name": "Staff",
        "permissions": {
            "characters_view_all",
            "characters_view_details",
            "characters_search",
            "characters_hide",
            "characters_show",
            "users_view"
        }
    },

    # 20
    "helper": {
        "name": "Helper",
        "permissions": {
            "characters_view_details",
            "characters_search"
        }
    }
}


# =========================================================
# أقسام الموقع
# =========================================================

DEPARTMENTS = {

    "police": "الشرطة",

    "justice": "وزارة العدل",

    "health": "الصحة",

    "gangs": "العصابات"
}


# =========================================================
# رتب القطاعات
# =========================================================

DEPARTMENT_RANKS = {

    # =====================================================
    # الشرطة
    # =====================================================

    "police": [

        "جندي مستجد",

        "جندي",

        "جندي أول",

        "عريف",

        "وكيل رقيب",

        "رقيب",

        "رقيب أول",

        "رئيس رقباء",

        "ملازم",

        "ملازم أول",

        "نقيب",

        "رائد",

        "مقدم",

        "عقيد",

        "عميد",

        "لواء",

        "فريق",

        "فريق أول",

        "جنرال"
    ],


    # =====================================================
    # وزارة العدل
    # =====================================================

    "justice": [

        "معالي وزير العدل",

        "معالي نائب وزير العدل",

        "رئيس المحكمة العليا",

        "رئيس محكمة الاستئناف",

        "قاضي استئناف (A)",

        "قاضي استئناف (B)",

        "رئيس محكمة عامة (A)",

        "رئيس محكمة عامة (B)",

        "قاضي محكمة عامة",

        "باحث قضائي"
    ],


    # =====================================================
    # الصحة
    # =====================================================

    "health": [

        "متدرب",

        "مساعد صحي",

        "فني صحي",

        "فني أول",

        "أخصائي",

        "أخصائي أول",

        "أخصائي استشاري",

        "استشاري",

        "رئيس قسم",

        "مدير قسم",

        "نائب مدير المستشفى",

        "مدير المستشفى",

        "نائب مدير الصحة",

        "مدير الصحة",

        "وكيل وزارة الصحة",

        "نائب وزير الصحة",

        "وزير الصحة"
    ],


    # =====================================================
    # العصابات
    # =====================================================

    "gangs": [

        "عضو",

        "عضو أول",

        "نائب القائد",

        "القائد"
    ]
}


# =========================================================
# قاعدة البيانات
# =========================================================

def get_db():

    db = sqlite3.connect(
        DATABASE
    )

    db.row_factory = sqlite3.Row

    db.execute(
        "PRAGMA foreign_keys = ON"
    )

    return db


# =========================================================
# إنشاء الجداول
# =========================================================

def init_db():

    db = get_db()


    # =====================================================
    # المستخدمون
    # =====================================================

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            password_hash TEXT NOT NULL,

            is_banned INTEGER DEFAULT 0,

            is_disabled INTEGER DEFAULT 0,

            is_owner INTEGER DEFAULT 0,

            role TEXT DEFAULT 'helper',

            created_at TIMESTAMP
            DEFAULT CURRENT_TIMESTAMP
        )
    """)


    # =====================================================
    # إضافة role إذا قاعدة البيانات قديمة
    # =====================================================

    columns = db.execute(
        "PRAGMA table_info(users)"
    ).fetchall()

    column_names = {
        column["name"]
        for column in columns
    }

    if "role" not in column_names:

        db.execute("""
            ALTER TABLE users

            ADD COLUMN role TEXT
            DEFAULT 'helper'
        """)


    # =====================================================
    # الشخصيات
    # =====================================================

    db.execute("""
        CREATE TABLE IF NOT EXISTS characters (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            first_name TEXT NOT NULL,

            second_name TEXT NOT NULL,

            full_name TEXT NOT NULL,

            full_name_key TEXT UNIQUE NOT NULL,

            country TEXT NOT NULL,

            nationality TEXT NOT NULL,

            birth_date TEXT NOT NULL,

            hidden INTEGER DEFAULT 0,

            created_at TIMESTAMP
            DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
            REFERENCES users(id)

            ON DELETE SET NULL
        )
    """)


    # =====================================================
    # صلاحيات المستخدمين
    # =====================================================

    db.execute("""
        CREATE TABLE IF NOT EXISTS user_permissions (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL,

            permission TEXT NOT NULL,

            UNIQUE(
                user_id,
                permission
            ),

            FOREIGN KEY (user_id)
            REFERENCES users(id)

            ON DELETE CASCADE
        )
    """)


    # =====================================================
    # أقسام الشخصيات
    # =====================================================

    db.execute("""
        CREATE TABLE IF NOT EXISTS character_departments (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            character_id INTEGER NOT NULL,

            department TEXT NOT NULL,

            UNIQUE(
                character_id,
                department
            ),

            FOREIGN KEY (character_id)
            REFERENCES characters(id)

            ON DELETE CASCADE
        )
    """)


    # =====================================================
    # رتب الشخصيات
    # =====================================================

    db.execute("""
        CREATE TABLE IF NOT EXISTS character_ranks (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            character_id INTEGER NOT NULL,

            department TEXT NOT NULL,

            rank_name TEXT NOT NULL,

            UNIQUE(
                character_id,
                department
            ),

            FOREIGN KEY (character_id)
            REFERENCES characters(id)

            ON DELETE CASCADE
        )
    """)


    # =====================================================
    # السجلات
    # =====================================================

    db.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            action TEXT NOT NULL,

            created_at TIMESTAMP
            DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
            REFERENCES users(id)

            ON DELETE SET NULL
        )
    """)


    db.commit()

    db.close()


# =========================================================
# إنشاء Owner
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
            INSERT INTO users
            (
                username,
                password_hash,
                is_owner,
                role
            )

            VALUES
            (?, ?, 1, 'owner')
        """, (
            username,
            generate_password_hash(
                password
            )
        ))

        db.commit()


    else:

        db.execute("""
            UPDATE users

            SET
                role = 'owner',
                is_owner = 1

            WHERE is_owner = 1
        """)

        db.commit()


    db.close()


# =========================================================
# المستخدم الحالي
# =========================================================

def current_user():

    user_id = session.get(
        "user_id"
    )

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
# صلاحيات الرتبة
# =========================================================

def get_role_permissions(user):

    if not user:

        return set()

    if user["is_owner"]:

        return set(
            PERMISSIONS.keys()
        )

    role_key = (
        user["role"]
        or "helper"
    )

    role = ROLES.get(
        role_key
    )

    if not role:

        return set()

    return set(
        role["permissions"]
    )


# =========================================================
# فحص الصلاحية
# =========================================================

def has_permission(permission):

    user = current_user()

    if not user:

        return False

    if user["is_owner"]:

        return True

    if permission in get_role_permissions(
        user
    ):

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


# =========================================================
# حماية الصفحات
# =========================================================

def permission_required(permission):

    def decorator(function):

        @wraps(function)
        def wrapper(
            *args,
            **kwargs
        ):

            user = current_user()

            if not user:

                return redirect(
                    url_for("login")
                )

            if not has_permission(
                permission
            ):

                flash(
                    "ليس لديك صلاحية لهذا الإجراء."
                )

                return redirect(
                    url_for("home")
                )

            return function(
                *args,
                **kwargs
            )

        return wrapper

    return decorator


# =========================================================
# تسجيل العمليات
# =========================================================

def log_action(action):

    user = current_user()

    if not user:

        return

    db = get_db()

    db.execute("""
        INSERT INTO activity_logs
        (
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
# توحيد الاسم
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

        name = name.replace(
            old,
            new
        )

    name = name.replace(
        "ـ",
        ""
    )

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

        current_user=user,

        user=user,

        has_permission=has_permission
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
                "بيانات الدخول غير صحيحة."
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
                "بيانات الدخول غير صحيحة."
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
# تسجيل شخصية
# =========================================================

@app.route(
    "/characters/register",
    methods=["GET", "POST"]
)
def register_character():

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

            flash(
                "فضلاً عب جميع البيانات."
            )

            return redirect(
                url_for(
                    "register_character"
                )
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
        """, (
            full_name_key,
        )).fetchone()


        if exists:

            db.close()

            flash(
                "اسم الشخصية مستخدم مسبقًا."
            )

            return redirect(
                url_for(
                    "register_character"
                )
            )


        cursor = db.execute("""
            INSERT INTO characters
            (
                user_id,
                first_name,
                second_name,
                full_name,
                full_name_key,
                country,
                nationality,
                birth_date
            )

            VALUES
            (
                NULL,
                ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            first_name,
            second_name,
            full_name,
            full_name_key,
            country,
            nationality,
            birth_date
        ))


        character_id = cursor.lastrowid


        # الرتبة العامة
        db.execute("""
            INSERT INTO character_ranks
            (
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


        flash(
            "تم إنشاء الشخصية بنجاح."
        )

        return redirect(
            url_for(
                "character_details",
                character_id=character_id
            )
        )


    return render_template(
        "register_character.html"
    )


# =========================================================
# الشخصيات
# =========================================================

@app.route("/characters")
def characters():

    user = current_user()

    db = get_db()


    if user and has_permission(
        "characters_view_all"
    ):

        rows = db.execute("""
            SELECT
                characters.*,
                users.username

            FROM characters

            LEFT JOIN users

            ON users.id =
               characters.user_id

            ORDER BY characters.id DESC
        """).fetchall()

        admin_view = True


    else:

        rows = db.execute("""
            SELECT *

            FROM characters

            WHERE hidden = 0

            ORDER BY id DESC
        """).fetchall()

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
            SELECT
                department

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
        ),

        user=user,

        DEPARTMENTS=DEPARTMENTS,

        DEPARTMENT_RANKS=DEPARTMENT_RANKS
    )


# =========================================================
# تفاصيل الشخصية
# =========================================================

@app.route(
    "/characters/<int:character_id>"
)
def character_details(character_id):

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


    # إذا الشخصية مخفية
    user = current_user()

    if character["hidden"]:

        if not (
            user
            and has_permission(
                "characters_view_all"
            )
        ):

            db.close()

            flash(
                "الشخصية غير متاحة."
            )

            return redirect(
                url_for("characters")
            )


    departments = db.execute("""
        SELECT
            character_departments.department,
            character_ranks.rank_name

        FROM character_departments

        LEFT JOIN character_ranks

        ON character_ranks.character_id =
           character_departments.character_id

        AND character_ranks.department =
            character_departments.department

        WHERE character_departments.character_id = ?
    """, (
        character_id,
    )).fetchall()


    general_rank = db.execute("""
        SELECT rank_name

        FROM character_ranks

        WHERE character_id = ?

        AND department = 'general'

        LIMIT 1
    """, (
        character_id,
    )).fetchone()


    db.close()


    return render_template(
        "character_details.html",

        character=character,

        departments=departments,

        general_rank=general_rank,

        user=user
    )


# =========================================================
# حذف الشخصية
# =========================================================

@app.route(
    "/characters/<int:character_id>/delete",
    methods=["POST"]
)
def delete_character(character_id):

    user = current_user()

    if not user or not has_permission(
        "characters_delete_all"
    ):

        flash(
            "لا تملك صلاحية حذف الشخصية."
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
        DELETE FROM characters

        WHERE id = ?
    """, (
        character_id,
    ))

    db.commit()

    db.close()


    log_action(
        f"حذف شخصية: {character['full_name']}"
    )


    flash(
        "تم حذف الشخصية."
    )

    return redirect(
        url_for("characters")
    )


# =========================================================
# تعديل الشخصية
# =========================================================

@app.route(
    "/admin/characters/<int:character_id>/edit",
    methods=["POST"]
)
@permission_required(
    "characters_edit_all"
)
def admin_edit_character(character_id):

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
# إخفاء الشخصية
# =========================================================

@app.route(
    "/admin/characters/<int:character_id>/hide",
    methods=["POST"]
)
@permission_required(
    "characters_hide"
)
def hide_character(character_id):

    db = get_db()

    db.execute("""
        UPDATE characters

        SET hidden = 1

        WHERE id = ?
    """, (
        character_id,
    ))

    db.commit()

    db.close()


    log_action(
        f"إخفاء شخصية رقم {character_id}"
    )


    flash(
        "تم إخفاء الشخصية."
    )

    return redirect(
        url_for("characters")
    )


# =========================================================
# إظهار الشخصية
# =========================================================

@app.route(
    "/admin/characters/<int:character_id>/show",
    methods=["POST"]
)
@permission_required(
    "characters_show"
)
def show_character(character_id):

    db = get_db()

    db.execute("""
        UPDATE characters

        SET hidden = 0

        WHERE id = ?
    """, (
        character_id,
    ))

    db.commit()

    db.close()


    log_action(
        f"إظهار شخصية رقم {character_id}"
    )


    flash(
        "تم إظهار الشخصية."
    )

    return redirect(
        url_for("characters")
    )


# =========================================================
# تعيين الشخصية إلى قسم
# =========================================================

@app.route(
    "/admin/characters/<int:character_id>/department",
    methods=["POST"]
)
def assign_department(character_id):

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


    permission = (
        f"{department}_manage"
    )


    if not (
        has_permission(permission)

        or has_permission(
            "site_sections"
        )

        or has_permission(
            "admins_all_sections"
        )
    ):

        flash(
            "لا تملك صلاحية إدارة هذا القسم."
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


    # إضافة القسم
    db.execute("""
        INSERT OR IGNORE INTO
        character_departments
        (
            character_id,
            department
        )

        VALUES (?, ?)
    """, (
        character_id,
        department
    ))


    # =====================================================
    # الرتبة الافتراضية حسب القسم
    # =====================================================

    default_rank = DEPARTMENT_RANKS[
        department
    ][0]


    db.execute("""
        INSERT OR IGNORE INTO
        character_ranks
        (
            character_id,
            department,
            rank_name
        )

        VALUES (?, ?, ?)
    """, (
        character_id,
        department,
        default_rank
    ))


    db.commit()

    db.close()


    log_action(
        f"تعيين {character['full_name']} إلى "
        f"{DEPARTMENTS[department]} "
        f"برتبته الابتدائية: {default_rank}"
    )


    flash(
        f"تم تعيين الشخصية إلى "
        f"{DEPARTMENTS[department]} "
        f"برتبته {default_rank}."
    )


    return redirect(
        url_for("characters")
    )


# =========================================================
# إزالة الشخصية من القسم
# =========================================================

@app.route(
    "/admin/characters/<int:character_id>/department/remove",
    methods=["POST"]
)
def remove_department(character_id):

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


    permission = (
        f"{department}_remove"
    )


    if not (
        has_permission(permission)

        or has_permission(
            f"{department}_manage"
        )

        or has_permission(
            "site_sections"
        )
    ):

        flash(
            "لا تملك صلاحية إزالة الشخصية من القسم."
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


    remaining = db.execute("""
        SELECT COUNT(*)

        FROM character_departments

        WHERE character_id = ?
    """, (
        character_id,
    )).fetchone()[0]


    if remaining == 0:

        db.execute("""
            INSERT OR REPLACE INTO
            character_ranks
            (
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


    flash(
        "تمت إزالة الشخصية من القسم."
    )

    return redirect(
        url_for("characters")
    )


# =========================================================
# تغيير رتبة الشخصية
# =========================================================

@app.route(
    "/admin/characters/<int:character_id>/rank",
    methods=["POST"]
)
def assign_rank(character_id):

    department = request.form.get(
        "department",
        ""
    ).strip()

    rank = request.form.get(
        "rank",
        ""
    ).strip()


    if not department or not rank:

        flash(
            "بيانات الرتبة ناقصة."
        )

        return redirect(
            url_for("characters")
        )


    if department not in DEPARTMENTS:

        flash(
            "القسم غير صحيح."
        )

        return redirect(
            url_for("characters")
        )


    # =====================================================
    # منع إدخال رتبة غير موجودة
    # =====================================================

    if rank not in DEPARTMENT_RANKS[
        department
    ]:

        flash(
            "الرتبة غير صحيحة."
        )

        return redirect(
            url_for("characters")
        )


    # =====================================================
    # الصلاحية
    # =====================================================

    if not (
        has_permission(
            f"{department}_change_rank"
        )

        or has_permission(
            f"{department}_assign_rank"
        )

        or has_permission(
            f"{department}_manage"
        )

        or has_permission(
            "site_sections"
        )

        or has_permission(
            "admins_all_sections"
        )
    ):

        flash(
            "لا تملك صلاحية تغيير الرتبة."
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
        INSERT OR REPLACE INTO
        character_ranks
        (
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
        f"تغيير رتبة الشخصية رقم "
        f"{character_id} إلى {rank}"
    )


    flash(
        f"تم تغيير الرتبة إلى {rank}."
    )


    return redirect(
        url_for("characters")
    )


# =========================================================
# جلب شخصيات قسم
# =========================================================

def get_department_characters(
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

        AND characters.hidden = 0

        ORDER BY characters.id DESC
    """, (
        department,
        department
    )).fetchall()


    db.close()


    return characters


# =========================================================
# الشرطة
# =========================================================

@app.route("/police")
def police():

    user = current_user()


    characters = []


    if user and (
        has_permission(
            "police_view"
        )

        or has_permission(
            "police_manage"
        )
    ):

        characters = get_department_characters(
            "police"
        )


    return render_template(
        "police.html",

        characters=characters,

        user=user,

        ranks=DEPARTMENT_RANKS["police"],

        DEPARTMENT_RANKS=DEPARTMENT_RANKS
    )


# =========================================================
# وزارة العدل
# =========================================================

@app.route("/justice")
def justice():

    user = current_user()


    characters = []


    if user and (
        has_permission(
            "justice_view"
        )

        or has_permission(
            "justice_manage"
        )
    ):

        characters = get_department_characters(
            "justice"
        )


    return render_template(
        "justice.html",

        characters=characters,

        user=user,

        ranks=DEPARTMENT_RANKS["justice"],

        DEPARTMENT_RANKS=DEPARTMENT_RANKS
    )


# =========================================================
# الصحة
# =========================================================

@app.route("/health")
def health():

    user = current_user()


    characters = []


    if user and (
        has_permission(
            "health_view"
        )

        or has_permission(
            "health_manage"
        )
    ):

        characters = get_department_characters(
            "health"
        )


    return render_template(
        "health.html",

        characters=characters,

        user=user,

        ranks=DEPARTMENT_RANKS["health"],

        DEPARTMENT_RANKS=DEPARTMENT_RANKS
    )


# =========================================================
# العصابات
# =========================================================

@app.route("/gangs")
def gangs():

    user = current_user()


    characters = []


    if user and (
        has_permission(
            "gangs_view"
        )

        or has_permission(
            "gangs_manage"
        )
    ):

        characters = get_department_characters(
            "gangs"
        )


    return render_template(
        "gangs.html",

        characters=characters,

        user=user,

        ranks=DEPARTMENT_RANKS["gangs"],

        DEPARTMENT_RANKS=DEPARTMENT_RANKS
    )


# =========================================================
# صفحة الإدارة والصلاحيات
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
            is_owner,
            role

        FROM users

        ORDER BY username
    """).fetchall()


    user_permissions = {}

    user_roles = {}


    for user in users:

        user_roles[
            user["id"]
        ] = (

            "owner"

            if user["is_owner"]

            else (
                user["role"]
                or "helper"
            )
        )


        rows = db.execute("""
            SELECT permission

            FROM user_permissions

            WHERE user_id = ?
        """, (
            user["id"],
        )).fetchall()


        user_permissions[
            user["id"]
        ] = {

            row["permission"]

            for row in rows
        }


    db.close()


    return render_template(
        "permissions.html",

        users=users,

        permissions=PERMISSIONS,

        user_permissions=user_permissions,

        user_roles=user_roles,

        ROLES=ROLES,

        current_user=current_user(),

        selected_user=None,

        selected_permissions=set()
    )


# =========================================================
# تحديث الرتبة والصلاحيات
# =========================================================

@app.route(
    "/admin/permissions/<int:user_id>",
    methods=["POST"]
)
@permission_required(
    "permissions_give"
)
def update_permissions(user_id):

    db = get_db()


    current = db.execute("""
        SELECT *

        FROM users

        WHERE id = ?
    """, (
        session.get("user_id"),
    )).fetchone()


    target = db.execute("""
        SELECT *

        FROM users

        WHERE id = ?
    """, (
        user_id,
    )).fetchone()


    if not current:

        db.close()

        flash(
            "جلسة المستخدم غير موجودة."
        )

        return redirect(
            url_for("login")
        )


    if not target:

        db.close()

        flash(
            "المستخدم غير موجود."
        )

        return redirect(
            url_for("permissions")
        )


    # =====================================================
    # حماية Owner
    # =====================================================

    if (
        target["is_owner"]
        and not current["is_owner"]
    ):

        db.close()

        flash(
            "لا يمكنك تعديل مالك الموقع."
        )

        return redirect(
            url_for("permissions")
        )


    role_key = request.form.get(
        "role",
        "helper"
    ).strip()


    if role_key not in ROLES:

        role_key = "helper"


    selected = request.form.getlist(
        "permissions"
    )


    # =====================================================
    # إعطاء Owner
    # =====================================================

    if role_key == "owner":

        if not current["is_owner"]:

            db.close()

            flash(
                "فقط Owner يستطيع تعيين Owner."
            )

            return redirect(
                url_for("permissions")
            )


        db.execute("""
            UPDATE users

            SET
                role = 'owner',
                is_owner = 1

            WHERE id = ?
        """, (
            user_id,
        ))


        db.execute("""
            DELETE FROM user_permissions

            WHERE user_id = ?
        """, (
            user_id,
        ))


        db.commit()

        db.close()


        log_action(
            f"تعيين Owner للمستخدم: "
            f"{target['username']}"
        )


        flash(
            f"تم تعيين "
            f"{target['username']} كـ Owner."
        )


        return redirect(
            url_for("permissions")
        )


    # =====================================================
    # إزالة Owner
    # =====================================================

    if target["is_owner"]:

        if not current["is_owner"]:

            db.close()

            flash(
                "لا يمكنك تغيير رتبة Owner."
            )

            return redirect(
                url_for("permissions")
            )


        db.execute("""
            UPDATE users

            SET
                is_owner = 0,
                role = ?

            WHERE id = ?
        """, (
            role_key,
            user_id
        ))


    else:

        db.execute("""
            UPDATE users

            SET
                role = ?,
                is_owner = 0

            WHERE id = ?
        """, (
            role_key,
            user_id
        ))


    # =====================================================
    # الصلاحيات اليدوية
    # =====================================================

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
            INSERT OR IGNORE INTO
            user_permissions
            (
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
        f"تحديث رتبة وصلاحيات المستخدم: "
        f"{target['username']}"
    )


    flash(
        "تم تحديث الرتبة والصلاحيات."
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
            role,
            created_at

        FROM users

        ORDER BY id DESC
    """).fetchall()


    db.close()


    user_roles = {}


    for account in users_list:

        if account["is_owner"]:

            user_roles[
                account["id"]
            ] = "Owner"


        else:

            role_key = (
                account["role"]
                or "helper"
            )

            role = ROLES.get(
                role_key
            )


            user_roles[
                account["id"]
            ] = (

                role["name"]

                if role

                else "بدون رتبة"
            )


    return render_template(
        "users.html",

        users=users_list,

        user_roles=user_roles,

        ROLES=ROLES
    )


# =========================================================
# إضافة مدير / مستخدم إداري
# =========================================================

@app.route(
    "/admin/users/add",
    methods=["POST"]
)
@permission_required(
    "admins_add"
)
def add_user():

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    role_key = request.form.get(
        "role",
        "helper"
    ).strip()


    if not username or not password:

        flash(
            "اسم المستخدم وكلمة المرور مطلوبة."
        )

        return redirect(
            url_for("users")
        )


    if role_key not in ROLES:

        role_key = "helper"


    current = current_user()


    # فقط Owner يستطيع إنشاء Owner
    if (
        role_key == "owner"
        and not current["is_owner"]
    ):

        flash(
            "فقط Owner يستطيع إنشاء Owner."
        )

        return redirect(
            url_for("users")
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
            "اسم المستخدم موجود مسبقًا."
        )

        return redirect(
            url_for("users")
        )


    is_owner = (
        1
        if role_key == "owner"
        else 0
    )


    db.execute("""
        INSERT INTO users
        (
            username,
            password_hash,
            is_owner,
            role
        )

        VALUES (?, ?, ?, ?)
    """, (
        username,
        generate_password_hash(
            password
        ),
        is_owner,
        role_key
    ))


    db.commit()

    db.close()


    log_action(
        f"إنشاء مستخدم إداري: "
        f"{username}"
    )


    flash(
        f"تم إنشاء المستخدم {username}."
    )


    return redirect(
        url_for("users")
    )


# =========================================================
# حظر المستخدم
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


    flash(
        "تم حظر المستخدم."
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


    flash(
        "تم فك الحظر."
    )


    return redirect(
        url_for("users")
    )


# =========================================================
# تعطيل المستخدم
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


    flash(
        "تم تعطيل المستخدم."
    )


    return redirect(
        url_for("users")
    )


# =========================================================
# تفعيل المستخدم
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


    flash(
        "تم تفعيل المستخدم."
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


    flash(
        "تم حذف المستخدم."
    )


    return redirect(
        url_for("users")
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

        ON users.id =
           activity_logs.user_id

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
# تشغيل الموقع
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
