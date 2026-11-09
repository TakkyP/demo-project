"""Worklist — ระบบมอบหมายและตรวจเช็คงาน (Flask + SQLite)"""
import os
import secrets
import sqlite3
import uuid
from datetime import datetime
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# ฐานข้อมูล: ถ้ามี DATABASE_URL (เช่น Neon/Vercel Postgres) จะใช้ Postgres ไม่งั้นใช้ SQLite ในโฟลเดอร์ data/
DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
USE_PG = bool(DATABASE_URL)
# บน Vercel เขียนไฟล์ได้เฉพาะ /tmp และไม่ถาวร — ใช้งานจริงบน Vercel ต้องตั้ง DATABASE_URL
ON_VERCEL = bool(os.environ.get("VERCEL"))
DATA_DIR = os.environ.get("WORKLIST_DATA") or (
    "/tmp/worklist" if ON_VERCEL else os.path.join(BASE_DIR, "data"))
DB_PATH = os.path.join(DATA_DIR, "worklist.db")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")  # ใช้กับรูปเก่าที่เก็บเป็นไฟล์ (ก่อนเก็บรูปในฐานข้อมูล)
ALLOWED_EXT = {"jpg", "jpeg", "png", "gif", "webp", "heic", "heif"}
MIME = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif",
        "webp": "image/webp", "heic": "image/heic", "heif": "image/heif"}
# Vercel รับข้อมูลได้ไม่เกิน 4.5 MB ต่อคำขอ (เบราว์เซอร์จะย่อรูปก่อนส่งให้อยู่แล้ว)
UPLOAD_LIMIT_MB = 4 if ON_VERCEL else 60

ROLES = {"employer": "นายจ้าง", "employee": "ลูกจ้าง"}
STATUSES = {
    "pending": "รอดำเนินการ",
    "submitted": "ส่งงานแล้ว รอตรวจ",
    "approved": "ผ่าน",
    "rejected": "ให้แก้ไข",
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = UPLOAD_LIMIT_MB * 1024 * 1024

USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('employer', 'employee')),
    created_at TEXT NOT NULL
);
"""

TASKS_TABLE = """
CREATE TABLE IF NOT EXISTS {name} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    -- NULL = มอบหมายให้ทุกคน: ลูกจ้างทุกคนเห็น และคนแรกที่กด "รับงาน" จะได้งานนี้ไปคนเดียว
    assigned_to INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    due_date TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    employee_note TEXT NOT NULL DEFAULT '',
    feedback TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    submitted_at TEXT,
    reviewed_at TEXT,
    archived INTEGER NOT NULL DEFAULT 0  -- 1 = นำออกจากแท็บรายการงานแล้ว (ยังอยู่ในรายการงานทั้งหมด)
);
"""

PHOTOS_TABLE = """
CREATE TABLE IF NOT EXISTS photos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    mime TEXT,
    data BLOB  -- ตัวรูป (เก็บในฐานข้อมูล เพื่อให้ใช้บน Vercel ได้) ; NULL = รูปเก่าที่เก็บเป็นไฟล์
);
"""

SETTINGS_TABLE = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _pg_sql(sql):
    """แปลง SQL แบบ SQLite ให้ใช้กับ Postgres ได้"""
    return (sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
               .replace(" BLOB", " BYTEA"))


# ---------------------------------------------------------------- database
class Database:
    """ตัวกลางเล็ก ๆ ให้โค้ดเดียวกันใช้ได้ทั้ง SQLite และ Postgres (ใช้ ? เป็น placeholder ได้ทั้งคู่)"""

    def __init__(self):
        if USE_PG:
            import psycopg
            from psycopg.rows import dict_row
            self.conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        else:
            self.conn = sqlite3.connect(DB_PATH)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")

    def execute(self, sql, params=()):
        if USE_PG:
            sql = sql.replace("?", "%s")
        return self.conn.execute(sql, params)

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


def db():
    if "db" not in g:
        g.db = Database()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


TASK_COLS = ("id, title, description, location, assigned_to, created_by, due_date, status, "
             "employee_note, feedback, created_at, submitted_at, reviewed_at, archived")


def init_db():
    if USE_PG:
        import psycopg
        with psycopg.connect(DATABASE_URL) as conn:
            conn.execute(_pg_sql(USERS_TABLE + TASKS_TABLE.format(name="tasks") + PHOTOS_TABLE + SETTINGS_TABLE))
        return
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(USERS_TABLE + TASKS_TABLE.format(name="tasks") + PHOTOS_TABLE + SETTINGS_TABLE)
        # migration: เพิ่มคอลัมน์ให้ฐานข้อมูลเดิมที่สร้างก่อนมีฟีเจอร์นั้น
        cols = {r[1] for r in conn.execute("PRAGMA table_info(tasks)")}
        if "location" not in cols:
            conn.execute("ALTER TABLE tasks ADD COLUMN location TEXT NOT NULL DEFAULT ''")
        if "archived" not in cols:
            conn.execute("ALTER TABLE tasks ADD COLUMN archived INTEGER NOT NULL DEFAULT 0")
        photo_cols = {r[1] for r in conn.execute("PRAGMA table_info(photos)")}
        if "data" not in photo_cols:
            conn.execute("ALTER TABLE photos ADD COLUMN mime TEXT")
            conn.execute("ALTER TABLE photos ADD COLUMN data BLOB")
        # migration: ฐานข้อมูลเดิมบังคับ assigned_to NOT NULL -> สร้างตารางใหม่ให้รองรับ "ทุกคน"
        notnull = {r[1]: r[3] for r in conn.execute("PRAGMA table_info(tasks)")}
        if notnull.get("assigned_to"):
            conn.commit()
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.executescript(
                "BEGIN;"
                + TASKS_TABLE.format(name="tasks_new")
                + f"INSERT INTO tasks_new ({TASK_COLS}) SELECT {TASK_COLS} FROM tasks;"
                "DROP TABLE tasks; ALTER TABLE tasks_new RENAME TO tasks; COMMIT;"
            )


def _secret_key():
    """ใช้ SECRET_KEY จาก env ถ้ามี ไม่งั้นสร้างครั้งเดียวแล้วเก็บไว้ในฐานข้อมูล (ทุกเครื่องบน Vercel ใช้ค่าเดียวกัน)"""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    d = Database()
    try:
        d.execute("INSERT INTO settings (key, value) VALUES ('secret_key', ?) ON CONFLICT (key) DO NOTHING",
                  (secrets.token_hex(32),))
        d.commit()
        return d.execute("SELECT value FROM settings WHERE key = 'secret_key'").fetchone()["value"]
    finally:
        d.close()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


# ---------------------------------------------------------------- auth helpers
def current_user():
    if "user" not in g:
        uid = session.get("user_id")
        g.user = db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone() if uid else None
    return g.user


def login_required(role=None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            if role and user["role"] != role:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get("csrf")
        if not token or token != request.form.get("csrf"):
            abort(400, "CSRF token ไม่ถูกต้อง กรุณารีเฟรชหน้าแล้วลองใหม่")


@app.context_processor
def inject_globals():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return {"user": current_user(), "csrf": session["csrf"], "ROLES": ROLES, "STATUSES": STATUSES,
            "UPLOAD_LIMIT_MB": UPLOAD_LIMIT_MB}


def fetch_task(task_id):
    task = db().execute(
        """SELECT t.*, u.name AS assignee_name, c.name AS creator_name
           FROM tasks t LEFT JOIN users u ON u.id = t.assigned_to
           LEFT JOIN users c ON c.id = t.created_by WHERE t.id = ?""",
        (task_id,),
    ).fetchone()
    if not task:
        abort(404)
    user = current_user()
    # ลูกจ้างเห็นงานของตัวเอง และงาน "ทุกคน" ที่ยังไม่มีใครรับ
    if user["role"] == "employee" and task["assigned_to"] not in (user["id"], None):
        abort(403)
    return task


def employees():
    return db().execute("SELECT id, name FROM users WHERE role = 'employee' ORDER BY name").fetchall()


INVALID = object()  # ค่าที่ parse_assignee คืนเมื่อผู้ใช้กรอกไม่ถูก


def parse_assignee(value):
    """'all' -> None (ทุกคน), id ลูกจ้าง -> int, อย่างอื่น -> INVALID"""
    if value == "all":
        return None
    if value.isdigit() and int(value) in {e["id"] for e in employees()}:
        return int(value)
    return INVALID


# ---------------------------------------------------------------- login / setup
@app.route("/setup", methods=["GET", "POST"])
def setup():
    """หน้าสร้างบัญชีนายจ้างคนแรก (ใช้ได้เฉพาะตอนยังไม่มีผู้ใช้ในระบบ)"""
    if db().execute("SELECT 1 FROM users LIMIT 1").fetchone():
        return redirect(url_for("login"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not name or not username or len(password) < 6:
            flash("กรอกข้อมูลให้ครบ และรหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร", "error")
        else:
            db().execute(
                "INSERT INTO users (username, password_hash, name, role, created_at) VALUES (?,?,?,?,?)",
                (username, generate_password_hash(password), name, "employer", now()),
            )
            db().commit()
            flash("สร้างบัญชีนายจ้างเรียบร้อย กรุณาเข้าสู่ระบบ", "success")
            return redirect(url_for("login"))
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if not db().execute("SELECT 1 FROM users LIMIT 1").fetchone():
        return redirect(url_for("setup"))
    if request.method == "POST":
        user = db().execute(
            "SELECT * FROM users WHERE username = ?", (request.form.get("username", "").strip(),)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("tasks"))
        flash("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    return redirect(url_for("tasks"))


# ---------------------------------------------------------------- tab: รายการงาน (ทั้งสอง role)
@app.route("/tasks")
@login_required()
def tasks():
    user = current_user()
    status = request.args.get("status", "")
    sql = """SELECT t.*, u.name AS assignee_name,
                    (SELECT COUNT(*) FROM photos p WHERE p.task_id = t.id) AS photo_count
             FROM tasks t LEFT JOIN users u ON u.id = t.assigned_to WHERE t.archived = 0"""
    params = []
    if user["role"] == "employee":
        sql += " AND (t.assigned_to = ? OR t.assigned_to IS NULL)"
        params.append(user["id"])
    if status in STATUSES:
        sql += " AND t.status = ?"
        params.append(status)
    sql += """ ORDER BY t.assigned_to IS NOT NULL, CASE t.status
                 WHEN 'submitted' THEN 0 WHEN 'rejected' THEN 1
                 WHEN 'pending' THEN 2 ELSE 3 END,
               COALESCE(t.due_date, '9999'), t.id DESC"""
    rows = db().execute(sql, params).fetchall()

    count_sql = "SELECT status, COUNT(*) AS n FROM tasks WHERE archived = 0"
    count_params = []
    if user["role"] == "employee":
        count_sql += " AND (assigned_to = ? OR assigned_to IS NULL)"
        count_params.append(user["id"])
    counts = {r["status"]: r["n"] for r in db().execute(count_sql + " GROUP BY status", count_params)}
    return render_template("tasks.html", tasks=rows, status=status, counts=counts, tab="tasks")


@app.route("/tasks/<int:task_id>")
@login_required()
def task_detail(task_id):
    if current_user()["role"] == "employee":
        row = db().execute("SELECT assigned_to FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row and row["assigned_to"] not in (current_user()["id"], None):
            flash("มีคนอื่นรับงานนี้ไปแล้ว", "error")
            return redirect(url_for("tasks"))
    task = fetch_task(task_id)
    photos = db().execute("SELECT id, task_id, filename, uploaded_at FROM photos WHERE task_id = ? ORDER BY id",
                          (task_id,)).fetchall()
    return render_template("task_detail.html", task=task, photos=photos, tab="tasks")


# ---------- ลูกจ้าง: รับงาน "ทุกคน"
@app.route("/tasks/<int:task_id>/claim", methods=["POST"])
@login_required("employee")
def task_claim(task_id):
    if not db().execute("SELECT 1 FROM tasks WHERE id = ?", (task_id,)).fetchone():
        abort(404)
    # อัปเดตแบบมีเงื่อนไขในคำสั่งเดียว: ถ้ากดพร้อมกันหลายคน จะมีแค่คนแรกที่สำเร็จ
    cur = db().execute(
        "UPDATE tasks SET assigned_to = ? WHERE id = ? AND assigned_to IS NULL AND archived = 0",
        (current_user()["id"], task_id),
    )
    db().commit()
    if cur.rowcount:
        flash("รับงานเรียบร้อย งานนี้เป็นของคุณแล้ว ถ่ายรูปและส่งงานได้เลย", "success")
        return redirect(url_for("task_detail", task_id=task_id))
    flash("มีคนอื่นรับงานนี้ไปแล้ว", "error")
    return redirect(url_for("tasks"))


# ---------- ลูกจ้าง: อัปโหลดรูปและส่งงาน
@app.route("/tasks/<int:task_id>/upload", methods=["POST"])
@login_required("employee")
def task_upload(task_id):
    task = fetch_task(task_id)
    if task["assigned_to"] != current_user()["id"]:
        flash("ต้องกด \"รับงาน\" ก่อนจึงจะส่งงานได้", "error")
        return redirect(url_for("task_detail", task_id=task_id))
    if task["status"] == "approved" or task["archived"]:
        flash("งานนี้ปิดแล้ว ไม่สามารถส่งเพิ่มได้", "error")
        return redirect(url_for("task_detail", task_id=task_id))

    files = [f for f in request.files.getlist("photos") if f and f.filename]
    saved = 0
    for f in files:
        ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
        if ext not in ALLOWED_EXT:
            flash(f"ข้ามไฟล์ {f.filename}: รองรับเฉพาะไฟล์รูปภาพ", "error")
            continue
        name = f"{task_id}_{uuid.uuid4().hex}.{ext}"
        # เก็บตัวรูปในฐานข้อมูล (ใช้ได้ทั้งในเครื่องและบน Vercel ซึ่งไม่มีดิสก์ถาวร)
        db().execute("INSERT INTO photos (task_id, filename, uploaded_at, mime, data) VALUES (?,?,?,?,?)",
                     (task_id, name, now(), MIME.get(ext, "application/octet-stream"), f.read()))
        saved += 1

    has_photos = saved or db().execute("SELECT 1 FROM photos WHERE task_id = ?", (task_id,)).fetchone()
    if not has_photos:
        flash("กรุณาถ่ายรูปหรือเลือกรูปอย่างน้อย 1 รูปก่อนส่งงาน", "error")
        return redirect(url_for("task_detail", task_id=task_id))

    db().execute(
        "UPDATE tasks SET status = 'submitted', submitted_at = ?, employee_note = ? WHERE id = ?",
        (now(), request.form.get("note", "").strip(), task_id),
    )
    db().commit()
    flash(f"ส่งงานเรียบร้อย (อัปโหลด {saved} รูป)", "success")
    return redirect(url_for("task_detail", task_id=task_id))


@app.route("/photos/<int:photo_id>/delete", methods=["POST"])
@login_required()
def photo_delete(photo_id):
    photo = db().execute("SELECT id, task_id, filename FROM photos WHERE id = ?", (photo_id,)).fetchone()
    if not photo:
        abort(404)
    task = fetch_task(photo["task_id"])
    if current_user()["role"] == "employee" and (task["status"] == "approved"
                                                  or task["assigned_to"] != current_user()["id"]):
        abort(403)
    _remove_file(photo["filename"])
    db().execute("DELETE FROM photos WHERE id = ?", (photo_id,))
    db().commit()
    flash("ลบรูปแล้ว", "success")
    return redirect(url_for("task_detail", task_id=task["id"]))


@app.route("/uploads/<int:photo_id>")
@login_required()
def photo_file(photo_id):
    photo = db().execute("SELECT * FROM photos WHERE id = ?", (photo_id,)).fetchone()
    if not photo:
        abort(404)
    fetch_task(photo["task_id"])  # ตรวจสิทธิ์
    if photo["data"] is None:  # รูปเก่าที่เก็บเป็นไฟล์
        return send_from_directory(UPLOAD_DIR, photo["filename"])
    resp = Response(bytes(photo["data"]), mimetype=photo["mime"] or "image/jpeg")
    resp.headers["Cache-Control"] = "private, max-age=86400"  # รูปไม่เปลี่ยน ให้เบราว์เซอร์เก็บไว้
    return resp


# ---------- นายจ้าง: ตรวจงาน
@app.route("/tasks/<int:task_id>/review", methods=["POST"])
@login_required("employer")
def task_review(task_id):
    fetch_task(task_id)
    decision = request.form.get("decision")
    if decision not in ("approved", "rejected"):
        abort(400)
    db().execute("UPDATE tasks SET status = ?, feedback = ?, reviewed_at = ? WHERE id = ?",
                 (decision, request.form.get("feedback", "").strip(), now(), task_id))
    db().commit()
    flash("บันทึกผลการตรวจแล้ว: " + STATUSES[decision], "success")
    return redirect(url_for("task_detail", task_id=task_id))


# ---------------------------------------------------------------- tab: เพิ่มรายการ (นายจ้าง)
@app.route("/tasks/new", methods=["GET", "POST"])
@login_required("employer")
def task_new():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        assigned_to = parse_assignee(request.form.get("assigned_to", ""))
        if not title or assigned_to is INVALID:
            flash("กรุณากรอกชื่องานและเลือกผู้รับผิดชอบ", "error")
        else:
            db().execute(
                """INSERT INTO tasks (title, description, location, assigned_to, created_by, due_date, created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (title, request.form.get("description", "").strip(),
                 request.form.get("location", "").strip(), assigned_to,
                 current_user()["id"], request.form.get("due_date") or None, now()),
            )
            db().commit()
            flash("เพิ่มงานให้ทุกคนเรียบร้อย (คนแรกที่กดรับงานจะได้งานนี้)" if assigned_to is None
                  else "เพิ่มงานเรียบร้อย", "success")
            return redirect(url_for("task_new"))
    rows = db().execute(
        """SELECT t.*, u.name AS assignee_name FROM tasks t
           LEFT JOIN users u ON u.id = t.assigned_to ORDER BY t.id DESC"""
    ).fetchall()
    return render_template("task_new.html", tasks=rows, employees=employees(), tab="new")


@app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@login_required("employer")
def task_edit(task_id):
    task = fetch_task(task_id)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        assigned_to = parse_assignee(request.form.get("assigned_to", ""))
        if not title or assigned_to is INVALID:
            flash("กรุณากรอกชื่องานและเลือกผู้รับผิดชอบ", "error")
        else:
            db().execute(
                """UPDATE tasks SET title = ?, description = ?, location = ?, assigned_to = ?, due_date = ?
                   WHERE id = ?""",
                (title, request.form.get("description", "").strip(),
                 request.form.get("location", "").strip(), assigned_to,
                 request.form.get("due_date") or None, task_id),
            )
            db().commit()
            flash("แก้ไขงานเรียบร้อย", "success")
            return redirect(url_for("task_new"))
    return render_template("task_edit.html", task=task, employees=employees(), tab="new")


@app.route("/tasks/<int:task_id>/archive", methods=["POST"])
@login_required("employer")
def task_archive(task_id):
    """ลบจากแท็บรายการงาน: ซ่อนงานจากรายการ แต่ยังเก็บไว้ในรายการงานทั้งหมดเพื่อนำกลับมาใช้ใหม่"""
    fetch_task(task_id)
    db().execute("UPDATE tasks SET archived = 1 WHERE id = ?", (task_id,))
    db().commit()
    flash("นำงานออกจากรายการแล้ว (ยังอยู่ในรายการงานทั้งหมดที่แท็บเพิ่มรายการ)", "success")
    nxt = request.form.get("next", "")
    if not nxt.startswith("/") or nxt.startswith("//"):  # กัน redirect ออกนอกเว็บ
        nxt = url_for("tasks")
    return redirect(nxt)


@app.route("/tasks/<int:task_id>/reuse", methods=["POST"])
@login_required("employer")
def task_reuse(task_id):
    """นำงานกลับมาใช้ใหม่: เริ่มรอบใหม่เป็น 'รอดำเนินการ' และล้างรูป/ความเห็นของรอบก่อน"""
    task = fetch_task(task_id)
    assigned_to = parse_assignee(request.form.get("assigned_to", ""))
    if assigned_to is INVALID:
        assigned_to = task["assigned_to"]
    for p in db().execute("SELECT filename FROM photos WHERE task_id = ?", (task_id,)):
        _remove_file(p["filename"])
    db().execute("DELETE FROM photos WHERE task_id = ?", (task_id,))
    db().execute(
        """UPDATE tasks SET archived = 0, status = 'pending', assigned_to = ?, due_date = ?,
                  employee_note = '', feedback = '', submitted_at = NULL, reviewed_at = NULL
           WHERE id = ?""",
        (assigned_to, request.form.get("due_date") or None, task_id),
    )
    db().commit()
    flash(f"นำงาน \"{task['title']}\" กลับมาใช้ใหม่แล้ว", "success")
    return redirect(url_for("task_new"))


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required("employer")
def task_delete(task_id):
    """ลบถาวร (จากตารางรายการงานทั้งหมดเท่านั้น)"""
    fetch_task(task_id)
    for p in db().execute("SELECT filename FROM photos WHERE task_id = ?", (task_id,)):
        _remove_file(p["filename"])
    db().execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    db().commit()
    flash("ลบงานถาวรแล้ว", "success")
    return redirect(url_for("task_new"))


# ---------------------------------------------------------------- เปลี่ยนรหัสผ่านตัวเอง (ทุก role)
@app.route("/account", methods=["GET", "POST"])
@login_required()
def account():
    if request.method == "POST":
        user = current_user()
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        if not check_password_hash(user["password_hash"], current):
            flash("รหัสผ่านปัจจุบันไม่ถูกต้อง", "error")
        elif len(new) < 6:
            flash("รหัสผ่านใหม่ต้องยาวอย่างน้อย 6 ตัวอักษร", "error")
        elif new != request.form.get("confirm_password", ""):
            flash("ยืนยันรหัสผ่านใหม่ไม่ตรงกัน", "error")
        else:
            db().execute("UPDATE users SET password_hash = ? WHERE id = ?",
                         (generate_password_hash(new), user["id"]))
            db().commit()
            flash("เปลี่ยนรหัสผ่านเรียบร้อย", "success")
            return redirect(url_for("account"))
    return render_template("account.html", tab="account")


# ---------------------------------------------------------------- tab: จัดการบุคคล (นายจ้าง)
@app.route("/users", methods=["GET", "POST"])
@login_required("employer")
def users():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role")
        if not name or not username or len(password) < 6 or role not in ROLES:
            flash("กรอกข้อมูลให้ครบ และรหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร", "error")
        elif db().execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            flash(f"ชื่อผู้ใช้ '{username}' ถูกใช้แล้ว", "error")
        else:
            db().execute(
                "INSERT INTO users (username, password_hash, name, role, created_at) VALUES (?,?,?,?,?)",
                (username, generate_password_hash(password), name, role, now()),
            )
            db().commit()
            flash(f"เพิ่มผู้ใช้ {name} เรียบร้อย", "success")
            return redirect(url_for("users"))
    rows = db().execute(
        """SELECT u.*, (SELECT COUNT(*) FROM tasks t WHERE t.assigned_to = u.id) AS task_count
           FROM users u ORDER BY u.role, u.name"""
    ).fetchall()
    return render_template("users.html", users=rows, tab="users")


@app.route("/users/<int:user_id>/update", methods=["POST"])
@login_required("employer")
def user_update(user_id):
    target = db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        abort(404)
    name = request.form.get("name", "").strip() or target["name"]
    role = request.form.get("role") if request.form.get("role") in ROLES else target["role"]
    if user_id == current_user()["id"] and role != "employer":
        flash("ไม่สามารถเปลี่ยน role ของตัวเองได้", "error")
        return redirect(url_for("users"))
    if target["role"] == "employee" and role == "employer" and _has_tasks(user_id):
        flash("ผู้ใช้นี้ยังมีงานที่ได้รับมอบหมาย ลบหรือโอนงานก่อนเปลี่ยนเป็นนายจ้าง", "error")
        return redirect(url_for("users"))
    db().execute("UPDATE users SET name = ?, role = ? WHERE id = ?", (name, role, user_id))
    password = request.form.get("password", "")
    if password:
        if len(password) < 6:
            flash("รหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร", "error")
            return redirect(url_for("users"))
        db().execute("UPDATE users SET password_hash = ? WHERE id = ?",
                     (generate_password_hash(password), user_id))
    db().commit()
    flash(f"บันทึกข้อมูล {name} แล้ว", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required("employer")
def user_delete(user_id):
    if user_id == current_user()["id"]:
        flash("ไม่สามารถลบบัญชีของตัวเองได้", "error")
        return redirect(url_for("users"))
    for p in db().execute(
        "SELECT p.filename FROM photos p JOIN tasks t ON t.id = p.task_id WHERE t.assigned_to = ?", (user_id,)
    ):
        _remove_file(p["filename"])
    db().execute("DELETE FROM users WHERE id = ?", (user_id,))
    db().commit()
    flash("ลบผู้ใช้แล้ว (งานที่มอบหมายให้ผู้ใช้นี้ถูกลบด้วย)", "success")
    return redirect(url_for("users"))


def _has_tasks(user_id):
    return db().execute("SELECT 1 FROM tasks WHERE assigned_to = ?", (user_id,)).fetchone() is not None


def _remove_file(filename):
    path = os.path.join(UPLOAD_DIR, os.path.basename(filename))
    if os.path.exists(path):
        os.remove(path)


@app.errorhandler(413)
def too_large(_e):
    flash(f"ไฟล์รวมใหญ่เกินไป (สูงสุด {UPLOAD_LIMIT_MB} MB ต่อครั้ง) ลองส่งทีละน้อยรูป", "error")
    return redirect(request.referrer or url_for("tasks"))


init_db()
app.secret_key = _secret_key()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5050)), debug=os.environ.get("DEBUG") == "1")
