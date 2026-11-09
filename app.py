"""Worklist — ระบบมอบหมายและตรวจเช็คงาน (Flask + MongoDB)"""
import atexit
import os
import secrets
import uuid
from datetime import datetime
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from pymongo import ASCENDING, MongoClient, ReturnDocument
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_dotenv():
    """อ่านไฟล์ .env (ถ้ามี) สำหรับรันในเครื่อง — ไฟล์นี้ไม่ถูก push ขึ้น GitHub (.gitignore)"""
    path = os.path.join(BASE_DIR, ".env")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()

# ฐานข้อมูล MongoDB: ตั้ง MONGODB_URI ใน Vercel (Settings → Environment Variables) หรือในไฟล์ .env
MONGODB_URI = os.environ.get("MONGODB_URI")
MONGODB_DB = os.environ.get("MONGODB_DB", "worklist")
ON_VERCEL = bool(os.environ.get("VERCEL"))
# Vercel รับข้อมูลได้ไม่เกิน 4.5 MB ต่อคำขอ (เบราว์เซอร์ย่อรูปก่อนส่งให้อยู่แล้ว)
UPLOAD_LIMIT_MB = int(os.environ.get("UPLOAD_LIMIT_MB", 4 if ON_VERCEL else 60))
MAX_PHOTO_BYTES = 15 * 1024 * 1024  # เอกสาร MongoDB ใหญ่ได้ไม่เกิน 16 MB
ALLOWED_EXT = {"jpg", "jpeg", "png", "gif", "webp", "heic", "heif"}
MIME = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif",
        "webp": "image/webp", "heic": "image/heic", "heif": "image/heif"}

ROLES = {"employer": "นายจ้าง", "employee": "ลูกจ้าง"}
STATUSES = {
    "pending": "รอดำเนินการ",
    "submitted": "ส่งงานแล้ว รอตรวจ",
    "approved": "ผ่าน",
    "rejected": "ให้แก้ไข",
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = UPLOAD_LIMIT_MB * 1024 * 1024

# ---------------------------------------------------------------- database
# collections:
#   users    {_id:int, username, password_hash, name, role, created_at}
#   tasks    {_id:int, title, description, location, assigned_to:int|None (None = ทุกคน ยังไม่มีคนรับ),
#             created_by, due_date, status, employee_note, feedback, created_at, submitted_at,
#             reviewed_at, archived:0|1}
#   photos   {_id:int, task_id, filename, uploaded_at, mime, data:bytes}
#   counters {_id:"users"|"tasks"|"photos", seq}   — ใช้ทำเลข id เรียงกัน (ใช้ใน URL)
#   settings {_id:"secret_key", value}
_client = None


def mongo():
    global _client
    if not MONGODB_URI:
        raise RuntimeError("ยังไม่ได้ตั้งค่า MONGODB_URI (ใส่ใน Vercel → Settings → Environment Variables "
                           "หรือในไฟล์ .env ตอนรันในเครื่อง)")
    if _client is None:  # ใช้ client เดียวทั้งแอป (pymongo จัดการ connection pool ให้)
        _client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=8000)
        atexit.register(_client.close)
    return _client.get_default_database(default=MONGODB_DB)


def next_id(name):
    doc = mongo().counters.find_one_and_update(
        {"_id": name}, {"$inc": {"seq": 1}}, upsert=True, return_document=ReturnDocument.AFTER)
    return doc["seq"]


def with_id(doc):
    """ให้ template ใช้ .id ได้เหมือนเดิม"""
    if doc is not None:
        doc["id"] = doc["_id"]
    return doc


def user_names():
    return {u["_id"]: u["name"] for u in mongo().users.find({}, {"name": 1})}


def photo_counts(task_ids):
    rows = mongo().photos.aggregate([
        {"$match": {"task_id": {"$in": list(task_ids)}}},
        {"$group": {"_id": "$task_id", "n": {"$sum": 1}}},
    ])
    return {r["_id"]: r["n"] for r in rows}


def init_db():
    d = mongo()
    d.users.create_index([("username", ASCENDING)], unique=True)
    d.tasks.create_index([("assigned_to", ASCENDING)])
    d.photos.create_index([("task_id", ASCENDING)])


def _secret_key():
    """ใช้ SECRET_KEY จาก env ถ้ามี ไม่งั้นสร้างครั้งเดียวแล้วเก็บไว้ในฐานข้อมูล (ทุกเครื่องบน Vercel ใช้ค่าเดียวกัน)"""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    doc = mongo().settings.find_one_and_update(
        {"_id": "secret_key"}, {"$setOnInsert": {"value": secrets.token_hex(32)}},
        upsert=True, return_document=ReturnDocument.AFTER)
    return doc["value"]


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


# ---------------------------------------------------------------- auth helpers
def current_user():
    if "user" not in g:
        uid = session.get("user_id")
        g.user = with_id(mongo().users.find_one({"_id": uid})) if uid else None
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
    task = with_id(mongo().tasks.find_one({"_id": task_id}))
    if not task:
        abort(404)
    user = current_user()
    # ลูกจ้างเห็นงานของตัวเอง และงาน "ทุกคน" ที่ยังไม่มีใครรับ
    if user["role"] == "employee" and task["assigned_to"] not in (user["id"], None):
        abort(403)
    names = user_names()
    task["assignee_name"] = names.get(task["assigned_to"])
    task["creator_name"] = names.get(task.get("created_by"))
    return task


def employees():
    return [with_id(u) for u in mongo().users.find({"role": "employee"}, {"name": 1}).sort("name", ASCENDING)]


INVALID = object()  # ค่าที่ parse_assignee คืนเมื่อผู้ใช้กรอกไม่ถูก


def parse_assignee(value):
    """'all' -> None (ทุกคน), id ลูกจ้าง -> int, อย่างอื่น -> INVALID"""
    if value == "all":
        return None
    if value.isdigit() and int(value) in {e["id"] for e in employees()}:
        return int(value)
    return INVALID


def delete_tasks(query):
    """ลบงานตามเงื่อนไข พร้อมรูปของงานนั้น"""
    ids = [t["_id"] for t in mongo().tasks.find(query, {"_id": 1})]
    if ids:
        mongo().photos.delete_many({"task_id": {"$in": ids}})
        mongo().tasks.delete_many({"_id": {"$in": ids}})


# ---------------------------------------------------------------- login / setup
@app.route("/setup", methods=["GET", "POST"])
def setup():
    """หน้าสร้างบัญชีนายจ้างคนแรก (ใช้ได้เฉพาะตอนยังไม่มีผู้ใช้ในระบบ)"""
    if mongo().users.find_one({}, {"_id": 1}):
        return redirect(url_for("login"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not name or not username or len(password) < 6:
            flash("กรอกข้อมูลให้ครบ และรหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร", "error")
        else:
            mongo().users.insert_one({
                "_id": next_id("users"), "username": username, "password_hash": generate_password_hash(password),
                "name": name, "role": "employer", "created_at": now()})
            flash("สร้างบัญชีนายจ้างเรียบร้อย กรุณาเข้าสู่ระบบ", "success")
            return redirect(url_for("login"))
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if not mongo().users.find_one({}, {"_id": 1}):
        return redirect(url_for("setup"))
    if request.method == "POST":
        user = mongo().users.find_one({"username": request.form.get("username", "").strip()})
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session["user_id"] = user["_id"]
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
STATUS_ORDER = {"submitted": 0, "rejected": 1, "pending": 2}


@app.route("/tasks")
@login_required()
def tasks():
    user = current_user()
    status = request.args.get("status", "")
    query = {"archived": 0}
    if user["role"] == "employee":
        query["assigned_to"] = {"$in": [user["id"], None]}
    all_rows = [with_id(t) for t in mongo().tasks.find(query)]

    counts = {}
    for t in all_rows:
        counts[t["status"]] = counts.get(t["status"], 0) + 1
    rows = [t for t in all_rows if t["status"] == status] if status in STATUSES else all_rows

    names = user_names()
    photos = photo_counts(t["id"] for t in rows)
    for t in rows:
        t["assignee_name"] = names.get(t["assigned_to"])
        t["photo_count"] = photos.get(t["id"], 0)
    # เรียง: งาน "ทุกคน" ที่ยังไม่มีคนรับ → รอตรวจ → ให้แก้ไข → รอดำเนินการ → ผ่าน แล้วตามกำหนดส่ง
    rows.sort(key=lambda t: -t["id"])
    rows.sort(key=lambda t: (t["assigned_to"] is not None, STATUS_ORDER.get(t["status"], 3),
                             t.get("due_date") or "9999"))
    return render_template("tasks.html", tasks=rows, status=status, counts=counts, tab="tasks")


@app.route("/tasks/<int:task_id>")
@login_required()
def task_detail(task_id):
    if current_user()["role"] == "employee":
        row = mongo().tasks.find_one({"_id": task_id}, {"assigned_to": 1})
        if row and row["assigned_to"] not in (current_user()["id"], None):
            flash("มีคนอื่นรับงานนี้ไปแล้ว", "error")
            return redirect(url_for("tasks"))
    task = fetch_task(task_id)
    photos = [with_id(p) for p in mongo().photos.find({"task_id": task_id}, {"data": 0}).sort("_id", ASCENDING)]
    return render_template("task_detail.html", task=task, photos=photos, tab="tasks")


# ---------- ลูกจ้าง: รับงาน "ทุกคน"
@app.route("/tasks/<int:task_id>/claim", methods=["POST"])
@login_required("employee")
def task_claim(task_id):
    if not mongo().tasks.find_one({"_id": task_id}, {"_id": 1}):
        abort(404)
    # อัปเดตแบบมีเงื่อนไขในคำสั่งเดียว (atomic): ถ้ากดพร้อมกันหลายคน จะมีแค่คนแรกที่สำเร็จ
    res = mongo().tasks.update_one({"_id": task_id, "assigned_to": None, "archived": 0},
                                   {"$set": {"assigned_to": current_user()["id"]}})
    if res.modified_count:
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
        data = f.read()
        if len(data) > MAX_PHOTO_BYTES:
            flash(f"ข้ามไฟล์ {f.filename}: รูปใหญ่เกิน 15 MB", "error")
            continue
        mongo().photos.insert_one({
            "_id": next_id("photos"), "task_id": task_id, "filename": f"{task_id}_{uuid.uuid4().hex}.{ext}",
            "uploaded_at": now(), "mime": MIME.get(ext, "application/octet-stream"), "data": data})
        saved += 1

    if not saved and not mongo().photos.find_one({"task_id": task_id}, {"_id": 1}):
        flash("กรุณาถ่ายรูปหรือเลือกรูปอย่างน้อย 1 รูปก่อนส่งงาน", "error")
        return redirect(url_for("task_detail", task_id=task_id))

    mongo().tasks.update_one({"_id": task_id}, {"$set": {
        "status": "submitted", "submitted_at": now(), "employee_note": request.form.get("note", "").strip()}})
    flash(f"ส่งงานเรียบร้อย (อัปโหลด {saved} รูป)", "success")
    return redirect(url_for("task_detail", task_id=task_id))


@app.route("/photos/<int:photo_id>/delete", methods=["POST"])
@login_required()
def photo_delete(photo_id):
    photo = mongo().photos.find_one({"_id": photo_id}, {"task_id": 1})
    if not photo:
        abort(404)
    task = fetch_task(photo["task_id"])
    if current_user()["role"] == "employee" and (task["status"] == "approved"
                                                  or task["assigned_to"] != current_user()["id"]):
        abort(403)
    mongo().photos.delete_one({"_id": photo_id})
    flash("ลบรูปแล้ว", "success")
    return redirect(url_for("task_detail", task_id=task["id"]))


@app.route("/uploads/<int:photo_id>")
@login_required()
def photo_file(photo_id):
    photo = mongo().photos.find_one({"_id": photo_id})
    if not photo:
        abort(404)
    fetch_task(photo["task_id"])  # ตรวจสิทธิ์
    resp = Response(bytes(photo["data"]), mimetype=photo.get("mime") or "image/jpeg")
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
    mongo().tasks.update_one({"_id": task_id}, {"$set": {
        "status": decision, "feedback": request.form.get("feedback", "").strip(), "reviewed_at": now()}})
    flash("บันทึกผลการตรวจแล้ว: " + STATUSES[decision], "success")
    return redirect(url_for("task_detail", task_id=task_id))


# ---------------------------------------------------------------- tab: เพิ่มรายการ (นายจ้าง)
def task_fields():
    return {
        "title": request.form.get("title", "").strip(),
        "description": request.form.get("description", "").strip(),
        "location": request.form.get("location", "").strip(),
        "due_date": request.form.get("due_date") or None,
    }


@app.route("/tasks/new", methods=["GET", "POST"])
@login_required("employer")
def task_new():
    if request.method == "POST":
        fields = task_fields()
        assigned_to = parse_assignee(request.form.get("assigned_to", ""))
        if not fields["title"] or assigned_to is INVALID:
            flash("กรุณากรอกชื่องานและเลือกผู้รับผิดชอบ", "error")
        else:
            mongo().tasks.insert_one({
                "_id": next_id("tasks"), **fields, "assigned_to": assigned_to,
                "created_by": current_user()["id"], "status": "pending", "employee_note": "", "feedback": "",
                "created_at": now(), "submitted_at": None, "reviewed_at": None, "archived": 0})
            flash("เพิ่มงานให้ทุกคนเรียบร้อย (คนแรกที่กดรับงานจะได้งานนี้)" if assigned_to is None
                  else "เพิ่มงานเรียบร้อย", "success")
            return redirect(url_for("task_new"))
    names = user_names()
    rows = [with_id(t) for t in mongo().tasks.find().sort("_id", -1)]
    for t in rows:
        t["assignee_name"] = names.get(t["assigned_to"])
    return render_template("task_new.html", tasks=rows, employees=employees(), tab="new")


@app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@login_required("employer")
def task_edit(task_id):
    task = fetch_task(task_id)
    if request.method == "POST":
        fields = task_fields()
        assigned_to = parse_assignee(request.form.get("assigned_to", ""))
        if not fields["title"] or assigned_to is INVALID:
            flash("กรุณากรอกชื่องานและเลือกผู้รับผิดชอบ", "error")
        else:
            mongo().tasks.update_one({"_id": task_id}, {"$set": {**fields, "assigned_to": assigned_to}})
            flash("แก้ไขงานเรียบร้อย", "success")
            return redirect(url_for("task_new"))
    return render_template("task_edit.html", task=task, employees=employees(), tab="new")


@app.route("/tasks/<int:task_id>/archive", methods=["POST"])
@login_required("employer")
def task_archive(task_id):
    """ลบจากแท็บรายการงาน: ซ่อนงานจากรายการ แต่ยังเก็บไว้ในรายการงานทั้งหมดเพื่อนำกลับมาใช้ใหม่"""
    fetch_task(task_id)
    mongo().tasks.update_one({"_id": task_id}, {"$set": {"archived": 1}})
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
    mongo().photos.delete_many({"task_id": task_id})
    mongo().tasks.update_one({"_id": task_id}, {"$set": {
        "archived": 0, "status": "pending", "assigned_to": assigned_to,
        "due_date": request.form.get("due_date") or None, "employee_note": "", "feedback": "",
        "submitted_at": None, "reviewed_at": None}})
    flash(f"นำงาน \"{task['title']}\" กลับมาใช้ใหม่แล้ว", "success")
    return redirect(url_for("task_new"))


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required("employer")
def task_delete(task_id):
    """ลบถาวร (จากตารางรายการงานทั้งหมดเท่านั้น)"""
    fetch_task(task_id)
    delete_tasks({"_id": task_id})
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
            mongo().users.update_one({"_id": user["id"]}, {"$set": {"password_hash": generate_password_hash(new)}})
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
        elif mongo().users.find_one({"username": username}, {"_id": 1}):
            flash(f"ชื่อผู้ใช้ '{username}' ถูกใช้แล้ว", "error")
        else:
            mongo().users.insert_one({
                "_id": next_id("users"), "username": username, "password_hash": generate_password_hash(password),
                "name": name, "role": role, "created_at": now()})
            flash(f"เพิ่มผู้ใช้ {name} เรียบร้อย", "success")
            return redirect(url_for("users"))
    task_counts = {r["_id"]: r["n"] for r in mongo().tasks.aggregate(
        [{"$group": {"_id": "$assigned_to", "n": {"$sum": 1}}}])}
    rows = [with_id(u) for u in mongo().users.find().sort([("role", ASCENDING), ("name", ASCENDING)])]
    for u in rows:
        u["task_count"] = task_counts.get(u["id"], 0)
    return render_template("users.html", users=rows, tab="users")


@app.route("/users/<int:user_id>/update", methods=["POST"])
@login_required("employer")
def user_update(user_id):
    target = mongo().users.find_one({"_id": user_id})
    if not target:
        abort(404)
    name = request.form.get("name", "").strip() or target["name"]
    role = request.form.get("role") if request.form.get("role") in ROLES else target["role"]
    if user_id == current_user()["id"] and role != "employer":
        flash("ไม่สามารถเปลี่ยน role ของตัวเองได้", "error")
        return redirect(url_for("users"))
    if target["role"] == "employee" and role == "employer" and mongo().tasks.find_one({"assigned_to": user_id}):
        flash("ผู้ใช้นี้ยังมีงานที่ได้รับมอบหมาย ลบหรือโอนงานก่อนเปลี่ยนเป็นนายจ้าง", "error")
        return redirect(url_for("users"))
    password = request.form.get("password", "")
    if password and len(password) < 6:
        flash("รหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร", "error")
        return redirect(url_for("users"))
    changes = {"name": name, "role": role}
    if password:
        changes["password_hash"] = generate_password_hash(password)
    mongo().users.update_one({"_id": user_id}, {"$set": changes})
    flash(f"บันทึกข้อมูล {name} แล้ว", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required("employer")
def user_delete(user_id):
    if user_id == current_user()["id"]:
        flash("ไม่สามารถลบบัญชีของตัวเองได้", "error")
        return redirect(url_for("users"))
    delete_tasks({"assigned_to": user_id})  # งานที่มอบหมายให้คนนี้ถูกลบด้วย
    mongo().tasks.update_many({"created_by": user_id}, {"$set": {"created_by": None}})
    mongo().users.delete_one({"_id": user_id})
    flash("ลบผู้ใช้แล้ว (งานที่มอบหมายให้ผู้ใช้นี้ถูกลบด้วย)", "success")
    return redirect(url_for("users"))


@app.errorhandler(413)
def too_large(_e):
    flash(f"ไฟล์รวมใหญ่เกินไป (สูงสุด {UPLOAD_LIMIT_MB} MB ต่อครั้ง) ลองส่งทีละน้อยรูป", "error")
    return redirect(request.referrer or url_for("tasks"))


if MONGODB_URI:
    init_db()
    app.secret_key = _secret_key()
else:  # ให้เปิดหน้าเว็บแล้วเห็นข้อความแจ้งชัดเจน แทนที่จะพังตอนเริ่ม
    app.secret_key = "not-configured"

    @app.before_request
    def _not_configured():
        return Response("ยังไม่ได้ตั้งค่า MONGODB_URI — ใส่ใน Vercel → Settings → Environment Variables "
                        "แล้ว Redeploy (หรือใส่ในไฟล์ .env ตอนรันในเครื่อง)", status=500,
                        mimetype="text/plain; charset=utf-8")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5050)), debug=os.environ.get("DEBUG") == "1")
