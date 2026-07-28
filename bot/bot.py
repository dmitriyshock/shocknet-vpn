#!/usr/bin/env python3
import json, os, subprocess, uuid, base64, secrets, time
from pathlib import Path
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

load_dotenv("/opt/vpnserver/.env")

BOT_TOKEN      = os.getenv("BOT_TOKEN")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "").lower().lstrip("@")
USERS_FILE     = Path("/opt/vpnbot/users.json")
XRAY_CFG       = Path("/opt/xray/config.json")
XRAY2_CFG      = Path("/opt/xray2/config.json")
SERVER_IP      = os.getenv("SERVER_IP", "")
TRIAL_DAYS     = 7

XRAY = {
    "private_key": os.getenv("XRAY_PRIVATE_KEY", ""),
    "public_key":  os.getenv("XRAY_PUBLIC_KEY", ""),
    "short_id":    os.getenv("XRAY_SHORT_ID", ""),
    "sni":         os.getenv("XRAY_SNI", "www.microsoft.com"),
    "port":        int(os.getenv("XRAY_PORT", "443")),
}


# ── storage ──────────────────────────────────────────────────────────────────

def load_db() -> dict:
    db = json.loads(USERS_FILE.read_text())
    if "trial_keys" not in db:
        db["trial_keys"] = {}
    return db

def save_db(db: dict):
    USERS_FILE.write_text(json.dumps(db, indent=2, ensure_ascii=False))

def get_admin_id() -> int:
    return load_db().get("admin_id", 0)

def set_admin_id(aid: int):
    db = load_db(); db["admin_id"] = aid; save_db(db)


# ── xray ─────────────────────────────────────────────────────────────────────

XRAY_API    = "127.0.0.1:10085"
STATS_FILE  = Path("/opt/vpnbot/stats_persistent.json")

def _snapshot_stats():
    """Save live xray counters to file before restart so they aren't lost."""
    try:
        r = subprocess.run(
            ["/opt/xray/xray", "api", "statsquery", f"--server={XRAY_API}"],
            capture_output=True, text=True, timeout=3
        )
        live = {}
        for item in json.loads(r.stdout).get("stat", []):
            n, v = item["name"], int(item.get("value", 0))
            if "user>>>" in n:
                parts = n.split(">>>")
                em, direction = parts[1], parts[3]
                live.setdefault(em, {"uplink": 0, "downlink": 0})[direction] = v
        saved = json.loads(STATS_FILE.read_text()) if STATS_FILE.exists() else {}
        for em, vals in live.items():
            saved.setdefault(em, {"uplink": 0, "downlink": 0})
            saved[em]["uplink"]   += vals.get("uplink", 0)
            saved[em]["downlink"] += vals.get("downlink", 0)
        STATS_FILE.write_text(json.dumps(saved))
    except Exception:
        pass

def _cfg_add(cfg_path: Path, uid: str, email: str) -> bool:
    cfg = json.loads(cfg_path.read_text())
    changed = False
    for inbound in cfg["inbounds"]:
        if inbound.get("protocol") != "vless":
            continue
        clients = inbound["settings"]["clients"]
        if any(c["id"] == uid for c in clients):
            continue
        if inbound.get("port") in (4443, 8443, 8444, 8445, 8446):
            clients.append({"id": uid, "email": email, "flow": "xtls-rprx-vision"})
        else:
            clients.append({"id": uid, "email": email})
        changed = True
    if changed:
        cfg_path.write_text(json.dumps(cfg, indent=2))
    return changed

def _cfg_remove(cfg_path: Path, email: str) -> bool:
    cfg = json.loads(cfg_path.read_text())
    changed = False
    for inbound in cfg["inbounds"]:
        if inbound.get("protocol") != "vless":
            continue
        before = len(inbound["settings"]["clients"])
        inbound["settings"]["clients"] = [
            c for c in inbound["settings"]["clients"]
            if c.get("email") != email
        ]
        if len(inbound["settings"]["clients"]) != before:
            changed = True
    if changed:
        cfg_path.write_text(json.dumps(cfg, indent=2))
    return changed

def xray_add(uid: str, email: str):
    c1 = _cfg_add(XRAY_CFG, uid, email)
    c2 = _cfg_add(XRAY2_CFG, uid, email)   # xray2 = профиль VK (8443) — обязательно!
    if c1:
        _snapshot_stats()
        subprocess.run(["systemctl", "reload-or-restart", "xray"], check=False)
    if c2:
        subprocess.run(["systemctl", "reload-or-restart", "xray2"], check=False)

def xray_remove(email: str):
    c1 = _cfg_remove(XRAY_CFG, email)
    c2 = _cfg_remove(XRAY2_CFG, email)
    if c1:
        _snapshot_stats()
        subprocess.run(["systemctl", "reload-or-restart", "xray"], check=False)
    if c2:
        subprocess.run(["systemctl", "reload-or-restart", "xray2"], check=False)


# ── helpers ───────────────────────────────────────────────────────────────────

def gen_token() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(24)).decode().rstrip("=")

DOMAIN = os.getenv("DOMAIN", "shocknet.online")

def sub_url(token: str) -> str:
    return f"https://{DOMAIN}/sub/{token}"

def fmt_date(ts: float) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M")

def cleanup_expired_trials():
    """Remove expired trial keys from xray and db."""
    db = load_db()
    now = time.time()
    changed = False
    for token, t in list(db["trial_keys"].items()):
        if t.get("expires_at", 0) < now:
            xray_remove(t["email"])
            del db["trial_keys"][token]
            changed = True
    if changed:
        save_db(db)


# ── admin menu ────────────────────────────────────────────────────────────────

STATIC_TOKEN = os.getenv("STATIC_TOKEN", "user1")

def admin_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("👥 Пользователи",    callback_data="menu:users"),
         InlineKeyboardButton("🔑 Тест ключи",      callback_data="menu:trial")],
        [InlineKeyboardButton("🎁 Создать тест ключ", callback_data="menu:new_trial"),
         InlineKeyboardButton("❌ Убрать подписку",  callback_data="menu:revoke")],
        [InlineKeyboardButton("🔗 Мой конфиг (user1)", callback_data="menu:my_config")],
    ])

async def send_admin_menu(target, ctx, text="👑 Меню администратора:"):
    """Send or edit admin menu. target = message or query."""
    if hasattr(target, "edit_message_text"):
        await target.edit_message_text(text, reply_markup=admin_keyboard(), parse_mode="Markdown")
    else:
        await target.reply_text(text, reply_markup=admin_keyboard(), parse_mode="Markdown")


# ── handlers ─────────────────────────────────────────────────────────────────

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user  = update.effective_user
    tuid  = str(user.id)
    uname = (user.username or "").lower().lstrip("@")

    # Auto-detect admin
    if uname == ADMIN_USERNAME and get_admin_id() == 0:
        set_admin_id(user.id)

    if user.id == get_admin_id():
        await send_admin_menu(update.message, ctx,
            f"👑 Привет, {user.first_name}! Ты администратор MyVPN.")
        return

    db = load_db()
    u  = db["users"].get(tuid)

    if u and u.get("approved"):
        page_url = sub_url(u["token"])
        await update.message.reply_text(
            f"👋 Привет, {user.first_name}!\n\nТвоя личная страница:\n{page_url}")
        return

    if u and u.get("pending"):
        await update.message.reply_text("⏳ Твой запрос уже отправлен. Ожидай решения.")
        return

    kb = [[InlineKeyboardButton("📨 Запросить доступ к VPN", callback_data="req")]]
    await update.message.reply_text(
        f"👋 Привет, {user.first_name}!\n\nЭто бот *MyVPN*. Нажми кнопку чтобы запросить доступ.",
        reply_markup=InlineKeyboardMarkup(kb), parse_mode="Markdown")


# ── admin menu callbacks ──────────────────────────────────────────────────────

async def cb_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id != get_admin_id():
        return

    action = query.data.split(":")[1]
    cleanup_expired_trials()
    db = load_db()

    # ── users list ──
    if action == "users":
        approved = [(tid, u) for tid, u in db["users"].items() if u.get("approved")]
        if not approved:
            await query.edit_message_text("Нет активных пользователей.",
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton("« Назад", callback_data="menu:back")]]))
            return
        rows = []
        for tid, u in approved:
            name = u.get("name", tid)
            rows.append([InlineKeyboardButton(
                f"🔗 {name}", callback_data=f"user_link:{tid}")])
        rows.append([InlineKeyboardButton("« Назад", callback_data="menu:back")])
        await query.edit_message_text(
            "👥 *Активные пользователи:*\n\nНажми на пользователя — покажу его ссылку подписки для копирования.",
            reply_markup=InlineKeyboardMarkup(rows), parse_mode="Markdown")

    # ── trial keys list ──
    elif action == "trial":
        trials = db.get("trial_keys", {})
        if not trials:
            await query.edit_message_text("Нет активных тестовых ключей.",
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton("🎁 Создать", callback_data="menu:new_trial"),
                    InlineKeyboardButton("« Назад",   callback_data="menu:back")]]))
            return
        rows = []
        lines = ["🔑 *Тестовые ключи:*\n"]
        for token, t in trials.items():
            label = t.get("label", token[:8])
            exp   = fmt_date(t.get("expires_at", 0))
            lines.append(f"• *{label}* — до {exp}\n  `{sub_url(token)}`")
            rows.append([InlineKeyboardButton(
                f"🗑 Удалить — {label}", callback_data=f"trial_del:{token}")])
        rows.append([InlineKeyboardButton("🎁 Создать ещё", callback_data="menu:new_trial"),
                     InlineKeyboardButton("« Назад",        callback_data="menu:back")])
        await query.edit_message_text("\n".join(lines),
            reply_markup=InlineKeyboardMarkup(rows), parse_mode="Markdown")

    # ── create trial key ──
    elif action == "new_trial":
        token     = gen_token()
        user_uuid = str(uuid.uuid4())
        now       = time.time()
        exp       = now + TRIAL_DAYS * 86400
        db        = load_db()
        num       = len(db.get("trial_keys", {})) + 1
        label     = f"Тестовый #{num}"
        email     = f"trial_{token[:8]}"

        db["trial_keys"][token] = {
            "uuid":       user_uuid,
            "email":      email,
            "label":      label,
            "created_at": now,
            "expires_at": exp,
        }
        save_db(db)
        xray_add(user_uuid, email)

        url = sub_url(token)
        await query.edit_message_text(
            f"✅ *{label}* создан!\n\n"
            f"🔗 Ссылка (действует до {fmt_date(exp)}):\n`{url}`\n\n"
            f"Скопируй и отправь пользователю.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("« В меню", callback_data="menu:back"),
                InlineKeyboardButton("🔑 Все ключи", callback_data="menu:trial")]]),
            parse_mode="Markdown")

    # ── revoke select ──
    elif action == "revoke":
        approved = [(tid, u) for tid, u in db["users"].items() if u.get("approved")]
        if not approved:
            await query.edit_message_text("Нет активных пользователей для отзыва.",
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton("« Назад", callback_data="menu:back")]]))
            return
        rows = [[InlineKeyboardButton(
            f"❌ {u.get('name', tid)}", callback_data=f"revoke_u:{tid}")]
            for tid, u in approved]
        rows.append([InlineKeyboardButton("« Назад", callback_data="menu:back")])
        await query.edit_message_text("Выбери пользователя для отзыва доступа:",
            reply_markup=InlineKeyboardMarkup(rows))

    # ── my config ──
    elif action == "my_config":
        url = sub_url(STATIC_TOKEN)
        await query.edit_message_text(
            f"🔗 *Твой конфиг (user1):*\n\n`{url}`",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("« Назад", callback_data="menu:back")]]),
            parse_mode="Markdown")

    # ── back to main menu ──
    elif action == "back":
        await send_admin_menu(query, ctx)


# ── revoke user via menu ──────────────────────────────────────────────────────

async def cb_revoke_user(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id != get_admin_id():
        return

    tuid = query.data.split(":")[1]
    db   = load_db()
    u    = db["users"].get(tuid)
    if not u or not u.get("approved"):
        await query.edit_message_text("Пользователь не найден.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("« Назад", callback_data="menu:back")]]))
        return

    xray_remove(u.get("email", f"tg_{tuid}"))
    db["users"][tuid].update({"approved": False, "pending": False, "token": None, "uuid": None})
    save_db(db)

    try:
        kb = [[InlineKeyboardButton("📨 Запросить доступ снова", callback_data="req")]]
        await ctx.bot.send_message(
            chat_id=int(tuid),
            text="⛔ Ваш доступ к MyVPN был отозван администратором.\n\nВы можете подать новый запрос:",
            reply_markup=InlineKeyboardMarkup(kb))
    except Exception:
        pass

    name = u.get("name", tuid)
    await query.edit_message_text(f"✅ Доступ отозван у *{name}*.",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("« В меню", callback_data="menu:back"),
            InlineKeyboardButton("👥 Пользователи", callback_data="menu:users")]]),
        parse_mode="Markdown")


# ── показать ссылку пользователя (для копирования) ────────────────────────────

async def cb_user_link(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id != get_admin_id():
        return

    tuid = query.data.split(":")[1]
    db   = load_db()
    u    = db["users"].get(tuid)
    if not u or not u.get("approved") or not u.get("token"):
        await query.edit_message_text("Пользователь не найден или без подписки.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("« К списку", callback_data="menu:users")]]))
        return

    name  = u.get("name", tuid)
    uname = f"@{u['username']}" if u.get("username") else ""
    url   = sub_url(u["token"])
    text = (f"👤 *{name}* {uname}\n"
            f"ID: `{tuid}`\n\n"
            f"🔗 *Ссылка подписки* (нажми чтобы скопировать):\n"
            f"`{url}`")
    await query.edit_message_text(text, parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("❌ Отозвать доступ", callback_data=f"revoke_u:{tuid}")],
            [InlineKeyboardButton("« К списку", callback_data="menu:users")]]))


# ── delete trial key ──────────────────────────────────────────────────────────

async def cb_trial_del(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id != get_admin_id():
        return

    token = query.data[len("trial_del:"):]
    db    = load_db()
    t     = db.get("trial_keys", {}).get(token)
    if not t:
        await query.answer("Ключ не найден.", show_alert=True)
        return

    xray_remove(t["email"])
    del db["trial_keys"][token]
    save_db(db)

    label = t.get("label", token[:8])
    await query.edit_message_text(f"🗑 Тестовый ключ *{label}* удалён.",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("« В меню",    callback_data="menu:back"),
            InlineKeyboardButton("🔑 Все ключи", callback_data="menu:trial")]]),
        parse_mode="Markdown")


# ── user request access ───────────────────────────────────────────────────────

async def cb_request(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user  = query.from_user
    tuid  = str(user.id)
    db    = load_db()

    if db["users"].get(tuid, {}).get("approved"):
        await query.edit_message_text("✅ У тебя уже есть доступ. Напиши /start"); return
    if db["users"].get(tuid, {}).get("pending"):
        await query.edit_message_text("⏳ Запрос уже отправлен. Ожидай."); return

    db["users"][tuid] = {
        "approved": False, "pending": True,
        "name": user.full_name, "username": user.username or "",
        "token": None, "uuid": None,
    }
    save_db(db)

    admin_id = get_admin_id()
    if admin_id:
        user_link = f"[{user.full_name}](tg://user?id={user.id})"
        uname_str = f"@{user.username}" if user.username else "нет username"
        kb = [[
            InlineKeyboardButton("✅ Выдать",  callback_data=f"ok:{tuid}"),
            InlineKeyboardButton("❌ Отказать", callback_data=f"no:{tuid}"),
        ]]
        await ctx.bot.send_message(
            chat_id=admin_id,
            text=f"🔔 *Новый запрос на VPN*\n\n👤 {user_link}\n🔗 {uname_str}\n🆔 `{user.id}`",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="Markdown")
    await query.edit_message_text("✅ Запрос отправлен! Ожидай решения администратора.")


# ── approve / deny ───────────────────────────────────────────────────────────

async def cb_approve(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id != get_admin_id():
        return

    tuid = query.data.split(":")[1]
    db   = load_db()
    u    = db["users"].get(tuid, {})
    if u.get("approved"):
        await query.edit_message_text(query.message.text + "\n\n✅ Уже выдан", parse_mode="Markdown")
        return

    token     = gen_token()
    user_uuid = str(uuid.uuid4())
    email     = f"tg_{tuid}"
    db["users"][tuid].update({"approved": True, "pending": False,
                               "token": token, "uuid": user_uuid, "email": email})
    save_db(db)
    xray_add(user_uuid, email)

    page_url = sub_url(token)
    await ctx.bot.send_message(
        chat_id=int(tuid),
        text=(f"✅ Вам выдан доступ к MyVPN!\n\n"
              f"Ваша личная страница с ключами и статистикой:\n{page_url}\n\n"
              f"На странице вы найдёте:\n"
              f"• Ссылки подписки для HAPP и Koala Clash\n"
              f"• VLESS ключ для ручного подключения\n"
              f"• Статистику расхода трафика"))
    name = u.get("name", tuid)
    await query.edit_message_text(
        query.message.text + f"\n\n✅ *Выдан* — {name}", parse_mode="Markdown")


async def cb_deny(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id != get_admin_id():
        return

    tuid = query.data.split(":")[1]
    db   = load_db()
    if tuid in db["users"]:
        db["users"][tuid]["pending"] = False
        save_db(db)

    await ctx.bot.send_message(chat_id=int(tuid),
        text="❌ Администратор отклонил твой запрос.")
    name = db["users"].get(tuid, {}).get("name", tuid)
    await query.edit_message_text(
        query.message.text + f"\n\n❌ *Отказано* — {name}", parse_mode="Markdown")


# ── /users и /revoke (текстовые команды оставляем) ───────────────────────────

async def cmd_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != get_admin_id():
        return
    await send_admin_menu(update.message, ctx)

async def cmd_revoke(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != get_admin_id():
        return
    args = ctx.args
    if not args:
        await update.message.reply_text("Использование: /revoke <telegram_id>")
        return
    tuid = args[0]
    db   = load_db()
    u    = db["users"].get(tuid)
    if not u or not u.get("approved"):
        await update.message.reply_text("Пользователь не найден.")
        return
    xray_remove(u.get("email", f"tg_{tuid}"))
    db["users"][tuid].update({"approved": False, "pending": False, "token": None, "uuid": None})
    save_db(db)
    try:
        kb = [[InlineKeyboardButton("📨 Запросить доступ снова", callback_data="req")]]
        await ctx.bot.send_message(chat_id=int(tuid),
            text="⛔ Ваш доступ к MyVPN был отозван администратором.\n\nВы можете подать новый запрос:",
            reply_markup=InlineKeyboardMarkup(kb))
    except Exception:
        pass
    await update.message.reply_text(f"✅ Доступ отозван у {u['name']}.")


def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start",  cmd_start))
    app.add_handler(CommandHandler("users",  cmd_users))
    app.add_handler(CommandHandler("revoke", cmd_revoke))
    app.add_handler(CallbackQueryHandler(cb_request,    pattern="^req$"))
    app.add_handler(CallbackQueryHandler(cb_approve,    pattern="^ok:"))
    app.add_handler(CallbackQueryHandler(cb_deny,       pattern="^no:"))
    app.add_handler(CallbackQueryHandler(cb_menu,       pattern="^menu:"))
    app.add_handler(CallbackQueryHandler(cb_revoke_user, pattern="^revoke_u:"))
    app.add_handler(CallbackQueryHandler(cb_user_link,   pattern="^user_link:"))
    app.add_handler(CallbackQueryHandler(cb_trial_del,  pattern="^trial_del:"))
    print("VPN bot started")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
