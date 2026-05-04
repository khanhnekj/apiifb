#!/usr/bin/env python3
"""
FB Login API - Hỗ trợ 2FA (2 bước)
=====================================
Bước 1: POST /login   { email, password }
  → Nếu OK ngay      : { success: true, uid, appState, cookie_str }
  → Nếu cần 2FA      : { success: false, need_2fa: true, session_id }

Bước 2: POST /verify  { session_id, otp_code }
  → { success: true, uid, appState, cookie_str }

GET  /health  → kiểm tra API còn sống không
GET  /        → thông tin API
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import asyncio
import uuid
import time
import uvicorn
from playwright.async_api import async_playwright, BrowserContext, Page

app = FastAPI(title="FB Login API", version="2.0", description="Login Facebook + 2FA")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== SESSION STORE ====================
# Lưu session đang chờ OTP: { session_id: { context, page, expires_at } }
pending_sessions: dict = {}
SESSION_TTL = 300  # Session hết hạn sau 5 phút

def cleanup_sessions():
    """Xóa session hết hạn"""
    now = time.time()
    expired = [sid for sid, s in pending_sessions.items() if s["expires_at"] < now]
    for sid in expired:
        try:
            asyncio.create_task(pending_sessions[sid]["context"].close())
        except:
            pass
        del pending_sessions[sid]

# ==================== MODELS ====================
class LoginRequest(BaseModel):
    email: str
    password: str

class VerifyRequest(BaseModel):
    session_id: str
    otp_code: str

class LoginResponse(BaseModel):
    success: bool
    uid: Optional[str] = None
    appState: Optional[list] = None
    cookie_str: Optional[str] = None
    need_2fa: Optional[bool] = None
    session_id: Optional[str] = None
    error: Optional[str] = None

# ==================== UTILS ====================
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)

async def extract_appstate(context: BrowserContext, page: Page) -> dict:
    """Lấy appState và uid từ context sau khi đã đăng nhập"""
    cookies = await context.cookies()

    uid = next(
        (c["value"] for c in cookies if c["name"] == "c_user"),
        None
    )
    if not uid:
        return {"success": False, "error": "Không lấy được UID sau đăng nhập"}

    app_state = [
        {
            "key": c["name"],
            "value": c["value"],
            "domain": c.get("domain", ".facebook.com"),
            "path": c.get("path", "/"),
            "hostOnly": c.get("hostOnly", False),
            "creation": "2024-01-01T00:00:00.000Z",
            "lastAccessed": "2024-01-01T00:00:00.000Z",
        }
        for c in cookies
        if "facebook" in c.get("domain", "")
    ]

    cookie_str = "; ".join(
        f"{c['name']}={c['value']}"
        for c in cookies
        if "facebook" in c.get("domain", "")
    )

    return {
        "success": True,
        "uid": uid,
        "appState": app_state,
        "cookie_str": cookie_str,
    }

def detect_page_state(url: str, content: str) -> str:
    """
    Phân tích URL/content để biết trang đang ở trạng thái nào
    Returns: 'logged_in' | 'need_2fa' | 'need_otp_confirm' | 'checkpoint' | 'wrong_password' | 'unknown'
    """
    if "checkpoint" in url:
        # Checkpoint có thể là OTP hoặc xác minh danh tính
        if any(x in content for x in ["two_factor", "approvals", "mfa", "otp", "code"]):
            return "need_2fa"
        return "checkpoint"

    if "two_step" in url or "two_factor" in url:
        return "need_2fa"

    if "login" in url:
        if any(x in content for x in ["wrong password", "sai mật khẩu", "incorrect password"]):
            return "wrong_password"
        return "still_on_login"

    if "home" in url or url.endswith("facebook.com/") or "feed" in url:
        return "logged_in"

    return "logged_in"  # Mặc định coi là đã login nếu không phải login page


# ==================== ROUTE: /login ====================
@app.post("/login", response_model=LoginResponse)
async def login(req: LoginRequest):
    cleanup_sessions()

    if not req.email.strip() or not req.password.strip():
        raise HTTPException(status_code=400, detail="Thiếu email hoặc password")

    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
    )
    context = await browser.new_context(
        user_agent=USER_AGENT,
        locale="vi-VN",
        viewport={"width": 1280, "height": 800},
    )
    page = await context.new_page()

    try:
        await page.goto("https://www.facebook.com/login", wait_until="domcontentloaded", timeout=30000)
        await asyncio.sleep(1)

        # Nhập thông tin
        await page.fill("#email", req.email.strip())
        await asyncio.sleep(0.3)
        await page.fill("#pass", req.password.strip())
        await asyncio.sleep(0.3)
        await page.click("#loginbutton")
        await page.wait_for_load_state("domcontentloaded", timeout=20000)
        await asyncio.sleep(3)

        url = page.url
        content = await page.content()
        state = detect_page_state(url, content)

        # ✅ Đăng nhập thành công ngay
        if state == "logged_in":
            result = await extract_appstate(context, page)
            await context.close()
            await browser.close()
            await playwright.stop()
            return LoginResponse(**result)

        # 🔐 Cần nhập mã 2FA
        if state == "need_2fa":
            session_id = str(uuid.uuid4())
            pending_sessions[session_id] = {
                "context": context,
                "page": page,
                "browser": browser,
                "playwright": playwright,
                "expires_at": time.time() + SESSION_TTL,
            }
            return LoginResponse(
                success=False,
                need_2fa=True,
                session_id=session_id,
                error="Tài khoản bật xác minh 2 bước. Hãy gọi POST /verify với session_id và otp_code."
            )

        # ❌ Sai mật khẩu
        if state == "wrong_password":
            await context.close()
            await browser.close()
            await playwright.stop()
            return LoginResponse(success=False, error="Sai email hoặc mật khẩu")

        # ⛔ Checkpoint khác (yêu cầu xác minh danh tính, ảnh...)
        if state == "checkpoint":
            await context.close()
            await browser.close()
            await playwright.stop()
            return LoginResponse(success=False, error="Tài khoản bị checkpoint (yêu cầu xác minh danh tính). Cần xử lý thủ công.")

        # Không xác định
        await context.close()
        await browser.close()
        await playwright.stop()
        return LoginResponse(success=False, error=f"Trạng thái không xác định. URL: {url}")

    except Exception as e:
        try:
            await context.close()
            await browser.close()
            await playwright.stop()
        except:
            pass
        return LoginResponse(success=False, error=str(e))


# ==================== ROUTE: /verify ====================
@app.post("/verify", response_model=LoginResponse)
async def verify(req: VerifyRequest):
    cleanup_sessions()

    session = pending_sessions.get(req.session_id)
    if not session:
        raise HTTPException(
            status_code=404,
            detail="session_id không tồn tại hoặc đã hết hạn (5 phút)"
        )
    if time.time() > session["expires_at"]:
        del pending_sessions[req.session_id]
        raise HTTPException(status_code=410, detail="Session đã hết hạn. Vui lòng đăng nhập lại.")

    page: Page = session["page"]
    context: BrowserContext = session["context"]
    browser = session["browser"]
    playwright = session["playwright"]

    try:
        # Tìm ô nhập OTP trên trang hiện tại
        otp_selectors = [
            'input[name="approvals_code"]',
            'input[name="otp"]',
            'input[type="text"][autocomplete="one-time-code"]',
            'input[id*="code"]',
            'input[placeholder*="code"]',
            'input[placeholder*="mã"]',
            'input[type="number"]',
            '#approvals_code',
        ]

        otp_input = None
        for selector in otp_selectors:
            try:
                el = await page.wait_for_selector(selector, timeout=3000)
                if el:
                    otp_input = selector
                    break
            except:
                continue

        if not otp_input:
            # Chụp screenshot để debug nếu cần
            content = await page.content()
            del pending_sessions[req.session_id]
            await context.close()
            await browser.close()
            await playwright.stop()
            return LoginResponse(
                success=False,
                error="Không tìm thấy ô nhập OTP trên trang. Trang hiện tại: " + page.url
            )

        # Nhập OTP
        await page.fill(otp_input, req.otp_code.strip())
        await asyncio.sleep(0.5)

        # Tìm nút Submit/Continue
        submit_selectors = [
            'button[type="submit"]',
            'button[name="submit"]',
            '#checkpointSubmitButton',
            'input[type="submit"]',
            'button:has-text("Continue")',
            'button:has-text("Tiếp tục")',
            'button:has-text("Submit")',
        ]
        for sel in submit_selectors:
            try:
                btn = await page.query_selector(sel)
                if btn:
                    await btn.click()
                    break
            except:
                continue

        await page.wait_for_load_state("domcontentloaded", timeout=20000)
        await asyncio.sleep(3)

        url = page.url
        content = await page.content()
        state = detect_page_state(url, content)

        del pending_sessions[req.session_id]

        if state == "logged_in":
            result = await extract_appstate(context, page)
            await context.close()
            await browser.close()
            await playwright.stop()
            return LoginResponse(**result)

        # OTP sai hoặc cần bước tiếp
        if "checkpoint" in url or "login" in url:
            await context.close()
            await browser.close()
            await playwright.stop()
            return LoginResponse(success=False, error="Mã OTP sai hoặc trang yêu cầu thêm xác minh")

        # Một số tài khoản có thêm trang "Lưu thiết bị này?"
        try:
            dont_save = await page.query_selector('button[name="dont_save"]')
            if dont_save:
                await dont_save.click()
                await page.wait_for_load_state("domcontentloaded", timeout=10000)
                await asyncio.sleep(2)
        except:
            pass

        result = await extract_appstate(context, page)
        await context.close()
        await browser.close()
        await playwright.stop()
        return LoginResponse(**result)

    except Exception as e:
        try:
            del pending_sessions[req.session_id]
            await context.close()
            await browser.close()
            await playwright.stop()
        except:
            pass
        return LoginResponse(success=False, error=str(e))


# ==================== ROUTE: /health ====================
@app.get("/health")
def health():
    return {
        "status": "ok",
        "pending_sessions": len(pending_sessions),
        "version": "2.0"
    }

@app.get("/")
def root():
    return {
        "name": "FB Login API",
        "version": "2.0",
        "endpoints": {
            "POST /login": "Đăng nhập bằng email + password",
            "POST /verify": "Nhập mã 2FA (nếu cần)",
            "GET /health": "Kiểm tra trạng thái API",
        },
        "flow": "POST /login → nếu need_2fa=true → POST /verify với session_id + otp_code"
    }


# ==================== MAIN ====================
if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=False)
