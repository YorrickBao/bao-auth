// bao-auth 前端逻辑：状态机 + API 调用 + 倒计时 + 二维码解析。
(function () {
  "use strict";

  // ---- 状态 ----
  const TOKEN_KEY = "bao_token";
  // BASE 为部署路径前缀（根路径部署时为空串），由 index.html 注入。
  const BASE = window.__BASE__ || "";
  let token = sessionStorage.getItem(TOKEN_KEY) || "";
  let accounts = [];      // 后端返回的账户（含实时 code）
  let filter = "";
  let editingId = null;   // 编辑模式时设为账户 id
  let tickTimer = null;   // 自动刷新定时器

  // ---- DOM ----
  const $ = (id) => document.getElementById(id);
  const screens = ["boot", "setup", "login", "main"];

  function showScreen(name) {
    for (const s of screens) {
      $(s).classList.toggle("hidden", s !== name);
    }
  }

  // ---- API ----
  async function api(path, opts = {}) {
    const headers = Object.assign({}, opts.headers || {});
    let body = opts.body;
    if (body && typeof body === "object") {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(body);
    }
    if (token) headers["Authorization"] = "Bearer " + token;
    const res = await fetch(BASE + path, Object.assign({}, opts, { headers, body }));
    let data = null;
    const text = await res.text();
    if (text) {
      try { data = JSON.parse(text); } catch { data = { raw: text }; }
    }
    if (!res.ok) {
      const msg = (data && data.error) || ("HTTP " + res.status);
      const e = new Error(msg);
      e.status = res.status;
      e.data = data;
      throw e;
    }
    return data;
  }

  function setToken(t) {
    token = t;
    if (t) sessionStorage.setItem(TOKEN_KEY, t);
    else sessionStorage.removeItem(TOKEN_KEY);
  }

  // ---- Toast ----
  let toastTimer = null;
  function toast(msg, kind) {
    const el = $("toast");
    el.textContent = msg;
    el.classList.remove("hidden");
    el.style.borderColor = kind === "error" ? "var(--danger)" : "var(--border)";
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add("hidden"), 2200);
  }

  // ---- 启动：判断状态 ----
  async function boot() {
    try {
      const st = await api("/api/status");
      if (!st.initialized) {
        showScreen("setup");
      } else if (token && st.unlocked) {
        // 服务器仍持有 KEK，直接进入主界面
        await enterMain();
      } else {
        // 有 token 但服务器重启清空了 KEK，或无 token
        setToken("");
        showScreen("login");
        $("login-password").focus();
      }
    } catch (e) {
      showError("boot", "无法连接服务器：" + e.message);
    }
  }

  function showError(screenId, msg) {
    const el = $(screenId + "-error");
    if (el) { el.textContent = msg; el.classList.remove("hidden"); }
  }
  function hideError(screenId) {
    const el = $(screenId + "-error");
    if (el) el.classList.add("hidden");
  }

  // ---- 设置主密码 ----
  $("setup-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    hideError("setup");
    const pw = $("setup-password").value;
    const cf = $("setup-confirm").value;
    if (pw.length < 8) return showError("setup", "主密码至少 8 位");
    if (pw !== cf) return showError("setup", "两次输入不一致");
    try {
      const r = await api("/api/setup", { method: "POST", body: { password: pw } });
      setToken(r.token);
      await enterMain();
    } catch (err) {
      showError("setup", err.message);
    }
  });

  // ---- 登录 ----
  $("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    hideError("login");
    const pw = $("login-password").value;
    try {
      const r = await api("/api/login", { method: "POST", body: { password: pw } });
      setToken(r.token);
      $("login-password").value = "";
      await enterMain();
    } catch (err) {
      if (err.status === 429) {
        showError("login", "尝试过于频繁，请稍后再试");
      } else {
        showError("login", err.message);
      }
    }
  });

  // ---- 登出 ----
  async function logout() {
    try { await api("/api/logout", { method: "POST" }); } catch {}
    setToken("");
    stopTick();
    accounts = [];
    showScreen("login");
    $("login-password").focus();
  }
  $("btn-logout").addEventListener("click", logout);

  // ---- 主界面 ----
  async function enterMain() {
    showScreen("main");
    await refreshAccounts();
    startTick();
  }

  async function refreshAccounts() {
    try {
      const r = await api("/api/accounts");
      accounts = r.accounts || [];
      renderList();
    } catch (err) {
      if (err.status === 401) {
        setToken("");
        stopTick();
        showScreen("login");
      } else {
        toast("加载失败：" + err.message, "error");
      }
    }
  }

  // ---- 渲染列表 ----
  function renderList() {
    const list = $("list");
    list.innerHTML = "";
    const q = filter.trim().toLowerCase();
    const filtered = q
      ? accounts.filter(a =>
          (a.issuer || "").toLowerCase().includes(q) ||
          (a.label || "").toLowerCase().includes(q))
      : accounts;

    $("empty-tip").classList.toggle("hidden", accounts.length > 0);

    for (const a of filtered) {
      list.appendChild(renderAccount(a));
    }
  }

  function renderAccount(a) {
    const el = document.createElement("div");
    el.className = "acc";
    el.dataset.id = a.id;

    const meta = document.createElement("div");
    meta.className = "meta";
    const issuer = document.createElement("div");
    issuer.className = "issuer";
    issuer.textContent = a.issuer || a.label || "(未命名)";
    if (a.error) {
      const warn = document.createElement("span");
      warn.textContent = "⚠ " + a.error;
      warn.style.cssText = "color:var(--danger);font-size:11px;font-weight:normal;";
      issuer.appendChild(warn);
    }
    const label = document.createElement("div");
    label.className = "label";
    label.textContent = a.label || "";
    meta.appendChild(issuer);
    meta.appendChild(label);

    // 验证码
    const codeWrap = document.createElement("div");
    codeWrap.className = "code-wrap";
    const code = document.createElement("div");
    code.className = "code";
    code.textContent = a.code ? formatCode(a.code, a.digits) : "------";
    code.title = "点击复制";
    code.addEventListener("click", () => copy(a.code));
    codeWrap.appendChild(code);

    // 倒计时圆环
    const ring = makeRing(a.period, a.remaining);
    codeWrap.appendChild(ring.el);

    // 工具
    const tools = document.createElement("div");
    tools.className = "tools";
    const editBtn = document.createElement("button");
    editBtn.className = "icon-btn";
    editBtn.textContent = "✏";
    editBtn.title = "编辑";
    editBtn.addEventListener("click", () => openEdit(a));
    const delBtn = document.createElement("button");
    delBtn.className = "icon-btn";
    delBtn.textContent = "🗑";
    delBtn.title = "删除";
    delBtn.addEventListener("click", () => del(a));
    tools.appendChild(editBtn);
    tools.appendChild(delBtn);

    el.appendChild(meta);
    el.appendChild(codeWrap);
    el.appendChild(tools);
    return el;
  }

  function formatCode(code, digits) {
    // 6 位按 3-3 分组，8 位按 4-4 分组
    code = String(code);
    if (code.length === 6) return code.slice(0, 3) + " " + code.slice(3);
    if (code.length === 8) return code.slice(0, 4) + " " + code.slice(4);
    return code;
  }

  // ---- 倒计时圆环 ----
  const RING_R = 16, RING_C = 2 * Math.PI * RING_R;
  function makeRing(period, remaining) {
    const wrap = document.createElement("div");
    wrap.className = "ring";
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("width", 40); svg.setAttribute("height", 40);
    const bg = document.createElementNS(ns, "circle");
    bg.setAttribute("cx", 20); bg.setAttribute("cy", 20); bg.setAttribute("r", RING_R);
    bg.setAttribute("class", "bg");
    const fg = document.createElementNS(ns, "circle");
    fg.setAttribute("cx", 20); fg.setAttribute("cy", 20); fg.setAttribute("r", RING_R);
    fg.setAttribute("class", "fg");
    fg.setAttribute("stroke-dasharray", RING_C);
    svg.appendChild(bg); svg.appendChild(fg);
    const num = document.createElement("div");
    num.className = "num";
    wrap.appendChild(svg); wrap.appendChild(num);

    const obj = { el: wrap, fg, num, period: period || 30 };
    updateRing(obj, remaining == null ? obj.period : remaining);
    return obj;
  }

  function updateRing(r, remaining) {
    const ratio = Math.max(0, Math.min(1, remaining / r.period));
    r.fg.setAttribute("stroke-dashoffset", RING_C * (1 - ratio));
    r.num.textContent = Math.max(0, Math.ceil(remaining));
    r.fg.classList.toggle("warn", remaining <= 5);
  }

  // 每秒更新所有圆环；到周期边界时自动拉取新码
  function startTick() {
    stopTick();
    tickTimer = setInterval(tick, 1000);
  }
  function stopTick() { if (tickTimer) { clearInterval(tickTimer); tickTimer = null; } }

  function tick() {
    const now = Math.floor(Date.now() / 1000);
    let needRefresh = false;
    document.querySelectorAll(".acc").forEach(el => {
      const id = el.dataset.id;
      const a = accounts.find(x => x.id === id);
      if (!a || !a.next_tick_at) return;
      const remaining = a.next_tick_at - now;
      if (remaining <= 0) {
        needRefresh = true;
        return;
      }
      // 更新圆环
      const ringEl = el.querySelector(".ring");
      if (ringEl) {
        const fg = ringEl.querySelector(".fg");
        const num = ringEl.querySelector(".num");
        const period = a.period || 30;
        const ratio = Math.max(0, Math.min(1, remaining / period));
        fg.setAttribute("stroke-dashoffset", RING_C * (1 - ratio));
        num.textContent = Math.max(0, remaining);
        fg.classList.toggle("warn", remaining <= 5);
      }
      // 即将过期：验证码变红
      const code = el.querySelector(".code");
      if (code) code.classList.toggle("expiring", remaining <= 5);
    });
    if (needRefresh) refreshAccounts();
  }

  // ---- 复制 ----
  async function copy(text) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      toast("已复制：" + text);
    } catch {
      // 降级：临时输入框
      const tmp = document.createElement("input");
      tmp.value = text; document.body.appendChild(tmp); tmp.select();
      try { document.execCommand("copy"); toast("已复制：" + text); }
      catch { toast("复制失败", "error"); }
      document.body.removeChild(tmp);
    }
  }

  // ---- 搜索 ----
  $("search").addEventListener("input", (e) => { filter = e.target.value; renderList(); });

  // ---- 添加 / 编辑 弹窗 ----
  $("btn-add").addEventListener("click", () => openAdd());
  $("btn-add-empty").addEventListener("click", () => openAdd());
  $("modal-cancel").addEventListener("click", closeModal);
  document.querySelector(".modal-backdrop").addEventListener("click", closeModal);

  function openAdd() {
    editingId = null;
    $("modal-title").textContent = "添加账户";
    resetForm();
    $("modal").classList.remove("hidden");
  }
  function openEdit(a) {
    editingId = a.id;
    $("modal-title").textContent = "编辑账户";
    resetForm();
    $("f-issuer").value = a.issuer || "";
    $("f-label").value = a.label || "";
    $("f-digits").value = a.digits || 6;
    $("f-period").value = a.period || 30;
    $("f-algo").value = a.algorithm || "SHA1";
    // 编辑时 secret 留空表示不修改
    $("f-secret").required = false;
    $("f-secret").placeholder = "留空则不修改密钥";
    switchTab("manual");
    $("modal").classList.remove("hidden");
  }
  function closeModal() {
    $("modal").classList.add("hidden");
    editingId = null;
    stopCamera(); // 关弹窗时务必释放摄像头，避免指示灯常亮
  }
  function resetForm() {
    $("account-form").reset();
    $("f-secret").required = true;
    $("f-secret").placeholder = "JBSWY3DPEHPK3PXP";
    $("f-period").value = 30;
    hideError("uri"); hideError("qr");
    switchTab("qr"); // 添加账户时回到默认 tab（最便捷的扫码）
  }

  // ---- Tab 切换 ----
  document.querySelectorAll(".tab").forEach(t => {
    t.addEventListener("click", () => switchTab(t.dataset.tab));
  });
  function switchTab(name) {
    document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.toggle("hidden", p.dataset.pane !== name));
    hideError("qr"); hideError("uri"); // 切 tab 时清除旧错误提示
  }

  // ---- 解析 otpauth URI ----
  // parseURI 核心逻辑：解析 URI 并填充表单，errScreen 指定失败时错误显示在哪个 tab。
  async function parseURI(uri, errScreen) {
    uri = uri.trim();
    if (!uri) return false;
    hideError(errScreen);
    try {
      const p = await api("/api/parse-uri", { method: "POST", body: { uri } });
      $("f-issuer").value = p.issuer || "";
      $("f-label").value = p.label || "";
      $("f-secret").value = p.secret || "";
      $("f-digits").value = p.digits || 6;
      $("f-period").value = p.period || 30;
      $("f-algo").value = (p.algorithm || "SHA1");
      switchTab("manual");
      toast("已解析，请确认后保存");
      return true;
    } catch (err) {
      showError(errScreen, err.message);
      return false;
    }
  }

  $("btn-parse-uri").addEventListener("click", () => parseURI($("f-uri").value, "uri"));

  // ---- 扫描二维码：摄像头 + 上传图片 ----

  let qrStream = null;      // MediaStream
  let qrScanTimer = null;   // 帧扫描定时器
  let qrCanvas = document.createElement("canvas");
  let qrCtx = qrCanvas.getContext("2d", { willReadFrequently: true });

  const qrVideo = $("qr-video");
  const qrOverlay = $("qr-overlay");
  const qrStatus = $("qr-status");

  // 启动摄像头扫描（优先背面摄像头）
  $("btn-qr-camera").addEventListener("click", openCamera);
  $("btn-qr-stop").addEventListener("click", stopCamera);

  // 粘贴图片：仅在弹窗打开且处于扫码 tab 时响应，方便 PC 用户截图后直接 Ctrl+V
  document.addEventListener("paste", (e) => {
    if ($("modal").classList.contains("hidden")) return;
    if (!document.querySelector('.tab[data-tab="qr"]').classList.contains("active")) return;
    const items = e.clipboardData && e.clipboardData.items;
    if (!items) return;
    for (const it of items) {
      if (it.type.startsWith("image/")) {
        const file = it.getAsFile();
        if (file) {
          hideError("qr");
          decodeQRFile(file).then(handleQRResult).catch((err) => {
            showError("qr", "无法识别粘贴的二维码：" + err.message);
          });
          e.preventDefault(); // 阻止粘贴图片的其他副作用
          return;
        }
      }
    }
  });

  async function openCamera() {
    hideError("qr");
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      showError("qr", "此浏览器不支持摄像头，请改用上传图片。");
      return;
    }
    try {
      // facingMode: ideal 'environment' = 背面摄像头。
      // 用 ideal 而非 exact：手机上优先选背面，桌面无背面时也能降级。
      qrStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: "environment" } },
        audio: false,
      });
    } catch (err) {
      const msg = err.name === "NotAllowedError"
        ? "摄像头权限被拒绝，请在浏览器设置中允许后重试。"
        : "无法访问摄像头：" + err.message + "（也可改用上传图片）";
      showError("qr", msg);
      return;
    }

    qrVideo.srcObject = qrStream;
    qrVideo.classList.add("mirror-off"); // 背面摄像头无需镜像
    await qrVideo.play();

    qrOverlay.classList.add("active"); // 隐藏占位层，露出实时画面
    $("btn-qr-camera").classList.add("hidden");
    $("btn-qr-stop").classList.remove("hidden");
    qrStatus.textContent = "将二维码对准摄像头…";

    // 定时抓取视频帧解码（每 250ms 一次，平衡性能与响应）
    qrScanTimer = setInterval(scanFrame, 250);
  }

  function stopCamera() {
    if (qrScanTimer) { clearInterval(qrScanTimer); qrScanTimer = null; }
    if (qrStream) {
      qrStream.getTracks().forEach(t => t.stop()); // 释放摄像头，熄灭指示灯
      qrStream = null;
    }
    qrVideo.srcObject = null;
    qrOverlay.classList.remove("active"); // 恢复占位层
    $("btn-qr-camera").classList.remove("hidden");
    $("btn-qr-stop").classList.add("hidden");
    qrStatus.textContent = "摄像头已关闭";
  }

  // 从当前视频帧尝试解码二维码
  function scanFrame() {
    if (!qrStream || qrVideo.readyState < 2) return; // HAVE_CURRENT_DATA
    const w = qrVideo.videoWidth, h = qrVideo.videoHeight;
    if (!w || !h) return;
    qrCanvas.width = w; qrCanvas.height = h;
    qrCtx.drawImage(qrVideo, 0, 0, w, h);
    const imgData = qrCtx.getImageData(0, 0, w, h);
    const code = jsQR(imgData.data, w, h);
    if (code && code.data) {
      handleQRResult(code.data);
    }
  }

  // 扫到码后的统一处理（摄像头和上传共用）
  function handleQRResult(uri) {
    stopCamera();
    $("f-uri").value = uri;
    // 解析失败时错误显示在 qr tab（用户当前所在 tab），而非 uri tab
    parseURI(uri, "qr");
  }

  // 上传图片扫码（保留原有功能）
  $("f-qr").addEventListener("change", async (e) => {
    hideError("qr");
    const file = e.target.files[0];
    if (!file) return;
    try {
      const uri = await decodeQRFile(file);
      handleQRResult(uri);
    } catch (err) {
      showError("qr", "无法识别二维码：" + err.message);
    } finally {
      e.target.value = "";
    }
  });

  function decodeQRFile(file) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        const cv = document.createElement("canvas");
        cv.width = img.naturalWidth; cv.height = img.naturalHeight;
        const ctx = cv.getContext("2d");
        ctx.drawImage(img, 0, 0);
        const imgData = ctx.getImageData(0, 0, cv.width, cv.height);
        const code = jsQR(imgData.data, cv.width, cv.height);
        if (code && code.data) resolve(code.data);
        else reject(new Error("图片中未找到二维码"));
      };
      img.onerror = () => reject(new Error("图片加载失败"));
      img.src = URL.createObjectURL(file);
    });
  }

  // ---- 提交表单（新增/编辑）----
  $("account-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const body = {
      issuer: $("f-issuer").value.trim(),
      label: $("f-label").value.trim(),
      secret: $("f-secret").value.trim(),
      digits: parseInt($("f-digits").value, 10) || 6,
      period: parseInt($("f-period").value, 10) || 30,
      algorithm: $("f-algo").value,
    };
    try {
      if (editingId) {
        await api("/api/accounts/" + encodeURIComponent(editingId), { method: "PUT", body });
        toast("已更新");
      } else {
        await api("/api/accounts", { method: "POST", body });
        toast("已添加");
      }
      closeModal();
      await refreshAccounts();
    } catch (err) {
      toast("保存失败：" + err.message, "error");
    }
  });

  // ---- 删除 ----
  async function del(a) {
    const name = a.issuer || a.label || "此账户";
    if (!confirm("确定删除「" + name + "」吗？此操作不可恢复。")) return;
    try {
      await api("/api/accounts/" + encodeURIComponent(a.id), { method: "DELETE" });
      toast("已删除");
      await refreshAccounts();
    } catch (err) {
      toast("删除失败：" + err.message, "error");
    }
  }

  // ---- 导出 ----
  $("btn-export").addEventListener("click", async () => {
    if (!confirm("导出将把所有密钥以明文下载。请妥善保管此文件。继续？")) return;
    try {
      const r = await api("/api/export");
      const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "bao-auth-backup-" + new Date().toISOString().slice(0, 10) + ".json";
      a.click();
      URL.revokeObjectURL(url);
      toast("已导出");
    } catch (err) {
      toast("导出失败：" + err.message, "error");
    }
  });

  // ---- 导入 ----
  // 用一个隐藏的 file input 触发文件选择，避免污染顶栏布局。
  const importInput = document.createElement("input");
  importInput.type = "file";
  importInput.accept = ".json,application/json";
  importInput.style.display = "none";
  document.body.appendChild(importInput);

  $("btn-import").addEventListener("click", () => importInput.click());

  importInput.addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    e.target.value = ""; // 允许重复选同一文件
    try {
      const text = await file.text();
      // 先本地解析做预览，让用户确认数量
      const parsed = JSON.parse(text);
      const accs = Array.isArray(parsed) ? parsed
        : (Array.isArray(parsed.accounts) ? parsed.accounts
        : (parsed.secret ? [parsed] : []));
      if (accs.length === 0) {
        toast("文件中未找到账户", "error");
        return;
      }
      if (!confirm("即将导入 " + accs.length + " 个账户。继续？")) return;
      const r = await api("/api/import", { method: "POST", body: parsed });
      const msg = "导入完成：成功 " + r.imported + " 个" + (r.skipped ? "，跳过 " + r.skipped + " 个" : "");
      toast(msg, r.skipped ? "error" : "success");
      await refreshAccounts();
    } catch (err) {
      toast("导入失败：" + err.message, "error");
    }
  });

  // ---- 启动 ----
  boot();
})();
