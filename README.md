# ☁️ LX IMG (零星图床)

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange?logo=cloudflare)](https://workers.cloudflare.com/)
[![Cloudflare R2](https://img.shields.io/badge/Cloudflare-R2-yellow?logo=cloudflare)](https://www.cloudflare.com/products/r2/)
[![Cloudflare D1](https://img.shields.io/badge/Cloudflare-D1-blue?logo=cloudflare)](https://www.cloudflare.com/developer-platform/d1/)
[![License](https://img.shields.io/github/license/gzy318/lx_img)](https://github.com/gzy318/lx_img/blob/main/LICENSE)

**Zero Star Host (零星图床)** 是一个基于 Cloudflare 全家桶（Workers + Pages + R2 + D1）构建的现代化、Serverless 极速图床。

它不仅仅是一个图片存储工具，更集成了 **AI 辅助功能**、**隐私保护**、**极速秒传**以及**强大的后台管理**系统。无需服务器，免费额度足够个人及小型团队使用。

🔗 **项目仓库**: [https://github.com/gzy318/lx_img](https://github.com/gzy318/lx_img)
🔗 **演示网站**: [https://img.gzy.wang](https://img.gzy.wang/)

---

## ✨ 功能特性 (Features)

### 🚀 极致性能与体验
*   **⚡ 极速秒传**：基于 SHA-256 哈希去重，重复图片瞬间返回，不消耗存储与流量。
*   **📉 智能压缩**：支持上传前自动压缩（Browser-image-compression），大幅节省带宽。
*   **🖼️ WebP 转换**：可选自动转换为 WebP 格式，体积减少 50% 以上。
*   **🕒 本地历史记录**：侧边栏自动保存上传历史，防丢失，无需登录即可查看。

### 🛡️ 安全与隐私
*   **🕵️ 隐私保护**：支持上传时自动抹除 Exif 信息（GPS、相机参数）。
*   **🔥 阅后即焚**：支持设置图片过期时间（1小时/1天/7天），到期自动销毁。
*   **🔒 防盗链 (Hotlink Protection)**：支持设置 Referer 白名单，防止流量被盗用。
*   **🚫 IP 黑名单**：后台一键封禁恶意 IP，支持解封。
*   **🚧 维护模式**：一键开启维护模式，暂停游客上传，仅管理员可用。

### 🎨 图像处理与 AI 工具箱
*   **💧 前端水印**：支持上传前添加自定义文字水印（Canvas 绘制）。
*   **🎨 实时滤镜**：内置黑白、复古、反色等滤镜，上传即生效。
*   **📝 OCR 文字识别**：集成 Tesseract.js，一键提取图片中的文字。
*   **🌈 色彩分析**：智能分析图片主色调，生成 HEX 色板。

### ⚙️ 强大的管理后台
*   **👤 身份管理**：游客可用（受限额控制），管理员凭 Token 无限上传。
*   **📊 可视化管理**：网格/列表视图切换，支持按文件名、大小、时间排序。
*   **📦 批量操作**：支持批量删除、批量导出 Markdown/URL 链接。
*   **📈 动态限额**：后台实时调整每日上传张数和流量限制。
*   **📢 全站公告**：支持自定义 HTML 公告，实时推送到首页。
*   **🛠️ 外部工具支持**：一键生成 **ShareX** / **PicGo** 配置文件。

---

## 🛠️ 技术栈 (Tech Stack)

*   **Frontend**: HTML5, Tailwind CSS, Alpine.js (单文件纯静态，极速加载)
*   **Backend**: Cloudflare Workers (处理核心逻辑)
*   **Database**: Cloudflare D1 (SQLite 边缘数据库，存储元数据与配置)
*   **Storage**: Cloudflare R2 (对象存储，存储实际图片文件)

---

## 🚀 部署指南 (Deployment)

### 1. 准备工作
你需要一个 [Cloudflare](https://dash.cloudflare.com/) 账号。

### 2. 创建资源
在 Cloudflare Dashboard 中创建以下资源：
*   **R2 Bucket**: 命名为 `my-img-bucket` (自定义)。
*   **D1 Database**: 命名为 `my-img-db`。

### 3. 初始化数据库
进入 D1 数据库的控制台 (Console)，执行以下 SQL 语句初始化表结构：

```sql
-- 1. 图片元数据表
CREATE TABLE IF NOT EXISTS images (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL,
  filename TEXT,
  url TEXT,
  size INTEGER,
  created_at INTEGER,
  ip TEXT,
  expire_at INTEGER,
  hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_images_hash ON images(hash);

-- 2. 每日统计表
CREATE TABLE IF NOT EXISTS daily_stats (
  date TEXT PRIMARY KEY, 
  count INTEGER DEFAULT 0, 
  size INTEGER DEFAULT 0
);

-- 3. 系统设置表
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY, 
  value TEXT
);

-- 4. IP 黑名单表
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    created_at INTEGER
);

-- 5. 写入默认配置
INSERT OR IGNORE INTO settings (key, value) VALUES ('limit_count', '50');
INSERT OR IGNORE INTO settings (key, value) VALUES ('limit_size', '50');
INSERT OR IGNORE INTO settings (key, value) VALUES ('compress_limit', '2');
INSERT OR IGNORE INTO settings (key, value) VALUES ('allowed_referers', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('announcement', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('maintenance_mode', 'false');
```

### 4. 部署后端 (Worker)
1.  创建一个新的 Cloudflare Worker。
2.  将项目中的 `worker.js` 代码复制进去。
3.  在 Worker 的 **Settings -> Variables** 中配置：
    *   **Environment Variables**: 添加 `ADMIN_TOKEN`，值为你的管理员密码。
    *   **R2 Bucket Bindings**: 变量名 `MY_BUCKET`，绑定你创建的 R2 存储桶。
    *   **D1 Database Bindings**: 变量名 `DB`，绑定你创建的 D1 数据库。
4.  点击 **Deploy**。

### 5. 部署前端 (Pages)
1.  下载本项目中的 `index.html`。
2.  修改代码中的 `API_BASE` 常量为你 Worker 的域名：
    ```javascript
    const API_BASE = 'https://你的Worker域名.workers.dev';
    ```
3.  创建一个 Cloudflare Pages 项目。
4.  直接上传包含 `index.html` 的文件夹即可。

---

## 📖 使用说明 (Usage)

### 👤 游客模式
*   直接拖拽或点击上传图片。
*   可在下方工具栏开启“压缩”、“转WebP”、“水印”或“隐私去除”。
*   上传成功后会自动显示链接、Markdown 和二维码。

### 👑 管理员模式
1.  点击右上角的 **“管理”** 按钮。
2.  输入在 Worker 环境变量中设置的 `ADMIN_TOKEN`。
3.  进入后台后，可以：
    *   **图片管理**：查看、搜索、批量删除、批量导出链接。
    *   **IP 管理**：查看封禁列表，解封误杀 IP。
    *   **系统设置**：调整限额、发布公告、开启维护模式、设置防盗链。
    *   **工具**：下载 ShareX 配置文件。

---

## 🤝 贡献 (Contributing)

非常欢迎对本项目感兴趣的开发者参与贡献！无论是修复 Bug、提交新功能，还是完善文档，我们都非常感谢。

**项目官方仓库**：[https://github.com/gzy318/img](https://github.com/gzy318/img)

### 如何参与贡献：

1.  **Fork 本仓库**
    点击 GitHub 页面右上角的 "Fork" 按钮，将项目复制到你自己的 GitHub 账户中。

2.  **克隆到本地**
    ```bash
    git clone https://github.com/gzy318/img.git
    cd img
    ```

3.  **创建新分支**
    建议为你开发的每个新功能或 Bug 修复创建一个独立分支：
    ```bash
    git checkout -b feature/AmazingFeature
    ```

4.  **提交更改**
    ```bash
    git commit -m 'Add some AmazingFeature'
    ```

5.  **推送到远程分支**
    ```bash
    git push origin feature/AmazingFeature
    ```

6.  **提交 Pull Request**
    回到 GitHub 页面，点击 "New Pull Request" 按钮提交你的更改，我们会尽快审核！

---

## 📄 开源协议 (License)

[![License](https://img.shields.io/github/license/gzy318/lx_img)](https://github.com/gzy318/lx_img/blob/main/LICENSE)

