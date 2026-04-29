# 本地 2FA 驗證器

一個純前端的 TOTP (Time-based One-Time Password) 驗證器，直接在瀏覽器中運行，無需伺服器或網路連線。所有計算使用 Web Crypto API 在本地完成。

## 功能

### 核心驗證
- 輸入 Base32 祕鑰即時產生 TOTP 驗證碼
- 支援 SHA-1 / SHA-256 / SHA-512 演算法
- 支援 6 位 / 8 位驗證碼
- 支援 30 秒 / 60 秒週期
- 可設定允許誤差步數（±1 / ±2）
- 進度條顯示剩餘有效時間
- 驗證輸入的代碼是否正確

### 多帳戶管理
- 儲存多組帳戶（名稱 + 祕鑰 + 個別參數配置）
- 歷史帳戶以標籤列表顯示，點擊即可快速切換
- 支援刪除帳戶
- 資料使用 localStorage 持久保存，不依賴 Cookie 或伺服器

### QR Code
- 產生：根據當前祕鑰產生 QR Code（純 JS 實現，無外部依賴）
- 掃描：使用攝像頭掃描 QR Code，自動解析 `otpauth://` URI
- 掃描功能需 HTTPS 或 localhost 環境

### 匯入匯出
- 支援 `otpauth://totp/...` URI 匯入，自動解析 issuer、帳戶名稱與參數
- 一鍵複製驗證碼到剪貼簿

## 使用方式

1. 用瀏覽器開啟 `index.html`（建議透過本地伺服器以使用 QR 掃描功能）
2. 在「Base32 祕鑰」欄位貼上你的 TOTP 祕鑰
3. 驗證碼會即時顯示並每秒更新
4. 點擊「儲存帳戶」可將當前配置存入歷史記錄
5. 點擊歷史標籤可快速切換帳戶

## 技術細節

- **TOTP 計算**：Web Crypto API（HMAC-SHA1/256/512）
- **QR 產生**：純 JavaScript 實現（含 Reed-Solomon 糾錯碼）
- **QR 掃描**：jsQR（透過 CDN 載入）
- **資料儲存**：localStorage，JSON 格式
- **UI 風格**：淺色毛玻璃（Glassmorphism）響應式設計
- 無框架依賴，可離線運作

## 檔案結構

```
index.html  — 主頁面
app.js      — TOTP 計算、帳戶管理、QR 編解碼、UI 邏輯
style.css   — 淺色毛玻璃主題樣式
README.md   — 本文件
```

## 授權

MIT
