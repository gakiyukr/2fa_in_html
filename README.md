# 本地 2FA 驗證器

一個純前端的 TOTP (Time-based One-Time Password) 驗證器，直接在瀏覽器中運行，無需伺服器或網路連線。

## 功能

- 輸入 Base32 祕鑰即時產生 TOTP 驗證碼
- 支援 6 位 / 8 位驗證碼
- 支援 30 秒 / 60 秒週期
- 可設定允許誤差步數 (±1 / ±2)
- 一鍵複製驗證碼到剪貼簿
- 驗證輸入的代碼是否正確
- 進度條顯示剩餘有效時間
- 支援透過 URL 路徑傳入祕鑰 (例如 `index.html/JBSWY3DPEHPK3PXP`)

## 使用方式

1. 用瀏覽器直接開啟 `index.html`
2. 在「Base32 祕鑰」欄位貼上你的 TOTP 祕鑰
3. 驗證碼會即時顯示並每秒更新
4. 點擊 📋 按鈕可複製驗證碼
5. 可在「要驗證的代碼」欄位輸入代碼進行比對驗證

## 技術細節

- 使用 Web Crypto API (HMAC-SHA1) 計算 TOTP
- 所有計算在瀏覽器本地完成，不發送任何網路請求
- 相容所有支援 Web Crypto 的現代瀏覽器
- 無任何外部依賴

## 檔案結構

```
index.html  — 主頁面
app.js      — TOTP 計算與 UI 邏輯
style.css   — 樣式
README.md   — 本文件
```

## 授權

MIT
