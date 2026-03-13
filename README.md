# vCenter Dashboard v1.4

以 **NiceGUI** + **pyVmomi** 建立的 vCenter 監控儀表板，透過瀏覽器即可檢視多台 vCenter 的運算、儲存、網路與 VM 總覽資訊，無需安裝任何用戶端軟體。

## 功能

### 四大頁籤

| 頁籤 | 說明 |
|------|------|
| 運算 (Compute) | 以 ESXi 主機為單位，呈現 CPU / 記憶體使用率及主機資訊（型號、處理器、邏輯核心、運作時間），並列出各主機所屬 VM；CPU 或記憶體超過 80% 時卡片邊框閃爍警示 |
| 儲存 (Storage) | 依 Datastore 分組，標題顯示已用 / 上限容量；顯示 VM 已用 / 佈建容量及所屬 VMDK |
| 網路 (Network) | 依 Network Group (Port Group) 分組，顯示每台 VM 在該網路的 IP；開機中的 VM 優先排列 |
| VM 總覽 | 所有 VM 的一覽表，含電源狀態、IP、Network Group、主機、儲存區、來源 vCenter；VM 名稱欄位固定寬度，過長以 … 截斷 |

### VM 詳細資訊

- 每張 NIC 的介面類型（VMXNET 3 / E1000e 等）、MAC 位址、所屬網路、IP 清單
- DirectPath I/O（SR-IOV）狀態
- 滑鼠懸停 VM 名稱可查看 NIC 詳細 tooltip

### 搜尋

- 四個頁籤均提供即時搜尋，支援模糊比對
- 搜尋結果以黃底 highlight 標示匹配關鍵字
- 搜尋輸入採 debounce 設計，避免每次按鍵觸發大量 DOM 更新

### VM 總覽表格

- 多筆 IP / Network Group / 儲存區逐行分開顯示
- 支援每頁 20 / 100 / 全部筆數切換
- 欄位可排序
- 一鍵匯出 CSV（UTF-8 BOM，Excel 可直接開啟）

### 其他

- 支援同時連接多台 vCenter，資料自動合併顯示
- 背景定時更新，原地更新 DOM 不干擾使用者操作
- AD（NTLM）驗證登入
- Session 過期自動重連

## 安裝

需要 Python 3.10+。

```bash
pip install -r requirements.txt
```

## 執行

```bash
python main_light.py
```

啟動後瀏覽器開啟 `http://localhost:8082`。

預設登入帳號：`admin`，密碼：`admin`。

## 設定

vCenter 連線資訊儲存於 `config.json`（由介面操作自動寫入，勿將帳密寫入原始碼或提交至版控）。

## 版本記錄

| 版本 | 主要變更 |
|------|----------|
| v1.4 | 儲存頁籤容量改以百分比進度條顯示（仿運算頁籤樣式）、使用率 ≥ 80% 閃爍警示、修復瀏覽器斷線後 timer 持續觸發錯誤 |
| v1.3 | 運算卡片主機資訊（型號 / 處理器類型 / 邏輯核心 / 運作時間）、CPU/RAM ≥ 80% 閃爍警示、儲存卡片容量顯示、網路頁籤開機優先排序、VM 名稱欄位固定寬截斷 |
| v1.2 | 全欄搜尋 highlight、VM 總覽多值欄位換行、DirectPath I/O 修正、搜尋 debounce 效能優化 |
| v1.1 | 每張 NIC IP 顯示、CSV 匯出 |
| v1.0 | 新增驗證頁、AD 帳密驗證 |
| v0.3 | 背景原地更新 |
| v0.2 | 多 vCenter 支援 |
| v0.1 | 初始版本，運算 / 儲存 / 網路 / VM 總覽四頁籤 |
