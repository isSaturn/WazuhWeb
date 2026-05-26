using System;
using System.Collections.Generic;

namespace WazuhWeb.Helpers
{
    /// <summary>
    /// Prompt templates cho phân tích JSON → báo cáo Markdown (SOC/DFIR).
    /// Mỗi prompt mô tả rõ schema JSON đầu vào và cấu trúc báo cáo đầu ra.
    /// </summary>
    public static class SecurityPrompts
    {
        // =========================================================
        // CORE — vai trò & quy tắc chung
        // =========================================================
        private const string Role =
@"Bạn là chuyên gia SOC / Blue Team / DFIR, nhiệm vụ biên soạn **báo cáo an toàn thông tin** từ dữ liệu JSON.

## Nguyên tắc bắt buộc
1. **Chỉ dùng dữ liệu trong JSON** — không bịa agent, IP, file, lỗi, phiên bản, hoặc sự kiện không có trong JSON.
2. Nếu JSON thiếu trường (ví dụ: không có phiên bản Wazuh, không có danh sách agent active chi tiết) → ghi rõ *""Không có trong dữ liệu""* — **không suy đoán**.
3. Phân tích **100% bản ghi** trong JSON; có thể **gộp nhóm** lỗi giống nhau nhưng phải liệt kê **đủ** máy/agent trong nhóm.
4. Mỗi phát hiện / agent có vấn đề: ghi **Agent ID — Hostname — IP** (nếu có trong JSON).
5. Viết **tiếng Việt**, Markdown rõ ràng, súc tích — **không** lý thuyết dài, **không** lặp ý.

## IP nội bộ (không coi là IOC)
- 10.0.0.0/8, 172.16.0.0–172.31.255.255, 192.168.0.0/16
- Dải nội bộ tổ chức (ví dụ 172.0.x.x trong JSON) → hợp lệ, **không** cảnh báo chỉ vì là IP private.

## Trọng tâm phân tích bảo mật
IOC, persistence, malware, privilege escalation, lateral movement, process/file/registry đáng ngờ, rootkit, CIS/SCA fail, file integrity, defense evasion — **chỉ khi có căn cứ trong JSON**.
";

        private const string OutputFormat =
@"
## Định dạng đầu ra
- Bắt đầu bằng tiêu đề `#` cấp 1.
- Dùng bảng Markdown khi liệt kê nhiều dòng (agent, phát hiện, IOC).
- Mức rủi ro: **THẤP** | **TRUNG BÌNH** | **CAO** | **NGHIÊM TRỌNG** (in đậm).
- Kết thúc bằng mục **Kết luận** và **Khuyến nghị ưu tiên** (hành động cụ thể, có thể gán P1/P2/P3).
";

        private static string WrapJson(string json)
        {
            return $@"
## Dữ liệu đầu vào (JSON)

```json
{json}
```
";
        }

        // =========================================================
        // AGENTS — fleet snapshot; có thể lọc disconnected theo lastKeepAlive
        // =========================================================
        public static string AgentsReport(
            string json,
            string dateFrom = null,
            string dateTo = null,
            bool filterApplied = false)
        {
            if (filterApplied)
            {
                return Role + $@"

# BÁO CÁO AGENTS WAZUH — THEO KHOẢNG THỜI GIAN

## Phạm vi dữ liệu
- **Chế độ:** `date_filtered`
- **Khoảng:** **{dateFrom}** → **{dateTo}** (trường `lastKeepAlive`)
- JSON **chỉ** chứa agent trong khoảng — **KHÔNG** có Total/Active/Disconnected toàn fleet, **KHÔNG** có `HealthyActiveGroups`.
- Số liệu thống kê **chỉ** lấy từ `Summary.AgentsInScope` và mảng `UnhealthyOrOfflineAgents`.
- **Cấm** nhắc tới 148 agents, 132 active, 16 disconnected hoặc bất kỳ con số nào không có trong JSON.

## Cấu trúc JSON

| Khóa | Ý nghĩa |
|------|---------|
| `ReportScope` | Phạm vi lọc |
| `Summary` | `AgentsInScope`, `DateFrom`, `DateTo` |
| `UnhealthyOrOfflineAgents` | Toàn bộ agent cần phân tích (đã lọc) |

" + WrapJson(json) + @"

## Viết báo cáo (chỉ trong phạm vi JSON)

### 1. Tóm tắt điều hành
3–5 câu: khoảng ngày, `Summary.AgentsInScope`, rủi ro chính **trong phạm vi**. Nếu `AgentsInScope` = 0 → ""Không có agent lỗi trong khoảng thời gian"".

### 2. Thống kê trong phạm vi
| Chỉ số | Giá trị |
| Khoảng ngày | từ Summary |
| Số agent cần xem xét | Summary.AgentsInScope |

### 3. Chi tiết 100% agent (`UnhealthyOrOfflineAgents`)
Bảng đủ từng dòng: Agent ID | Hostname | IP | Trạng thái | OS | Last Keep Alive | Đánh giá

### 4. Rủi ro & khuyến nghị
Mức độ **THẤP/TRUNG BÌNH/CAO/NGHIÊM TRỌNG** + bảng P1/P2/P3 chỉ cho agent trong JSON.

### 5. Kết luận

" + OutputFormat;
            }

            return Role + @"

# BÁO CÁO GIÁM SÁT AGENTS WAZUH — TOÀN FLEET

## Phạm vi dữ liệu
- **Chế độ:** `full_snapshot` — không lọc theo ngày.
- JSON gồm `FleetSummary`, `HealthyActiveGroups`, `UnhealthyOrOfflineAgents`.

## Cấu trúc JSON

| Khóa | Ý nghĩa |
|------|---------|
| `FleetSummary` | Total, Active, Disconnected, NeverConnected |
| `HealthyActiveGroups` | Nhóm OS (active), không liệt kê từng máy |
| `UnhealthyOrOfflineAgents` | Tất cả agent không active |

" + WrapJson(json) + @"

## Viết báo cáo

### 1. Tóm tắt điều hành
### 2. Thống kê (`FleetSummary` + % disconnected)
### 3. Phân bố OS (`HealthyActiveGroups`)
### 4. Bảng đủ mọi `UnhealthyOrOfflineAgents`
### 5. Rủi ro & khuyến nghị P1/P2/P3
### 6. Kết luận

" + OutputFormat;
        }

        // =========================================================
        // SYSCHECK / ROOTCHECK / SCA — mảng phát hiện (có thể lọc ngày)
        // =========================================================
        public static string GeneralSecurityReport(
            string json,
            string reportType = "Security Analysis",
            string dateFrom = null,
            string dateTo = null,
            string dateFieldDescription = "timestamp sự kiện",
            bool filterApplied = false)
        {
            var dateScope = DateRangeHelper.BuildDateScope(
                reportType, dateFrom, dateTo, dateFieldDescription, filterApplied);

            var schemaHint = GetSchemaHint(reportType, filterApplied);
            var statsRule = filterApplied
                ? "**Thống kê:** chỉ dùng `Summary.TotalRecords` và `Summary.AgentsAffected` — **cấm** ước lượng tổng phát hiện toàn hệ thống ngoài JSON."
                : "**Thống kê:** đếm từ toàn bộ phần tử trong mảng JSON.";

            return Role + $@"

# BÁO CÁO BẢO MẬT — {reportType.ToUpperInvariant()}

## Phạm vi dữ liệu
{dateScope}

{statsRule}

{schemaHint}

" + WrapJson(json) + @"

## Yêu cầu — viết báo cáo theo đúng các mục sau

### 1. Tóm tắt điều hành
Số phát hiện **trong JSON**, số agent bị ảnh hưởng **trong JSON**, 3 rủi ro chính. Nếu không có bản ghi → ""Không có phát hiện trong phạm vi"".

### 2. Thống kê (chỉ từ JSON)
| Chỉ số | Giá trị |
| Tổng bản ghi | Summary hoặc đếm mảng |
| Số agent (AgentId) | Summary hoặc đếm distinct |
| Nhóm phát hiện chính | tên nhóm · số lượng · số agent |

### 3. Phân tích chi tiết theo nhóm
Với mỗi nhóm lỗi/pattern (gộp log/path/policy giống nhau):
- **Mô tả nhóm**
- **Mức độ:** THẤP / TRUNG BÌNH / CAO / NGHIÊM TRỌNG
- **Agents bị ảnh hưởng:** liệt kê đủ AgentId (và hostname nếu có trong JSON)
- **Chi tiết:** bảng hoặc danh sách từng bản ghi quan trọng (Path/Log/Policy, Date/DateLast/EndScan, ChangeType/Status/Score…)
- **IOC** (chỉ trích từ JSON: file path, registry, hash nếu có — không bịa)
- **Đánh giá:** compromise? malware/persistence? — có căn cứ hoặc ghi ""chưa đủ dữ liệu""

### 4. Ma trận ưu tiên xử lý
| Ưu tiên | Agent / nhóm | Lý do | Hành động đề xuất |

### 5. Kết luận & khuyến nghị
Rủi ro tổng thể + việc cần làm ngay (P1).

" + OutputFormat;
        }

        private static string GetSchemaHint(string reportType, bool filterApplied)
        {
            var recordsKey = filterApplied
                ? "Phân tích từng phần tử trong `Records`."
                : "Phân tích từng phần tử trong mảng JSON.";

            if (reportType.IndexOf("Syscheck", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                var wrap = filterApplied
                    ? "## Schema JSON\n| Khóa | Ý nghĩa |\n| `Summary` | TotalRecords, AgentsAffected, DateFrom, DateTo |\n| `Records` | Danh sách thay đổi đã lọc |\n\n"
                    : "## Schema JSON (mảng)\n";

                return wrap + @"| Trường (mỗi bản ghi) | Ý nghĩa |
| `AgentId` | Mã agent |
| `Path` | File/registry |
| `Date` | Thời điểm thay đổi |
| `ChangeType` | added/modified / deleted |
| `RegistryValue` | Registry (nếu có) |

" + recordsKey + " Tập trung: exe/dll/ps1, startup, Run key, persistence.";
            }

            if (reportType.IndexOf("Rootcheck", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                var wrap = filterApplied
                    ? "## Schema JSON\n| `Summary` | TotalRecords, AgentsAffected |\n| `Records` | Phát hiện đã lọc |\n\n"
                    : "## Schema JSON (mảng)\n";

                return wrap + @"| Trường | Ý nghĩa |
| `AgentId` | Mã agent |
| `Log` | Nội dung phát hiện |
| `Status` | Trạng thái |
| `DateLast` | Lần phát hiện gần nhất |

" + recordsKey;
            }

            if (reportType.IndexOf("SCA", StringComparison.OrdinalIgnoreCase) >= 0
                || reportType.IndexOf("CIS", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                var wrap = filterApplied
                    ? "## Schema JSON\n| `Summary` | TotalRecords, AgentsAffected |\n| `Records` | Policy vi phạm đã lọc |\n\n"
                    : "## Schema JSON (mảng)\n";

                return wrap + @"| Trường | Ý nghĩa |
| `AgentId` | Mã agent |
| `PolicyId`, `Name` | Policy SCA |
| `Score`, `Pass`, `Fail` | Điểm |
| `EndScan` | Thời điểm quét |

" + recordsKey + " Không bịa chi tiết CIS check ID.";
            }

            return "## Schema JSON\n" + recordsKey;
        }

        // =========================================================
        // SYSCHECK — một agent (nếu dùng sau này)
        // =========================================================
        public static string SyscheckReport(
            string agentId,
            string json,
            string dateFrom = null,
            string dateTo = null,
            bool filterApplied = false)
        {
            var dateScope = DateRangeHelper.BuildDateScope(
                $"Syscheck — Agent {agentId}",
                dateFrom,
                dateTo,
                "trường date",
                filterApplied);

            return Role + $@"

# BÁO CÁO FILE INTEGRITY — AGENT {agentId}

## Phạm vi
{dateScope}

" + WrapJson(json) + @"

Viết báo cáo: Executive Summary → bảng thay đổi (Time | Path | ChangeType | Đánh giá) → file/registry đáng ngờ → IOC → khuyến nghị P1/P2.

" + OutputFormat;
        }

        // =========================================================
        // ROOTCHECK — một agent
        // =========================================================
        public static string RootcheckReport(
            string agentId,
            string json,
            string dateFrom = null,
            string dateTo = null,
            bool filterApplied = false)
        {
            var dateScope = DateRangeHelper.BuildDateScope(
                $"Rootcheck — Agent {agentId}",
                dateFrom,
                dateTo,
                "trường date_last",
                filterApplied);

            return Role + $@"

# BÁO CÁO ROOTCHECK — AGENT {agentId}

## Phạm vi
{dateScope}

" + WrapJson(json) + @"

Viết báo cáo: Executive Summary (có cần isolate?) → bảng đủ mọi phát hiện (DateLast | Status | Log | Mức độ) → IOC → IR (Containment / Eradication / Recovery).

" + OutputFormat;
        }

        // =========================================================
        // SCA — một agent
        // =========================================================
        public static string ScaReport(
            string agentId,
            string policyJson,
            string failedJson,
            string dateFrom = null,
            string dateTo = null,
            bool filterApplied = false)
        {
            var dateScope = DateRangeHelper.BuildDateScope(
                $"SCA/CIS — Agent {agentId}",
                dateFrom,
                dateTo,
                "trường end_scan",
                filterApplied);

            return Role + $@"

# BÁO CÁO TUÂN THỦ SCA/CIS — AGENT {agentId}

## Phạm vi
{dateScope}

## Policy (JSON)
```json
{policyJson}
```

## Failed checks (JSON)
```json
{failedJson}
```

Viết báo cáo: điểm Pass/Fail/Score → bảng **tất cả** failed checks (CIS ID nếu có | Mô tả | Risk | Khắc phục) → nhóm theo hạng mục (Firewall, Defender, Audit…) → lệnh/cấu hình khắc phục cụ thể.

" + OutputFormat;
        }

        // =========================================================
        // BATCH / MERGE (giữ API, prompt gọn)
        // =========================================================
        public static string AgentBatchReport(
            List<(string agentId, string agentName, string json)> batch,
            int batchNum,
            int totalBatches,
            string reportType)
        {
            var sb = new System.Text.StringBuilder();
            sb.Append(Role);
            sb.Append($@"

# PHÂN TÍCH BATCH {batchNum}/{totalBatches} — {reportType}

Phân tích từng khối JSON dưới đây, gộp lỗi giống nhau, liệt kê đủ agent. Đầu ra: Markdown báo cáo ngắn gọn.

");
            foreach (var item in batch)
            {
                sb.Append($"\n## Agent {item.agentId} — {item.agentName}\n");
                sb.Append(WrapJson(item.json));
            }
            sb.Append(OutputFormat);
            return sb.ToString();
        }

        public static string MergeBatchResults(
            string reportType,
            int totalAgents,
            List<string> batchReports,
            string dateFrom,
            string dateTo,
            string dateFieldDescription = "timestamp sự kiện",
            bool filterApplied = false)
        {
            var dateScope = DateRangeHelper.BuildDateScope(
                reportType, dateFrom, dateTo, dateFieldDescription, filterApplied);

            var combined = string.Join("\n\n---\n\n", batchReports);

            return Role + $@"

# TỔNG HỢP BÁO CÁO — {reportType.ToUpperInvariant()}

Tổng số agents trong hệ thống: {totalAgents}

## Phạm vi
{dateScope}

## Các báo cáo batch
{combined}

## Yêu cầu
Tổng hợp thành **một** báo cáo Markdown: bảng Agent | Vấn đề | Risk | pattern lặp | IOC chung | kế hoạch P1/P2/P3.

" + OutputFormat;
        }
    }
}
