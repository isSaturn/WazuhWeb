using System;
using System.Collections.Generic;
using System.Text;

namespace WazuhWeb.Helpers
{
    public static class SecurityPrompts
    {
        // =========================================================
        // GLOBAL PREAMBLE
        // =========================================================
        private const string Preamble =
@"Bạn là chuyên gia SOC/Blue Team, DFIR và Threat Hunting.

Nhiệm vụ:
- Phân tích TOÀN BỘ dữ liệu JSON được cung cấp.
- KHÔNG bỏ sót lỗi/phát hiện nào.
- KHÔNG chỉ phân tích top lỗi.
- Nếu có 100 lỗi thì phải phân tích đầy đủ 100 lỗi.
- Gộp các lỗi giống nhau thành nhóm để tránh lặp nội dung.
- Phải ghi rõ máy nào bị ảnh hưởng.
- Nếu nhiều máy cùng lỗi thì liệt kê đầy đủ danh sách máy.

QUY TẮC QUAN TRỌNG:
- Toàn bộ IP private/internal:
  + 10.x.x.x
  + 172.16.x.x → 172.31.x.x
  + 192.168.x.x
là hạ tầng nội bộ hợp lệ.

- KHÔNG đánh dấu private IP là bất thường.
- Chỉ cảnh báo IP public hoặc kết nối đáng ngờ nếu thật sự nguy hiểm.
- Không viết lý thuyết dài dòng.
- Không giải thích lan man.
- Tập trung IOC, persistence, malware, privilege escalation,
  lateral movement, suspicious process, rootkit,
  CIS failed, file integrity, defense evasion.

Output phải là Markdown rõ ràng.
";

        // =========================================================
        // GENERIC SECURITY REPORT
        // =========================================================
        public static string GeneralSecurityReport(
            string json,
            string reportType = "Security Analysis",
            string dateFrom = null,
            string dateTo = null)
        {
            return Preamble + $@"

# PHÂN TÍCH BẢO MẬT HỆ THỐNG — {reportType.ToUpper()}

{(string.IsNullOrWhiteSpace(dateFrom)
? ""
: $"Khoảng thời gian: {dateFrom} → {dateTo}")}

DỮ LIỆU JSON:

```json
{json}

YÊU CẦU PHÂN TÍCH:

Tổng quan hệ thống
Tổng số phát hiện
Tổng số máy bị ảnh hưởng
Các nhóm lỗi chính
Mức độ rủi ro toàn hệ thống:
THẤP
TRUNG BÌNH
CAO
NGHIÊM TRỌNG
Thống kê theo nhóm lỗi
Nhóm lỗi Số lượng Máy bị ảnh hưởng Mức độ
Phân tích chi tiết TẤT CẢ phát hiện

[Tên nhóm lỗi]

Máy bị ảnh hưởng
Hostname — IP — Agent ID

Phát hiện
Liệt kê đầy đủ tất cả event/log liên quan
Không bỏ sót dữ liệu quan trọng

IOC
Process
File
Registry
Service
Scheduled Task
IP
Domain
Command line
Hash

Đánh giá
Nguyên nhân có thể
Mức độ nguy hiểm
Có dấu hiệu compromise không
Có khả năng malware/persistence/lateral movement không

Khuyến nghị xử lý
Hành động cụ thể
Không viết chung chung

Các máy cần ưu tiên xử lý
Máy Lý do Mức độ
Kết luận
Tóm tắt nguy cơ chính

Những vấn đề cần xử lý ngay
";
        }

        // =========================================================
        // AGENTS REPORT
        // =========================================================
        public static string AgentsReport(string json)
        {
            return Preamble + $@"

PHÂN TÍCH AGENTS WAZUH

{json}
Tổng quan
Tổng số agents
Active / Disconnected / Never connected
Phân loại OS
Phiên bản Wazuh
Danh sách toàn bộ agents
Agent ID Hostname IP OS Version Status
Agents có vấn đề
Offline lâu
Không có group
Phiên bản cũ
Không gửi log
Agent lỗi
Nhóm lỗi chung
Gộp các agents có cùng vấn đề
Đánh giá rủi ro
THẤP / TRUNG BÌNH / CAO / NGHIÊM TRỌNG

Khuyến nghị
Hành động cụ thể cho từng nhóm lỗi
";
        }

        // =========================================================
        // SYSCHECK
        // =========================================================
        public static string SyscheckReport(
            string agentId,
            string json,
            string dateFrom = null,
            string dateTo = null)
        {
            return Preamble + $@"

PHÂN TÍCH FILE INTEGRITY — AGENT {agentId}

{(string.IsNullOrWhiteSpace(dateFrom)
       ? ""
       : $"Khoảng thời gian: {dateFrom} → {dateTo}")}

{json}
Tổng quan thay đổi
Tổng số file thay đổi
File nguy hiểm
Registry thay đổi
Toàn bộ thay đổi
Time File Action Suspicious
File đáng ngờ
exe/dll/ps1/bat/vbs
startup
run key
system32
temp
appdata
ADS
IOC
File
Hash
Process
Registry
User
Đánh giá
Persistence?
Malware?
Defense evasion?
Lateral movement?

Khuyến nghị xử lý
";
        }

        // =========================================================
        // ROOTCHECK
        // =========================================================
        public static string RootcheckReport(
            string agentId,
            string json,
            string dateFrom = null,
            string dateTo = null)
        {
            return Preamble + $@"

PHÂN TÍCH ROOTCHECK — AGENT {agentId}

{(string.IsNullOrWhiteSpace(dateFrom)
       ? ""
       : $"Khoảng thời gian: {dateFrom} → {dateTo}")}

{json}
Executive Summary
Có dấu hiệu compromise không
Có cần isolate máy không
TẤT CẢ phát hiện
Time Type Description Severity
Phân tích nguy cơ
Rootkit
Hidden process
Hidden port
Trojan
Persistence
Defense evasion
Privilege escalation
IOC
Type Value Risk
Đánh giá tổng thể
THẤP / TRUNG BÌNH / CAO / NGHIÊM TRỌNG

Hướng xử lý IR
Containment
Eradication
Recovery
";
        }

        // =========================================================
        // SCA REPORT
        // =========================================================
        public static string ScaReport(
            string agentId,
            string policyJson,
            string failedJson,
            string dateFrom = null,
            string dateTo = null)
        {
            return Preamble + $@"

PHÂN TÍCH SCA/CIS — AGENT {agentId}

{(string.IsNullOrWhiteSpace(dateFrom)
       ? ""
       : $"Khoảng thời gian: {dateFrom} → {dateTo}")}

POLICY:

{policyJson}

FAILED CHECKS:

{failedJson}
Tổng quan tuân thủ
Pass Fail Score
TẤT CẢ failed checks
CIS ID Description Risk Fix
Phân nhóm lỗi
Password Policy
Firewall
Defender
Audit
Logging
Account Lockout
Privilege
RDP
SMB
Các cấu hình nguy hiểm
Anonymous access
SMBv1
Weak password policy
Defender disabled
Firewall disabled

Khuyến nghị hardening
Ghi rõ lệnh hoặc cấu hình cụ thể
";
        }

        // =========================================================
        // BATCH REPORT
        // =========================================================
        public static string AgentBatchReport(
            List<(string agentId, string agentName, string json)> batch,
            int batchNum,
            int totalBatches,
            string reportType)
        {
            return Preamble + $@"

PHÂN TÍCH BATCH {batchNum}/{totalBatches}

Loại: {reportType}

YÊU CẦU:

Phân tích đầy đủ tất cả lỗi.
Gộp lỗi giống nhau.
Ghi rõ máy ảnh hưởng.

Không bỏ sót IOC.
";
        }

        // =========================================================
        // MERGE REPORT
        // =========================================================
        public static string MergeBatchResults(
            string reportType,
            int totalAgents,
            List<string> batchReports,
            string dateFrom,
            string dateTo)
        {
            return Preamble + $@"

TỔNG HỢP BÁO CÁO — {reportType.ToUpper()}

Tổng agents: {totalAgents}

{(string.IsNullOrWhiteSpace(dateFrom)
    ? ""
    : $"Khoảng thời gian: {dateFrom} → {dateTo}")}

YÊU CẦU:

Bảng tổng hợp toàn bộ agents
Agent Vấn đề Risk
Gộp lỗi chung
Các máy cùng lỗi
Các pattern lặp lại
Root cause
IOC tổng hợp toàn hệ thống
Các máy nguy hiểm nhất
Liệt kê đầy đủ

Kế hoạch xử lý ưu tiên
Priority Action Agents
";
        }

        

    }
}