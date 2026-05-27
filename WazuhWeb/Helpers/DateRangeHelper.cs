using System;
using System.Globalization;

namespace WazuhWeb.Helpers
{
    public static class DateRangeHelper
    {
        public static bool TryParseDate(string value, out DateTime date)
        {
            date = default;
            if (string.IsNullOrWhiteSpace(value))
                return false;

            return DateTime.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out date) 
                || DateTime.TryParse(value, out date);
        }

        public static bool IsInRange(string dateValue, string dateFrom, string dateTo)
        {
            if (!TryParseDate(dateValue, out var eventDate))
                return false;

            var day = eventDate.Date;

            if (!string.IsNullOrWhiteSpace(dateFrom) && TryParseDate(dateFrom, out var from))
            {
                if (day < from.Date)
                    return false;
            }

            if (!string.IsNullOrWhiteSpace(dateTo) && TryParseDate(dateTo, out var to))
            {
                if (day > to.Date)
                    return false;
            }

            return true;
        }

        public static bool HasFilter(string dateFrom, string dateTo)
        {
            return !string.IsNullOrWhiteSpace(dateFrom) || !string.IsNullOrWhiteSpace(dateTo);
        }

        public static string BuildDateScope(
            string reportType,
            string dateFrom,
            string dateTo,
            string dateFieldDescription,
            bool filterApplied)
        {
            if (!filterApplied)
            {
                return "- **Lọc thời gian:** Không — toàn bộ bản ghi hiện có trong JSON.\n"
                    + "- Chỉ mô tả sự kiện có trong JSON; không suy đoán ngoài dữ liệu.";
            }

            var fromLabel = string.IsNullOrWhiteSpace(dateFrom) ? "(sớm nhất)" : dateFrom;
            var toLabel = string.IsNullOrWhiteSpace(dateTo) ? "(muộn nhất)" : dateTo;

            return "- **Lọc thời gian:** Có — " + dateFieldDescription + " trong **"
                + fromLabel + "** → **" + toLabel + "**.\n"
                + "- **Loại báo cáo:** " + reportType + ".\n"
                + "- JSON **chỉ** chứa bản ghi trong khoảng (`Summary` + `Records`). "
                + "**Không** suy ra tổng số phát hiện/agent toàn hệ thống.";
        }
    }
}
