using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

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

        public static string ToDateOnly(DateTime date)
        {
            return date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
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

        public static bool IsFullRange(string dateFrom, string dateTo, string boundMin, string boundMax)
        {
            if (string.IsNullOrWhiteSpace(boundMin) || string.IsNullOrWhiteSpace(boundMax))
                return !HasFilter(dateFrom, dateTo);

            return string.Equals(dateFrom, boundMin, StringComparison.Ordinal)
                && string.Equals(dateTo, boundMax, StringComparison.Ordinal);
        }

        public static void CollectBounds(IEnumerable<string> dateValues, ref DateTime? min, ref DateTime? max)
        {
            if (dateValues == null)
                return;

            foreach (var raw in dateValues)
            {
                if (!TryParseDate(raw, out var dt))
                    continue;

                var day = dt.Date;
                if (!min.HasValue || day < min.Value)
                    min = day;
                if (!max.HasValue || day > max.Value)
                    max = day;
            }
        }

        public static object BoundsDto(DateTime? min, DateTime? max)
        {
            return new
            {
                min = min.HasValue ? ToDateOnly(min.Value) : (string)null,
                max = max.HasValue ? ToDateOnly(max.Value) : (string)null
            };
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
