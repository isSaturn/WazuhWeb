using System;
using System.Collections.Generic;
using System.Linq;

namespace WazuhWeb.Helpers
{
    public static class DateFilterHelper
    {
        /// <summary>
        /// Builds an empty date filter string for Wazuh API calls.
        /// The API does not support date range filtering, so we return an empty string.
        /// This method is kept for compatibility with existing controller code.
        /// </summary>
        public static string BuildDateFilter(string from, string to)
        {
            // No server-side filtering; client will filter after retrieval.
            return string.Empty;
        }

        /// <summary>
        /// Applies client‑side date filtering to a list of items.
        /// The <paramref name="dateSelector"/> extracts a date string from each item.
        /// </summary>
        public static List<T> ApplyDateFilter<T>(List<T> items, Func<T, string> dateSelector, string from, string to)
        {
            if (!string.IsNullOrEmpty(from) && DateTime.TryParse(from, out var dtFrom))
            {
                items = items.Where(i =>
                {
                    var s = dateSelector(i);
                    return !string.IsNullOrEmpty(s) && DateTime.TryParse(s, out var d) && d >= dtFrom;
                }).ToList();
            }
            if (!string.IsNullOrEmpty(to) && DateTime.TryParse(to, out var dtTo))
            {
                items = items.Where(i =>
                {
                    var s = dateSelector(i);
                    return !string.IsNullOrEmpty(s) && DateTime.TryParse(s, out var d) && d <= dtTo.AddDays(1);
                }).ToList();
            }
            return items;
        }
    }
}
