// Thêm file này vào thư mục Helpers/
// File: Helpers/NoTimeoutAttribute.cs

using System.Web.Mvc;

namespace WazuhWeb.Helpers
{
    /// <summary>
    /// Attribute tắt hoàn toàn timeout cho action — dùng cho các phân tích AI dài
    /// Áp dụng lên action: [NoTimeout]
    /// </summary>
    public class NoTimeoutAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            // Tắt script timeout của ASP.NET
            filterContext.HttpContext.Server.ScriptTimeout = int.MaxValue;
            base.OnActionExecuting(filterContext);
        }
    }
}
