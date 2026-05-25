using System;
using System.Linq;
using System.Threading.Tasks;
using System.Web.Mvc;
using Newtonsoft.Json;
using WazuhWeb.Helpers;
using WazuhWeb.Models;

namespace WazuhWeb.Controllers
{
    public class AgentsController : Controller
    {
        // GET /Agents?dateFrom=2026-01-01&dateTo=2026-12-31
        public async Task<ActionResult> Index(string dateFrom = null, string dateTo = null)
        {
            string token = Session["WazuhToken"] as string;
            if (string.IsNullOrEmpty(token))
                return RedirectToAction("Login", "Auth");

            ViewBag.DateFrom = dateFrom;
            ViewBag.DateTo = dateTo;

            try
            {
                string json = await WazuhApiClient.GetAsync("/agents?limit=500", token);
                var response = JsonConvert.DeserializeObject<AgentListResponse>(json);
                var items = response?.data?.affected_items ?? new System.Collections.Generic.List<Agent>();

                // Filter theo dateAdd
                if (!string.IsNullOrEmpty(dateFrom) && DateTime.TryParse(dateFrom, out var from))
                    items = items.Where(a => !string.IsNullOrEmpty(a.dateAdd) &&
                        DateTime.TryParse(a.dateAdd, out var d) && d >= from).ToList();
                if (!string.IsNullOrEmpty(dateTo) && DateTime.TryParse(dateTo, out var to))
                    items = items.Where(a => !string.IsNullOrEmpty(a.dateAdd) &&
                        DateTime.TryParse(a.dateAdd, out var d) && d <= to.AddDays(1)).ToList();

                var data = new AgentData
                {
                    affected_items = items,
                    total_affected_items = items.Count
                };
                return View(data);
            }
            catch (Exception ex)
            {
                ViewBag.Error = "Không thể lấy dữ liệu agents: " + ex.Message;
                return View(new AgentData());
            }
        }
    }
}