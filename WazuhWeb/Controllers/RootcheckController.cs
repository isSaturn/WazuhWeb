using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web.Mvc;
using Newtonsoft.Json;
using WazuhWeb.Helpers;
using WazuhWeb.Models;

namespace WazuhWeb.Controllers
{
    public class RootcheckController : Controller
    {
        public async Task<ActionResult> Index(string agentId = "001",
                                              string dateFrom = null,
                                              string dateTo = null)
        {
            string token = Session["WazuhToken"] as string;
            if (string.IsNullOrEmpty(token))
                return RedirectToAction("Login", "Auth");

            List<Agent> allAgents = await GetAllAgents(token);
            ViewBag.AllAgents = allAgents;
            ViewBag.AgentId = agentId;

            try
            {
                string json = await WazuhApiClient.GetAsync($"/rootcheck/{agentId}?limit=500", token);
                var resp = JsonConvert.DeserializeObject<RootcheckListResponse>(json);
                var items = resp?.data?.affected_items ?? new List<RootcheckItem>();

                // Filter theo date_last
                if (!string.IsNullOrEmpty(dateFrom) && DateTime.TryParse(dateFrom, out var dtFrom))
                    items = items.Where(i => !string.IsNullOrEmpty(i.date_last) &&
                        DateTime.TryParse(i.date_last, out var d) && d >= dtFrom).ToList();
                if (!string.IsNullOrEmpty(dateTo) && DateTime.TryParse(dateTo, out var dtTo))
                    items = items.Where(i => !string.IsNullOrEmpty(i.date_last) &&
                        DateTime.TryParse(i.date_last, out var d) && d <= dtTo.AddDays(1)).ToList();

                var vm = new RootcheckViewModel
                {
                    Items = items,
                    Total = items.Count,
                    AgentId = agentId,
                    DateFrom = dateFrom,
                    DateTo = dateTo
                };
                return View(vm);
            }
            catch (Exception ex)
            {
                ViewBag.Error = "Lỗi rootcheck: " + ex.Message;
                return View(new RootcheckViewModel { AgentId = agentId });
            }
        }

        private async Task<List<Agent>> GetAllAgents(string token)
        {
            try
            {
                var json = await WazuhApiClient.GetAsync("/agents?limit=500", token);
                var resp = JsonConvert.DeserializeObject<AgentListResponse>(json);
                return resp?.data?.affected_items ?? new List<Agent>();
            }
            catch { return new List<Agent>(); }
        }
    }
}