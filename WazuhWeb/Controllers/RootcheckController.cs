using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web.Mvc;
using Newtonsoft.Json;
using WazuhWeb.Helpers;
using WazuhWeb.Models;

namespace WazuhWeb.Controllers
{
    public class RootcheckController : Controller
    {
        public async Task<ActionResult> Index(string agentId)
        {
            string token = Session["WazuhToken"] as string;
            if (string.IsNullOrEmpty(token))
                return RedirectToAction("Login", "Auth");

            List<Agent> allAgents = await GetAllAgents(token);
            ViewBag.AllAgents = allAgents;
            ViewBag.AgentId = agentId;

            try
            {
                string json = await WazuhApiClient.GetAsync($"/rootcheck/{agentId}", token);
                var resp = JsonConvert.DeserializeObject<RootcheckListResponse>(json);
                var items = resp?.data?.affected_items ?? new List<RootcheckItem>();

                var vm = new RootcheckViewModel
                {
                    Items = items,
                    Total = items.Count,
                    AgentId = agentId
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
                var json = await WazuhApiClient.GetAsync("/agents", token);
                var resp = JsonConvert.DeserializeObject<AgentListResponse>(json);
                return resp?.data?.affected_items ?? new List<Agent>();
            }
            catch { return new List<Agent>(); }
        }
    }
}
