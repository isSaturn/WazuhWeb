using System;
using System.Threading.Tasks;
using System.Web.Mvc;
using Newtonsoft.Json;
using WazuhWeb.Helpers;
using WazuhWeb.Models;

namespace WazuhWeb.Controllers
{
    public class AgentsController : Controller
    {
        public async Task<ActionResult> Index()
        {
            string token = Session["WazuhToken"] as string;
            if (string.IsNullOrEmpty(token))
                return RedirectToAction("Login", "Auth");

            try
            {
                string json = await WazuhApiClient.GetAsync("/agents", token);
                var response = JsonConvert.DeserializeObject<AgentListResponse>(json);
                var items = response?.data?.affected_items ?? new System.Collections.Generic.List<Agent>();

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
