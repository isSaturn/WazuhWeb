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
    public class SyscheckController : Controller
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
                var fileTask = WazuhApiClient.GetAsync(
                    $"/syscheck/{agentId}?type=file&sort=-date", token);
                var regTask = WazuhApiClient.GetAsync(
                    $"/syscheck/{agentId}?type=registry_value&limit=500&sort=-date", token);

                await Task.WhenAll(fileTask, regTask);

                var fileResp = JsonConvert.DeserializeObject<SyscheckListResponse>(fileTask.Result);
                var regResp = JsonConvert.DeserializeObject<SyscheckListResponse>(regTask.Result);

                var files = fileResp?.data?.affected_items ?? new List<SyscheckItem>();
                var regs = regResp?.data?.affected_items ?? new List<SyscheckItem>();

                foreach (var f in files) f.changeType = f.changes <= 1 ? "added" : "modified";
                foreach (var r in regs) r.changeType = "modified";

                var vm = new SyscheckViewModel
                {
                    Files = files,
                    Registries = regs,
                    TotalFiles = files.Count,
                    TotalRegs = regs.Count,
                    AgentId = agentId
                };
                return View(vm);
            }
            catch (Exception ex)
            {
                ViewBag.Error = "Lỗi syscheck: " + ex.Message;
                return View(new SyscheckViewModel { AgentId = agentId });
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
