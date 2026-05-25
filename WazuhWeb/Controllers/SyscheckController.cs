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
        // GET /Syscheck/Index?agentId=001&dateFrom=&dateTo=
        public async Task<ActionResult> Index(string agentId = "001",
                                              string dateFrom = null,
                                              string dateTo = null)
        {
            string token = Session["WazuhToken"] as string;
            if (string.IsNullOrEmpty(token))
                return RedirectToAction("Login", "Auth");

            // Lấy danh sách tất cả agent để hiện dropdown
            List<Agent> allAgents = await GetAllAgents(token);
            ViewBag.AllAgents = allAgents;
            ViewBag.AgentId = agentId;

            try
            {
                // Build query string date filter cho Wazuh API
                string dateFilter = BuildDateFilter(dateFrom, dateTo);

                var fileTask = WazuhApiClient.GetAsync(
                    $"/syscheck/{agentId}?type=file&limit=500&sort=-date{dateFilter}", token);
                var regTask = WazuhApiClient.GetAsync(
                    $"/syscheck/{agentId}?type=registry_value&limit=500&sort=-date{dateFilter}", token);

                await Task.WhenAll(fileTask, regTask);

                var fileResp = JsonConvert.DeserializeObject<SyscheckListResponse>(fileTask.Result);
                var regResp = JsonConvert.DeserializeObject<SyscheckListResponse>(regTask.Result);

                var files = fileResp?.data?.affected_items ?? new List<SyscheckItem>();
                var regs = regResp?.data?.affected_items ?? new List<SyscheckItem>();

                // Client-side date filter bổ sung nếu API không hỗ trợ
                files = ApplyDateFilter(files, i => i.date, dateFrom, dateTo);
                regs = ApplyDateFilter(regs, i => i.date, dateFrom, dateTo);

                foreach (var f in files) f.changeType = f.changes <= 1 ? "added" : "modified";
                foreach (var r in regs) r.changeType = "modified";

                var vm = new SyscheckViewModel
                {
                    Files = files,
                    Registries = regs,
                    TotalFiles = files.Count,
                    TotalRegs = regs.Count,
                    AgentId = agentId,
                    DateFrom = dateFrom,
                    DateTo = dateTo
                };
                return View(vm);
            }
            catch (Exception ex)
            {
                ViewBag.Error = "Lỗi syscheck: " + ex.Message;
                return View(new SyscheckViewModel { AgentId = agentId });
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────────

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

        private static string BuildDateFilter(string from, string to)
        {
            // Wazuh API hỗ trợ older_than / newer_than theo seconds, nên ta lọc client-side
            return "";
        }

        private static List<SyscheckItem> ApplyDateFilter(
            List<SyscheckItem> items,
            Func<SyscheckItem, string> dateSelector,
            string from, string to)
        {
            if (!string.IsNullOrEmpty(from) && DateTime.TryParse(from, out var dtFrom))
                items = items.Where(i => {
                    var s = dateSelector(i);
                    return !string.IsNullOrEmpty(s) && DateTime.TryParse(s, out var d) && d >= dtFrom;
                }).ToList();
            if (!string.IsNullOrEmpty(to) && DateTime.TryParse(to, out var dtTo))
                items = items.Where(i => {
                    var s = dateSelector(i);
                    return !string.IsNullOrEmpty(s) && DateTime.TryParse(s, out var d) && d <= dtTo.AddDays(1);
                }).ToList();
            return items;
        }
    }
}