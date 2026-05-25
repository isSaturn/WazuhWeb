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
    public class ScaController : Controller
    {
        // GET /Sca/Index?agentId=001
        public async Task<ActionResult> Index(string agentId = "001")
        {
            string token = Session["WazuhToken"] as string;
            if (string.IsNullOrEmpty(token))
                return RedirectToAction("Login", "Auth");

            // ── Giống SyscheckController: fetch toàn bộ agent list ──
            List<Agent> allAgents = await GetAllAgents(token);
            ViewBag.AllAgents = allAgents;
            ViewBag.AgentId = agentId;

            try
            {
                // Lấy danh sách policy SCA của agent
                var policiesJson = await WazuhApiClient.GetAsync(
                    $"/sca/{agentId}?limit=500", token);
                var policiesResp = JsonConvert.DeserializeObject<ScaSummaryResponse>(policiesJson);
                var policies = policiesResp?.data?.affected_items ?? new List<ScaPolicy>();

                if (!policies.Any())
                {
                    ViewBag.Error = $"Không có SCA policy nào cho agent {agentId}.";
                    return View(new ScaPageViewModel { AgentId = agentId });
                }

                var policy = policies.First();

                var checksJson = await WazuhApiClient.GetAsync(
                    $"/sca/{agentId}/checks/{policy.policy_id}?limit=500", token);
                var checksResp = JsonConvert.DeserializeObject<ScaChecksResponse>(checksJson);
                var checks = checksResp?.data?.affected_items ?? new List<ScaCheck>();

                return View(new ScaPageViewModel
                {
                    AgentId = agentId,
                    Policy = policy,
                    Checks = checks
                });
            }
            catch (Exception ex)
            {
                ViewBag.Error = "Lỗi SCA: " + ex.Message;
                return View(new ScaPageViewModel { AgentId = agentId });
            }
        }

        // ── Helpers ──────────────────────────────────────────────────────────

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
