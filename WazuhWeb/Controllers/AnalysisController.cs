using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web.Mvc;
using WazuhWeb.Helpers;

namespace WazuhWeb.Controllers
{
    public class AnalysisController : Controller
    {
        private string Token
        {
            get { return Session["WazuhToken"] as string; }
            set { Session["WazuhToken"] = value; }
        }

        private string Username => Session["WazuhUsername"] as string;

        private string Password => Session["WazuhPassword"] as string;

        private bool IsAuth => !string.IsNullOrEmpty(Token);

        // =========================
        // API
        // =========================

        private async Task<string> ApiGetAsync(string endpoint)
        {
            var (json, newToken) =
                await WazuhApiClient.GetWithAutoRefreshAsync(
                    endpoint,
                    Token,
                    Username,
                    Password);

            if (!string.IsNullOrEmpty(newToken))
            {
                Token = newToken;
            }

            return json;
        }

        // =========================
        // INDEX
        // =========================

        public ActionResult Index()
        {
            if (!IsAuth)
            {
                return RedirectToAction("Login", "Auth");
            }

            return View();
        }

        // =========================
        // OLLAMA STATUS
        // =========================

        [HttpGet]
        public async Task<ActionResult> OllamaStatus()
        {
            try
            {
                string model =
                    await OllamaService.GetAvailableModelAsync();

                return Json(new
                {
                    online = true,
                    model
                }, JsonRequestBehavior.AllowGet);
            }
            catch
            {
                return Json(new
                {
                    online = false,
                    model = ""
                }, JsonRequestBehavior.AllowGet);
            }
        }

        // =========================
        // AGENTS — snapshot fleet; lọc disconnected theo lastKeepAlive khi chọn ngày
        // =========================

        [HttpPost]
        [ValidateAntiForgeryToken]
        [NoTimeout]
        public async Task<ActionResult> AnalyzeAgents(
            string dateFrom = null,
            string dateTo = null)
        {
            if (!IsAuth)
            {
                return Json(new
                {
                    success = false,
                    error = "Chưa đăng nhập"
                });
            }

            try
            {
                string json = await ApiGetAsync("/agents");

                var root = JToken.Parse(json);
                JArray rawAgents = null;
                if (root is JArray)
                {
                    rawAgents = (JArray)root;
                }
                else if (root is JObject)
                {
                    rawAgents = root["data"]?["affected_items"] as JArray ??
                                root["agents"] as JArray ??
                                root["items"] as JArray;
                }

                if (rawAgents == null)
                {
                    rawAgents = new JArray();
                }

                var agentsList = rawAgents.Children<JObject>().ToList();
                int totalAgents = agentsList.Count;
                int activeCount = agentsList.Count(a => (string)a["status"] == "active");
                int disconnectedCount = agentsList.Count(a => (string)a["status"] == "disconnected");
                int neverConnectedCount = agentsList.Count(a => (string)a["status"] == "never_connected");

                bool filterApplied = DateRangeHelper.HasFilter(dateFrom, dateTo);

                var unhealthyAgents = agentsList
                    .Where(a => (string)a["status"] != "active")
                    .Select(a => new
                    {
                        id = (string)a["id"],
                        name = (string)a["name"],
                        status = (string)a["status"],
                        ip = (string)a["ip"],
                        lastKeepAlive = (string)(a["lastKeepAlive"] ?? a["last_keep_alive"]),
                        os = a["os"]?["name"] != null ? $"{(string)a["os"]?["name"]} {(string)a["os"]?["version"]}" : "Unknown"
                    })
                    .ToList();

                var agentsInScope = unhealthyAgents;
                if (filterApplied)
                {
                    agentsInScope = unhealthyAgents
                        .Where(a => DateRangeHelper.IsInRange(a.lastKeepAlive, dateFrom, dateTo))
                        .ToList();
                }

                var healthyOsGroups = agentsList
                    .Where(a => (string)a["status"] == "active")
                    .GroupBy(a => a["os"]?["name"] != null ? (string)a["os"]?["name"] : "Unknown")
                    .Select(g => new { OS = g.Key, Count = g.Count() })
                    .ToList();

                var reportScope = new
                {
                    Mode = filterApplied ? "date_filtered" : "full_snapshot",
                    FilterApplied = filterApplied,
                    DateFrom = filterApplied ? dateFrom : null,
                    DateTo = filterApplied ? dateTo : null,
                    DateField = "lastKeepAlive",
                    Note = filterApplied
                        ? "JSON chỉ chứa dữ liệu trong khoảng ngày đã chọn — không có thống kê toàn hệ thống."
                        : "Toàn bộ agent không active tại thời điểm truy vấn."
                };

                object optimizedData;
                if (filterApplied)
                {
                    // Chỉ gửi dữ liệu trong phạm vi lọc — không gửi FleetSummary / HealthyActiveGroups
                    optimizedData = new
                    {
                        ReportScope = reportScope,
                        Summary = new
                        {
                            AgentsInScope = agentsInScope.Count,
                            DateFrom = dateFrom,
                            DateTo = dateTo
                        },
                        UnhealthyOrOfflineAgents = agentsInScope
                    };
                }
                else
                {
                    optimizedData = new
                    {
                        ReportScope = reportScope,
                        FleetSummary = new
                        {
                            Total = totalAgents,
                            Active = activeCount,
                            Disconnected = disconnectedCount,
                            NeverConnected = neverConnectedCount
                        },
                        HealthyActiveGroups = healthyOsGroups,
                        UnhealthyOrOfflineAgents = agentsInScope
                    };
                }

                string cleanJson = Newtonsoft.Json.JsonConvert.SerializeObject(optimizedData, Newtonsoft.Json.Formatting.Indented);

                var prompt = SecurityPrompts.AgentsReport(
                    cleanJson,
                    dateFrom,
                    dateTo,
                    filterApplied);
                var result = await OllamaService.GenerateAsync(prompt);

                return BuildResult(result, "Agents Report");
            }
            catch (Exception ex)
            {
                return ErrorJson(ex.Message);
            }
        }

        // =========================
        // SYSCHECK
        // =========================

        [HttpPost]
        [ValidateAntiForgeryToken]
        [NoTimeout]
        public async Task<ActionResult> AnalyzeSyscheck(
            string dateFrom = null,
            string dateTo = null)
        {
            if (!IsAuth)
            {
                return Json(new
                {
                    success = false,
                    error = "Chưa đăng nhập"
                });
            }

            try
            {
                var ids = await GetAgentIdsAsync();
                bool filterApplied = DateRangeHelper.HasFilter(dateFrom, dateTo);

                var tasks = ids.Select(async id =>
                {
                    var json = await ApiGetAsync($"/syscheck/{id}");

                    try
                    {
                        var root = JObject.Parse(json);
                        var rawItems = root["data"]?["affected_items"] as JArray ?? new JArray();

                        var changes = rawItems.Children<JObject>()
                            .Where(item =>
                            {
                                var chg = item["changes"];
                                return chg != null && (int)chg > 0;
                            })
                            .Select(item => new SyscheckChangeDto
                            {
                                AgentId = id,
                                Path = (string)item["file"],
                                Date = (string)item["date"],
                                ChangeType = (int)item["changes"] <= 1 ? "added/modified" : "deleted",
                                RegistryValue = item["value"]?["name"] != null ? (string)item["value"]["name"] : null
                            })
                            .ToList();

                        if (filterApplied)
                        {
                            changes = changes
                                .Where(c => DateRangeHelper.IsInRange(c.Date, dateFrom, dateTo))
                                .ToList();
                        }

                        return changes.Cast<object>().ToList();
                    }
                    catch
                    {
                        return new List<object>();
                    }
                });

                var results = await Task.WhenAll(tasks);
                var allChanges = results.SelectMany(x => x).ToList();

                string cleanJson = BuildAnalysisJson(
                    allChanges,
                    filterApplied,
                    dateFrom,
                    dateTo,
                    "date");

                var prompt = SecurityPrompts.GeneralSecurityReport(
                    cleanJson,
                    "Syscheck File Integrity & Registry Changes",
                    dateFrom,
                    dateTo,
                    "trường date (thời điểm phát hiện thay đổi file/registry)",
                    filterApplied);

                var result = await OllamaService.GenerateAsync(prompt);

                return BuildResult(result, "Syscheck Report");
            }
            catch (Exception ex)
            {
                return ErrorJson(ex.Message);
            }
        }

        // =========================
        // ROOTCHECK
        // =========================

        [HttpPost]
        [ValidateAntiForgeryToken]
        [NoTimeout]
        public async Task<ActionResult> AnalyzeRootcheck(
            string dateFrom = null,
            string dateTo = null)
        {
            if (!IsAuth)
            {
                return Json(new
                {
                    success = false,
                    error = "Chưa đăng nhập"
                });
            }

            try
            {
                var ids = await GetAgentIdsAsync();
                bool filterApplied = DateRangeHelper.HasFilter(dateFrom, dateTo);

                var tasks = ids.Select(async id =>
                {
                    var json = await ApiGetAsync($"/rootcheck/{id}");

                    try
                    {
                        var root = JObject.Parse(json);
                        var rawItems = root["data"]?["affected_items"] as JArray ?? new JArray();

                        var activeThreats = rawItems.Children<JObject>()
                            .Where(item => (string)item["status"] != "resolved")
                            .Select(item => new RootcheckThreatDto
                            {
                                AgentId = id,
                                Log = (string)item["log"],
                                Status = (string)item["status"],
                                DateLast = (string)item["date_last"]
                            })
                            .ToList();

                        if (filterApplied)
                        {
                            activeThreats = activeThreats
                                .Where(t => DateRangeHelper.IsInRange(t.DateLast, dateFrom, dateTo))
                                .ToList();
                        }

                        return activeThreats.Cast<object>().ToList();
                    }
                    catch
                    {
                        return new List<object>();
                    }
                });

                var results = await Task.WhenAll(tasks);
                var allThreats = results.SelectMany(x => x).ToList();

                string cleanJson = BuildAnalysisJson(
                    allThreats,
                    filterApplied,
                    dateFrom,
                    dateTo,
                    "date_last");

                var prompt = SecurityPrompts.GeneralSecurityReport(
                    cleanJson,
                    "Rootcheck Active Security Vulnerabilities",
                    dateFrom,
                    dateTo,
                    "trường date_last (lần phát hiện gần nhất)",
                    filterApplied);

                var result = await OllamaService.GenerateAsync(prompt);

                return BuildResult(result, "Rootcheck Report");
            }
            catch (Exception ex)
            {
                return ErrorJson(ex.Message);
            }
        }

        // =========================
        // SCA
        // =========================

        [HttpPost]
        [ValidateAntiForgeryToken]
        [NoTimeout]
        public async Task<ActionResult> AnalyzeSca(
            string dateFrom = null,
            string dateTo = null)
        {
            if (!IsAuth)
            {
                return Json(new
                {
                    success = false,
                    error = "Chưa đăng nhập"
                });
            }

            try
            {
                var ids = await GetAgentIdsAsync();
                bool filterApplied = DateRangeHelper.HasFilter(dateFrom, dateTo);

                var tasks = ids.Select(async id =>
                {
                    var json = await ApiGetAsync($"/sca/{id}");

                    try
                    {
                        var root = JObject.Parse(json);
                        var rawItems = root["data"]?["affected_items"] as JArray ?? new JArray();

                        var failedPolicies = rawItems.Children<JObject>()
                            .Where(item =>
                            {
                                var failVal = item["fail"];
                                return failVal != null && (int)failVal > 0;
                            })
                            .Select(item => new ScaFailureDto
                            {
                                AgentId = id,
                                PolicyId = (string)item["policy_id"],
                                Name = (string)item["name"],
                                Score = (int)item["score"],
                                Pass = (int)item["pass"],
                                Fail = (int)item["fail"],
                                EndScan = (string)item["end_scan"]
                            })
                            .ToList();

                        if (filterApplied)
                        {
                            failedPolicies = failedPolicies
                                .Where(p => DateRangeHelper.IsInRange(p.EndScan, dateFrom, dateTo))
                                .ToList();
                        }

                        return failedPolicies.Cast<object>().ToList();
                    }
                    catch
                    {
                        return new List<object>();
                    }
                });

                var results = await Task.WhenAll(tasks);
                var allScaFailures = results.SelectMany(x => x).ToList();

                string cleanJson = BuildAnalysisJson(
                    allScaFailures,
                    filterApplied,
                    dateFrom,
                    dateTo,
                    "end_scan");

                var prompt = SecurityPrompts.GeneralSecurityReport(
                    cleanJson,
                    "SCA/CIS Compliance Deviations",
                    dateFrom,
                    dateTo,
                    "trường end_scan (thời điểm kết thúc quét SCA)",
                    filterApplied);

                var result = await OllamaService.GenerateAsync(prompt);

                return BuildResult(result, "SCA Report");
            }
            catch (Exception ex)
            {
                return ErrorJson(ex.Message);
            }
        }

        /// <summary>
        /// Khi lọc ngày: bọc JSON chỉ gồm bản ghi trong phạm vi (không gửi thống kê toàn hệ thống).
        /// Khi full range: giữ mảng phát hiện như cũ.
        /// </summary>
        private static string BuildAnalysisJson(
            List<object> records,
            bool filterApplied,
            string dateFrom,
            string dateTo,
            string dateField)
        {
            if (!filterApplied)
            {
                return Newtonsoft.Json.JsonConvert.SerializeObject(
                    records,
                    Newtonsoft.Json.Formatting.Indented);
            }

            var agents = records
                .Select(r =>
                {
                    var t = r.GetType();
                    var p = t.GetProperty("AgentId");
                    return p != null ? p.GetValue(r) as string : null;
                })
                .Where(id => !string.IsNullOrEmpty(id))
                .Distinct()
                .ToList();

            var payload = new
            {
                ReportScope = new
                {
                    Mode = "date_filtered",
                    FilterApplied = true,
                    DateFrom = dateFrom,
                    DateTo = dateTo,
                    DateField = dateField,
                    Note = "Chỉ dữ liệu trong khoảng ngày — không có tổng số toàn hệ thống."
                },
                Summary = new
                {
                    TotalRecords = records.Count,
                    AgentsAffected = agents.Count,
                    DateFrom = dateFrom,
                    DateTo = dateTo
                },
                Records = records
            };

            return Newtonsoft.Json.JsonConvert.SerializeObject(
                payload,
                Newtonsoft.Json.Formatting.Indented);
        }

        // =========================
        // GET AGENT IDS
        // =========================

        private async Task<List<string>> GetAgentIdsAsync()
        {
            var ids = new List<string>();

            try
            {
                string json = await ApiGetAsync("/agents");

                if (string.IsNullOrEmpty(json))
                {
                    return ids;
                }

                var root = JToken.Parse(json);

                var array =
                    root["data"]?["affected_items"] as JArray ??
                    root["data"] as JArray ??
                    root["agents"] as JArray ??
                    (root as JArray);

                if (array != null)
                {
                    foreach (var item in array)
                    {
                        var idToken =
                            item["id"] ??
                            item["agent"]?["id"] ??
                            item["agent_id"] ??
                            item["agentId"];

                        if (idToken != null)
                        {
                            ids.Add(idToken.ToString());
                        }
                        else if (
                            item.Type == JTokenType.String ||
                            item.Type == JTokenType.Integer)
                        {
                            ids.Add(item.ToString());
                        }
                    }
                }
                else
                {
                    foreach (var t in root.SelectTokens("..id"))
                    {
                        if (t != null)
                        {
                            ids.Add(t.ToString());
                        }
                    }
                }
            }
            catch
            {
            }

            return ids.Distinct().ToList();
        }

        // =========================
        // BUILD RESULT
        // =========================

        private ActionResult BuildResult(
            OllamaResult r,
            string title)
        {
            if (!r.Success)
            {
                return Json(new
                {
                    success = false,
                    error = r.Error,
                    model = r.Model
                });
            }

            return Json(new
            {
                success = true,
                report = r.Response,
                title,
                model = r.Model,
                duration = (int)r.Duration.TotalSeconds
            });
        }

        private ActionResult ErrorJson(string msg)
        {
            return Json(new
            {
                success = false,
                error = msg
            });
        }

        private class SyscheckChangeDto
        {
            public string AgentId { get; set; }
            public string Path { get; set; }
            public string Date { get; set; }
            public string ChangeType { get; set; }
            public string RegistryValue { get; set; }
        }

        private class RootcheckThreatDto
        {
            public string AgentId { get; set; }
            public string Log { get; set; }
            public string Status { get; set; }
            public string DateLast { get; set; }
        }

        private class ScaFailureDto
        {
            public string AgentId { get; set; }
            public string PolicyId { get; set; }
            public string Name { get; set; }
            public int Score { get; set; }
            public int Pass { get; set; }
            public int Fail { get; set; }
            public string EndScan { get; set; }
        }
    }
}
