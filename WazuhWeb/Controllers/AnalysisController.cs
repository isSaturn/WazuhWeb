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
        // JSON FILTER
        // =========================

        private string FilterJson(
            string json,
            string dateField,
            string dateFrom,
            string dateTo)
        {
            if (string.IsNullOrEmpty(dateFrom) &&
                string.IsNullOrEmpty(dateTo))
            {
                return json;
            }

            JToken token;

            try
            {
                token = JToken.Parse(json);
            }
            catch
            {
                return json;
            }

            JArray array = null;

            if (token.Type == JTokenType.Array)
            {
                array = (JArray)token;
            }
            else if (token.Type == JTokenType.Object)
            {
                var obj = (JObject)token;

                if (obj["data"] is JArray da)
                    array = da;
                else if (obj["agents"] is JArray aa)
                    array = aa;
                else if (obj["items"] is JArray ia)
                    array = ia;
            }

            if (array == null)
                return json;

            var filtered = array.Where(item =>
            {
                var objItem = item as JObject;

                if (objItem == null)
                    return false;

                var dateStr = (string)objItem[dateField];

                if (string.IsNullOrEmpty(dateStr))
                    return false;

                if (DateTime.TryParse(dateStr, out var dt))
                {
                    bool afterFrom = true;
                    bool beforeTo = true;

                    if (!string.IsNullOrEmpty(dateFrom) &&
                        DateTime.TryParse(dateFrom, out var fromDt))
                    {
                        afterFrom = dt >= fromDt;
                    }

                    if (!string.IsNullOrEmpty(dateTo) &&
                        DateTime.TryParse(dateTo, out var toDt))
                    {
                        beforeTo = dt < toDt.AddDays(1);
                    }

                    return afterFrom && beforeTo;
                }

                return false;
            }).ToArray();

            if (token.Type == JTokenType.Array)
            {
                return new JArray(filtered).ToString();
            }
            else
            {
                var obj = (JObject)token;

                if (obj["data"] is JArray)
                    obj["data"] = new JArray(filtered);
                else if (obj["agents"] is JArray)
                    obj["agents"] = new JArray(filtered);
                else if (obj["items"] is JArray)
                    obj["items"] = new JArray(filtered);

                return obj.ToString();
            }
        }

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
        // AGENTS
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

                if (!string.IsNullOrEmpty(dateFrom) ||
                    !string.IsNullOrEmpty(dateTo))
                {
                    json = FilterJson(
                        json,
                        "dateAdd",
                        dateFrom,
                        dateTo);
                }

                // Tiền xử lý thông tin Agents thông minh
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

                // Chỉ liệt kê chi tiết các agent offline hoặc có lỗi
                var unhealthyAgents = agentsList
                    .Where(a => (string)a["status"] != "active")
                    .Select(a => new
                    {
                        id = (string)a["id"],
                        name = (string)a["name"],
                        status = (string)a["status"],
                        ip = (string)a["ip"],
                        lastKeepAlive = (string)a["lastKeepAlive"],
                        os = a["os"]?["name"] != null ? $"{(string)a["os"]?["name"]} {(string)a["os"]?["version"]}" : "Unknown"
                    })
                    .ToList();

                // Gom nhóm các agent khỏe mạnh đang active theo OS
                var healthyOsGroups = agentsList
                    .Where(a => (string)a["status"] == "active")
                    .GroupBy(a => a["os"]?["name"] != null ? (string)a["os"]?["name"] : "Unknown")
                    .Select(g => new { OS = g.Key, Count = g.Count() })
                    .ToList();

                var optimizedData = new
                {
                    Summary = new
                    {
                        Total = totalAgents,
                        Active = activeCount,
                        Disconnected = disconnectedCount,
                        NeverConnected = neverConnectedCount
                    },
                    HealthyActiveGroups = healthyOsGroups,
                    UnhealthyOrOfflineAgents = unhealthyAgents
                };

                string cleanJson = Newtonsoft.Json.JsonConvert.SerializeObject(optimizedData, Newtonsoft.Json.Formatting.Indented);

                var prompt = SecurityPrompts.AgentsReport(cleanJson);
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

                var tasks = ids.Select(async id =>
                {
                    var json = await ApiGetAsync($"/syscheck/{id}");

                    if (!string.IsNullOrEmpty(dateFrom) ||
                        !string.IsNullOrEmpty(dateTo))
                    {
                        json = FilterJson(
                            json,
                            "date",
                            dateFrom,
                            dateTo);
                    }

                    try
                    {
                        var root = JObject.Parse(json);
                        var rawItems = root["data"]?["affected_items"] as JArray ?? new JArray();

                        // Chỉ giữ lại các file/registry thực tế thay đổi (changes > 0)
                        var changes = rawItems.Children<JObject>()
                            .Where(item => {
                                var chg = item["changes"];
                                return chg != null && (int)chg > 0;
                            })
                            .Select(item => new {
                                AgentId = id,
                                Path = (string)item["file"],
                                Date = (string)item["date"],
                                ChangeType = (int)item["changes"] <= 1 ? "added/modified" : "deleted",
                                RegistryValue = item["value"]?["name"] != null ? (string)item["value"]["name"] : null
                            })
                            .Cast<object>()
                            .ToList();

                        return changes;
                    }
                    catch
                    {
                        return new List<object>();
                    }
                });

                var results = await Task.WhenAll(tasks);
                var allChanges = results.SelectMany(x => x).ToList();

                string cleanJson = Newtonsoft.Json.JsonConvert.SerializeObject(allChanges, Newtonsoft.Json.Formatting.Indented);

                var prompt = SecurityPrompts.GeneralSecurityReport(
                    cleanJson, 
                    "Syscheck File Integrity & Registry Changes", 
                    dateFrom, 
                    dateTo);

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

                var tasks = ids.Select(async id =>
                {
                    var json = await ApiGetAsync($"/rootcheck/{id}");

                    if (!string.IsNullOrEmpty(dateFrom) ||
                        !string.IsNullOrEmpty(dateTo))
                    {
                        json = FilterJson(
                            json,
                            "date",
                            dateFrom,
                            dateTo);
                    }

                    try
                    {
                        var root = JObject.Parse(json);
                        var rawItems = root["data"]?["affected_items"] as JArray ?? new JArray();

                        // Chỉ lọc các mối nguy hại đang active (chưa được resolve)
                        var activeThreats = rawItems.Children<JObject>()
                            .Where(item => (string)item["status"] != "resolved")
                            .Select(item => new {
                                AgentId = id,
                                Log = (string)item["log"],
                                Status = (string)item["status"],
                                DateLast = (string)item["date_last"]
                            })
                            .Cast<object>()
                            .ToList();

                        return activeThreats;
                    }
                    catch
                    {
                        return new List<object>();
                    }
                });

                var results = await Task.WhenAll(tasks);
                var allThreats = results.SelectMany(x => x).ToList();

                string cleanJson = Newtonsoft.Json.JsonConvert.SerializeObject(allThreats, Newtonsoft.Json.Formatting.Indented);

                var prompt = SecurityPrompts.GeneralSecurityReport(
                    cleanJson, 
                    "Rootcheck Active Security Vulnerabilities", 
                    dateFrom, 
                    dateTo);

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

                var tasks = ids.Select(async id =>
                {
                    var json = await ApiGetAsync($"/sca/{id}");

                    if (!string.IsNullOrEmpty(dateFrom) ||
                        !string.IsNullOrEmpty(dateTo))
                    {
                        json = FilterJson(
                            json,
                            "date",
                            dateFrom,
                            dateTo);
                    }

                    try
                    {
                        var root = JObject.Parse(json);
                        var rawItems = root["data"]?["affected_items"] as JArray ?? new JArray();

                        // Chỉ giữ lại các chính sách/CIS bị vi phạm
                        var failedPolicies = rawItems.Children<JObject>()
                            .Where(item => {
                                var failVal = item["fail"];
                                return failVal != null && (int)failVal > 0;
                            })
                            .Select(item => new {
                                AgentId = id,
                                PolicyId = (string)item["policy_id"],
                                Name = (string)item["name"],
                                Score = (int)item["score"],
                                Pass = (int)item["pass"],
                                Fail = (int)item["fail"],
                                EndScan = (string)item["end_scan"]
                            })
                            .Cast<object>()
                            .ToList();

                        return failedPolicies;
                    }
                    catch
                    {
                        return new List<object>();
                    }
                });

                var results = await Task.WhenAll(tasks);
                var allScaFailures = results.SelectMany(x => x).ToList();

                string cleanJson = Newtonsoft.Json.JsonConvert.SerializeObject(allScaFailures, Newtonsoft.Json.Formatting.Indented);

                var prompt = SecurityPrompts.GeneralSecurityReport(
                    cleanJson, 
                    "SCA/CIS Compliance Deviations", 
                    dateFrom, 
                    dateTo);

                var result = await OllamaService.GenerateAsync(prompt);

                return BuildResult(result, "SCA Report");
            }
            catch (Exception ex)
            {
                return ErrorJson(ex.Message);
            }
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

        // =========================
        // ERROR
        // =========================

        private ActionResult ErrorJson(string msg)
        {
            return Json(new
            {
                success = false,
                error = msg
            });
        }
    }
}