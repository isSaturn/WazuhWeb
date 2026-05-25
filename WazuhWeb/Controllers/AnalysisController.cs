using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web.Mvc;
using Newtonsoft.Json;
using WazuhWeb.Helpers;
using WazuhWeb.Models;
using YourProject.Services;

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

        private async Task<string> ApiGetAsync(string endpoint)
        {
            var (json, newToken) =
                await WazuhApiClient.GetWithAutoRefreshAsync(
                    endpoint,
                    Token,
                    Username,
                    Password);

            if (!string.IsNullOrEmpty(newToken))
                Token = newToken;

            return json;
        }

        public ActionResult Index()
        {
            if (!IsAuth)
                return RedirectToAction("Login", "Auth");

            return View();
        }

        [HttpGet]
        public async Task<ActionResult> OllamaStatus()
        {
            try
            {
                string model = await OllamaService.GetAvailableModelAsync();

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
        public async Task<ActionResult> AnalyzeAgents()
        {
            if (!IsAuth)
                return Json(new
                {
                    success = false,
                    error = "Chưa đăng nhập"
                });

            try
            {
                string json = await ApiGetAsync("/agents");

                var prompt = SecurityPrompts.AgentsReport(json);

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
        public async Task<ActionResult> AnalyzeSyscheck()
        {
            if (!IsAuth)
                return Json(new
                {
                    success = false,
                    error = "Chưa đăng nhập"
                });

            try
            {
                string json =
                    await ApiGetAsync("/syscheck?limit=1000");

                var result =
                    await OllamaService.GenerateAsync(
                        "Phân tích Syscheck từ JSON sau:\n\n" + json);

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
        public async Task<ActionResult> AnalyzeRootcheck()
        {
            if (!IsAuth)
                return Json(new
                {
                    success = false,
                    error = "Chưa đăng nhập"
                });

            try
            {
                string json =
                    await ApiGetAsync("/rootcheck?limit=1000");

                var result =
                    await OllamaService.GenerateAsync(
                        "Phân tích Rootcheck từ JSON sau:\n\n" + json);

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
        public async Task<ActionResult> AnalyzeSca()
        {
            if (!IsAuth)
                return Json(new
                {
                    success = false,
                    error = "Chưa đăng nhập"
                });

            try
            {
                string json =
                    await ApiGetAsync("/sca?limit=500");

                var result =
                    await OllamaService.GenerateAsync(
                        "Phân tích SCA từ JSON sau:\n\n" + json);

                return BuildResult(result, "SCA Report");
            }
            catch (Exception ex)
            {
                return ErrorJson(ex.Message);
            }
        }

        // =========================
        // RESULT
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
    }
}