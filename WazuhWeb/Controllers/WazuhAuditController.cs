using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web.Mvc;
using Newtonsoft.Json;
using WazuhWeb.Helpers;
using WazuhWeb.Models;
using WazuhWeb.Services;

namespace WazuhWeb.Controllers
{
    public class WazuhAuditController : Controller
    {
        // GET: /WazuhAudit/RunAudit
        public async Task<JsonResult> RunAudit()
        {
            string token = Session["WazuhToken"] as string;
            if (string.IsNullOrEmpty(token))
                return Json(new { error = "Authentication required" }, JsonRequestBehavior.AllowGet);

            var auditService = new WazuhAuditService();
            var agents = await auditService.GetAgentsAsync(token);
            var results = new List<AuditResult>();

            var tasks = new List<Task>();
            foreach (var agent in agents)
            {
                var aid = agent.id;
                var result = new AuditResult { Agent = agent };
                results.Add(result);
                tasks.Add(Task.Run(async () =>
                {
                    result.Syscheck = await auditService.GetSyscheckAsync(token, aid);
                    result.Sca = await auditService.GetScaAsync(token, aid);
                    if (!string.IsNullOrEmpty(result.Sca?.PolicyName))
                    {
                        result.ScaChecks = await auditService.GetScaChecksAsync(token, aid, result.Sca.PolicyName);
                    }
                    result.Rootcheck = await auditService.GetRootcheckAsync(token, aid);
                }));
            }
            await Task.WhenAll(tasks);

            return Json(results, JsonRequestBehavior.AllowGet);
        }
    }
}
