using System;
using System.Threading.Tasks;
using System.Web.Mvc;
using WazuhWeb.Helpers;

namespace WazuhWeb.Controllers
{
    public class AuthController : Controller
    {
        private const string FixedUsername = "admin";
        private const string FixedPassword = "Bvcuchi.123";

        [HttpGet]
        public async Task<ActionResult> Login()
        {
            if (Session["WazuhToken"] != null)
                return RedirectToAction("Index", "Agents");
            try
            {
                string token = await WazuhApiClient.AuthenticateAsync(FixedUsername, FixedPassword);

                Session["WazuhToken"] = token;
                Session["WazuhUsername"] = FixedUsername; // để auto-refresh khi token hết hạn
                Session["WazuhPassword"] = FixedPassword; // để auto-refresh khi token hết hạn

                return RedirectToAction("Index", "Agents");
            }
            catch (Exception ex)
            {
                ViewBag.Error = ex.Message;
                return View();
            }
        }
    }
}