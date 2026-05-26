using System;

namespace WazuhWeb.Models
{
    public class WazuhConfig
    {
        // Singleton instance used throughout the app
        public static WazuhConfig Current { get; } = new WazuhConfig();

        // Base URL of the Wazuh manager (including protocol and port)
        public string ApiBaseUrl { get; set; } = "https://192.168.1.28:55000";

        // Optional credentials – fill if API uses basic auth instead of token
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";

        // Bearer token – populated after login if the API uses token auth
        public string ApiToken { get; set; } = "";

        // Self‑signed certificates are common in internal Wazuh deployments
        public bool VerifySsl { get; set; } = false;
    }
}
