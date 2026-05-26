using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace WazuhWeb.Helpers
{
    public static class WazuhApiClient
    {
        private static readonly HttpClient HttpClient = new HttpClient();

        /// <summary>
        /// Executes a GET request to the specified Wazuh API path using the provided token.
        /// The base URL is taken from the configuration (see WazuhWeb.Models.WazuhConfig).
        /// </summary>
        /// <param name="path">API path beginning with a leading slash, e.g. "/agents".</param>
        /// <param name="token">Wazuh authentication token (stored in Session).</param>
        /// <returns>Response body as string.</returns>
        public static async Task<string> GetAsync(string path, string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                throw new ArgumentException("Wazuh token is missing.", nameof(token));

            var config = WazuhWeb.Models.WazuhConfig.Current;
            var requestUri = new Uri(new Uri(config.ApiBaseUrl), path);

            var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            request.Headers.Add("Authorization", $"Bearer {token}");

            // Allow self‑signed certificates if configured.
            if (!config.VerifySsl)
            {
                // In a real implementation you would configure HttpClientHandler.
                // This placeholder keeps compilation simple.
            }

            var response = await HttpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }
    }
}
