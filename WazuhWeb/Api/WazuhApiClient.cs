using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace WazuhWeb.Helpers
{
    public class WazuhApiClient
    {
        private static readonly string BaseUrl = "https://192.168.1.28:55000";

        private static HttpClient CreateClient(string token = null)
        {
            var handler = new WebRequestHandler();
            handler.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;
            var client = new HttpClient(handler);
            client.BaseAddress = new Uri(BaseUrl);
            client.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));
            if (!string.IsNullOrEmpty(token))
                client.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", token);
            return client;
        }

        /// <summary>
        /// Xác thực và lấy JWT token từ Wazuh
        /// </summary>
        public static async Task<string> AuthenticateAsync(string username, string password)
        {
            using (var client = CreateClient())
            {
                var credentials = Convert.ToBase64String(
                    Encoding.ASCII.GetBytes($"{username}:{password}"));
                client.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Basic", credentials);
                var response = await client.PostAsync("/security/user/authenticate", null);
                response.EnsureSuccessStatusCode();
                var json = await response.Content.ReadAsStringAsync();
                dynamic result = JsonConvert.DeserializeObject(json);
                return result.data.token;
            }
        }

        /// <summary>
        /// GET thông thường — giữ nguyên để không breaking change
        /// </summary>
        public static async Task<string> GetAsync(string endpoint, string token)
        {
            using (var client = CreateClient(token))
            {
                var response = await client.GetAsync(endpoint);
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsStringAsync();
            }
        }

        /// <summary>
        /// GET với tự động refresh token khi gặp 401.
        /// Truyền vào username/password để re-authenticate.
        /// newToken trả về token mới (nếu đã refresh) để caller cập nhật Session.
        /// </summary>
        public static async Task<(string json, string newToken)> GetWithAutoRefreshAsync(
            string endpoint,
            string token,
            string username,
            string password)
        {
            // Lần 1: thử với token hiện tại
            using (var client = CreateClient(token))
            {
                var response = await client.GetAsync(endpoint);

                // Thành công → trả về ngay, newToken = null (không đổi)
                if (response.IsSuccessStatusCode)
                    return (await response.Content.ReadAsStringAsync(), null);

                // 401 → token hết hạn, thử refresh
                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    // Re-authenticate lấy token mới
                    string refreshed = await AuthenticateAsync(username, password);

                    // Lần 2: gọi lại với token mới
                    using (var client2 = CreateClient(refreshed))
                    {
                        var response2 = await client2.GetAsync(endpoint);
                        response2.EnsureSuccessStatusCode();
                        return (await response2.Content.ReadAsStringAsync(), refreshed);
                    }
                }

                // Lỗi khác (403, 500...) → throw như cũ
                response.EnsureSuccessStatusCode();
                return (null, null); // unreachable
            }
        }
    }
}