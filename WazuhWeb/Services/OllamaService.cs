using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace WazuhWeb.Helpers
{
    public static class OllamaService
    {
        private const string OllamaBase = "http://localhost:11434";

        private static readonly string[] PreferredModels =
        {
            "gpt-oss:120b-cloud"
        };

        private static HttpClient CreateClient()
            => new HttpClient { Timeout = TimeSpan.FromMinutes(10) };

        public static async Task<string> GetAvailableModelAsync()
        {
            try
            {
                using (var c = CreateClient())
                {
                    var resp = await c.GetAsync($"{OllamaBase}/api/tags");
                    if (!resp.IsSuccessStatusCode) return "gpt-oss:120b-cloud";
                    var obj = JObject.Parse(await resp.Content.ReadAsStringAsync());
                    var models = obj["models"] as JArray;
                    if (models == null || models.Count == 0) return "gpt-oss:120b-cloud";
                    foreach (var pref in PreferredModels)
                        foreach (var m in models)
                        {
                            var n = m["name"]?.ToString() ?? "";
                            if (n.StartsWith(pref, StringComparison.OrdinalIgnoreCase)) return n;
                        }
                    return models[0]["name"]?.ToString() ?? "gpt-oss:120b-cloud";
                }
            }
            catch { return "gpt-oss:120b-cloud"; }
        }

        public static async Task<OllamaResult> GenerateAsync(string prompt, string model = null)
        {
            if (string.IsNullOrEmpty(model))
                model = await GetAvailableModelAsync();

            using (var c = CreateClient())
            {
                var body = JsonConvert.SerializeObject(new
                {
                    model = model,
                    prompt = prompt,
                    stream = false,
                    options = new { temperature = 0.5, num_predict = 3000 }
                });
                try
                {
                    var resp = await c.PostAsync($"{OllamaBase}/api/generate",
                        new StringContent(body, Encoding.UTF8, "application/json"));
                    if (!resp.IsSuccessStatusCode)
                        return new OllamaResult
                        {
                            Success = false,
                            Error = $"HTTP {(int)resp.StatusCode}: {await resp.Content.ReadAsStringAsync()}",
                            Model = model
                        };

                    var obj = JObject.Parse(await resp.Content.ReadAsStringAsync());
                    long ns = obj["total_duration"] != null ? (long)obj["total_duration"] : 0;
                    return new OllamaResult
                    {
                        Success = true,
                        Response = obj["response"]?.ToString() ?? "",
                        Model = obj["model"]?.ToString() ?? model,
                        Duration = TimeSpan.FromMilliseconds(ns / 1_000_000.0)
                    };
                }
                catch (TaskCanceledException)
                {
                    return new OllamaResult
                    {
                        Success = false,
                        Error = "Timeout — model đang tải hoặc phản hồi quá chậm. Thử lại.",
                        Model = model
                    };
                }
                catch (Exception ex)
                {
                    return new OllamaResult
                    {
                        Success = false,
                        Error = $"Không kết nối Ollama ({OllamaBase}): {ex.Message}",
                        Model = model
                    };
                }
            }
        }
    }

    public class OllamaResult
    {
        public bool Success { get; set; }
        public string Response { get; set; }
        public string Error { get; set; }
        public string Model { get; set; }
        public TimeSpan Duration { get; set; }
    }
}