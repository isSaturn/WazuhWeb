using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using WazuhWeb.Helpers;

namespace YourProject.Services
{

    public static class Ds2ApiService
    {
        private static readonly HttpClient client;

        static Ds2ApiService()
        {
            client = new HttpClient
            {
                BaseAddress = new Uri("http://192.168.1.222:5001/"),
                Timeout = TimeSpan.FromMinutes(10)
            };

            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue(
                    "Bearer",
                    "sk-63001e78d947458ea3669feec5aa5dfd"
                );

            client.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json")
            );
        }

        // =========================
        // CHECK MODEL ONLINE
        // =========================
        public static async Task<string> GetAvailableModelAsync()
        {
            HttpResponseMessage response =
                await client.GetAsync("v1/models");

            response.EnsureSuccessStatusCode();

            string json =
                await response.Content.ReadAsStringAsync();

            dynamic obj = JsonConvert.DeserializeObject(json);

            try
            {
                return obj.data[0].id.ToString();
            }
            catch
            {
                return "unknown";
            }
        }

        // =========================
        // GENERATE AI
        // =========================
        public static async Task<OllamaResult> GenerateAsync(
            string prompt,
            string model = "gpt-5.5"
        )
        {
            Stopwatch sw = Stopwatch.StartNew();

            try
            {
                if (string.IsNullOrWhiteSpace(model))
                {
                    model = await GetAvailableModelAsync();
                }

                var body = new
                {
                    model = model,
                    messages = new[]
                    {
                        new
                        {
                            role = "user",
                            content = prompt
                        }
                    },
                    temperature = 0.3,
                    stream = false
                };

                string json =
                    JsonConvert.SerializeObject(body);

                StringContent content =
                    new StringContent(
                        json,
                        Encoding.UTF8,
                        "application/json"
                    );

                HttpResponseMessage response =
                    await client.PostAsync(
                        "v1/chat/completions",
                        content
                    );

                string result =
                    await response.Content.ReadAsStringAsync();

                sw.Stop();

                if (!response.IsSuccessStatusCode)
                {
                    return new OllamaResult
                    {
                        Success = false,
                        Error = result,
                        Model = model,
                        Duration = sw.Elapsed
                    };
                }

                dynamic obj =
                    JsonConvert.DeserializeObject(result);

                string aiText = "";

                try
                {
                    aiText =
                        obj.choices[0].message.content.ToString();
                }
                catch
                {
                    aiText = result;
                }

                return new OllamaResult
                {
                    Success = true,
                    Response = aiText,
                    Model = model,
                    Duration = sw.Elapsed
                };
            }
            catch (Exception ex)
            {
                sw.Stop();

                return new OllamaResult
                {
                    Success = false,
                    Error = ex.Message,
                    Model = model,
                    Duration = sw.Elapsed
                };
            }
        }

        // =========================
        // RAW POST
        // =========================
        public static async Task<OllamaResult> PostAsync(
            string endpoint,
            object body
        )
        {
            Stopwatch sw = Stopwatch.StartNew();

            try
            {
                string json =
                    JsonConvert.SerializeObject(body);

                StringContent content =
                    new StringContent(
                        json,
                        Encoding.UTF8,
                        "application/json"
                    );

                HttpResponseMessage response =
                    await client.PostAsync(endpoint, content);

                string result =
                    await response.Content.ReadAsStringAsync();

                sw.Stop();

                return new OllamaResult
                {
                    Success = response.IsSuccessStatusCode,
                    Response = result,
                    Error = response.IsSuccessStatusCode
                        ? null
                        : result,
                    Duration = sw.Elapsed
                };
            }
            catch (Exception ex)
            {
                sw.Stop();

                return new OllamaResult
                {
                    Success = false,
                    Error = ex.Message,
                    Duration = sw.Elapsed
                };
            }
        }

        // =========================
        // RAW GET
        // =========================
        public static async Task<OllamaResult> GetAsync(
            string endpoint
        )
        {
            Stopwatch sw = Stopwatch.StartNew();

            try
            {
                HttpResponseMessage response =
                    await client.GetAsync(endpoint);

                string result =
                    await response.Content.ReadAsStringAsync();

                sw.Stop();

                return new OllamaResult
                {
                    Success = response.IsSuccessStatusCode,
                    Response = result,
                    Error = response.IsSuccessStatusCode
                        ? null
                        : result,
                    Duration = sw.Elapsed
                };
            }
            catch (Exception ex)
            {
                sw.Stop();

                return new OllamaResult
                {
                    Success = false,
                    Error = ex.Message,
                    Duration = sw.Elapsed
                };
            }
        }
    }
}