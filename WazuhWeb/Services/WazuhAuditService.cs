using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;
using WazuhWeb.Helpers;
using WazuhWeb.Models;

namespace WazuhWeb.Services
{
    public class WazuhAuditService
    {
        public async Task<List<Agent>> GetAgentsAsync(string token)
        {
            var json = await WazuhApiClient.GetAsync("/agents?limit=500", token);
            var resp = JsonConvert.DeserializeObject<AgentListResponse>(json);
            return resp?.data?.affected_items ?? new List<Agent>();
        }

        public async Task<SyscheckResult> GetSyscheckAsync(string token, string agentId)
        {
            // Files
            var fileJson = await WazuhApiClient.GetAsync($"/syscheck/{agentId}?type=file&sort=-date", token);
            var fileResp = JsonConvert.DeserializeObject<SyscheckListResponse>(fileJson);
            var fileItems = fileResp?.data?.affected_items ?? new List<SyscheckItem>();

            // Registry
            var regJson = await WazuhApiClient.GetAsync($"/syscheck/{agentId}?type=registry_value&limit=500&sort=-date", token);
            var regResp = JsonConvert.DeserializeObject<SyscheckListResponse>(regJson);
            var regItems = regResp?.data?.affected_items ?? new List<SyscheckItem>();

            var result = new SyscheckResult();

            foreach (var item in fileItems)
            {
                var change = new FileChange
                {
                    Path = item.file,
                    PreHash = item.md5,
                    PostHash = item.sha1, // using sha1 as example
                    ChangeType = item.changes <= 1 ? "added" : "modified",
                    Timestamp = item.date
                };
                if (item.changes == 0)
                    result.CreatedFiles.Add(change);
                else if (item.changes == 1)
                    result.ModifiedFiles.Add(change);
                else
                    result.DeletedFiles.Add(change);
            }

            foreach (var item in regItems)
            {
                var rc = new RegistryChange
                {
                    Key = item.file,
                    ValueName = item.value?.name,
                    OldData = item.value?.type,
                    NewData = item.type,
                    Timestamp = item.date
                };
                result.RegistryChanges.Add(rc);
            }

            return result;
        }

        public async Task<ScaPolicy> GetScaAsync(string token, string agentId)
        {
            var json = await WazuhApiClient.GetAsync($"/sca/{agentId}", token);
            var resp = JsonConvert.DeserializeObject<ScaSummaryResponse>(json);
            return resp?.data?.affected_items?.FirstOrDefault();
        }

        public async Task<List<ScaCheck>> GetScaChecksAsync(string token, string agentId, string policyId)
        {
            var json = await WazuhApiClient.GetAsync($"/sca/{agentId}/checks/{policyId}", token);
            var resp = JsonConvert.DeserializeObject<ScaChecksResponse>(json);
            return resp?.data?.affected_items ?? new List<ScaCheck>();
        }

        public async Task<RootcheckResult> GetRootcheckAsync(string token, string agentId)
        {
            var json = await WazuhApiClient.GetAsync($"/rootcheck/{agentId}", token);
            var resp = JsonConvert.DeserializeObject<RootcheckListResponse>(json);
            var items = resp?.data?.affected_items ?? new List<RootcheckItem>();
            return new RootcheckResult { Items = items };
        }
    }
}
