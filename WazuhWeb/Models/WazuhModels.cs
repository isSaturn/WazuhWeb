using System;
using System.Collections.Generic;

namespace WazuhWeb.Models
{
    // ─── AGENT ───────────────────────────────────────────────────────────────────

    public class AgentListResponse
    {
        public AgentData data { get; set; }
        public int error { get; set; }
    }

    public class AgentData
    {
        public List<Agent> affected_items { get; set; }
        public int total_affected_items { get; set; }
    }

    public class Agent
    {
        public string id { get; set; }
        public string name { get; set; }
        public string ip { get; set; }
        public string status { get; set; }
        public string version { get; set; }
        public string manager { get; set; }
        public string node_name { get; set; }
        public string lastKeepAlive { get; set; }
        public string dateAdd { get; set; }
        public AgentOs os { get; set; }
        public List<string> group { get; set; }
    }

    public class AgentOs
    {
        public string name { get; set; }
        public string version { get; set; }
        public string platform { get; set; }
        public string arch { get; set; }
    }

    // ─── SYSCHECK ────────────────────────────────────────────────────────────────

    public class SyscheckListResponse
    {
        public SyscheckData data { get; set; }
        public int error { get; set; }
    }

    public class SyscheckData
    {
        public List<SyscheckItem> affected_items { get; set; }
        public int total_affected_items { get; set; }
    }

    public class SyscheckItem
    {
        public string file { get; set; }
        public string type { get; set; }
        public string date { get; set; }
        public string md5 { get; set; }
        public string sha1 { get; set; }
        public string sha256 { get; set; }
        public long? size { get; set; }
        public int changes { get; set; }
        public string arch { get; set; }
        public RegistryValue value { get; set; }
        public string changeType { get; set; }
    }

    public class RegistryValue
    {
        public string name { get; set; }
        public string type { get; set; }
    }

    public class SyscheckViewModel
    {
        public List<SyscheckItem> Files { get; set; } = new List<SyscheckItem>();
        public List<SyscheckItem> Registries { get; set; } = new List<SyscheckItem>();
        public int TotalFiles { get; set; }
        public int TotalRegs { get; set; }
        public string AgentId { get; set; }
        // Filter
        public string DateFrom { get; set; }
        public string DateTo { get; set; }
    }

    // ─── SCA ─────────────────────────────────────────────────────────────────────

    public class ScaChecksResponse
    {
        public ScaChecksData data { get; set; }
        public int error { get; set; }
    }

    public class ScaChecksData
    {
        public List<ScaCheck> affected_items { get; set; }
        public int total_affected_items { get; set; }
    }

    public class ScaCheck
    {
        public int id { get; set; }
        public string title { get; set; }
        public string result { get; set; }
        public string description { get; set; }
        public string rationale { get; set; }
        public string remediation { get; set; }
        public string command { get; set; }
        public string reason { get; set; }
        public string policy_id { get; set; }
        public string condition { get; set; }
        public List<ComplianceItem> compliance { get; set; }
        public List<ScaRule> rules { get; set; }
    }

    public class ComplianceItem
    {
        public string key { get; set; }
        public string value { get; set; }
    }

    public class ScaRule
    {
        public string rule { get; set; }
        public string type { get; set; }
    }

    public class ScaPageViewModel
    {
        public ScaPolicy Policy { get; set; }
        public List<ScaCheck> Checks { get; set; } = new List<ScaCheck>();
        public string AgentId { get; set; }
        // Filter (SCA dùng end_scan date)
        public string DateFrom { get; set; }
        public string DateTo { get; set; }
    }

    // ─── ROOTCHECK ───────────────────────────────────────────────────────────────

    public class RootcheckListResponse
    {
        public RootcheckData data { get; set; }
        public int error { get; set; }
    }

    public class RootcheckData
    {
        public List<RootcheckItem> affected_items { get; set; }
        public int total_affected_items { get; set; }
    }

    public class RootcheckItem
    {
        public string log { get; set; }
        public string status { get; set; }
        public string date_first { get; set; }
        public string date_last { get; set; }
        public string pci_dss { get; set; }
    }

    public class RootcheckViewModel
    {
        public List<RootcheckItem> Items { get; set; } = new List<RootcheckItem>();
        public int Total { get; set; }
        public string AgentId { get; set; }
        public string DateFrom { get; set; }
        public string DateTo { get; set; }
    }

    // ─── SCA POLICY SUMMARY ──────────────────────────────────────────────────────

    public class ScaSummaryResponse
    {
        public ScaSummaryData data { get; set; }
        public int error { get; set; }
    }

    public class ScaSummaryData
    {
        public List<ScaPolicy> affected_items { get; set; }
    }

    public class ScaPolicy
    {
        public string policy_id { get; set; }
        public string name { get; set; }
        public int pass { get; set; }
        public int fail { get; set; }
        public int invalid { get; set; }
        public int total_checks { get; set; }
        public int score { get; set; }
        public string end_scan { get; set; }
        public string start_scan { get; set; }
    }
}