using System.Collections.Generic;

namespace WazuhWeb.Models
{
    // Represents detailed information for a single SCA check
    public class ScaCheckDetail
    {
        public int id { get; set; }
        public string title { get; set; }
        public string result { get; set; }
        public string description { get; set; }
        public string rationale { get; set; }
        public string remediation { get; set; }
        public string command { get; set; }
        public string condition { get; set; }
        public List<ComplianceItem> compliance { get; set; }
        public List<ScaRule> rules { get; set; }
    }

    // Represents the Rootcheck scan result container
    public class RootcheckResult
    {
        public List<RootcheckItem> Items { get; set; } = new List<RootcheckItem>();
    }
}
