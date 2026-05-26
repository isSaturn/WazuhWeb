using System.Collections.Generic;

namespace WazuhWeb.Models
{
    public class AuditResult
    {
        public Agent Agent { get; set; }
        public SyscheckResult Syscheck { get; set; }
        public ScaPolicy Sca { get; set; }
        public List<ScaCheckDetail> ScaChecks { get; set; }
        public RootcheckResult Rootcheck { get; set; }
    }
}
