using System.Collections.Generic;

namespace WazuhWeb.Models
{
    public class SyscheckResult
    {
        // Files changed
        public List<FileChange> CreatedFiles { get; set; } = new();
        public List<FileChange> ModifiedFiles { get; set; } = new();
        public List<FileChange> DeletedFiles { get; set; } = new();
        // Registry changes
        public List<RegistryChange> RegistryChanges { get; set; } = new();
    }

    public class FileChange
    {
        public string Path { get; set; }
        public string PreHash { get; set; }
        public string PostHash { get; set; }
        public string ChangeType { get; set; } // added, modified, deleted
        public string Timestamp { get; set; }
    }

    public class RegistryChange
    {
        public string Key { get; set; }
        public string ValueName { get; set; }
        public string OldData { get; set; }
        public string NewData { get; set; }
        public string Timestamp { get; set; }
    }
}
