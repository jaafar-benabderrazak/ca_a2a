# 🏷️ CA A2A AWS Tagging Quick Reference

## Standard Tags (Copy & Paste)

### For AWS CLI
```bash
--tags "Key=Project,Value=CA-A2A" "Key=Environment,Value=Production" "Key=Owner,Value=j.benabderrazak@reply.com" "Key=ManagedBy,Value=Terraform" "Key=CostCenter,Value=CA-Reply" "Key=Application,Value=Agent-Based-Architecture" "Key=Version,Value=1.0.0"
```

### For Terraform
```hcl
tags = local.common_tags
```

### For PowerShell
```powershell
$tags = @{
    "Project" = "CA-A2A"
    "Environment" = "Production"
    "Owner" = "j.benabderrazak@reply.com"
    "ManagedBy" = "Terraform"
    "CostCenter" = "CA-Reply"
    "Application" = "Agent-Based-Architecture"
    "Version" = "1.0.0"
}
```

### For JSON (AWS Console)
```json
{
  "Project": "CA-A2A",
  "Environment": "Production",
  "Owner": "j.benabderrazak@reply.com",
  "ManagedBy": "Terraform",
  "CostCenter": "CA-Reply",
  "Application": "Agent-Based-Architecture",
  "Version": "1.0.0"
}
```

---

## Quick Commands

### Tag All Resources
```powershell
.\scripts\tag-specific-resources.ps1
```

### Query by Project
```bash
aws resourcegroupstaggingapi get-resources --region eu-west-3 --tag-filters "Key=Project,Values=CA-A2A"
```

### Count Resources
```powershell
(aws resourcegroupstaggingapi get-resources --region eu-west-3 --tag-filters "Key=Project,Values=CA-A2A" | ConvertFrom-Json).ResourceTagMappingList.Count
```

---

## Agent-Specific Tags

| Agent | AgentName | AgentRole |
|-------|-----------|-----------|
| Orchestrator | `orchestrator` | `coordinator` |
| Extractor | `extractor` | `data-extraction` |
| Classifier | `classifier` | `document-classification` |
| QA Agent | `qa-agent` | `quality-assurance` |

---

## Cost Allocation Tags (Enable in Billing)
- ✅ `Project`
- ✅ `Environment`
- ✅ `CostCenter`
- ✅ `Owner`
- ✅ `Component`
- ✅ `AgentName`

---

**Account**: 555043101106  
**Region**: eu-west-3  
**Owner**: j.benabderrazak@reply.com

