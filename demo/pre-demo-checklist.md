# 📋 Pre-Demo Checklist - CA A2A

## ⏰ Timeline: 30 Minutes Before Demo

---

## 🔧 Infrastructure Checks

### AWS Services
- [ ] **RDS Status**: `aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --query 'DBInstances[0].DBInstanceStatus'`
  - Expected: `"available"`
  
- [ ] **S3 Bucket Access**: `aws s3 ls s3://ca-a2a-documents-555043101106/`
  - Should list contents without errors

- [ ] **AWS Profile Set**: `$env:AWS_PROFILE = "AWSAdministratorAccess-555043101106"`
  - Or ensure logged in via SSO

- [ ] **Internet Connection**: Test with `ping 8.8.8.8`

### Local Environment
- [ ] **Python Version**: `python --version` (3.9+)
- [ ] **Dependencies Installed**: `pip list | grep -E "(fastapi|boto3|psycopg2)"`
- [ ] **PostgreSQL Client**: `psql --version` (for database demos)
- [ ] **Git Status Clean**: `git status` (no uncommitted changes)

---

## 📁 Demo Files Setup

- [ ] **Run Setup Script**: `.\demo\setup-demo.ps1`
- [ ] **Verify S3 Upload**: `aws s3 ls s3://ca-a2a-documents-555043101106/demo/`
- [ ] **Local Files Exist**: Check `demo/documents/` folder has files
- [ ] **Demo Commands Ready**: Open `demo/demo-commands.txt`

---

## 🖥️ Terminal Setup

### Terminal 1: Agent Logs
```bash
cd c:\Users\j.benabderrazak\OneDrive - Reply\Bureau\work\CA\A2A\ca_a2a
python run_agents.py
```
- [ ] All 4 agents started successfully
- [ ] No error messages in logs
- [ ] Font size: 14-16pt (visible to audience)
- [ ] Background: Dark theme (easier on eyes)

### Terminal 2: Demo Commands
```bash
cd c:\Users\j.benabderrazak\OneDrive - Reply\Bureau\work\CA\A2A\ca_a2a
```
- [ ] Working directory is project root
- [ ] Font size: 14-16pt
- [ ] Have `demo/demo-script-terminal.txt` open for reference

### Terminal 3: Database Queries
```bash
psql -h ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com -U postgres -d postgres
```
- [ ] Connected to RDS successfully
- [ ] Can run `SELECT * FROM documents LIMIT 1;`
- [ ] Font size: 14-16pt

### Terminal 4: Monitoring (Optional)
```bash
# Watch CloudWatch logs or S3 bucket
```

---

## 🧪 Smoke Tests

Run these to ensure everything works:

### Test 1: Health Check
```bash
python client.py health
```
- [ ] All 4 agents respond "healthy"
- [ ] Response time < 1 second

### Test 2: Agent Discovery
```bash
python discover_agents.py
```
- [ ] Lists all 4 agents
- [ ] Shows skills for each agent

### Test 3: Single Document
```bash
python client.py process "demo/good/financial-report-q4-2024.txt"
```
- [ ] Returns task_id
- [ ] Processing completes successfully
- [ ] Can see in logs
- [ ] Appears in database

### Test 4: Database Query
```sql
SELECT COUNT(*) FROM documents;
```
- [ ] Query executes without error
- [ ] Shows test document(s)

---

## 🎬 Presentation Setup

### Screen Layout
- [ ] **Main Screen**: Terminals arranged in grid (2x2)
- [ ] **Second Screen** (if available): Architecture diagram or slides
- [ ] **Close unnecessary apps**: Email, Slack, notifications
- [ ] **Do Not Disturb Mode**: Enabled on OS

### Materials Ready
- [ ] **Demo Guide**: `demo/DEMO_GUIDE.md` printed or on tablet
- [ ] **Demo Script**: `demo/demo-script-terminal.txt` in separate window
- [ ] **Architecture Diagram**: Open in browser or PowerPoint
- [ ] **Q&A Slide**: Ready to display after demo
- [ ] **Backup Video**: Available if live demo fails
- [ ] **Business Cards**: In pocket

### Audio/Video
- [ ] **Microphone tested**: Can audience hear you?
- [ ] **Screen sharing works**: If virtual demo
- [ ] **Recording started**: If you want to record
- [ ] **Camera positioned**: If using webcam

---

## 🎭 Personal Preparation

### Physical
- [ ] **Water bottle**: Within reach
- [ ] **Comfortable position**: Chair, standing, lighting
- [ ] **Phone on silent**: Notifications off
- [ ] **Restroom break**: Taken before demo

### Mental
- [ ] **Reviewed demo script**: Know the flow
- [ ] **Practiced timing**: 15-20 minutes
- [ ] **Prepared for questions**: Reviewed Q&A section
- [ ] **Backup plan ready**: What if something breaks?
- [ ] **Relaxed and confident**: You got this! 💪

---

## 🚨 Emergency Contacts

### If Things Go Wrong
- **Technical Issue**: Use backup video
- **AWS Down**: Show architecture diagram, explain system
- **Database Locked**: Show logs only, skip DB queries
- **Agent Crashes**: Restart with `python run_agents.py`

### Quick Recovery Commands
```bash
# Restart everything
pkill -f "python.*agent"
python run_agents.py

# Check AWS status
.\scripts\check-deployment-status.ps1

# Verify S3
aws s3 ls s3://ca-a2a-documents-555043101106/demo/
```

---

## ✅ Final 5-Minute Check

**Before audience arrives or shares screen:**

1. [ ] **All terminals running and visible**
2. [ ] **Smoke test passed (health check)**
3. [ ] **Demo files in S3**
4. [ ] **Database accessible**
5. [ ] **Phone on silent**
6. [ ] **Do Not Disturb enabled**
7. [ ] **Water nearby**
8. [ ] **Confident and ready**

---

## 🎯 Demo Day Mindset

**Remember:**
- It's a demo, not a test - things can go wrong
- Your enthusiasm matters more than perfection
- The audience wants you to succeed
- You know this system better than anyone
- Have fun and enjoy showing your work!

---

**GOOD LUCK! 🚀🎬**

*Last checked: _____________*
*Checked by: _____________*

