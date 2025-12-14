# 🎬 CA A2A Demo Materials

This folder contains everything you need to deliver an impressive technical demo of the CA A2A Multi-Agent Document Processing Pipeline.

## 📁 Contents

### Core Files
- **`DEMO_GUIDE.md`** - Complete 15-20 minute demo script with timing
- **`pre-demo-checklist.md`** - 30-minute checklist before demo
- **`demo-script-terminal.txt`** - Copy-paste commands for live demo
- **`setup-demo.ps1`** - Automated demo environment setup

### Demo Documents
Created by `setup-demo.ps1`:
- `documents/good/` - Well-formatted documents (high validation scores)
- `documents/bad/` - Incomplete documents (shows validation features)
- `documents/batch/` - Multiple documents for batch processing demo

## 🚀 Quick Start

### 1. Setup (30 minutes before demo)
```powershell
# Run setup script
.\demo\setup-demo.ps1

# Start agents
python run_agents.py

# Test
python client.py health
```

### 2. During Demo
- Follow `DEMO_GUIDE.md` for script and timing
- Use `demo-script-terminal.txt` for commands
- Reference `pre-demo-checklist.md` if issues arise

## 🎯 Demo Scenarios Available

### Scenario 1: Live Technical Demo (15-20 min)
**Audience**: Developers, architects, DevOps
**Files**: All files in this folder
**Focus**: Architecture, agent collaboration, code, AWS deployment

### Scenario 2: Business Demo (10 min)
**Audience**: Management, stakeholders, non-technical
**Files**: Create `business-demo-script.py` (simplified)
**Focus**: Business value, ROI, use cases

### Scenario 3: Video Demo (5 min)
**Audience**: Asynchronous viewing, marketing
**Files**: Record using `DEMO_GUIDE.md` as script
**Focus**: Quick overview, highlights, call-to-action

## 📊 Demo Flow Overview

```
1. Introduction & Architecture (3 min)
   ├─ Discover agents
   └─ Explain A2A protocol

2. Agent Cards (2 min)
   ├─ Show self-description
   └─ Demonstrate discoverability

3. Health Check (1 min)
   └─ Verify all systems operational

4. Single Document Processing (5 min)
   ├─ Process good document
   ├─ Show logs (agent collaboration)
   ├─ Query database
   └─ Explain each step

5. Status Tracking (2 min)
   └─ Show task lifecycle

6. Batch Processing (3 min)
   └─ Process multiple documents in parallel

7. Validation Intelligence (2 min)
   └─ Process bad document, show scoring

8. Resilience Demo (2 min)
   ├─ Kill an agent
   ├─ Show retry logic
   └─ Restart and succeed

9. AWS Deployment (2 min)
   └─ Show production infrastructure
```

## 🎭 Terminal Setup

You need **4 terminals** for optimal demo:

### Terminal 1: Agent Logs
```bash
python run_agents.py
```
**Purpose**: Show real-time agent collaboration

### Terminal 2: CLI Commands
```bash
python client.py <command>
```
**Purpose**: Execute demo commands

### Terminal 3: Database Queries
```bash
psql -h <rds-endpoint> -U postgres -d postgres
```
**Purpose**: Show data persistence

### Terminal 4: Monitoring (Optional)
```bash
.\scripts\check-deployment-status.ps1
```
**Purpose**: Show AWS infrastructure status

## 📋 Pre-Demo Checklist

Quick version (see `pre-demo-checklist.md` for complete list):

- [ ] Run `.\demo\setup-demo.ps1`
- [ ] Start agents: `python run_agents.py`
- [ ] Test health: `python client.py health`
- [ ] Verify AWS: RDS available, S3 accessible
- [ ] Terminals arranged (2x2 grid)
- [ ] Font size: 14-16pt (visible to audience)
- [ ] Phone on silent
- [ ] Water nearby
- [ ] Backup plan ready

## 🚨 Emergency Recovery

If something breaks during demo:

```powershell
# Restart all agents
pkill -f "python.*agent"
python run_agents.py

# Re-upload demo files
.\demo\setup-demo.ps1

# Check AWS
.\scripts\check-deployment-status.ps1

# Use backup video (if prepared)
```

## 💡 Demo Tips

### Do's ✅
- Practice timing (run through once)
- Increase font sizes
- Explain "why" not just "what"
- Show enthusiasm
- Pause for questions at end of sections
- Have backup plan

### Don'ts ❌
- Don't rush through slides
- Don't apologize for minor glitches
- Don't go over time limit
- Don't skip resilience demo (most impressive!)
- Don't forget to breathe

## 🎤 Common Questions

**Prepare answers for:**
- Why agents vs. monolith?
- How does it scale?
- What about security?
- Cost of running in AWS?
- How long to implement?
- Can it process images/other formats?

See `DEMO_GUIDE.md` for detailed Q&A section.

## 📞 Support

- **Demo issues**: Check `pre-demo-checklist.md`
- **Technical issues**: See `../DOCUMENTATION.md`
- **AWS issues**: See `../AWS_DEPLOYMENT.md`
- **Last resort**: Use backup video

## 🎬 After Demo

### Follow-up Actions
1. Share repository link
2. Provide contact information
3. Send architecture diagram
4. Schedule deeper technical session
5. Ask for feedback

### Demo Recording
If you recorded:
1. Edit highlights (first 5 minutes most interesting)
2. Add title slide and captions
3. Upload to company portal
4. Share link in follow-up email

## 📈 Success Metrics

**A successful demo includes:**
- ✅ All agents working
- ✅ At least one document processed end-to-end
- ✅ Database query showing results
- ✅ Resilience feature demonstrated
- ✅ Positive audience reactions
- ✅ Good questions during Q&A
- ✅ Follow-up interest

## 🚀 Next Steps

After successful demo:
1. Document feedback and questions
2. Improve demo based on lessons learned
3. Create additional demo scenarios if needed
4. Consider creating video version
5. Share success with team

---

**Remember**: The goal is to showcase the technology and generate interest. Have fun and be proud of what you've built! 🎉

**Questions?** Refer to `DEMO_GUIDE.md` for complete instructions.

