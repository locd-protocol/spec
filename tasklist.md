# Task: legacy-bridge-7

Integrate with Key Hierarchy module to obtain Tier 2 Device Key and perform HKDF operations within TPM trust boundary. Submit HKDF derivation request to TPM, receive derived key in sealed memory buffer.

## Acceptance Criteria

- Task implemented correctly
- Code follows project conventions

---

## Workflow

### Stage 0: Plan
1. Explore the codebase to understand the current state
2. Write your implementation plan — what files you'll create/modify and what changes
3. Save your plan:

```bash
cat > plan.md << 'PLAN'
# Plan: legacy-bridge-7

## Files to modify
- [list files]

## Changes
- [describe each change]

## Approach
[brief approach description]
PLAN
```

4. Notify the PM for review:

```bash
tmux send-keys -t ccm-pm-legacy-bridge "PLAN_READY ccm-worker-legacy-bridge-7 $(pwd)/plan.md" && sleep 3 && tmux send-keys -t ccm-pm-legacy-bridge C-m
```

5. **STOP. Wait for the PM to respond.** Do NOT proceed until you receive a message.

### Stage 1: Build
After the PM approves your plan, implement it. When done, run:

```bash
python3 /mnt/ccm/ccm-code/scripts/minor_task_complete.py \
    "$(pwd)" \
    "ccm-worker-legacy-bridge-7" \
    "Build complete: legacy-bridge-7" \
    --continue-with "Read and execute validation.md"
```

This commits your work, clears context, and loads the validation stage.

### Stage 2: Validate
After the clear, you will be asked to read validation.md.
Follow its instructions to validate your work.

---

**Start with Stage 0. Write your plan, notify the PM, then wait.**
