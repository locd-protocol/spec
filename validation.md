# Validation: legacy-bridge-7

You are validating work that was just completed. You have NO memory of how it was built.
Review the code with fresh eyes.

## Task That Was Completed

Integrate with Key Hierarchy module to obtain Tier 2 Device Key and perform HKDF operations within TPM trust boundary. Submit HKDF derivation request to TPM, receive derived key in sealed memory buffer.

## Acceptance Criteria to Verify

- [ ] Task implemented correctly
- [ ] Code follows project conventions

## Validation Steps

1. Read the files that were modified (check git status)
2. Verify each acceptance criterion is actually met in the code
3. Check for obvious bugs, missing error handling, or incomplete implementations
4. Do NOT rewrite or improve the code — only verify it works

## When Validation is Complete

### If ALL criteria are met:
```bash
python3 /mnt/ccm/ccm-code/scripts/major_task_complete.py \
    "$(pwd)" \
    "/mnt/ccm/locd" \
    "legacy-bridge-7" \
    "ccm-worker-legacy-bridge-7" \
    "Validated: legacy-bridge-7" \
    --status done --pm-session "ccm-pm-legacy-bridge"
```

### If criteria are NOT met:
```bash
python3 /mnt/ccm/ccm-code/scripts/major_task_complete.py \
    "$(pwd)" \
    "/mnt/ccm/locd" \
    "legacy-bridge-7" \
    "ccm-worker-legacy-bridge-7" \
    "Validation failed: legacy-bridge-7" \
    --status failed \
    --issues "Describe what failed here" --pm-session "ccm-pm-legacy-bridge"
```

---

**Review the code. Verify the criteria. Call the appropriate script. That's it.**
