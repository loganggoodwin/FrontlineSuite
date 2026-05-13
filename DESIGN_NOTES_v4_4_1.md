# Frontline Suite v4.4.1 Design Notes

## Goal

Version 4.4.1 is a small but important report-accuracy polish pass. The main goal is to make the Checkup Report smarter when Microsoft Defender is disabled because a third-party antivirus product is installed.

## What changed

### 1. Antivirus-aware report wording

The report now adds an **Antivirus Protection** assessment before the raw Defender details. If Defender appears disabled, the wording no longer treats that as an automatic failure. It explains that this can be normal when a third-party antivirus product is installed and tells the technician to verify the active antivirus product.

### 2. Installed antivirus product inventory

The report now attempts to query Windows Security Center using PowerShell and lists installed antivirus products reported by Windows. This gives the technician more context before deciding whether Defender being disabled is a problem.

### 3. Better recommendations

If Defender is disabled and another antivirus product is detected, the recommendation becomes:

- Verify the third-party antivirus is active.
- Confirm it is updated.
- Confirm it is running normally before completing maintenance.

If no third-party product is detected, the report still flags antivirus protection as needing review.

### 4. Better primary IPv4 selection

The primary IPv4 logic now prefers adapters with a default gateway and DNS servers. It also deprioritizes likely virtual adapters such as VirtualBox, VMware, Hyper-V, Docker, WSL, and host-only interfaces.

## Why this version matters

Customer machines often use third-party antivirus software. A professional report should not imply that protection is missing just because Defender is inactive. This version makes the language more accurate and avoids creating unnecessary concern.

## Recommended next version

I think the next best step is **v4.5.0: Visual Report Polish and Branding**:

- Add the Frontline logo to the HTML report.
- Add report status badges such as Baseline OK, Needs Review, Warning, and Action Needed.
- Add a customer name / ticket number field.
- Add a technician notes box before export.
- Add a final Work Completed section for after-service documentation.
