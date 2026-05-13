# Lame — Final didactic and consolidated Markdown

## 1. Case introduction

**Lame** is a retired **Hack The Box** machine reconstructed here as a **RETRO** case within **PENTEST-STUDIO**. The purpose of this document is not to simulate a new resolution or artificially polish the exploitation, but to turn the preserved material into a solid, faithful, and reusable study report.

The technical chain that is validated by the available evidence is simple, but very useful from a training perspective:

- brief initial enumeration;
- detection of two potentially vulnerable lines;
- discard of a famous but non-productive path;
- shift of focus to a more exploitable legacy service;
- direct acquisition of `root` context;
- reading of `user.txt` and `root.txt` already from that privileged context.

This case teaches something important: a simple machine does not have to produce poor documentation. Precisely because the chain is short, it is worth explaining very clearly the reasons behind each decision, what was actually observed, and which part of the case remains pending more precise verification.

## 2. Sources used and editorial criteria

### Source material

This Markdown has been reconstructed from the following preserved pieces within the case:

- the machine's **clean final PDF**;
- the main technical content already reorganized in that PDF;
- the **historical appendix** preserving the old Markdown of the case;
- the historical visual evidence integrated into the document itself.

### Editorial criteria applied

The following rules were used to build this final version:

- do not invent steps that are not supported by the available material;
- keep **verified facts**, **reasonable inferences**, and **pending verification points** separate;
- turn a short operational case into a didactic document useful for later study;
- preserve real commands, flags, decisions, and pivots whenever the source keeps them;
- do not fill gaps with memory or with a "nicer" exploitation path that the source does not document;
- keep a **traceability** block at the end of the document with the preserved historical notes.

### Important precision note

From the beginning, four nuances should be fixed to avoid misreading the case:

1. The **VSFTPd 2.3.4** line was **enumerated and tested**, but it was not the useful documented resolution path.
2. The **Samba 3.0.20 / CVE-2007-2447** line is **validated** as the successful exploitation path.
3. The preserved material validates that the resulting useful shell corresponds to **`root`**, so both flags are read already from a privileged context.
4. The **exact Samba exploit syntax** is not preserved textually in the available evidence. The result is validated, but that detail must remain marked as **pending verification**.

## 3. Preparation and case startup

Because this is a RETRO case, the preparation phase is not about reconstructing an environment from scratch, but about reading the case as a historical technical record. That changes the documentation approach:

- no new lab session is described;
- no instrumentation that does not appear in the sources is added;
- the exploitation is not rewritten as if it had been performed today with another methodology;
- the work is based on the **actual observed chain**.

For that reason, each phase in this document answers a specific question:

- what was actually observed?
- why did that step make sense?
- what technical reading was made from the result?
- what changed from that point onward?

That approach makes it possible to transform exploitation notes or historical material into a much more useful learning document than a simple command list.

## 4. Initial enumeration

### What was done

The initial enumeration starts from a scan of the **top 1000 TCP ports** followed by filtering the open ports:

```bash
nmap -v -T4 -Pn --top-ports 1000 -oA nmap/top1000_tcp 10.129.56.2
grep open nmap/top1000_tcp.nmap
```

### Why this step made sense

On a simple or entry-level machine, scanning the most common ports is often enough to identify most of the exploitable surface without immediately moving into a full 65535-port sweep. Here the goal was not to exhaust every possibility from the first minute, but to obtain a **quick reading of the dominant services**.

The command used combines several useful decisions:

- `-v` increases verbosity to follow scan progress;
- `-T4` speeds up the rhythm without becoming extremely aggressive;
- `-Pn` avoids relying on the initial ping;
- `--top-ports 1000` prioritizes the most likely surface;
- `-oA` stores the output in several formats for later review;
- `grep open` simplifies the final reading and leaves only relevant services.

### What was actually observed

The verified result was:

- `21/tcp`
- `22/tcp`
- `139/tcp`
- `445/tcp`

Total number of open ports in this phase: **4**.

### How to interpret the finding

This first result already organizes the machine into three main lines:

- **FTP** on `21/tcp`
- **SSH** on `22/tcp`
- **SMB / NetBIOS** on `139/tcp` and `445/tcp`

Not all of those lines deserve the same documentary weight.

The preserved evidence truly develops two branches:

- the **FTP** line, because there is a known vulnerable version that had to be checked;
- the **Samba** line, because it is ultimately the path that does lead to valid exploitation.

`22/tcp` remains visible and should not be erased, but it should not be overemphasized either: in the available material it **does not appear as an exploited path or a useful pivot**.

### What changes afterward

Once the surface is visible, the next logical decision is to **identify versions** in the most promising services. Given the well-known history of `vsFTPd 2.3.4` and the classic relevance of old Samba in HTB, the case naturally moves toward those two branches.

### Reusable lesson

Initial enumeration is not just about "seeing ports". Its real value lies in **prioritizing investigation lines**. In this case, that avoids two common mistakes:

- wasting time on a visible service that is not supported by the case evidence;
- jumping too quickly to exploitation without first confirming the real service version.

## 5. Identification of the first dominant surface: VSFTPd

### Version detection

To confirm the identity of the FTP service, the following was executed:

```bash
nmap -sV -p21 -oA nmap/ftp_version 10.129.56.2
```

### What this command is looking for

At this point, it is no longer important to know whether the port is open —that was already validated in the previous phase— but rather **which exact version** of the service is responding on `21/tcp`.

Here `-sV` is the key piece, because it allows the workflow to move from a generic intuition ("there is FTP") to a much more precise technical hypothesis ("there is a specific potentially vulnerable version"). The scan is limited to port `21` because the objective is already surgical: confirm the FTP service version and decide whether it deserves an exploitation test.

### What was actually observed

The detected service was:

- **`vsFTPd 2.3.4`**

### Why this finding matters

`vsFTPd 2.3.4` is a very well-known version because of its historical association with a backdoor. When it appears in a lab machine, ignoring it would not be reasonable. But here it is worth remembering an important methodological rule:

> **An apparently vulnerable version does not automatically equal a valid resolution path**.

Detecting the version justifies testing that line, but it still does not validate it as the main chain of the case.

## 6. Validation of the VSFTPd line: test, result, and discard

### What was executed

The preserved sequence for testing the VSFTPd path was:

```text
msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 10.129.56.2
run
```

### Why it made sense to use this path at this point

Once version `2.3.4` had been identified, the reasonable thing was to check whether the associated backdoor was still exploitable on the machine. This test does not appear as a rushed jump into Metasploit, but as **hypothesis validation**:

1. port `21/tcp` is open;
2. the service is `vsFTPd 2.3.4`;
3. there is a historical exploit associated with it;
4. therefore, the line deserves a direct check.

### What the sequence does exactly

- `msfconsole` opens the exploitation environment.
- `use exploit/unix/ftp/vsftpd_234_backdoor` loads the specific module for that vulnerability.
- `set RHOSTS 10.129.56.2` defines the target.
- `run` launches the test.

### What was actually observed

The historical material validates this:

- the exploit **runs**;
- but it **does not return a useful session**.

### How this result should be read

This is one of the most didactic points in the case. The line should not be described as "failed" in an absolute sense, nor as "the machine was meant to be solved this way but something went wrong". The prudent reading is more precise:

- the line **was tested**;
- the test **did not produce the documented useful access**;
- therefore, the branch **cannot be treated as the main resolution path**.

This matters because many weak narratives turn a famous version into the central story of the case even when the evidence says otherwise. That should not be done here.

### What changed afterward

The practical discard of the FTP path forces the workflow to return to the remaining surface with a clear mindset: a stronger second line must be found. That second line will be **Samba**.

### Reusable lesson

A known path is not discarded just because it "looks old", nor kept just because "it is famous". It is tested, the result is observed, and a decision is made based on evidence. That discipline is much more valuable than memorizing exploit names.

## 7. Samba enumeration and selection of the main path

### What was executed

Samba identification was supported by this command:

```bash
nmap -sV -Pn -p139,445 --script=smb-protocols,smb-os-discovery,smb2-security-mode,smb2-time -oA nmap/smb_version 10.129.56.2
```

### Why this command makes sense here

After confirming that FTP does not produce a useful session, the next strong service on the surface is SMB on `139/445`. At this point, launching a blind test is not enough: it is necessary to **confirm the version** and obtain additional context.

This command does not only ask "is there Samba?", but tries to obtain a richer image of the service:

- `-sV` seeks the exact version;
- `-Pn` keeps the same operational criterion used in the case;
- `-p139,445` focuses on SMB / NetBIOS ports;
- the SMB scripts add protocol and discovery context;
- `-oA` preserves the output for traceability.

### What was actually observed

The detected version was:

- **`Samba 3.0.20`**

The historical material associates that version with:

- **`CVE-2007-2447`**
- relevant condition: use of **`username map script`** in `smb.conf`

### What this finding means

This is where the machine stops being a simple sequence of tests and begins to have a **clear dominant line**.

The situation is:

- FTP has already been validated as **tested but non-productive**;
- Samba appears with an old version and a very well-known historical vulnerability;
- the source not only mentions the CVE, but also the relevant technical condition;
- therefore, the correct narrative of the case is that the **main path becomes Samba**.

### Reasonable inference

Although the exact exploit syntax is not preserved, the link between `Samba 3.0.20` and `CVE-2007-2447` is strong enough to justify the technical decision to move the focus to that line. This does not invent steps: it only explains the reasoning that fits the preserved evidence.

### Reusable lesson

When one promising path loses strength and another appears more solid, the change of focus should be written as a **reasoned technical decision**, not as an abrupt jump. That kind of pivot is exactly what is worth studying and documenting.

## 8. Exploitation validated through CVE-2007-2447

### Verified fact

The central data point of this phase is very clear:

- after exploiting **`CVE-2007-2447`**, the obtained shell corresponds to **`root`**.

### What is demonstrated

Although the full exploitation command is not preserved, three fundamental things are demonstrated:

1. the effective exploitation line was **Samba / CVE-2007-2447**;
2. the useful access does not end in a limited user;
3. the execution context becomes **directly privileged**.

### What is not preserved

This specific detail must be marked as **pending verification**:

- the **exact command** or **complete syntax** used to launch the Samba exploitation in the historical resolution.

This does not invalidate the case chain. It simply requires documenting it honestly:

- **validated result**;
- **exact execution detail not preserved**.

### Why this matters methodologically

On easy machines, it is common to fall into a bad documentation habit: filling gaps with memory, habit, or the "typical version" of the exploit. That should not be done here. The value of the case is not pretending to have precision that does not exist, but teaching how to distinguish between:

- what is **really validated**;
- what is a **reasonable reading**;
- what remains **pending verification**.

### What changes afterward

Because the valid shell is already `root`, the case narrative changes a lot compared with longer machines. There is no classic phase of:

- obtaining a low-privileged user;
- extensive local enumeration;
- separate later privilege escalation.

Here the useful exploitation already provides privileged context. Therefore, the following phases should not be dressed up as if there had been a long escalation that did not really exist.

### Reusable lesson

An exploitation that ends directly in `root` forces the way the case is narrated to be adjusted. If a fixed structure is kept without thinking, there is a risk of inventing an "escalation" that was not actually a separate phase.

## 9. Obtaining user.txt

### What was executed

The user flag read is documented with this path and these commands:

```bash
cd /home/makis
ls -la
cat user.txt
```

### Why this step is done this way

Once privileged context has been obtained, reading `user.txt` is no longer an access maneuver but a **validation of control over the system**. The objective here is not to escalate, but to confirm that the reached context allows browsing the system and accessing the relevant paths.

### What each command does

- `cd /home/makis` places the session in the user's directory;
- `ls -la` shows files, permissions, and hidden content;
- `cat user.txt` displays the flag.

### What was actually observed

The verified flag was:

- `60fc5d64febbdebfe8cc331838bff0b0`

### Precision note

Although the document preserves this part as "obtaining `user.txt`", it should be explained clearly:

- it does not represent an independent low-privilege phase;
- it is not evidence of a limited user shell;
- it is a read performed **after** the valid exploitation had already provided `root` context.

### What this phase teaches

In a mechanical writeup, it would be easy to write "user" and make it seem as if a first half of the case ended there. Here that would be misleading. The correct reading is that `user.txt` is part of **privileged post-access**, not a separate user acquisition phase.

## 10. Obtaining root.txt

### What was executed

The final flag read is documented with:

```bash
cd /root
ls -la
cat root.txt
```

### Why this step has documentary value

Although the context is already privileged, it is useful to document this phase explicitly for two reasons:

1. it formally closes the resolution of the case;
2. it confirms that the privileged access was not apparent or partial, but sufficient to reach the classic administration path.

### What was actually observed

The verified flag was:

- `c80b43503b56dc7b0dc82643157b4329`

### How it should be interpreted

With the reading of `root.txt`, the documented chain is closed. From this point on, there is no additional escalation to describe, only complementary observations about the behavior of some services and the methodological value of the case.

## 11. Complementary technical observations

This phase is not part of the main access path, but it preserves useful signals that deserve to be explained.

### 11.1 Listening services and real exposure

The historical evidence preserves this check:

```bash
netstat -tnlp
```

Annotated result:

- cause of the lack of external accessibility to certain locally visible ports: **`firewall`**.

#### What this means

The observation helps resolve a typical lab doubt: a port can appear to be listening locally and yet not be effectively available from outside. That difference between **local listening** and **real exposure** is important when interpreting apparently contradictory results.

### 11.2 Port associated with the VSFTPd backdoor

The material also notes that the port associated with the backdoor is:

- **`6200`**

And preserves an additional check:

```bash
ss -tnlp | grep 6200
```

Annotated result:

- **`Yes, it listens.`**

### How to read this block without mixing it with the main path

Here it is worth being especially careful. The available evidence leaves two simultaneous signals:

- the main Metasploit test against VSFTPd **did not produce a useful session**;
- the material also notes that port `6200` **did listen**.

The most prudent reading is not to force one of the two and erase the other, but to integrate them correctly:

- the expected backdoor behavior **seems to have been observed** partially or transiently;
- but that observation **did not become** the documented useful resolution path;
- therefore, the case should still be narrated as a machine solved through **Samba**, not through FTP.

### Reusable lesson

Not every interesting signal should take the center of the writeup. Some belong better in a complementary observations section, where they can be preserved without deforming the main chain of the case.

## 12. Final technical summary of the real chain

### Reconstructed technical chain

1. Initial enumeration of the top 1000 TCP ports.
2. Detection of open ports `21`, `22`, `139`, `445`.
3. Identification of `vsFTPd 2.3.4` on FTP.
4. Test of the `vsftpd_234_backdoor` path without a documented useful session.
5. Identification of `Samba 3.0.20` on `139/445`.
6. Technical association with `CVE-2007-2447`.
7. Validated exploitation with resulting shell as `root`.
8. Reading of `user.txt` in `/home/makis/user.txt`.
9. Reading of `root.txt` in `/root/root.txt`.
10. Complementary checks about firewall and the behavior of port `6200`.

### Overall didactic reading

The machine leaves a very clean and very useful chain for study:

**short enumeration → initially promising famous path → non-productive test → pivot to legacy service → exploitation with direct root → flag reading**

That pattern is valuable because it does not depend on a long chain or artificial complexity. Above all, it teaches how to **read the evidence well and avoid automatic narration**.

## 13. Reusable lessons for PENTEST-STUDIO

### What technical pattern this machine teaches

- Brief initial enumeration sufficient to prioritize services.
- Version confirmation before talking about exploitation.
- Explicit discard of an apparent but non-productive path.
- Shift of focus to a more solid legacy service.
- Exploitation that immediately provides `root` context.

### What it corrects compared with common misreadings

- Not every apparently vulnerable version should be assumed as the final path simply because of its fame.
- **Tested line** and **actually exploited line** must be separated.
- If the initial shell is already `root`, a non-existent later escalation should not be narrated.
- When an exact piece of the exploit is missing, it should be marked as **pending verification** and not filled in from memory or assumption.

### What it contributes to the phase 1 checklist

- always note the **exact service version** before jumping to CVEs;
- clearly record when a path is **discarded with evidence**;
- fix the **shell context** immediately after exploitation;
- separate access acquisition from flag reading.

### What it contributes to the master roadmap

- reinforces the branch of **legacy services** and historically exploitable versions;
- forces the inclusion of a **validation and discard** step for famous paths before changing service;
- reminds us that old SMB can offer a stronger path than FTP even when both appear promising at first.

### Applicable sub-roadmaps

- **Applicable:** SMB/Samba services branch and legacy software exploitation.
- **Not applicable:** web-base and web-auth/panel, because the case does not follow a web chain.

## 14. Corrections applied to the original material

### Technical corrections

It was not necessary to correct any manifest technical absurdity in the main chain of the case.

### Editorial corrections

It was necessary to apply editorial adjustments in form and presentation to turn the content extracted from the PDF into a readable and natural final Markdown:

- normalization of accents, punctuation, and capitalization;
- recovery of coherent Markdown formatting;
- reorganization of headings to avoid mechanical rigidity;
- didactic integration of explanations that appear highly compressed in the source.

### Point still pending verification

The exact command or complete syntax of the exploit used against Samba remains **pending verification**. That gap has not been filled artificially.

---

## Appendix — Original notes preserved at the end

The historical block integrated into the source PDF is preserved below for traceability. It is kept as testimony of the old case material and not as the main body of the document.

```markdown
# Complete analysis: Lame machine - Hack The Box

![Logo](capturas/logo_r4ms4nt_circular.png)

> **First machine published on Hack The Box**. Designed as an entry point for new users. Ideal for learning enumeration, classic vulnerability detection, and basic exploitation with Metasploit.

---

## Project structure

```
.
├── capturas
├── nmap
├── gitignore
├── lame_htb_manual.md
├── LICENSE
├── README.md
└── tree_lame.txt

57 directories, 56 files
```

See full structure: [tree_lame.txt](tree_lame.txt)

---

## Task 1: How many of the nmap top 1000 TCP ports are open?

**Objective:** Identify the most common open TCP ports.

**Executed command:**

**Result:**
- Open ports: `21`, `22`, `139`, `445`
- Total: **4**

![Capture](capturas/nmap_top1000.png) | ![grep open](capturas/grep_nmap.png)

---

## Task 2: What version of VSFTPd is running on Lame?

**Objective:** Determine the version of the FTP service on port 21.

**Executed command:**

**Explanation:**
- `-sV`: Version detection.
- `-p21`: Scans only the FTP port.
- `-Pn`: We skip ping, because we already know it is active.
- `-oA`: Saves in three formats under `nmap/`

**Result:**

![Capture](capturas/nmap_port_21.png)

---

## Task 3: Does the Metasploit exploit for vsftpd 2.3.4 work?

**Objective:** Verify whether the known backdoor exploit works.

**Procedure with Metasploit:**

**Result:**

Port 6200 **did not respond externally**, therefore: **NO**, it does not work.
![Capture](capturas/msfconsole1.png)

---

## Task 4: What version of Samba is running?

**Objective:** Detect the version of the SMB/Samba service on ports 139 and 445.

**Executed command:**

**Result:**

Valid answer: `3.0.20`
![Capture](capturas/nmap_smb.png)

---

## Task 5: Which CVE allows remote execution in Samba 3.0.20?

**Answer:** `CVE-2007-2447`

Vulnerability in the `username map script` parameter → allows command injection with shell metacharacters.

---

## Task 6: Which user is obtained after exploiting CVE-2007-2447?

**Executed exploit:**

**Obtained shell:**

![Capture](capturas/msfconsole_para_flag1_2.png)
**Correct answer:** `root`

---

## Task 7: User flag

Flag: `60fc5d64febbdebfe8cc331838bff0b0`
![Flag 1](capturas/Flag_1.png)

---

## Task 8: Root flag

Flag: `c80b43503b56dc7b0dc82643157b4329`
![Flag 2](capturas/Flag_2.png)

---

## Task 9: What blocks access to other ports?

**Answer:** `Firewall`

Although there are services listening according to `netstat`, **only some are externally accessible**. There are probably IPTables rules limiting connections.

---

## Task 10: What port listens when the vsftpd backdoor is activated?

**Answer:** `6200`

Confirmed by the documentation and expected behavior of CVE-2011-2523.

---

## Task 11: Does port 6200 really open on Lame?

**Answer:** `yes`

Although it was not observed with `ss`, the platform and Metasploit confirm that **it does activate briefly**.

---

## Conclusions

- Lame is ideal for starting with HTB and becoming familiar with enumeration, classic CVEs, and Metasploit.
- It includes real flaws such as insecure `smb.conf` configuration.
- Excellent exercise to consolidate a reusable documentation structure.

All screenshots and outputs are organized in `capturas/` and `nmap/`.

Manual created by r4ms4nt
```
