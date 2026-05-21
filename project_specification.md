# Introduction to Deep Learning M2177.0043 - Term Project Specification

- **Course:** Introduction to Deep Learning M2177.0043
- **Institution:** Seoul National University
- **Date:** May 13, 2026
- **Due date:** June 8, 2026
- **Document type:** Term Project specification

---

## 1. Task Overview

Modern SSDs include built-in security features such as encryption, authentication, and access control. SSDs that provide such protection are often called **Self-Encrypting Drives (SEDs)**. These features are controlled by SSD security protocol commands.

In this project, the goal is to build a model that checks whether an SSD responds correctly to such commands.

- The input is a **command-response log** collected from an SSD.
- The model inspects the **whole log** and judges the **final response**.
- The output is a test verdict: **PASS** or **FAIL**.

Concretely, the program should read a trajectory from the provided dataset and output one label, `PASS` or `FAIL`, for the final target command.

The key difficulty is that the SSD is **stateful**. The same command may be correct or incorrect depending on what happened earlier, such as:

- whether a session was opened,
- which authority was authenticated,
- whether a protected storage region is locked or unlocked.

Therefore, the model must infer the current SSD state from the previous command-response history before judging the final response.

### Figures in the original PDF

- **Figure 1:** Example SSD command-response trajectory.
- **Figure 2:** PASS/FAIL prediction from a trajectory.

Figure 1 shows an SSD command trajectory: the host sends a command, the SSD returns a response, and this process repeats. Figure 2 summarizes the learning task: the model receives the full trajectory and predicts whether the final response is correct according to the protocol.

---

## 1.1. Key Concepts for This Task

## 1.2. What a Command-Response Record Looks Like

In the dataset, each trajectory consists of command-response records. A **command** is what the host sends to the SSD, and a **response** is what the SSD returns for that command. For TCG security protocol commands, this interaction is represented as an `IF-SEND` / `IF-RECV` pair.

For example, the host may send the following command to start a session:

```text
[Command #55] IF-SEND
Method: StartSession
Invoking ID: 00..00 FF
Args:
SPID: 0000020500000002
Write: 1
```

The SSD may then return the following response:

```text
[Command #55] IF-RECV
Response:
HostSessionID: 00000000
SPSessionID: 00001234
Status: SUCCESS
```

This means that the host requested a `StartSession` operation, and the SSD accepted it by returning `SUCCESS` along with session identifiers. Later commands in the trajectory may depend on these session identifiers and on the state created by this successful response.

A **test verdict** is the tester's judgment of whether that response is allowed by the protocol. The verdict is:

- **PASS** if the response is correct under the current protocol state.
- **FAIL** if the response violates the specification.

Important distinction:

- `PASS` does **not** mean that the SSD returned `SUCCESS`. It means that the SSD returned the correct response.
- `FAIL` does **not** mean that the SSD returned an error. It means that the SSD returned a response that was not allowed by the protocol.

### Example: Same Device Response, Different Verdict

Both examples have the same target command and the same device response: `Set(...)` returns `SUCCESS`. The verdict changes only because the previous authentication state is different.

#### PASS: Authenticated Access

Previous context:

```text
StartSession(LockingSP, Write=0)
-> SUCCESS

Authenticate(Admin, Password)
-> SUCCESS
```

Target command and device response:

```text
Set(Locking::GlobalRange, WriteLocked=True)
-> SUCCESS
```

Reasoning:

- Session was opened.
- Host was authenticated.
- The protected object was modified with proper authority.

Verdict: **PASS**

#### FAIL: Unauthenticated Access

Previous context:

```text
StartSession(LockingSP, Write=0)
-> SUCCESS

// Authenticate not performed
```

Target command and device response:

```text
Set(Locking::GlobalRange, WriteLocked=True)
-> SUCCESS
```

Reasoning:

- Session was opened.
- Host was not authenticated.
- Since this is a protected operation, the SSD should have returned `NOT AUTHORIZED`.

Verdict: **FAIL**

### Stateful Reasoning

The final command usually cannot be judged in isolation. The model should infer the current SSD state from the previous command-response pairs.

Key state variables include:

- **Session state:** Is a valid session currently open?
- **Authentication state:** Has the host authenticated as the required authority?
- **Locking state:** Is the target storage region enabled, locked, or unlocked?

Thus, an error response can be correct, and a `SUCCESS` response can still be a specification violation.

In other words, the model should behave like a **test oracle**:

1. Infer the state.
2. Determine the protocol-required response.
3. Compare it with the actual device response.

### Project Objective

Each team will design a verifier for SSD protocol compliance.

- The verifier receives command trajectories and predicts `PASS` or `FAIL` for the final target command.
- Teams may use deep learning models, LLMs, prompting, retrieval, fine-tuning, rule-based components, or other modeling strategies.
- The main objective is **stateful protocol reasoning**, not simple pattern matching.

---

## 2. Formal Task Definition

A test case is given as a sequence of JSON command-response records:

```text
X = ((c1, r1), (c2, r2), ..., (cN, rN))
```

where each `(ct, rt)` corresponds to a single command execution log. The command `ct` is sent by the host, and `rt` is the response returned by the SSD.

The final pair `(cN, rN)` is the **target command** and its actual response. Only the final response `rN` is evaluated. The previous pairs `(c1, r1), ..., (cN-1, rN-1)` are context for inferring the SSD state.

Given `X`, the goal is to predict:

```text
y ∈ {PASS, FAIL}
```

- **PASS:** the final response is compliant with the specification under the inferred state.
- **FAIL:** the final response violates the specification.

Each team will design a verifier for this binary prediction task. Teams may use deep learning models, LLMs, prompting, retrieval, fine-tuning, rule-based components, or other modeling strategies.

---

## 3. Background: TCG Storage and Test Cases

This section explains how to read the provided test cases and how to connect them to the TCG Storage specifications.

The goal is not to memorize every table in the documents. Instead, focus on:

1. identifying the final target command,
2. tracking the protocol state created by previous commands,
3. checking whether the final response is compliant.

---

## 3.1. Specification Documents at a Glance

The project uses several specification and reference documents.

### TCG Storage Architecture Core Specification

This is the base protocol document. It defines the common architecture and vocabulary:

- Host,
- TPer,
- Security Provider (SP),
- sessions,
- methods,
- tables,
- objects,
- UIDs,
- authorities,
- access control,
- status codes,
- method-call syntax.

### TCG Storage Opal SSC Specification

This specializes the Core Specification for Opal self-encrypting drives. It defines Opal-specific behavior, including:

- Admin SP,
- Locking SP,
- default authorities,
- default credentials,
- locking ranges,
- media encryption keys,
- required Opal features.

### Opal SSC Application Note

This is a workflow-oriented document. It is useful for understanding common scenarios such as:

- taking ownership,
- activating the Locking SP,
- configuring locking ranges,
- invoking `GenKey`,
- reverting the drive.

### README and Dataset Files

These describe:

- the exact JSON format,
- input/output interface,
- file layout,
- submission procedure used in this project.

---

## 3.2. How to Read a TCG Method Call

A TCG command in the dataset is usually represented as a method call. In the Core Specification, a method call is written conceptually as:

```text
<InvokingID>.<MethodName>[
    Required Parameter(s),
    Optional Parameter(s)
]
=>
[ Result ]
```

For this project, interpret the fields as follows.

| Field | Meaning |
|---|---|
| `invoking_id` | The object, table, SP, or session-manager object on which the method is invoked. In other words, it tells what the command is operating on. |
| `method.name` | The method being called, such as `StartSession`, `Get`, `Set`, `Activate`, or `GenKey`. |
| `method.args.required` | Required parameters. These are positional parameters defined by the method signature. |
| `method.args.optional` | Optional parameters. In the Core Specification, optional parameters are encoded as named values. |
| `output.status_codes` | The SSD's actual method-level status, such as `Success`, `NOT AUTHORIZED`, or `INVALID PARAMETER`. |
| `output.return_values` | Values returned by the SSD, such as session identifiers, table values, or other method results. |

### Reference Cue from the Core Specification

The Core Specification explains that a method header consists of an `InvokingID` and a `MethodID`:

- the `InvokingID` identifies the table, object, or SP on which the method operates,
- the `MethodID` identifies the method being invoked.

Optional parameters are submitted after required parameters as named value pairs.

### Example: `Set` on a `C_PIN` Object

The following JSON record invokes `Set` on a `C_PIN` object.

```json
{
  "input": {
    "method": {
      "name": "Set",
      "args": {
        "required": {},
        "optional": {
          "Values": [
            {"0x03": "D0104E65775F5349445F50617373776F7264"}
          ]
        }
      }
    },
    "invoking_id": {
      "uid": "00 00 00 0B 00 00 00 01",
      "name": "C_PIN"
    }
  },
  "output": {
    "return_values": [],
    "status_codes": "Success"
  }
}
```

This should be read as:

> Call `Set` on a `C_PIN` object, write a new value to column `0x03`, and observe that the SSD returned `Success`.

---

## 3.3. Reading Example Test Cases

A test case is a trajectory: a sequence of command-response records. The last record is the target command-response pair. The earlier records are context for inferring the SSD state.

---

## Example 1: TC-3 - Updating the SID Credential

- **File:** `tc3.json`
- **Expected verdict:** `PASS`

TC-3 is a compact credential-update flow. The host opens an Admin SP session, reads the default MSID-related credential value, opens an authenticated SID session, updates the SID PIN, and then tries to open another SID session using the new PIN.

Here:

- `SID` is the owner authority of the drive.
- `C_PIN` denotes a credential object that stores PIN-related values.
- This example tests whether the updated credential takes effect in a later session.

| Step | Command | Actual response |
|---:|---|---|
| 1 | `StartSession(AdminSP, Anybody, Write=1)` | `SUCCESS` |
| 2 | `Get(C_PIN_MSID, col=3)` | `SUCCESS`, returns credential value |
| 3 | `EndSession()` | `SUCCESS` |
| 4 | `StartSession(AdminSP, SID, HostChallenge=[old PIN], Write=1)` | `SUCCESS` |
| 5 | `Set(C_PIN_SID, Values=[new PIN])` | `SUCCESS` |
| 6 | `EndSession()` | `SUCCESS` |
| 7 | `StartSession(AdminSP, SID, HostChallenge=[new PIN], Write=1)` | `SUCCESS` |

### How to Interpret TC-3

The final target command is Step 7: `StartSession` as `SID` using the new PIN. To judge whether the final `SUCCESS` is correct, the verifier must infer the prior state.

Reasoning:

- Step 1 opens an Admin SP session.
- Step 2 reads a credential value from the `C_PIN` table.
- Step 4 opens an authenticated SID session.
- Step 5 updates the SID credential to a new PIN.
- Therefore, Step 7 should succeed when the host authenticates as SID using the new PIN.

Relevant specification cue:

- session startup,
- authority authentication,
- the `C_PIN` credential object,
- how credential updates affect later authentication attempts.

Expected verdict: **PASS**. The final `SUCCESS` is compliant because the SID credential was successfully updated before the final session attempt.

---

## Example 2: TC-20 - GenKey Failure Case

- **File:** `tc20.json`
- **Expected verdict:** `FAIL`

TC-20 tests whether key regeneration changes the media encryption key used for a locking range. The trajectory first performs setup operations such as taking ownership, activating the LockingSP, configuring a locking range, and preparing the associated media key. It then writes a known pattern, reads it back, invokes `GenKey`, and finally reads the same LBA range again.

An SED stores user data encrypted with a media encryption key. If this key is regenerated, old ciphertext should no longer decrypt to the same plaintext pattern. Therefore, after a successful `GenKey`, reading the same LBA range should not return the old pattern. This is the basic idea behind cryptographic erase.

| Step | Command | Actual response |
|---:|---|---|
| 1-32 | Take ownership, activate LockingSP, configure the locking range, and prepare the media key | `SUCCESS` |
| 33 | `Write(LBA=80--87, pattern=0x8E)` | `pass` |
| 34 | `Read(LBA=80--87)` | `Pattern 8E` |
| 35-36 | Open an authenticated Admin1 session and get the media-key object | `SUCCESS` |
| 37 | `GenKey(K_AES_256_Range_Key)` | `SUCCESS` |
| 38 | `EndSession()` | `SUCCESS` |
| 39 | `Read(LBA=80--87)` | `8E` |

The key operation in the JSON looks like this:

```json
{
  "index": 37,
  "input": {
    "method": {
      "name": "GenKey",
      "uid": "00 00 00 06 00 00 00 10",
      "args": {
        "required": {},
        "optional": {}
      }
    },
    "invoking_id": {
      "uid": "00 00 08 06 00 03 00 01",
      "name": "K_AES_256"
    },
    "status_codes": "SUCCESS"
  },
  "output": {
    "return_values": [],
    "status_codes": "SUCCESS"
  }
}
```

The final target record is the read after `GenKey`:

```json
{
  "index": 39,
  "input": {
    "command": "Read",
    "args": {
      "LBA": "80 ~ 87"
    }
  },
  "output": {
    "command": "Read",
    "args": {
      "result": "8E"
    }
  }
}
```

### How to Interpret TC-20

The final target command is not a TCG method. It is a normal data `Read`. However, its correctness depends on the previous TCG method `GenKey`.

Reasoning:

- Step 33 writes `Pattern 8E` to LBA range `80--87`.
- Step 34 confirms that the same pattern can be read back before key regeneration.
- Step 37 invokes `GenKey` on the `K_AES_256` media key object, and the method returns `SUCCESS`.
- Therefore, the verifier should treat the media key regeneration as having occurred.
- After key regeneration, the old ciphertext should no longer decrypt to the original `8E` pattern.

Relevant specification cue:

- The Core Specification describes `GenKey` as an object method used for key creation.
- `GenKey` fills an existing credential/key object with new key material and returns an empty result list.
- Success or failure is determined by the method status code.
- The Core Specification also defines the `K_AES_256` table as storing AES-256 media encryption keys and associated metadata.

Expected verdict: **FAIL**. The device reported `SUCCESS` for `GenKey`, but the old pattern was still readable. This suggests that the media key was not actually regenerated, so the final response is not compliant.

---

## 3.4. Practical Remarks

- **Always identify the final target record.** The label judges only the final response. Earlier records are context.
- **Track state only after successful operations.** If a command failed, do not assume that its intended state change happened.
- **Use symbolic names.** The JSON contains UIDs and byte strings, but the important meaning is often symbolic: `AdminSP`, `LockingSP`, `SID`, `Admin1`, `C_PIN`, `Locking`, or `K_AES_256`.
- **TCG commands can affect later non-TCG data commands.** For example, `GenKey` can change the expected result of a later `Read`, even though the final command is not itself a TCG method.
- **Consult the specification selectively.** For each test case, first identify the method, invoking object, authority, and state variable. Then look up only the relevant Core, Opal SSC, or Application Note sections.

---

## 3.5. Final Reminder: Verdict vs. Device Response

A **device response** is what the SSD actually returned: a status code, returned values, session identifiers, or data-read results.

A **test verdict** asks a different question:

> Was the final response allowed by the specification under the state created by the previous trajectory?

Therefore:

- `SUCCESS` can be `PASS` if success is allowed.
- `SUCCESS` can be `FAIL` if the command should have been rejected or should have produced a different effect.
- An error response can be `PASS` if the error is the correct protocol behavior.
- An error response can be `FAIL` if the command should have succeeded.

---

## 4. Evaluation Criteria

- Final evaluation will be conducted on a private dataset, which includes test scenarios not present in the public dataset or reflected in the leaderboard. Therefore, teams should not perform black-box optimization or attempt to reverse-engineer the leaderboard score.

- The final score will be measured by **accuracy**, defined as the fraction of test cases for which the submitted prediction matches the ground-truth label:

```text
Accuracy = (1 / N) * sum_{i=1}^{N} 1{ y_hat_i = y_i }
```

where:

- `N` is the number of test cases,
- `y_hat_i` is the predicted label for the `i`-th test case,
- `y_i` is the ground-truth label,
- `1{...}` denotes the indicator function.

- Additionally, each team is required to submit a **4-page report** that describes the method and analysis.

---

## 5. Practice Server Usage

In this term project, a practice server is provided for each team. Each practice server has:

- 1 NVIDIA L40S GPU with 48GB GPU memory,
- 24 CPU cores,
- 60GB CPU memory,
- separate storage volumes for the user home directory and workspace.

Each team is assigned a unique IP address and port number for SSH access. The server access information has been announced by email.

### Basic Server Instructions

- Contact TA if there are login issues.
- The base system storage is limited. However, two persistent storage volumes are provided:
  - `/home/student`: 100GB
  - `/workspace`: 1TB
- Important: Files stored under `/home/student` and `/workspace` will be preserved even if the server encounters system issues. Files stored outside these directories may not be recoverable.
- The public dataset is stored in the `/dl2026/dataset` directory on each server.
- Use `/home/student` for personal configuration files, source code, scripts, and small project files.
- Use `/workspace` for datasets, model checkpoints, generated outputs, and other large files.

### Submission Command

To submit the solution, run the following command at the project root directory:

```bash
submit
```

By default, this command submits the current directory.

Additional submission commands:

```bash
submit -n, --job-name <name>
submit -d, --dir <your_directory>
submit --list
```

### Required Submitted Directory Structure

The submitted directory must include:

```text
src/              # solver code
setup.sh          # script for preparing the evaluation environment
pyproject.toml    # dependency information
uv.lock           # dependency lock file
```

Optionally, it may include:

```text
artifacts/        # optional files such as fine-tuned model weights, checkpoints, or generated resources
```

### Important Submission Note

The evaluation server will use a separate evaluator and dataset. Do not assume that files such as `evaluate.py` or `predictions.jsonl` in the local directory will be submitted or used for final grading.

### Local Testing

Teams may test the solution locally before submitting it:

```bash
cd /workspace/project
bash setup.sh
python evaluate.py
```

---

## 6. Submission Policy

- Teams can make regular submissions using the `submit` command.
- The number of submissions per day is limited by the server policy.
- Submission history and current status can be checked with:

```bash
submit --list
```

- Each team can have at most one queued or running job at a time. If a previous job is still queued or running, a new submission will be rejected.

### Evaluation Phases

The evaluation process consists of two phases.

#### 1. Setup Phase

- Runs `setup.sh`.
- Prepares the environment.
- Network access is available.
- Time limit: **20 minutes**.

#### 2. Evaluation Phase

- Runs the evaluator on the dataset.
- Network access is disabled.
- Time limit: **3 hours**.

If either phase exceeds its time limit, the submission will receive zero score.

### Submission Packaging Rules

- The submission script packages only the allowed project files, such as:
  - `src/`,
  - `setup.sh`,
  - `pyproject.toml`,
  - `uv.lock`,
  - optionally `artifacts/`.
- The submission archive may contain large files such as model checkpoints.
- The archive size must not exceed **12GB**.
- Submissions larger than **12GB** will be rejected.
- If additional model weights or data files are used during evaluation, they must be prepared in `setup.sh` or included in `artifacts/`.
- The evaluation phase will run without network access.

### Default Pretrained Models Available on the Evaluation Server

Because the evaluation phase runs without network access, only the following pretrained models will be available by default on the evaluation server. These models will be pre-downloaded into the shared Hugging Face cache by the course staff:

```text
openai/gpt-oss-20b
Qwen/Qwen3.5-{0.8B,2B,4B,9B}
Qwen/Qwen3.5-27B-FP8
Qwen/Qwen3.5-35B-A3B-FP8
google/gemma-4-26B-A4B-it
google/gemma-4-{E2B,E4B,31B}-it
```

Other pretrained models will not be available during evaluation unless they are explicitly included in the submission or downloaded during `setup.sh`.

### Deadline and Conduct

- The submission deadline will be announced separately.
- If a team tries to attack the submission server, the evaluation server, or another team's server, the team will receive a strong penalty.

---

## LLM-Friendly Task Summary

This project is a binary classification / verifier task over SSD command-response trajectories.

The model must:

1. Read a trajectory consisting of command-response JSON records.
2. Treat only the final record as the target to be judged.
3. Use all previous records as context for inferring SSD protocol state.
4. Decide whether the final response was allowed by the specification under that inferred state.
5. Output exactly one verdict: `PASS` or `FAIL`.

Critical reasoning principle:

> The model should judge protocol compliance, not whether the SSD returned `SUCCESS` or an error.

A `SUCCESS` response may be correct or incorrect depending on prior state. An error response may also be correct or incorrect depending on prior state.

