# Agent C Core Methods Full Spec Audit

Scope constraints honored:
- Read only `documents/core/5.3*` document files for normative source material.
- Reviewed implementation in `v6/src/solver.py`, `v6/src/normalizer.py`, `v6/src/state.py`, `v6/src/oracle.py`, `v6/src/spec_docs.py`, and `v6/src/spec_tables.py`.
- Did not edit `v6/src` or any source code.

## 1. Documents Read

Count: 396 document files.

Exact list:

```text
documents/core/5.3.1.1.txt
documents/core/5.3.1.txt
documents/core/5.3.2.1.1.txt
documents/core/5.3.2.1.2.txt
documents/core/5.3.2.1.3.txt
documents/core/5.3.2.1.4.txt
documents/core/5.3.2.1.5.txt
documents/core/5.3.2.1.6.txt
documents/core/5.3.2.1.7.txt
documents/core/5.3.2.1.txt
documents/core/5.3.2.10.txt
documents/core/5.3.2.11.1.txt
documents/core/5.3.2.11.2.txt
documents/core/5.3.2.11.3.txt
documents/core/5.3.2.11.4.txt
documents/core/5.3.2.11.5.txt
documents/core/5.3.2.11.txt
documents/core/5.3.2.12.1.txt
documents/core/5.3.2.12.2.txt
documents/core/5.3.2.12.3.txt
documents/core/5.3.2.12.4.txt
documents/core/5.3.2.12.5.txt
documents/core/5.3.2.12.6.txt
documents/core/5.3.2.12.7.txt
documents/core/5.3.2.12.8.txt
documents/core/5.3.2.12.txt
documents/core/5.3.2.13.1.txt
documents/core/5.3.2.13.10.txt
documents/core/5.3.2.13.11.txt
documents/core/5.3.2.13.12.txt
documents/core/5.3.2.13.13.txt
documents/core/5.3.2.13.14.txt
documents/core/5.3.2.13.15.txt
documents/core/5.3.2.13.2.txt
documents/core/5.3.2.13.3.txt
documents/core/5.3.2.13.4.txt
documents/core/5.3.2.13.5.txt
documents/core/5.3.2.13.6.txt
documents/core/5.3.2.13.7.txt
documents/core/5.3.2.13.txt
documents/core/5.3.2.14.1.txt
documents/core/5.3.2.14.10.txt
documents/core/5.3.2.14.11.txt
documents/core/5.3.2.14.12.txt
documents/core/5.3.2.14.13.txt
documents/core/5.3.2.14.14.txt
documents/core/5.3.2.14.15.txt
documents/core/5.3.2.14.2.txt
documents/core/5.3.2.14.3.txt
documents/core/5.3.2.14.4.txt
documents/core/5.3.2.14.5.txt
documents/core/5.3.2.14.6.txt
documents/core/5.3.2.14.7.txt
documents/core/5.3.2.14.txt
documents/core/5.3.2.15.1.txt
documents/core/5.3.2.15.2.txt
documents/core/5.3.2.15.3.txt
documents/core/5.3.2.15.4.txt
documents/core/5.3.2.15.5.txt
documents/core/5.3.2.15.6.txt
documents/core/5.3.2.15.7.txt
documents/core/5.3.2.15.8.txt
documents/core/5.3.2.15.txt
documents/core/5.3.2.16.1.txt
documents/core/5.3.2.16.2.txt
documents/core/5.3.2.16.3.txt
documents/core/5.3.2.16.4.txt
documents/core/5.3.2.16.5.txt
documents/core/5.3.2.16.6.txt
documents/core/5.3.2.16.7.txt
documents/core/5.3.2.16.8.txt
documents/core/5.3.2.16.txt
documents/core/5.3.2.17.1.txt
documents/core/5.3.2.17.12.txt
documents/core/5.3.2.17.13.txt
documents/core/5.3.2.17.14.txt
documents/core/5.3.2.17.15.txt
documents/core/5.3.2.17.2.txt
documents/core/5.3.2.17.3.txt
documents/core/5.3.2.17.9.txt
documents/core/5.3.2.17.txt
documents/core/5.3.2.18.1.txt
documents/core/5.3.2.18.12.txt
documents/core/5.3.2.18.13.txt
documents/core/5.3.2.18.14.txt
documents/core/5.3.2.18.15.txt
documents/core/5.3.2.18.2.txt
documents/core/5.3.2.18.3.txt
documents/core/5.3.2.18.9.txt
documents/core/5.3.2.18.txt
documents/core/5.3.2.19.1.txt
documents/core/5.3.2.19.12.txt
documents/core/5.3.2.19.13.txt
documents/core/5.3.2.19.14.txt
documents/core/5.3.2.19.15.txt
documents/core/5.3.2.19.2.txt
documents/core/5.3.2.19.3.txt
documents/core/5.3.2.19.9.txt
documents/core/5.3.2.19.txt
documents/core/5.3.2.2.1.txt
documents/core/5.3.2.2.2.txt
documents/core/5.3.2.2.3.txt
documents/core/5.3.2.2.4.txt
documents/core/5.3.2.2.txt
documents/core/5.3.2.20.txt
documents/core/5.3.2.21.1.txt
documents/core/5.3.2.21.12.txt
documents/core/5.3.2.21.13.txt
documents/core/5.3.2.21.14.txt
documents/core/5.3.2.21.15.txt
documents/core/5.3.2.21.2.txt
documents/core/5.3.2.21.3.txt
documents/core/5.3.2.21.9.txt
documents/core/5.3.2.21.txt
documents/core/5.3.2.22.1.txt
documents/core/5.3.2.22.12.txt
documents/core/5.3.2.22.13.txt
documents/core/5.3.2.22.14.txt
documents/core/5.3.2.22.15.txt
documents/core/5.3.2.22.2.txt
documents/core/5.3.2.22.3.txt
documents/core/5.3.2.22.9.txt
documents/core/5.3.2.22.txt
documents/core/5.3.2.23.1.txt
documents/core/5.3.2.23.12.txt
documents/core/5.3.2.23.15.txt
documents/core/5.3.2.23.16.txt
documents/core/5.3.2.23.17.txt
documents/core/5.3.2.23.18.txt
documents/core/5.3.2.23.2.txt
documents/core/5.3.2.23.3.txt
documents/core/5.3.2.23.4.txt
documents/core/5.3.2.23.5.txt
documents/core/5.3.2.23.6.txt
documents/core/5.3.2.23.txt
documents/core/5.3.2.24.1.txt
documents/core/5.3.2.24.10.txt
documents/core/5.3.2.24.13.txt
documents/core/5.3.2.24.14.txt
documents/core/5.3.2.24.15.txt
documents/core/5.3.2.24.16.txt
documents/core/5.3.2.24.2.txt
documents/core/5.3.2.24.3.txt
documents/core/5.3.2.24.txt
documents/core/5.3.2.25.1.txt
documents/core/5.3.2.25.12.txt
documents/core/5.3.2.25.15.txt
documents/core/5.3.2.25.16.txt
documents/core/5.3.2.25.17.txt
documents/core/5.3.2.25.18.txt
documents/core/5.3.2.25.2.txt
documents/core/5.3.2.25.3.txt
documents/core/5.3.2.25.4.txt
documents/core/5.3.2.25.5.txt
documents/core/5.3.2.25.6.txt
documents/core/5.3.2.25.txt
documents/core/5.3.2.26.1.txt
documents/core/5.3.2.26.2.txt
documents/core/5.3.2.26.3.txt
documents/core/5.3.2.26.4.txt
documents/core/5.3.2.26.5.txt
documents/core/5.3.2.26.txt
documents/core/5.3.2.27.1.txt
documents/core/5.3.2.27.2.txt
documents/core/5.3.2.27.3.txt
documents/core/5.3.2.27.4.txt
documents/core/5.3.2.27.5.txt
documents/core/5.3.2.27.txt
documents/core/5.3.2.28.1.txt
documents/core/5.3.2.28.2.txt
documents/core/5.3.2.28.3.txt
documents/core/5.3.2.28.4.txt
documents/core/5.3.2.28.5.txt
documents/core/5.3.2.28.txt
documents/core/5.3.2.29.1.txt
documents/core/5.3.2.29.2.txt
documents/core/5.3.2.29.3.txt
documents/core/5.3.2.29.4.txt
documents/core/5.3.2.29.5.txt
documents/core/5.3.2.29.txt
documents/core/5.3.2.3.1.txt
documents/core/5.3.2.3.10.txt
documents/core/5.3.2.3.11.txt
documents/core/5.3.2.3.12.txt
documents/core/5.3.2.3.13.txt
documents/core/5.3.2.3.2.txt
documents/core/5.3.2.3.3.txt
documents/core/5.3.2.3.4.txt
documents/core/5.3.2.3.5.txt
documents/core/5.3.2.3.6.txt
documents/core/5.3.2.3.7.txt
documents/core/5.3.2.3.8.txt
documents/core/5.3.2.3.9.txt
documents/core/5.3.2.3.txt
documents/core/5.3.2.4.1.txt
documents/core/5.3.2.4.2.txt
documents/core/5.3.2.4.3.txt
documents/core/5.3.2.4.4.txt
documents/core/5.3.2.4.5.txt
documents/core/5.3.2.4.6.txt
documents/core/5.3.2.4.7.txt
documents/core/5.3.2.4.8.txt
documents/core/5.3.2.4.9.txt
documents/core/5.3.2.4.txt
documents/core/5.3.2.5.1.txt
documents/core/5.3.2.5.2.txt
documents/core/5.3.2.5.3.txt
documents/core/5.3.2.5.4.txt
documents/core/5.3.2.5.5.txt
documents/core/5.3.2.5.txt
documents/core/5.3.2.6.1.txt
documents/core/5.3.2.6.2.txt
documents/core/5.3.2.6.3.txt
documents/core/5.3.2.6.4.txt
documents/core/5.3.2.6.txt
documents/core/5.3.2.7.1.txt
documents/core/5.3.2.7.10.txt
documents/core/5.3.2.7.11.txt
documents/core/5.3.2.7.12.txt
documents/core/5.3.2.7.13.txt
documents/core/5.3.2.7.14.txt
documents/core/5.3.2.7.15.txt
documents/core/5.3.2.7.2.txt
documents/core/5.3.2.7.3.txt
documents/core/5.3.2.7.4.txt
documents/core/5.3.2.7.5.txt
documents/core/5.3.2.7.6.txt
documents/core/5.3.2.7.7.txt
documents/core/5.3.2.7.8.txt
documents/core/5.3.2.7.9.txt
documents/core/5.3.2.7.txt
documents/core/5.3.2.8.1.txt
documents/core/5.3.2.8.2.txt
documents/core/5.3.2.8.3.txt
documents/core/5.3.2.8.4.txt
documents/core/5.3.2.8.txt
documents/core/5.3.2.9.1.txt
documents/core/5.3.2.9.2.txt
documents/core/5.3.2.9.3.txt
documents/core/5.3.2.9.4.txt
documents/core/5.3.2.9.5.txt
documents/core/5.3.2.9.txt
documents/core/5.3.2.txt
documents/core/5.3.3.1.1.1.txt
documents/core/5.3.3.1.1.txt
documents/core/5.3.3.1.txt
documents/core/5.3.3.10.txt
documents/core/5.3.3.11.1.txt
documents/core/5.3.3.11.2.txt
documents/core/5.3.3.11.3.1.txt
documents/core/5.3.3.11.3.txt
documents/core/5.3.3.11.4.txt
documents/core/5.3.3.11.txt
documents/core/5.3.3.12.1.txt
documents/core/5.3.3.12.2.txt
documents/core/5.3.3.12.3.1.txt
documents/core/5.3.3.12.3.2.txt
documents/core/5.3.3.12.3.txt
documents/core/5.3.3.12.4.txt
documents/core/5.3.3.12.txt
documents/core/5.3.3.13.1.txt
documents/core/5.3.3.13.2.txt
documents/core/5.3.3.13.3.1.txt
documents/core/5.3.3.13.3.txt
documents/core/5.3.3.13.4.txt
documents/core/5.3.3.13.txt
documents/core/5.3.3.14.1.txt
documents/core/5.3.3.14.2.txt
documents/core/5.3.3.14.3.txt
documents/core/5.3.3.14.4.1.txt
documents/core/5.3.3.14.4.txt
documents/core/5.3.3.14.5.txt
documents/core/5.3.3.14.txt
documents/core/5.3.3.15.1.txt
documents/core/5.3.3.15.2.txt
documents/core/5.3.3.15.3.txt
documents/core/5.3.3.15.4.1.txt
documents/core/5.3.3.15.4.txt
documents/core/5.3.3.15.5.txt
documents/core/5.3.3.15.txt
documents/core/5.3.3.16.1.txt
documents/core/5.3.3.16.2.txt
documents/core/5.3.3.16.3.1.txt
documents/core/5.3.3.16.3.txt
documents/core/5.3.3.16.4.txt
documents/core/5.3.3.16.txt
documents/core/5.3.3.17.1.txt
documents/core/5.3.3.17.2.txt
documents/core/5.3.3.17.3.txt
documents/core/5.3.3.17.4.txt
documents/core/5.3.3.17.5.txt
documents/core/5.3.3.17.6.1.txt
documents/core/5.3.3.17.6.txt
documents/core/5.3.3.17.7.txt
documents/core/5.3.3.17.txt
documents/core/5.3.3.18.1.txt
documents/core/5.3.3.18.2.txt
documents/core/5.3.3.18.3.txt
documents/core/5.3.3.18.4.txt
documents/core/5.3.3.18.5.txt
documents/core/5.3.3.18.txt
documents/core/5.3.3.2.1.txt
documents/core/5.3.3.2.10.txt
documents/core/5.3.3.2.2.txt
documents/core/5.3.3.2.3.txt
documents/core/5.3.3.2.4.txt
documents/core/5.3.3.2.5.txt
documents/core/5.3.3.2.6.txt
documents/core/5.3.3.2.7.txt
documents/core/5.3.3.2.8.txt
documents/core/5.3.3.2.9.1.txt
documents/core/5.3.3.2.9.2.txt
documents/core/5.3.3.2.9.txt
documents/core/5.3.3.2.txt
documents/core/5.3.3.3.1.1.txt
documents/core/5.3.3.3.1.txt
documents/core/5.3.3.3.2.txt
documents/core/5.3.3.3.txt
documents/core/5.3.3.4.1.txt
documents/core/5.3.3.4.2.1.txt
documents/core/5.3.3.4.2.txt
documents/core/5.3.3.4.3.txt
documents/core/5.3.3.4.txt
documents/core/5.3.3.5.1.txt
documents/core/5.3.3.5.2.1.txt
documents/core/5.3.3.5.2.txt
documents/core/5.3.3.5.3.txt
documents/core/5.3.3.5.txt
documents/core/5.3.3.6.1.txt
documents/core/5.3.3.6.2.1.txt
documents/core/5.3.3.6.2.2.txt
documents/core/5.3.3.6.2.txt
documents/core/5.3.3.6.3.txt
documents/core/5.3.3.6.txt
documents/core/5.3.3.7.1.1.txt
documents/core/5.3.3.7.1.2.txt
documents/core/5.3.3.7.1.txt
documents/core/5.3.3.7.2.1.txt
documents/core/5.3.3.7.2.2.txt
documents/core/5.3.3.7.2.txt
documents/core/5.3.3.7.3.txt
documents/core/5.3.3.7.4.txt
documents/core/5.3.3.7.txt
documents/core/5.3.3.8.1.txt
documents/core/5.3.3.8.2.txt
documents/core/5.3.3.8.3.1.txt
documents/core/5.3.3.8.3.txt
documents/core/5.3.3.8.4.txt
documents/core/5.3.3.8.txt
documents/core/5.3.3.9.1.1.txt
documents/core/5.3.3.9.1.2.txt
documents/core/5.3.3.9.1.txt
documents/core/5.3.3.9.txt
documents/core/5.3.3.txt
documents/core/5.3.4.1.1.1.txt
documents/core/5.3.4.1.1.2.txt
documents/core/5.3.4.1.1.txt
documents/core/5.3.4.1.10.txt
documents/core/5.3.4.1.11.txt
documents/core/5.3.4.1.12.txt
documents/core/5.3.4.1.13.txt
documents/core/5.3.4.1.14.1.txt
documents/core/5.3.4.1.14.txt
documents/core/5.3.4.1.2.1.txt
documents/core/5.3.4.1.2.2.txt
documents/core/5.3.4.1.2.3.txt
documents/core/5.3.4.1.2.4.txt
documents/core/5.3.4.1.2.5.txt
documents/core/5.3.4.1.2.txt
documents/core/5.3.4.1.3.txt
documents/core/5.3.4.1.4.txt
documents/core/5.3.4.1.5.txt
documents/core/5.3.4.1.6.txt
documents/core/5.3.4.1.7.txt
documents/core/5.3.4.1.8.txt
documents/core/5.3.4.1.9.txt
documents/core/5.3.4.1.txt
documents/core/5.3.4.2.1.txt
documents/core/5.3.4.2.2.txt
documents/core/5.3.4.2.3.txt
documents/core/5.3.4.2.4.txt
documents/core/5.3.4.2.5.txt
documents/core/5.3.4.2.6.txt
documents/core/5.3.4.2.7.txt
documents/core/5.3.4.2.txt
documents/core/5.3.4.3.1.txt
documents/core/5.3.4.3.2.txt
documents/core/5.3.4.3.3.txt
documents/core/5.3.4.3.txt
documents/core/5.3.4.4.txt
documents/core/5.3.4.5.txt
documents/core/5.3.4.6.txt
documents/core/5.3.4.txt
documents/core/5.3.5.1.txt
documents/core/5.3.5.txt
documents/core/5.3.txt
```

## 2. Key Normative Requirements Relevant To Final-Response Judging

1. Base Template inclusion: all SPs incorporate a subset of Base Template tables and methods (`5.3.1.txt`). The solver should treat these method syntaxes and table schemas as general SP behavior, not only as Opal-specific shortcuts.

2. Table schemas and host mutability: SPInfo, SPTemplates, Table, Column, Type, MethodID, AccessControl, ACE, Authority, Certificates, C_PIN, C_RSA_*, C_AES_*, C_EC_*, C_HMAC_* tables define exact columns. Many UID/name/metadata columns SHALL NOT be host-modifiable. MethodID must be readable by Anybody and not modified. AccessControl rows must not be directly created or deleted by CreateRow/Delete/DeleteRow, only through side effects or DeleteMethod (`5.3.2.*`).

3. Access control model: AccessControl rows bind InvokingID/MethodID to ACL and meta-ACL columns. Empty ACL means the method is not invocable and attempts fail with NOT_AUTHORIZED. Meta-ACL methods AddACE, RemoveACE, GetACL, DeleteMethod must satisfy the matching AddACEACL/RemoveACEACL/GetACLACL/DeleteMethodACL column (`5.3.4.3.txt`, `5.3.4.3.1.txt`).

4. ACE BooleanExpr and Columns: ACE BooleanExpr encodes authorities and boolean operators. Empty BooleanExpr always resolves False. ACE Columns limits access for column-dependent methods; Set fails as a whole when any requested cell is unauthorized, while Get omits unauthorized object-table cells and returns empty results for unauthorized byte-table reads (`5.3.2.9.5.txt`, `5.3.4.2.2.txt`, `5.3.4.2.6.txt`, `5.3.4.3.3.txt`).

5. Authority authentication: class authorities cannot be directly authenticated. Individual authority authentication also authenticates its class, and one level of class nesting is valid. Anybody is always authenticated in a session and Authenticate(Anybody) succeeds if syntax is valid (`5.3.4.1.2.txt`, `5.3.4.1.2.1.txt`).

6. Authority Operation roles: Password/Sign/SymK/HMAC authorities are signing authorities for StartSession and are explicitly authenticatable; Exchange/TPerExchange are exchange authorities and are not explicitly authenticatable; TPerSign is only valid as SPSigningAuthority. Role mismatches in session startup are errors (`5.3.4.1.3.txt`).

7. Disabled and locked authorities: disabled authorities are not authenticatable. Disabled authority during session startup gives NOT_AUTHORIZED; disabled authority via Authenticate gives SUCCESS with Success=False. Once authenticated, disabling does not remove the current session authority. C_PIN TryLimit/Tries lockout applies to session startup and Authenticate; successful authentication or successful PIN modification by GenKey/Set/SetPackage resets Tries to 0 (`5.3.4.1.4.txt`, `5.3.4.1.1.2.txt`).

8. Authenticate method state machine: Password and Anybody authentication are single-call flows. Sign/SymK/HMAC are two-call challenge-response flows. Awaiting Challenge invalid syntax returns INVALID_PARAMETER. Awaiting Challenge Response must use the same authority; correct proof returns SUCCESS True, incorrect/invalid returns SUCCESS False, and the state returns to Awaiting Challenge (`5.3.3.12.*`, `5.3.4.1.14.txt`, `5.3.4.1.14.1.txt`).

9. Session startup: StartSession selects host/SP control authorities by HostSigningAuthority, HostExchangeAuthority, SPSigningAuthority, and SPExchangeAuthority precedence. If StartSession fails, the response is a SyncSession-shaped method response with HostSessionID/SPSessionID and non-success status. If startup completes, invoked authorities are considered authenticated (`5.3.4.1.5.txt`, `5.3.4.1.10.txt`).

10. Secure messaging/hash/sign/certificate startup requirements: Secure column, HashAndSign, session key exchange, and PresentCertificate impose startup requirements. Where traces expose these parameters, missing or wrong secure-messaging/hash/certificate material should affect compliance; otherwise cryptographic correctness is generally not executable from structural traces (`5.3.2.10.txt`, `5.3.4.1.6.txt` through `5.3.4.1.13.txt`).

11. Basic table methods: CreateTable requires NewTableName, Kind, GetSetACL, Columns, MinSize; byte-table Columns must be empty and MaxSize/HintSize on byte tables are INVALID_PARAMETER. CreateRow is unavailable on byte tables, requires all column values, enforces unique columns, and creates AccessControl rows/ACE side effects. Delete/DeleteRow have all-or-fail deletion semantics and must not delete Column, MethodID, AccessControl, or LogList rows directly. GetFreeSpace/GetFreeRows return capacity data or fail when the target table/SP does not exist (`5.3.3.2.*` through `5.3.3.10.txt`, `5.3.4.2.1.txt` through `5.3.4.2.5.txt`).

12. Get method: invalid Cellblock shape, row/table values on object methods, column values on byte tables, and out-of-bounds cells fail. Object-table RowValues must be in Column-table order. Unauthorized object-table cells are omitted, not a method error; unauthorized byte-table reads return an empty result list (`5.3.3.6.*`, `5.3.4.2.2.txt`).

13. Set method: object Set must omit Where; object-table Table.Set must use Where UID; byte-table Set must use Where Row if present. Values must be RowValues for objects/object tables and Bytes for byte tables. Missing Values succeeds with no effect. Duplicate columns in RowValues fail INVALID_PARAMETER. Any unauthorized cell makes the whole Set fail NOT_AUTHORIZED (`5.3.3.7.*`, `5.3.4.2.6.txt`).

14. Next method: valid only on object tables. Where is a uidref if present; Count is uinteger; omitted Count iterates to the end; omitted Where starts at the first row. Ordering is only required to remain consistent while the object table is unmodified (`5.3.3.8.*`, `5.3.4.2.7.txt`).

15. GenKey: valid target credential tables include C_AES_*, K_AES_*, C_EC_*, C_PIN, C_RSA_*, C_HMAC_*. It returns empty result and status controls success/failure. PublicExponent is only valid for C_RSA_*; PinLength only for C_PIN; PinLength defaults to 32 and maximum is 32. GenKey on C_PIN stores a generated PIN using CharSet rules and resets Tries (`5.3.3.16.*`, `5.3.4.1.1.1.txt`, `5.3.4.1.1.2.txt`).

16. GetPackage/SetPackage: target credential objects, wrapping/signing keys must be valid credentials, and GetPackage should only succeed when access control is also fulfilled for WrappingKey.Encrypt and SigningKey.Sign. SetPackage verifies/decrypts package material, writes key columns, and for C_PIN follows PIN-modification Try reset behavior (`5.3.3.17.*`, `5.3.3.18.*`, `5.3.4.5.txt`).

17. SP lifecycle: a Base Template SP in Disabled cannot perform user-invoked SP operations except Authenticate, DeleteSP, and Set used to re-enable it. Frozen or Disabled-Frozen SPs fail session startup (`5.3.2.1.7.txt`, `5.3.5.1.txt`).

18. Logging sections are mostly not final-response executable unless the trace exposes log-table side effects. Default logging settings alone do not change method success status (`5.3.4.6.txt`).

## 3. Implementation Coverage Assessment

High-level dispatch:
- `Solver.predict` and `Solver.predict_one` return lowercase `pass`/`fail` strings and judge only the final event after `track_state(events[:-1])` (`v6/src/solver.py:52`, `v6/src/solver.py:63`).
- `normalizer.normalize_record` extracts method names, invoking object/family, required/optional parameters, status, Cellblock, Values, Count, Where, authority, proof/challenge, and return columns (`v6/src/normalizer.py:564`).
- `state.track_state` applies only successful prior events, plus selected failed authentication counters, to infer sessions, credentials, table values, locking ranges, MBR, access policy rows, crypto streams, clock sequence, and read/write data history (`v6/src/state.py:889`, `v6/src/state.py:975`).
- `oracle.judge_final` dispatches all modeled final method/data events through preflight and per-method judges (`v6/src/oracle.py:2433`).

Table schema and mutability:
- Partially covered. Built-in column maps cover C_PIN, Authority, ACE, AccessControl, MethodID, Table, Column, SP, SecretProtect, etc. (`v6/src/spec_docs.py:100`, `v6/src/spec_docs.py:193`, `v6/src/spec_docs.py:220`). Read-only/write-only sets enforce many Set/Get cases (`v6/src/spec_docs.py:237`; `v6/src/oracle.py:678`, `v6/src/oracle.py:1597`, `v6/src/oracle.py:1728`).
- Gap: `SecretProtect` mapping is wrong/incomplete against Table 176. It maps `protect` to column 3 and omits `Table` at 1 and `ProtectMechanisms` at 3 (`v6/src/spec_docs.py:226` vs `documents/core/5.3.2.8.txt`). This can misjudge named-column Set/Get in hidden cases.
- Gap: credential families beyond C_PIN/MediaKey are not normalized into their exact table families. `credential_object_target` relies on object names beginning with C_RSA_/C_AES_/C_EC_/C_HMAC_ (`v6/src/oracle.py:1993`), but `normalizer.object_family` does not explicitly classify these UID spaces from the 5.3 credential tables. Hidden traces that use credential UIDs without names may be treated as unknown objects.

Access control and ACLs:
- Partially covered. `spec_docs.build_access_policy_from_index` can load ACE/AccessControl/Authority/C_PIN rows from artifacts (`v6/src/spec_docs.py:953`). `ace_policy_decision` evaluates matched rows, ACE BooleanExpr, and ACE column restrictions (`v6/src/oracle.py:507`). Empty BooleanExpr/list resolves False (`v6/src/oracle.py:350`).
- Gap: `Get` unauthorized object-table columns should be omitted with SUCCESS, but `judge_get` often expects auth_error for protected or write-only columns (`v6/src/oracle.py:1597`, `v6/src/oracle.py:1612`, `v6/src/oracle.py:1700`). That is stricter than `documents/core/5.3.4.2.2.txt` for object-table Get. It is correct to fail unauthorized byte-table reads only by empty results, not status.
- Gap: prior successful AddACE/RemoveACE/DeleteMethod do not mutate `state["access_control_rows"]` or ACL refs. Only direct Set on AccessControl/ACE columns changes policy (`v6/src/state.py:500`, `v6/src/state.py:889`). Final judging after meta-ACL changes can be stale.
- Gap: Delete/Create side effects on AccessControl/ACE/Column/Table are not tracked. CreateTable/CreateRow/Delete/DeleteRow judges are status-only (`v6/src/oracle.py:2122`, `v6/src/oracle.py:2141`, `v6/src/oracle.py:2165`) and `state.apply_event` has no handlers for these methods (`v6/src/state.py:908`).

Authority and authentication:
- Covered: disabled authorities, class authorities, explicit locked-out authorities, secure messaging flag on Authenticate, tracked credential match/mismatch, and Anybody default token are partially modeled (`v6/src/oracle.py:187`, `v6/src/oracle.py:209`, `v6/src/oracle.py:244`, `v6/src/oracle.py:303`, `v6/src/oracle.py:1460`).
- Gap: `authority_is_class` only uses rows where `is_class` is True. If a class authority is seen by UID/name but no row is loaded, class detection can miss Admins/Users/Makers (`v6/src/oracle.py:209`). Default class facts from `5.3.4.1.2.txt` should be hardcoded or guaranteed by the artifact.
- Gap: the Sign/SymK/HMAC two-step Authenticate state machine is not implemented. `judge_authenticate` rejects `Proof` to non-Password/non-Anybody authorities as INVALID_PARAMETER (`v6/src/oracle.py:1487`), but in Awaiting Challenge Response proof is required and should produce SUCCESS True/False (`documents/core/5.3.4.1.14.1.txt`). `state` has no pending authentication challenge state.
- Gap: TryLimit reset is incomplete. Successful Authenticate and PIN-column Set/GenKey reset tracked failed counts (`v6/src/state.py:249`, `v6/src/state.py:632`, `v6/src/state.py:668`), but Set of C_PIN Tries column to 0 and successful SetPackage on C_PIN do not reset counts as required by `5.3.4.1.1.2.txt`.
- Gap: state comment cites `core/3.3.7.4` for Tries reset (`v6/src/state.py:264`), but assigned source is `core/5.3.4.1.1.2`; this is documentation accuracy, not behavior.

Session startup and lifecycle:
- Covered: StartSession target/session-open/SPID checks, LockingSP inactive failure, simple authority credential match, disabled authority, TryLimit lockout, and successful response session ID validation (`v6/src/oracle.py:1357`, `v6/src/oracle.py:1295`).
- Gap: session startup role validation is incomplete. It checks only `HostSigningAuthority` for Exchange/TPerExchange/TPerSign (`v6/src/oracle.py:1388`), but does not validate HostExchangeAuthority, SPSigningAuthority, SPExchangeAuthority role compatibility required by `5.3.4.1.3.txt`.
- Gap: secure messaging/hash/sign/certificate structural requirements in StartSession/StartTrustedSession are mostly not enforced despite Authority.Secure/HashAndSign/PresentCertificate columns being parsed (`v6/src/oracle.py:1513` covers only Authenticate secure messaging).
- Gap: Base Template SPInfo Enabled/Disabled/Frozen lifecycle from `5.3.2.1.7.txt` and `5.3.5.1.txt` is not tracked. `state.sp_lifecycle` tracks Manufactured vs Manufactured-Inactive for LockingSP activation/revert (`v6/src/state.py:81`, `v6/src/state.py:651`, `v6/src/state.py:688`), but not Disabled/Frozen and not the exceptions allowing Authenticate/DeleteSP/re-enable Set.

Basic table methods:
- Covered: preflight required parameters for CreateTable/CreateRow/DeleteRow/GetFreeSpace/GetFreeRows and byte-table CreateTable `Columns`/`MaxSize` checks (`v6/src/oracle.py:818`, `v6/src/oracle.py:1094`, `v6/src/oracle.py:1207`). Set Where/Values shape and duplicate-column checks are implemented (`v6/src/oracle.py:1025`, `v6/src/oracle.py:1070`, `v6/src/oracle.py:1240`).
- Gap: CreateTable byte-table `HintSize` is not rejected, although `5.3.3.2.7.txt` says HintSize on byte tables SHALL fail INVALID_PARAMETER (`v6/src/oracle.py:1094` checks only MaxSize).
- Gap: CreateTable MinSize/MaxSize relationships and MaxSize lower than MinSize/current size are not judged except byte-table MaxSize. Existing-name uniqueness, insufficient space/rows, all-column requirements for CreateRow, unique column conflicts, and forbidden DeleteRow/Delete targets are not stateful/executable in current code.
- Gap: Set with missing Values correctly returns success by preflight, but if a family-specific judge later requires authorization (`v6/src/oracle.py:1712` onward), it may require authority for a no-effect Set. Spec says an otherwise correct invocation with no Values succeeds with no effect (`5.3.3.7.2.txt`); authorization probably still applies to invoking Set, but this should be explicit in tests.
- Gap: Get object-table unauthorized-cell omission is not compared to return_values. The oracle mostly judges status, not whether disallowed columns were omitted or allowed columns are in Column-table order.

GenKey/GetPackage/SetPackage:
- Covered: GenKey target family fallback, active LockingSP requirement for media keys, and key generation side effect for read/write data (`v6/src/oracle.py:1933`, `v6/src/state.py:668`).
- Gap: `judge_gen_key` rejects C_PIN GenKey as auth_error unconditionally (`v6/src/oracle.py:1946`), but Base Template explicitly defines GenKey on C_PIN and its PinLength behavior (`documents/core/5.3.3.16.2.txt`, `documents/core/5.3.4.1.1.1.txt`). Opal SSC may omit an ACE for C_PIN GenKey, but this audit scope is Base Template 5.3; the implementation needs either Base-vs-SSC policy context or should not hardcode universal auth_error.
- Gap: GenKey parameter validation is incomplete. It does not reject `PublicExponent` on non-C_RSA_* targets, `PinLength` on non-C_PIN targets, `PinLength > 32`, or bad RSA exponents (`v6/src/oracle.py:1933`).
- Gap: GetPackage/SetPackage only check target credential object and generic session authority (`v6/src/oracle.py:2004`, `v6/src/oracle.py:2017`). They do not validate wrapping/signing key credential existence, WrappingKey.Encrypt authorization, SigningKey.Sign authorization, signed hash verification status classes, or C_PIN SetPackage Tries reset.

Source file note:
- `v6/src/spec_tables.py` contains static policy definitions, but no current `v6/src` file imports it. `rg` shows no import/use. It appears stale v5 scaffolding and has no effect on `Solver.predict`; any apparent coverage there should not be credited unless it is wired in.

## 4. Required Edits

Priority P0:
1. Implement the two-step Authenticate state machine for Sign/SymK/HMAC authorities. Track pending authority/challenge after first successful challenge response and judge the second call according to `5.3.4.1.14.1.txt`; do not reject Proof in Awaiting Challenge Response.
2. Fix Base Template object-table Get semantics. Unauthorized object-table cells should not force auth_error; final judging should accept SUCCESS when unauthorized cells are omitted and fail only when forbidden cells are returned. Keep unauthorized byte-table Get as empty-result behavior.
3. Track and enforce SPInfo Enabled/Disabled/Frozen lifecycle. A successful Set disabling an SP should immediately enter Disabled; non-exempt user-invoked SP operations fail while disabled; Frozen and Disabled-Frozen fail session startup.
4. Add full GenKey parameter validation for C_PIN/C_RSA/nonmatching targets and revisit the unconditional C_PIN GenKey auth_error. Under Base Template, C_PIN GenKey is executable with PinLength/CharSet rules; if Opal policy blocks it, make the SSC dependency explicit in state/policy rather than applying it globally.
5. Mutate ACL state for AddACE/RemoveACE/DeleteMethod and remove related AccessControl rows for successful Delete/DeleteRow/Create side effects where later final responses depend on policy.

Priority P1:
1. Reject CreateTable byte-table `HintSize`, not only `MaxSize`; validate MinSize/MaxSize relationships where enough table state is known.
2. Reset C_PIN failed-auth counts when a successful Set writes Tries column to 0 and when successful SetPackage modifies a C_PIN credential.
3. Validate all StartSession authority role parameters against Operation: HostSigning/SPSigning vs HostExchange/SPExchange, including TPerSign/TPerExchange restrictions.
4. Fix `SecretProtect` column schema mapping to Table=1, ColumnNumber=2, ProtectMechanisms=3 and adjust mutability/read-only expectations accordingly.
5. Add UID/family recognition for C_RSA_*, C_AES_*, C_EC_*, C_HMAC_* credential tables so credential methods are judged correctly when traces omit friendly names.

Priority P2:
1. Model row/table existence enough to judge GetFreeRows, CreateRow, Delete, and DeleteRow fail cases after prior Create/Delete operations.
2. Validate Get return ordering for RowValues where the Column table order is known.
3. Either remove/stub `spec_tables.py` from the coverage story or wire it into the actual implementation. Right now it is dead code and can mislead future audits.
4. Add structural checks for HashAndSign, PresentCertificate, and secure messaging startup parameters when the trace exposes those values. Keep cryptographic verification intentionally out of scope unless byte-level material and algorithms are represented.

## 5. Ambiguities Or Intentionally Non-Executable Sections

- Cryptographic correctness for RSA/EC/AES/HMAC/EC-MQV/EC-DH is generally non-executable from command/response trajectories unless the trace includes actual key material, nonces, signatures, certificates, session key parameters, and algorithm context. Structural presence and role validation are executable; validating signatures/key exchange math is not.
- Logging defaults in `5.3.4.6.txt` normally do not alter the status of the invoked method. They are relevant only if final judging includes log-table side effects or AddLog/ClearLog/FlushLog traces.
- Capacity failures such as INSUFFICIENT_SPACE and INSUFFICIENT_ROWS require current free-space/free-row state. Without prior GetFreeSpace/GetFreeRows or tracked table allocation, a solver should avoid overconfident failure/success decisions.
- Some Base Template behavior is narrowed by SSC-specific AccessControl preconfiguration. The implementation includes Opal-specific comments and rules. For final judging, distinguish "Base method syntax permits this" from "current SSC policy authorizes this" and document which policy source decided the result.
- Hidden/protected credential columns are discoverable through SecretProtect. Without a reliable SecretProtect state, write-only/read-hidden decisions should rely on known built-in schema only and mark uncertain cases lower confidence.

## 6. Synthetic Tests Recommended

1. Authenticate Sign authority first call returns SUCCESS Challenge; second call with same authority and correct proof returns SUCCESS True; wrong authority/proof returns SUCCESS False, not INVALID_PARAMETER.
2. C_PIN TryLimit=2: two failed Authenticate calls lock out the authority; Set C_PIN Tries=0 resets lockout; successful SetPackage on C_PIN also resets lockout.
3. StartSession with HostExchangeAuthority using Operation=Password fails role validation; SPSigningAuthority using TPerSign is accepted only in the SP-signing role.
4. Object-table Get requesting columns allowed+disallowed under ACE Columns returns SUCCESS with only allowed columns; returning the disallowed column is fail.
5. Byte-table Get without ACL returns SUCCESS with empty result list, not NOT_AUTHORIZED status.
6. CreateTable byte table with `HintSize` present returns INVALID_PARAMETER.
7. GenKey C_PIN with PinLength=33 returns INVALID_PARAMETER; GenKey media key with PinLength present returns INVALID_PARAMETER; GenKey C_PIN with valid PinLength is judged by access policy, not categorically invalid.
8. AddACE success changes final Set/Get authorization; RemoveACE success revokes it; DeleteMethod success makes the InvokingID/MethodID non-invocable.
9. Successful Set SPInfo.Enabled=False causes later Get/Set/GenKey to fail except Authenticate, DeleteSP, and re-enable Set.
10. SecretProtect named-column Set/Get uses correct column numbers for Table, ColumnNumber, and ProtectMechanisms.

