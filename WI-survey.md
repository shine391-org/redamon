# WI-survey — Khảo sát Bước 0 cho 3 tool Type D (graph_diff / bloodhound_ingest / mimikatz_parse)

Ngày: 2026-10-25 · Worktree: `/data/work/redamon-typed` (branch `feature/graph-diff` từ `upstream/master` @ `4585b3442cf3c6e075fca5d3b512a8f47be501b6`)

## 0. Dev skills đã đọc (tồn tại thật trong repo, không phải phỏng đoán)

| Skill | Vai trò |
|---|---|
| `skills/agentic-tool-integration/SKILL.md` | Luật wiring tool agent: TOOL_REGISTRY bắt buộc 4 field (test `test_tool_registry_completeness.py` ép description ≥100 chars); elif dispatch cho tool cần chỉnh args; mirror `execute_tool_node.py`↔`execute_plan_node.py`; existing project không tự thấy tool mới trong TOOL_PHASE_MAP (jsonb replace, không merge) |
| `skills/graph-db-writes/SKILL.md` | MERGE tenant triple `{natural_key, user_id, project_id}` với entity; reference node (CVE) chỉ natural id; `ON CREATE SET` provenance + `SET += $props` enrichment; KHÔNG đặt map/list-map vào property; label mới khai báo ở `graph_db/schema_sections.md` (một nơi duy nhất) + `schema_keys.py` + seed `tooling/scripts/seed_schema_catalog.py` + `NODE_COLORS` webapp |
| `skills/project-settings-cascade/SKILL.md` | Không thêm settings column cho 3 tool này (tránh tầng Prisma/registry) — không áp dụng trực tiếp |
| `skills/redamon-testing/SKILL.md` | Gate Docker `./agentic/run_tests.sh` (per-file isolated, image `redamon-agent:latest`, repo mount /repo); KHÔNG host pytest; test agent → `agentic/tests/`; tier theo tên file: `_integration` = integration (chạy `run_tests.sh integration`/`all`), mặc định unit hermetic; chỉ pytest/pytest-asyncio/etc được guarantee; test cần stack phải self-skip |

## 1. PhaseAwareToolExecutor.execute() — file/dòng thật

- Class: `agentic/tools.py:2069` `class PhaseAwareToolExecutor`; `async def execute(` tại `tools.py:2403`.
- Thứ tự trong `execute()`: strip output_mode (:2425 cũ — giờ ~:2417) → **phase check** `is_tool_allowed_in_phase(tool_name, phase)` (:2428 vùng 2420-2435) → refusа returns `{"success": False, "output": None, "error": "Tool 'X' is not allowed in 'phase' phase. This tool requires: ..."}` → short-circuit fs_*/job_* (:2439-2442) → lookup `_all_tools` (:2445) → `_invoke(active_tool)` closure với chuỗi `if/elif` theo tool_name:
  - `query_graph` :2501 `ainvoke(tool_args.get("question",""))`
  - `graph_schema`/`graph_summary` :2503 `ainvoke({})`
  - ... các elif khác (web_search, shodan, execute_wpscan, execute_gau, cve_intel :2544) ...
  - **`else:` :2555-2556 `output = await active_tool.ainvoke(tool_args)`** ← tool nhận dict args nguyên vẹn đi thẳng qua else
- tool_args KHÔNG có validation chung — từng tool tự parse trong closure; sai cú pháp do tool tự trả lỗi.
- Kết luận: elif mới thêm NGAY TRƯỚC `else:` (thuần dòng +).

## 2. TOOL_PHASE_MAP — cấu trúc + cách thêm

- Nằm trong `DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']`, `agentic/project_settings.py:288`. Entry: `'tool_name': ['informational', 'exploitation', 'post_exploitation']` (vd `query_graph` :289).
- Check: `is_tool_allowed_in_phase()` `project_settings.py:1169` — unmapped tool → **False** (tool không map = không chạy được).
- ⚠️ `fetch_agent_settings` :571 REPLACE cả map từ `project.agentToolPhaseMap` (jsonb) — **project đã tồn tại (có map lưu sẵn) không thấy key mới** cho tới khi backfill jsonb. Đây là việc deployment (ghi rõ trong báo cáo; không sửa code — theo R6).
- Thêm entry: dòng mới cuối dict = thuần +.

## 3. Tool graph hiện có (query_graph) — pattern copy

- **Định nghĩa**: closure trong factory `get_tool()` của graph manager (class có `self.uri/user/password`, `Neo4jGraph` từ langchain), `agentic/tools.py:776-888`. `@tool async def query_graph(question: str)` :789.
- **Tenant**: `current_user_id.get()` / `current_project_id.get()` (contextvars import :102-103 từ orchestrator_helpers) :810-811, :969-970.
- **Read-only**: `_find_disallowed_write_operation(cypher)` (classmethod `tools.py:614`) từ chối write ops; `_scope_query()` :620 → `scope_query` share từ graph_db (import :24); chạy `manager.graph.query(filtered_cypher, params={tenant_user_id, tenant_project_id})` :852-857; wrap `_wrap_graph_result` :55.
- **Đăng ký**: `self._all_tools["query_graph"] = graph_tool` trong khối `if graph_tool:` `tools.py:2098-2104` (cùng điều kiện với graph_schema/graph_summary).
- **Registry**: `agentic/prompts/tool_registry.py:83` — entry `"query_graph"` với 4 field `purpose/when_to_use/args_format/description` (description dạng multi-line, ≥100 chars).
- **Trả về**: chuỗi (wrap JSON/text) — executor `maybe_offload` tự lo giới hạn kích thước.

## 4. Ghi Neo4j an toàn (cho WI-2/3)

- MERGE chuẩn (copy target trong skill, gốc `graph_db/mixins/graphql_mixin.py:189` vùng):
  ```cypher
  MERGE (n:Label {<natural_key>, user_id: $user_id, project_id: $project_id})
    ON CREATE SET n.source = '<tool>', n.updated_at = datetime()
    SET n += $props
  MERGE (a)-[:REL]->(b)
  ```
- Không set field tool khác sở hữu (dùng ON CREATE SET provenance); không map/list-map trong property (flatten); ingest-then-prune, KHÔNG clear.
- Label mới: khai báo `graph_db/schema_sections.md` (append section) + uniqueness key `graph_db/schema_keys.py` (append) + `python3 tooling/scripts/seed_schema_catalog.py` + `webapp/src/app/graph/config/colors.ts` NODE_COLORS (append).
- Label liên quan HIỆN CÓ: `Secret` (schema_sections.md:347, secret_type AWSAccessKey/APIKey...) — SEMANTICS khác credential host-derived → WI-3 tạo label `Credential` mới (tenant-scoped). KHÔNG có ADUser/ADGroup/ADComputer/bloodhound gì trong schema → WI-2 thêm mới.
- Agent env có `NEO4J_URI/USER/PASSWORD` (compose service agent) + `DATABASE_URL` postgres + `psycopg[binary,pool]>=3.2.0` nằm sẵn `agentic/requirements.txt:65` (precedent dùng: `agentic/tests/live_traffic_tools_probe.py:18`).

## 5. Cơ chế version scan theo thời gian (cơ sở graph_diff)

- **`ScanVersion`** — `webapp/prisma/schema.prisma:1572` (mục "SCAN TIMELINE"): mỗi project có dãy version `seq`, `label`, `isCurrent` (đúng 1 = live Neo4j, `snapshot=null`), version quá khứ giữ `snapshot` = **gzip(JSON {nodes, relationships})**; history sống trong Postgres, schema Neo4j không đổi.
- **Delta có sẵn** (Section 6.1): `webapp/src/app/api/projects/[id]/delta/route.ts` — `GET ?from=<versionId|current>&to=<versionId|current>`; 2 phía đọc cùng shape; tính bằng `computeReconDelta` (`webapp/src/lib/reconDelta.ts`) với **IDENTITY_KEYS per label** (Subdomain:name, IP:address, Port:ip+number+proto, ...) + FALLBACK_KEYS; read-only, không log snapshot content.
- **Vì sao không delegate qua HTTP**: route dùng `requireEffectiveUser` (user-session auth) — agent chỉ có INTERNAL key; và DOD yêu cầu test hermetic với fixture. → graph_diff đọc snapshot bytes trực tiếp từ Postgres (`ScanVersion`) bằng psycopg (env sẵn) + tự tính diff theo đúng ngữ nghĩa IDENTITY_KEYS (mirror bảng đó) + phía "current" capture read-only qua graph session tenant-scoped. Đây là điều chỉnh so với chữ "timestamps" trong đặc tả — cơ chế thật của repo là **version id/seq**, không có mốc timestamp; ghi vào danh sách phỏng đoán/điều chỉnh.
- "Node mất": chỉ đúng nghĩa với 2 SNAPSHOT; node bị prune cứng khỏi live graph không còn vết trong snapshot sau đó (stale_since chỉ dành cho node muted). Diff current↔version vẫn thấy "removed" vì phía snapshot giữ node cũ.

## 6. Cách chạy test + fixture pattern

- Gate: `./agentic/run_tests.sh` (unit, phải 100% xanh), `... integration` (tier `_integration` trong tên file), `... live`. Per-file isolated qua `tooling/scripts/pytest_isolated.py`; image `redamon-agent:latest`, repo mount `/repo`, workdir `/repo/agentic`. Cho phép truyền node id/file.
- Baseline đã chạy từ worktree: `./agentic/run_tests.sh tests/test_tool_registry_completeness.py` → **8 passed** (image platform-build chạy code upstream mount — env đồng nhất).
- `pytest.ini`: `asyncio_mode = auto`; test dùng stdlib + unittest.mock là chuẩn.
- Tier theo tên file trong conftest từng section (`_integration` = integration). Test cần stack/Neo4j: self-skip (pytest.skip) khi thiếu env.

## 7. Dangerous / approval (cho WI-2/3)

- `DANGEROUS_TOOLS = frozenset({...})` `agentic/project_settings.py:42-56` — multi-line, có comment — **append phần tử cuối = thuần dòng +**.
- Approval per-run: think_node quyết định `use_tool` + `tool_name in DANGEROUS_TOOLS` → `awaiting_tool_confirmation` → human approve/modify/reject (`tool_confirmation_nodes.py`). Tool dangerous không trong DANGEROUS_TOOLS sẽ không bao giờ xin approval → phải append.
- Per-tool stealth section: `agentic/prompts/stealth_rules.py` — các section `### proxy_brain — RESTRICTED` (:63), `### metasploit_console — HEAVILY RESTRICTED` (:183) trong string `STEALTH_MODE_RULES` → append section mới trong string = thuần +.
- `CATEGORY_TOOL_MAP` (`execute_plan_node.py:47-52`): dict literal trong hàm — thêm tool vào list `'exploitation'` có sẵn = SỬA dòng (phạm R6) → thay bằng append KEY MỚI `'post_exploitation': [...]` (thuần +) hoặc dựa ROE_FORBIDDEN_TOOLS setting (chấp nhận mọi tên tool). Ghi nhận trong danh sách phỏng đoán để reviewer quyết.

## 8. Quyết định kiến trúc từ khảo sát (áp cho cả 3 WI)

1. Mỗi tool = **module mới** `agentic/<tên>_tool.py` (logic thuần + factory `@tool`) — test độc lập không phải import tools.py nặng; tools.py chỉ thêm: 1 dòng import + khối đăng ký (sau khối graph tools :2098-2104) + 1 elif trước else :2555.
2. graph_diff: pure `compute_diff(payload_a, payload_b)` theo IDENTITY_KEYS; psycopg đọc ScanVersion; live capture qua callable query (tenant-scoped, chỉ MATCH/RETURN).
3. bloodhound_ingest / mimikatz_parse: driver Neo4j riêng từ env (NEO4J_URI...), MERGE tenant triple, label mới khai báo đủ 4 chỗ (schema_sections, schema_keys, seed, NODE_COLORS).
4. Approval test: đơn giản nhất hermetic = assert tên tool nằm trong DANGEROUS_TOOLS (frozenset) + executor/confirmation flow dùng đúng set đó (đã verify đường code); integration test mô phỏng reject approval = không gọi tool (không có path nào chạy tool khi chưa approve vì graph pause tại confirmation node — test hermetic assert thuộc tính set + tham chiếu code path có sẵn).

## 9. Danh sách phỏng đoán/điều chỉnh so với đặc tả (người review kiểm tra lại)

1. Đặc tả nói mode `"timestamps"` — repo KHÔNG có mốc timestamp cho graph; cơ chế thật = `ScanVersion` (seq/id). → mode thực tế: `last_two` | `versions` (id hoặc seq). 
2. Đặc tả nói "chạy bloodhound-python trực tiếp khi có domain credential" — bloodhound-python là CLI trong image KALI-SANDBOX (README.md:628), không có trong agent image → WI-2 nhận ĐƯỜNG DẪN file JSON (đã chạy/já giải nén trong workspace); phần "chạy trực tiếp" agent làm qua kali_shell (đã có playbook sẵn), không nằm trong tool.
3. bhgraph pathfinder: CLI trong kali image — test tích hợp trong agent không chạy được bhgraph; thay bằng Cypher shortestPath trên graph đã ingest (chứng minh tương đương: tồn tại đường user→DA) + chạy bhgraph tay trong sandbox làm evidence.
4. CATEGORY_TOOL_MAP: append key mới `'post_exploitation'` thay vì sửa list `'exploitation'` có sẵn (R6).
5. 100k-node benchmark: benchmark phần python (diff/summarize) trên payload synthetic — phần decode snapshot+capture thuộc hạ tầng có sẵn của upstream (postgres/neo4j), không phải code mới.
6. Giả định identity-key "changed" bỏ qua thuộc tính volatile (updated_at, stale_since, triage fields) — mirror tinh thần reconDelta (TRIAGE_PROPERTIES/VOLATILE); danh sách volatile cụ thể do tôi chọn, ghi trong module.
