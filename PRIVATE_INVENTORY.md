# PRIVATE INVENTORY — nhánh internal/main (kiến trúc no-core, 26/10)

File này là checklist sync upstream. Không push nhánh chứa file này lên repo công khai.

## Thành phần nhánh (so với upstream/master)
| commit | nội dung |
|---|---|
| infra | neo4j startup retry (agentic/orchestrator.py) + capture ingest static IP (recon_orchestrator/container_manager.py) — gốc 56a13af1 |
| infra | GVM ospd + pg-gvm restart unless-stopped (2 dòng docker-compose.yml) — hunk tách từ d177fe9c |
| merge | Type D: graph_diff + bloodhound_ingest + mimikatz_parse (branch integration đã test 4.902 unit + 13 integration) |
| fix | CVE fan-out: technology_cves qua domain fan-out merge (gốc 5f648765, PR #213) |

## KHÔNG còn trong nhánh (đã rời sang nơi khác — đừng mang vào lại)
- Platform patch 1.3.0 (proxy management + configuration control): UI vận hành giờ là controller egress `:18100/admin` (repo network-adapter, branch feat/admin-ui).
- Hot-patch bind-mount orchestrator.py trong docker-compose.kali-local.yml: đã bỏ (infra fix nằm trong image).

## Anchor conflict khi sync upstream
1. agentic/project_settings.py — cuối TOOL_PHASE_MAP + DANGEROUS_TOOLS (Type D)
2. agentic/prompts/tool_registry.py — cuối registry
3. agentic/tools.py — cuối chuỗi dispatch
4. agentic/tests/test_tool_confirmation.py — pin DANGEROUS_TOOLS
5. docker-compose.yml — 2 dòng restart GVM
Nguyên tắc: GIỮ CẢ HAI, chỉ append. Khi PR #213-#216 merge upstream thì xoá phần trùng (rebase về upstream).

## File KHÔNG BAO GIỜ commit
docker-compose.kali-local.yml, docker-compose.yml.bak.* (.git/info/exclude đã có).

## Sau này (V2 / Đợt 5)
implant_* MCP, aitm engine, RoE engine v2, audit hook — cập nhật section này khi thêm.
