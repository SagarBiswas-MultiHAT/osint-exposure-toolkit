"""Exposure graph generator using NetworkX and PyVis."""

from __future__ import annotations

from pathlib import Path

import networkx as nx
from pyvis.network import Network

from core.models import ReportContext


def _escape_html(value: str) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _hover_summary(
    *,
    label: str,
    status: str,
    module: str,
    details: str,
    url: str = "",
) -> str:
    lines = [
        f"{label}",
        f"Status: {status}",
        f"Module: {module}",
        f"Details: {details}",
    ]
    if url:
        lines.append(f"URL: {url}")
    return "\n".join(_escape_html(line) for line in lines)


def _detail_panel_markup() -> str:
        return """
<style>
    html, body {
        background: #0d1117 !important;
        margin: 0 !important;
        padding: 0 !important;
    }

    .vis-tooltip {
        background: #111827 !important;
        color: #e5e7eb !important;
        border: 1px solid #374151 !important;
        border-radius: 8px !important;
        box-shadow: 0 12px 24px rgba(0, 0, 0, 0.4) !important;
        font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif !important;
        font-size: 12px !important;
        white-space: pre-line !important;
        max-width: 420px !important;
        padding: 8px 10px !important;
    }

    .card {
        margin: 0 !important;
        border: none !important;
        background: transparent !important;
    }

    #mynetwork {
        min-height: 100vh !important;
        border: 0 !important;
    }

    .exposure-detail-panel {
        position: fixed;
        top: 16px;
        right: 16px;
        width: 380px;
        max-width: calc(100vw - 32px);
        max-height: calc(100vh - 32px);
        overflow-y: auto;
        background: #111827;
        border: 1px solid #374151;
        border-radius: 12px;
        padding: 14px;
        color: #e5e7eb;
        font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.45);
        z-index: 9999;
    }

    .exposure-detail-panel h3 {
        margin: 0 0 10px 0;
        font-size: 16px;
        line-height: 1.3;
    }

    .exposure-detail-grid {
        display: grid;
        grid-template-columns: 120px 1fr;
        gap: 8px 10px;
        margin-bottom: 14px;
    }

    .exposure-detail-grid .k {
        color: #9ca3af;
        font-size: 12px;
        font-weight: 600;
        letter-spacing: 0.01em;
    }

    .exposure-detail-grid .v {
        color: #f3f4f6;
        font-size: 13px;
        word-break: break-word;
    }

    .exposure-detail-grid .v.status-exposed {
        color: #f87171;
        font-weight: 700;
    }

    .exposure-detail-grid .v.status-unknown {
        color: #fbbf24;
        font-weight: 600;
    }

    .exposure-detail-grid .v.status-not_found {
        color: #9ca3af;
        font-weight: 600;
    }

    .exposure-detail-actions {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
    }

    .exposure-detail-actions button {
        border: 1px solid #4b5563;
        background: #1f2937;
        color: #f9fafb;
        border-radius: 8px;
        padding: 6px 10px;
        cursor: pointer;
        font-size: 12px;
    }

    .exposure-detail-actions button:hover {
        background: #374151;
    }

    .exposure-detail-toast {
        margin-top: 8px;
        color: #34d399;
        font-size: 12px;
    }
</style>
<div id=\"exposureDetailPanel\" class=\"exposure-detail-panel\" style=\"display:none\">\
    <h3 id=\"exposureDetailTitle\">Node Details</h3>\
    <div id=\"exposureDetailGrid\" class=\"exposure-detail-grid\"></div>\
    <div class=\"exposure-detail-actions\">\
        <button id=\"copyNodeSummary\" type=\"button\">Copy Node Summary</button>\
        <button id=\"copyNodeUrl\" type=\"button\">Copy URL</button>\
        <button id=\"openNodeUrl\" type=\"button\">Open URL</button>\
    </div>\
    <div id=\"exposureDetailToast\" class=\"exposure-detail-toast\"></div>\
</div>
"""


def _detail_panel_script() -> str:
        return """
<script>
(function () {
    const panel = document.getElementById("exposureDetailPanel");
    const titleEl = document.getElementById("exposureDetailTitle");
    const gridEl = document.getElementById("exposureDetailGrid");
    const copySummaryBtn = document.getElementById("copyNodeSummary");
    const copyUrlBtn = document.getElementById("copyNodeUrl");
    const openUrlBtn = document.getElementById("openNodeUrl");
    const toastEl = document.getElementById("exposureDetailToast");

    let lastNode = null;

    function escapeHtml(value) {
        const s = String(value ?? "");
        return s
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/\"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    function toast(message, isError) {
        if (!toastEl) return;
        toastEl.textContent = message;
        toastEl.style.color = isError ? "#f87171" : "#34d399";
        window.setTimeout(() => {
            if (toastEl.textContent === message) toastEl.textContent = "";
        }, 2200);
    }

    function buildSummary(node) {
        const lines = [];
        lines.push(`Node: ${node.label || node.id}`);
        lines.push(`Category: ${node.category || node.type || "N/A"}`);
        lines.push(`Module: ${node.module || "N/A"}`);
        if (node.status) lines.push(`Status: ${node.status}`);
        if (node.severity) lines.push(`Severity: ${node.severity}`);
        if (node.url) lines.push(`URL: ${node.url}`);
        if (node.details) lines.push(`Details: ${node.details}`);
        if (node.status_reason) lines.push(`Reason: ${node.status_reason}`);
        return lines.join("\\n");
    }

    function getNodeUrl(node) {
        const value = (node && node.url) ? String(node.url).trim() : "";
        if (!value) return "";
        return /^https?:\\/\\//i.test(value) ? value : "";
    }

    function statusClass(status) {
        const value = String(status || "").toUpperCase();
        if (value === "EXPOSED") return "status-exposed";
        if (value === "UNKNOWN") return "status-unknown";
        if (value === "NOT_FOUND") return "status-not_found";
        return "";
    }

    function renderGrid(node) {
        const fields = [
            ["Category", node.category || node.type || "N/A"],
            ["Module", node.module || "N/A"],
            ["Severity", node.severity || "N/A"],
            ["Status", node.status || "N/A"],
            ["URL", node.url || "N/A"],
            ["Details", node.details || "N/A"],
            ["Reason", node.status_reason || "N/A"],
            ["Source", node.source || "N/A"],
            ["Context", node.context || "N/A"],
        ];

        gridEl.innerHTML = fields
            .map(([key, value]) => {
                const extra = key === "Status" ? ` ${statusClass(value)}` : "";
                return `<div class=\"k\">${escapeHtml(key)}</div><div class=\"v${extra}\">${escapeHtml(value)}</div>`;
            })
            .join("");
    }

    async function copyText(content) {
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(content);
                return true;
            }
            const ta = document.createElement("textarea");
            ta.value = content;
            ta.style.position = "fixed";
            ta.style.opacity = "0";
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            const ok = document.execCommand("copy");
            document.body.removeChild(ta);
            return ok;
        } catch (_) {
            return false;
        }
    }

    copySummaryBtn?.addEventListener("click", async () => {
        if (!lastNode) {
            toast("No node selected", true);
            return;
        }
        const ok = await copyText(buildSummary(lastNode));
        toast(ok ? "Node summary copied" : "Failed to copy summary", !ok);
    });

    copyUrlBtn?.addEventListener("click", async () => {
        const url = getNodeUrl(lastNode);
        if (!url) {
            toast("No URL available for this node", true);
            return;
        }
        const ok = await copyText(url);
        toast(ok ? "URL copied" : "Failed to copy URL", !ok);
    });

    openUrlBtn?.addEventListener("click", () => {
        const url = getNodeUrl(lastNode);
        if (!url) {
            toast("No URL available for this node", true);
            return;
        }
        window.open(url, "_blank", "noopener,noreferrer");
    });

    function bindNetworkClick() {
        if (typeof network === "undefined" || !network || typeof nodes === "undefined") {
            window.setTimeout(bindNetworkClick, 100);
            return;
        }

        network.on("click", function (params) {
            if (!params.nodes || params.nodes.length === 0) {
                panel.style.display = "none";
                lastNode = null;
                return;
            }
            const nodeId = params.nodes[0];
            const node = nodes.get(nodeId);
            if (!node) return;
            lastNode = node;
            titleEl.textContent = node.label || String(node.id);
            renderGrid(node);
            panel.style.display = "block";
        });
    }

    bindNetworkClick();
})();
</script>
"""


def _inject_interactivity(html: str) -> str:
        marker = "</body>"
        if marker not in html:
                return html
        payload = f"{_detail_panel_markup()}\n{_detail_panel_script()}\n"
        return html.replace(marker, f"{payload}{marker}")


async def generate(context: ReportContext) -> Path:
    """Generate standalone HTML exposure graph from report context."""

    output_dir = Path(context.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "exposure_graph.html"

    graph = nx.Graph()
    target_node = context.target_email or context.target_domain or "target"

    graph.add_node(
        target_node,
        label=target_node,
        type="TARGET",
        category="TARGET",
        module="main",
        color="#58a6ff",
        size=40,
        severity="INFO",
        status="N/A",
        source="input",
        details=f"Primary target: {target_node}",
        context=f"Email={context.target_email or 'N/A'} | Domain={context.target_domain or 'N/A'}",
        title=_hover_summary(
            label=target_node,
            status="N/A",
            module="main",
            details=f"Primary target: {target_node}",
        ),
    )

    for idx, breach in enumerate(context.credential_leak.breaches, start=1):
        breach_node = f"breach:{idx}:{breach.name}"
        graph.add_node(
            breach_node,
            label=breach.name,
            type="BREACH",
            category="BREACH",
            module="credential_leak",
            color="#ff4d4f",
            size=max(12, min(45, breach.pwn_count // 10_000_000)),
            severity=str(breach.severity),
            status="EXPOSED",
            source="credential_leak",
            url=f"https://{breach.domain}" if breach.domain else "",
            details=f"{breach.name} ({breach.breach_date})",
            context=f"PwnCount={breach.pwn_count} | DataClasses={', '.join(breach.data_classes[:6])}",
            title=_hover_summary(
                label=breach.name,
                status="EXPOSED",
                module="credential_leak",
                details=f"Breach date: {breach.breach_date}",
                url=f"https://{breach.domain}" if breach.domain else "",
            ),
        )
        graph.add_edge(target_node, breach_node, label="found in breach")

    for idx, repo in enumerate(context.github_footprint.repositories, start=1):
        repo_node = f"repo:{idx}:{repo.name}"
        graph.add_node(
            repo_node,
            label=repo.name,
            type="GITHUB REPO",
            category="GITHUB_REPO",
            module="github_footprint",
            color="#f39c12",
            size=20,
            severity="INFO",
            status="EXPOSED",
            source="github_footprint",
            url=repo.html_url or "",
            details=repo.name,
            context=f"Stars={repo.stars} | Forks={repo.forks} | Language={repo.language or 'N/A'}",
            title=_hover_summary(
                label=repo.name,
                status="EXPOSED",
                module="github_footprint",
                details=f"Stars={repo.stars} | Forks={repo.forks}",
                url=repo.html_url or "",
            ),
        )
        graph.add_edge(target_node, repo_node, label="maintains")

    repo_id_by_name = {repo.name: f"repo:{idx}:{repo.name}" for idx, repo in enumerate(context.github_footprint.repositories, start=1)}

    for idx, secret in enumerate(context.github_footprint.secrets_found, start=1):
        secret_node = f"secret:{idx}:{secret.repo}:{secret.pattern_type}"
        graph.add_node(
            secret_node,
            label=secret.pattern_type,
            type="SECRET FOUND",
            category="SECRET",
            module="github_footprint",
            color="#ff0000",
            size=28,
            severity=str(secret.severity),
            status="EXPOSED",
            source="github_secret_scan",
            url="",
            details=secret.pattern_type,
            context=f"Repo={secret.repo} | File={secret.file_path} | Value={secret.masked_value}",
            title=_hover_summary(
                label=secret.pattern_type,
                status="EXPOSED",
                module="github_secret_scan",
                details=f"Repo={secret.repo} | File={secret.file_path}",
            ),
        )
        repo_ref = repo_id_by_name.get(secret.repo)
        graph.add_edge(repo_ref or target_node, secret_node, label="exposes secret")

    for idx, profile in enumerate(context.social_footprint.profiles, start=1):
        profile_node = f"profile:{idx}:{profile.platform}:{profile.username_tried or 'none'}"
        status_value = str(profile.status)
        if status_value == "EXPOSED":
            color = "#00bcd4"
            edge_label = "profile exposed"
            edge_color = "#ff4d4f"
            font_color = "#ff6b6b"
        elif status_value == "NOT_FOUND":
            color = "#6b7280"
            edge_label = "profile not found"
            edge_color = "#6b7280"
            font_color = "#c9d1d9"
        else:
            color = "#f59e0b"
            edge_label = "profile unknown"
            edge_color = "#f59e0b"
            font_color = "#fbbf24"

        graph.add_node(
            profile_node,
            label=profile.platform,
            type="SOCIAL PROFILE",
            category="SOCIAL_PROFILE",
            module="social_footprint",
            color=color,
            font={"color": font_color},
            size=16,
            severity="LOW" if status_value == "EXPOSED" else "INFO",
            status=status_value,
            status_reason=profile.status_reason or "",
            source="social_footprint",
            url=profile.url,
            details=(
                profile.status_reason
                or f"{profile.platform} profile {status_value.lower().replace('_', ' ')}"
            ),
            context=(
                f"Username={profile.username_tried or 'N/A'} | "
                f"PositiveSignal={profile.is_positive_signal}"
            ),
            title=_hover_summary(
                label=profile.platform,
                status=status_value,
                module="social_footprint",
                details=(
                    f"Username: {profile.username_tried or 'N/A'}"
                    + (
                        f" | Reason: {profile.status_reason}"
                        if profile.status_reason and status_value != "EXPOSED"
                        else ""
                    )
                ),
                url=profile.url,
            ),
        )
        graph.add_edge(target_node, profile_node, label=edge_label, color=edge_color)

    for idx, paste in enumerate(context.paste_monitor.pastes, start=1):
        paste_node = f"paste:{idx}:{paste.identifier}"
        graph.add_node(
            paste_node,
            label=paste.title,
            type="PASTE",
            category="PASTE",
            module="paste_monitor",
            color="#f1c40f",
            size=16,
            severity="MEDIUM",
            status="EXPOSED",
            source=paste.source,
            url="",
            details=paste.title,
            context=f"Identifier={paste.identifier} | Date={paste.date} | Emails={paste.email_count}",
            title=_hover_summary(
                label=paste.title,
                status="EXPOSED",
                module="paste_monitor",
                details=f"Source={paste.source} | Date={paste.date}",
            ),
        )
        graph.add_edge(target_node, paste_node, label="appeared in paste")

    for idx, finding in enumerate(context.metadata_extractor.findings, start=1):
        doc_node = f"doc:{idx}:{finding.document_url}"
        graph.add_node(
            doc_node,
            label=finding.field_name,
            type="DOCUMENT",
            category="DOCUMENT",
            module="metadata_extractor",
            color="#9ca3af",
            size=14,
            severity=str(finding.severity),
            status="EXPOSED",
            source="metadata_extractor",
            url=finding.document_url,
            details=finding.field_name,
            context=f"Value={finding.value}",
            title=_hover_summary(
                label=finding.field_name,
                status="EXPOSED",
                module="metadata_extractor",
                details=f"Value: {finding.value}",
                url=finding.document_url,
            ),
        )
        graph.add_edge(target_node, doc_node, label="document metadata")

    dns_node = f"dns:{context.target_domain or 'domain'}"
    graph.add_node(
        dns_node,
        label="DNS Email Auth",
        type="DNS RECORD",
        category="DNS_EMAIL_AUTH",
        module="dns_email_auth",
        color="#8e44ad",
        size=18,
        severity="HIGH" if context.dns_email_auth.spoofability_score >= 7 else "MEDIUM",
        status="N/A",
        source="dns_email_auth",
        url="",
        details=f"Spoofability {context.dns_email_auth.spoofability_score}/10",
        context=(
            f"SPF={context.dns_email_auth.spf.strength} | "
            f"DMARC={context.dns_email_auth.dmarc.policy or 'missing'} | "
            f"DKIM selectors={len(context.dns_email_auth.dkim.selectors_found)}"
        ),
        title=_hover_summary(
            label="DNS Email Auth",
            status="N/A",
            module="dns_email_auth",
            details=f"Spoofability: {context.dns_email_auth.spoofability_score}/10",
        ),
    )
    graph.add_edge(target_node, dns_node, label="email auth posture")

    network = Network(height="850px", width="100%", bgcolor="#0d1117", font_color="#c9d1d9", cdn_resources="in_line", notebook=False)
    network.from_nx(graph)
    network.toggle_physics(True)
    network.barnes_hut(gravity=-18000, central_gravity=0.18, spring_length=240, spring_strength=0.035, damping=0.09)
    network.save_graph(str(output_file))

    html = output_file.read_text(encoding="utf-8")
    html = _inject_interactivity(html)
    output_file.write_text(html, encoding="utf-8")

    return output_file
