"""Exposure graph generator using NetworkX and PyVis."""

from __future__ import annotations

from pathlib import Path

import networkx as nx
from pyvis.network import Network

from core.models import ReportContext


async def generate(context: ReportContext) -> Path:
    """Generate standalone HTML exposure graph from report context."""

    output_dir = Path(context.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "exposure_graph.html"

    graph = nx.Graph()
    target_node = context.target_email or context.target_domain or "target"

    graph.add_node(target_node, type="TARGET", color="#58a6ff", size=40)

    for breach in context.credential_leak.breaches:
        graph.add_node(
            breach.name,
            type="BREACH",
            color="#ff4d4f",
            size=max(12, min(45, breach.pwn_count // 10_000_000)),
            title=f"{breach.name} ({breach.breach_date})",
        )
        graph.add_edge(target_node, breach.name, label="found in breach")

    for repo in context.github_footprint.repositories:
        repo_node = f"repo:{repo.name}"
        graph.add_node(repo_node, type="GITHUB REPO", color="#f39c12", size=20, title=repo.name)
        graph.add_edge(target_node, repo_node, label="maintains")

    for secret in context.github_footprint.secrets_found:
        secret_node = f"secret:{secret.repo}:{secret.pattern_type}"
        graph.add_node(secret_node, type="SECRET FOUND", color="#ff0000", size=28, title=secret.pattern_type)
        graph.add_edge(f"repo:{secret.repo}", secret_node, label="exposes secret")

    for profile in context.social_footprint.profiles:
        profile_node = f"profile:{profile.platform}"
        color = "#00bcd4" if str(profile.status) == "EXPOSED" else "#6b7280"
        graph.add_node(profile_node, type="SOCIAL PROFILE", color=color, size=16, title=profile.url)
        graph.add_edge(target_node, profile_node, label="profile found")

    for paste in context.paste_monitor.pastes:
        paste_node = f"paste:{paste.identifier}"
        graph.add_node(paste_node, type="PASTE", color="#f1c40f", size=16, title=paste.title)
        graph.add_edge(target_node, paste_node, label="appeared in paste")

    for finding in context.metadata_extractor.findings:
        doc_node = f"doc:{finding.document_url}"
        graph.add_node(doc_node, type="DOCUMENT", color="#9ca3af", size=14, title=finding.field_name)
        graph.add_edge(target_node, doc_node, label="document metadata")

    graph.add_node(
        f"dns:{context.target_domain or 'domain'}",
        type="DNS RECORD",
        color="#8e44ad",
        size=18,
        title=f"Spoofability {context.dns_email_auth.spoofability_score}/10",
    )
    graph.add_edge(target_node, f"dns:{context.target_domain or 'domain'}", label="email auth posture")

    network = Network(height="850px", width="100%", bgcolor="#0d1117", font_color="#c9d1d9", cdn_resources="in_line", notebook=False)
    network.from_nx(graph)
    network.toggle_physics(True)
    network.barnes_hut(gravity=-20000, central_gravity=0.2, spring_length=180, spring_strength=0.04, damping=0.09)
    network.save_graph(str(output_file))

    return output_file
