"""
AIPT Security Knowledge Graph

Graph-based storage and analysis of security findings:
- Stores findings as nodes with relationships
- Finds attack paths through graph traversal
- Correlates findings across multiple scans
- Maps to MITRE ATT&CK techniques

This provides a structured way to understand relationships between findings.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from collections import defaultdict

from aipt_v2.models.findings import Finding, Severity, VulnerabilityType

logger = logging.getLogger(__name__)


# MITRE ATT&CK technique mapping
VULN_TO_MITRE = {
    VulnerabilityType.SQL_INJECTION: {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    VulnerabilityType.COMMAND_INJECTION: {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    VulnerabilityType.RCE: {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
    },
    VulnerabilityType.AUTH_BYPASS: {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Persistence",
    },
    VulnerabilityType.SSRF: {
        "technique_id": "T1090",
        "technique_name": "Proxy",
        "tactic": "Command and Control",
    },
    VulnerabilityType.XSS_STORED: {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
    },
    VulnerabilityType.IDOR: {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage Object",
        "tactic": "Collection",
    },
    VulnerabilityType.FILE_INCLUSION: {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "Collection",
    },
    VulnerabilityType.PRIVILEGE_ESCALATION: {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
    },
}


@dataclass
class GraphNode:
    """A node in the security knowledge graph."""
    node_id: str
    node_type: str  # "finding", "target", "technique", "asset"
    data: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class GraphEdge:
    """An edge connecting two nodes in the graph."""
    source_id: str
    target_id: str
    relation: str  # "has_vulnerability", "leads_to", "uses_technique", etc.
    weight: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    """A path through the graph representing an attack chain."""
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    total_weight: float
    start_node: str
    end_node: str

    @property
    def length(self) -> int:
        return len(self.nodes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.node_id for n in self.nodes],
            "edges": [(e.source_id, e.relation, e.target_id) for e in self.edges],
            "total_weight": self.total_weight,
            "length": self.length,
        }


class SecurityKnowledgeGraph:
    """
    Graph-based storage and analysis for security findings.

    Provides graph operations for:
    - Storing findings with relationships
    - Finding attack paths
    - Correlating findings
    - Mapping to MITRE ATT&CK

    Example:
        graph = SecurityKnowledgeGraph()

        # Add findings
        for finding in findings:
            graph.add_finding(finding)

        # Find attack paths to RCE
        paths = graph.find_attack_paths(
            goal_type="rce",
            max_depth=5
        )

        # Get MITRE mapping
        mitre_map = graph.get_mitre_coverage()
    """

    def __init__(self):
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self._adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self._reverse_adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)

    def add_finding(self, finding: Finding, target: str = None):
        """
        Add a finding to the graph.

        Creates nodes for the finding, its target, and MITRE technique,
        with appropriate edges connecting them.

        Args:
            finding: The finding to add
            target: Optional target identifier
        """
        # Create finding node
        finding_id = f"finding:{finding.fingerprint}"
        finding_node = GraphNode(
            node_id=finding_id,
            node_type="finding",
            data=finding.to_dict(),
            metadata={
                "severity": finding.severity.value,
                "vuln_type": finding.vuln_type.value,
                "confirmed": finding.confirmed,
            },
        )
        self._add_node(finding_node)

        # Create or link to target node
        target_id = target or self._extract_host(finding.url)
        if target_id:
            target_node_id = f"target:{target_id}"
            if target_node_id not in self.nodes:
                target_node = GraphNode(
                    node_id=target_node_id,
                    node_type="target",
                    data={"host": target_id},
                )
                self._add_node(target_node)

            # Connect finding to target
            self._add_edge(GraphEdge(
                source_id=target_node_id,
                target_id=finding_id,
                relation="has_vulnerability",
                weight=self._severity_to_weight(finding.severity),
            ))

        # Create MITRE technique node if mapped
        mitre_info = VULN_TO_MITRE.get(finding.vuln_type)
        if mitre_info:
            technique_id = f"technique:{mitre_info['technique_id']}"
            if technique_id not in self.nodes:
                technique_node = GraphNode(
                    node_id=technique_id,
                    node_type="technique",
                    data=mitre_info,
                )
                self._add_node(technique_node)

            # Connect finding to technique
            self._add_edge(GraphEdge(
                source_id=finding_id,
                target_id=technique_id,
                relation="uses_technique",
            ))

        # Add potential chain edges based on vulnerability type
        self._add_chain_edges(finding, finding_id)

        logger.debug(f"Added finding to graph: {finding.title}")

    def _add_chain_edges(self, finding: Finding, finding_id: str):
        """Add edges for potential vulnerability chains."""
        # Define what each vuln type can lead to
        leads_to = {
            VulnerabilityType.SSRF: [VulnerabilityType.RCE, VulnerabilityType.SQL_INJECTION],
            VulnerabilityType.SQL_INJECTION: [VulnerabilityType.AUTH_BYPASS, VulnerabilityType.RCE],
            VulnerabilityType.XSS_STORED: [VulnerabilityType.AUTH_BYPASS],
            VulnerabilityType.FILE_INCLUSION: [VulnerabilityType.RCE],
            VulnerabilityType.AUTH_BYPASS: [VulnerabilityType.PRIVILEGE_ESCALATION],
            VulnerabilityType.IDOR: [VulnerabilityType.PRIVILEGE_ESCALATION],
        }

        targets = leads_to.get(finding.vuln_type, [])

        # Find existing findings that this could chain to
        for node_id, node in self.nodes.items():
            if node.node_type != "finding":
                continue

            node_vuln_type = node.metadata.get("vuln_type")
            if node_vuln_type and VulnerabilityType(node_vuln_type) in targets:
                # Check if same target
                if self._same_target(finding, node):
                    self._add_edge(GraphEdge(
                        source_id=finding_id,
                        target_id=node_id,
                        relation="leads_to",
                        weight=0.8,
                    ))

    def _same_target(self, finding: Finding, node: GraphNode) -> bool:
        """Check if finding and node are for the same target."""
        try:
            node_url = node.data.get("url", "")
            return self._extract_host(finding.url) == self._extract_host(node_url)
        except Exception:
            return False

    def add_asset(self, asset_id: str, asset_type: str, metadata: dict = None):
        """
        Add an asset node (subdomain, IP, service, etc.)

        Args:
            asset_id: Unique identifier for the asset
            asset_type: Type of asset (subdomain, ip, service, port)
            metadata: Additional metadata
        """
        node_id = f"asset:{asset_id}"
        node = GraphNode(
            node_id=node_id,
            node_type="asset",
            data={
                "asset_id": asset_id,
                "asset_type": asset_type,
            },
            metadata=metadata or {},
        )
        self._add_node(node)

    def link_finding_to_asset(self, finding: Finding, asset_id: str):
        """Link a finding to a discovered asset."""
        finding_id = f"finding:{finding.fingerprint}"
        asset_node_id = f"asset:{asset_id}"

        if finding_id in self.nodes and asset_node_id in self.nodes:
            self._add_edge(GraphEdge(
                source_id=asset_node_id,
                target_id=finding_id,
                relation="has_vulnerability",
            ))

    def find_attack_paths(
        self,
        start_type: str = None,
        goal_type: str = "rce",
        max_depth: int = 5,
    ) -> list[AttackPath]:
        """
        Find attack paths through the graph.

        Args:
            start_type: Starting vulnerability type (None for all entry points)
            goal_type: Goal vulnerability type to reach
            max_depth: Maximum path depth

        Returns:
            List of AttackPath objects representing possible attack chains
        """
        paths = []

        # Find all potential starting nodes
        start_nodes = []
        for node_id, node in self.nodes.items():
            if node.node_type != "finding":
                continue

            if start_type:
                if node.metadata.get("vuln_type") == start_type:
                    start_nodes.append(node_id)
            else:
                # Use entry-point vulnerabilities as starts
                entry_types = ["sql_injection", "xss_reflected", "ssrf", "command_injection"]
                if node.metadata.get("vuln_type") in entry_types:
                    start_nodes.append(node_id)

        # Find goal nodes
        goal_nodes = []
        for node_id, node in self.nodes.items():
            if node.node_type == "finding" and node.metadata.get("vuln_type") == goal_type:
                goal_nodes.append(node_id)

        # BFS/DFS to find paths
        for start in start_nodes:
            for goal in goal_nodes:
                if start == goal:
                    continue
                found_paths = self._find_paths_bfs(start, goal, max_depth)
                paths.extend(found_paths)

        # Sort by total weight (lower is better - shorter/simpler paths)
        paths.sort(key=lambda p: p.total_weight)

        return paths[:10]  # Return top 10 paths

    def _find_paths_bfs(
        self,
        start: str,
        goal: str,
        max_depth: int,
    ) -> list[AttackPath]:
        """Find paths using BFS."""
        paths = []
        queue = [(start, [start], [], 0.0)]  # (current, path, edges, weight)
        visited_paths = set()

        while queue:
            current, path, edges, weight = queue.pop(0)

            if len(path) > max_depth:
                continue

            if current == goal:
                path_key = tuple(path)
                if path_key not in visited_paths:
                    visited_paths.add(path_key)
                    paths.append(AttackPath(
                        nodes=[self.nodes[n] for n in path],
                        edges=edges,
                        total_weight=weight,
                        start_node=start,
                        end_node=goal,
                    ))
                continue

            for neighbor, relation in self._adjacency.get(current, []):
                if neighbor not in path:  # Avoid cycles
                    edge = self._find_edge(current, neighbor, relation)
                    new_weight = weight + (edge.weight if edge else 1.0)
                    queue.append((
                        neighbor,
                        path + [neighbor],
                        edges + [edge] if edge else edges,
                        new_weight,
                    ))

        return paths

    def get_mitre_coverage(self) -> dict[str, Any]:
        """
        Get MITRE ATT&CK coverage based on findings.

        Returns:
            Dictionary with tactics and techniques covered
        """
        coverage = {
            "tactics": defaultdict(list),
            "techniques": [],
            "total_techniques": 0,
        }

        technique_nodes = [n for n in self.nodes.values() if n.node_type == "technique"]

        for node in technique_nodes:
            technique_id = node.data.get("technique_id")
            technique_name = node.data.get("technique_name")
            tactic = node.data.get("tactic")

            if technique_id:
                coverage["techniques"].append({
                    "id": technique_id,
                    "name": technique_name,
                    "tactic": tactic,
                })
                coverage["tactics"][tactic].append(technique_id)

        coverage["total_techniques"] = len(coverage["techniques"])

        return dict(coverage)

    def get_finding_relationships(self, finding: Finding) -> dict[str, Any]:
        """
        Get all relationships for a specific finding.

        Args:
            finding: The finding to analyze

        Returns:
            Dictionary of relationships
        """
        finding_id = f"finding:{finding.fingerprint}"

        if finding_id not in self.nodes:
            return {"error": "Finding not in graph"}

        # Get outgoing edges
        outgoing = []
        for neighbor, relation in self._adjacency.get(finding_id, []):
            outgoing.append({
                "target": neighbor,
                "relation": relation,
                "target_type": self.nodes[neighbor].node_type if neighbor in self.nodes else "unknown",
            })

        # Get incoming edges
        incoming = []
        for neighbor, relation in self._reverse_adjacency.get(finding_id, []):
            incoming.append({
                "source": neighbor,
                "relation": relation,
                "source_type": self.nodes[neighbor].node_type if neighbor in self.nodes else "unknown",
            })

        return {
            "finding_id": finding_id,
            "outgoing": outgoing,
            "incoming": incoming,
            "mitre_technique": self._get_mitre_for_finding(finding_id),
        }

    def _get_mitre_for_finding(self, finding_id: str) -> Optional[dict]:
        """Get MITRE technique for a finding."""
        for neighbor, relation in self._adjacency.get(finding_id, []):
            if relation == "uses_technique" and neighbor in self.nodes:
                return self.nodes[neighbor].data
        return None

    def get_statistics(self) -> dict[str, Any]:
        """Get graph statistics."""
        finding_nodes = [n for n in self.nodes.values() if n.node_type == "finding"]
        target_nodes = [n for n in self.nodes.values() if n.node_type == "target"]

        # Count by severity
        by_severity = defaultdict(int)
        for node in finding_nodes:
            sev = node.metadata.get("severity", "unknown")
            by_severity[sev] += 1

        # Count by vuln type
        by_type = defaultdict(int)
        for node in finding_nodes:
            vtype = node.metadata.get("vuln_type", "unknown")
            by_type[vtype] += 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "findings": len(finding_nodes),
            "targets": len(target_nodes),
            "by_severity": dict(by_severity),
            "by_vuln_type": dict(by_type),
            "mitre_coverage": self.get_mitre_coverage(),
        }

    def export_to_json(self) -> str:
        """Export graph to JSON format."""
        data = {
            "nodes": [
                {
                    "id": node.node_id,
                    "type": node.node_type,
                    "data": node.data,
                    "metadata": node.metadata,
                }
                for node in self.nodes.values()
            ],
            "edges": [
                {
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "relation": edge.relation,
                    "weight": edge.weight,
                }
                for edge in self.edges
            ],
        }
        return json.dumps(data, indent=2, default=str)

    def import_from_json(self, json_str: str):
        """Import graph from JSON format."""
        data = json.loads(json_str)

        for node_data in data.get("nodes", []):
            node = GraphNode(
                node_id=node_data["id"],
                node_type=node_data["type"],
                data=node_data.get("data", {}),
                metadata=node_data.get("metadata", {}),
            )
            self._add_node(node)

        for edge_data in data.get("edges", []):
            edge = GraphEdge(
                source_id=edge_data["source"],
                target_id=edge_data["target"],
                relation=edge_data["relation"],
                weight=edge_data.get("weight", 1.0),
            )
            self._add_edge(edge)

    def _add_node(self, node: GraphNode):
        """Add a node to the graph."""
        self.nodes[node.node_id] = node

    def _add_edge(self, edge: GraphEdge):
        """Add an edge to the graph."""
        # Avoid duplicate edges
        for existing in self.edges:
            if (existing.source_id == edge.source_id and
                existing.target_id == edge.target_id and
                existing.relation == edge.relation):
                return

        self.edges.append(edge)
        self._adjacency[edge.source_id].append((edge.target_id, edge.relation))
        self._reverse_adjacency[edge.target_id].append((edge.source_id, edge.relation))

    def _find_edge(self, source: str, target: str, relation: str) -> Optional[GraphEdge]:
        """Find an edge by source, target, and relation."""
        for edge in self.edges:
            if (edge.source_id == source and
                edge.target_id == target and
                edge.relation == relation):
                return edge
        return None

    def _extract_host(self, url: str) -> str:
        """Extract host from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split("/")[0]
        except Exception:
            return url

    def _severity_to_weight(self, severity: Severity) -> float:
        """Convert severity to edge weight (lower = more important)."""
        weights = {
            Severity.CRITICAL: 0.2,
            Severity.HIGH: 0.4,
            Severity.MEDIUM: 0.6,
            Severity.LOW: 0.8,
            Severity.INFO: 1.0,
        }
        return weights.get(severity, 0.5)

    def clear(self):
        """Clear all data from the graph."""
        self.nodes.clear()
        self.edges.clear()
        self._adjacency.clear()
        self._reverse_adjacency.clear()
