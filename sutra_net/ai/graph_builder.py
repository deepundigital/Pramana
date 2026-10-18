"""
Forensic Knowledge Graph: Builds temporal multi-entity correlation graphs
linking suspects, burner mobile numbers, UPI mule accounts, and C2 servers using NetworkX.
"""

from typing import List, Dict, Any, Optional
import networkx as nx


class ForensicKnowledgeGraph:
    """
    Constructs and queries heterogeneous forensic entity graphs.
    """

    def __init__(self):
        self.graph = nx.DiGraph()

    def add_entity(self, entity_id: str, entity_type: str, label: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
        """
        Adds a node to the forensic graph.
        """
        if not entity_id:
            return
        node_id = str(entity_id).strip()
        self.graph.add_node(
            node_id,
            entity_type=entity_type,
            label=label or node_id,
            metadata=metadata or {}
        )

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        relationship: str,
        timestamp: Optional[str] = None,
        weight: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Adds a directed relationship between entities.
        """
        if not source_id or not target_id:
            return
        s_id = str(source_id).strip()
        t_id = str(target_id).strip()

        if not self.graph.has_node(s_id):
            self.add_entity(s_id, "unknown", s_id)
        if not self.graph.has_node(t_id):
            self.add_entity(t_id, "unknown", t_id)

        self.graph.add_edge(
            s_id,
            t_id,
            relationship=relationship,
            timestamp=timestamp,
            weight=weight,
            metadata=metadata or {}
        )

    def ingest_mobile_entities(self, analyzed_messages: List[Dict[str, Any]]):
        """
        Populates graph from mobile messages (Senders -> UPI VPAs & Recipient Phones).
        """
        for msg in analyzed_messages:
            sender = msg.get("sender")
            if not sender:
                continue

            self.add_entity(sender, "phone_number", label=f"Phone: {sender}")
            entities = msg.get("entities", {})
            timestamp = msg.get("timestamp")

            # Link sender to extracted UPIs
            for upi in entities.get("upi_vpas", []):
                self.add_entity(upi, "upi_vpa", label=f"UPI: {upi}")
                self.add_relationship(
                    sender,
                    upi,
                    relationship="ASSOCIATED_UPI",
                    timestamp=timestamp,
                    weight=2.0
                )

            # Link sender to extracted phone references
            for phone in entities.get("phone_numbers", []):
                if phone != sender:
                    self.add_entity(phone, "phone_number", label=f"Contact: {phone}")
                    self.add_relationship(
                        sender,
                        phone,
                        relationship="CONTACTED",
                        timestamp=timestamp
                    )

    def ingest_network_flows(self, flows: List[Dict[str, Any]]):
        """
        Populates graph from network telemetry (Internal Host -> External C2 IP).
        """
        for flow in flows:
            src = flow.get("src_ip")
            dst = flow.get("dst_ip")
            if not src or not dst:
                continue

            threat = flow.get("threat_type", "BENIGN")
            is_mal = flow.get("is_malicious", False)

            self.add_entity(src, "internal_host", label=f"Host: {src}")
            self.add_entity(
                dst,
                "c2_server" if is_mal else "external_ip",
                label=f"{'C2: ' if is_mal else 'IP: '}{dst}",
                metadata={"threat": threat}
            )

            self.add_relationship(
                src,
                dst,
                relationship="C2_BEACON" if is_mal else "NETWORK_FLOW",
                timestamp=str(flow.get("start_time")),
                weight=3.0 if is_mal else 1.0,
                metadata={"bytes": flow.get("total_bytes")}
            )

    def find_mule_accounts(self) -> List[Dict[str, Any]]:
        """
        Identifies potential mule UPI accounts (high in-degree or central hub connectivity).
        """
        mules = []
        for node, in_deg in self.graph.in_degree():
            node_data = self.graph.nodes[node]
            if node_data.get("entity_type") == "upi_vpa":
                out_deg = self.graph.out_degree(node)
                senders = list(self.graph.predecessors(node))
                mules.append({
                    "upi_vpa": node,
                    "inbound_connections": in_deg,
                    "connected_senders": senders,
                    "risk_level": "CRITICAL_MULE" if in_deg >= 2 else "SUSPECT"
                })
        mules.sort(key=lambda x: x["inbound_connections"], reverse=True)
        return mules

    def to_cytoscape_json(self) -> Dict[str, Any]:
        """
        Converts the graph into Cytoscape.js format for interactive UI rendering.
        """
        elements = {"nodes": [], "edges": []}

        for node, data in self.graph.nodes(data=True):
            elements["nodes"].append({
                "data": {
                    "id": node,
                    "label": data.get("label", node),
                    "type": data.get("entity_type", "default"),
                    "metadata": data.get("metadata", {})
                }
            })

        for u, v, data in self.graph.edges(data=True):
            elements["edges"].append({
                "data": {
                    "id": f"{u}->{v}_{data.get('relationship', '')}",
                    "source": u,
                    "target": v,
                    "label": data.get("relationship", ""),
                    "timestamp": data.get("timestamp"),
                    "weight": data.get("weight", 1.0)
                }
            })

        return {
            "node_count": len(elements["nodes"]),
            "edge_count": len(elements["edges"]),
            "elements": elements
        }
