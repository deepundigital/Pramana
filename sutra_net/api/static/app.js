document.addEventListener("DOMContentLoaded", () => {
  // Tab Switching
  const navItems = document.querySelectorAll(".nav-item[data-tab]");
  const tabPanes = document.querySelectorAll(".tab-pane");

  navItems.forEach(item => {
    item.addEventListener("click", () => {
      const targetTab = item.getAttribute("data-tab");
      navItems.forEach(i => i.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));

      item.classList.add("active");
      const targetPane = document.getElementById(`tab-${targetTab}`);
      if (targetPane) targetPane.classList.add("active");

      if (targetTab === "network") loadNetworkTriage();
      if (targetTab === "mobile") loadMobileTriage();
      if (targetTab === "graph") loadKnowledgeGraph();
    });
  });

  // 1. Ingest Demo Evidence
  const btnIngest = document.getElementById("btn-ingest-samples");
  btnIngest.addEventListener("click", async () => {
    btnIngest.innerText = "⏳ Ingesting...";
    try {
      const res = await fetch("/api/ingest/sample", { method: "POST" });
      const data = await res.json();
      btnIngest.innerText = "✅ Evidence Ingested";
      setTimeout(() => btnIngest.innerText = "🚀 Ingest Demo Evidence", 3000);
      loadNetworkTriage();
      loadMobileTriage();
      loadKnowledgeGraph();
    } catch (err) {
      alert("Ingestion error: " + err);
      btnIngest.innerText = "🚀 Ingest Demo Evidence";
    }
  });

  // 2. Load Network Triage
  async function loadNetworkTriage() {
    const tbody = document.getElementById("flows-table-body");
    tbody.innerHTML = "<tr><td colspan='7'>Loading flow analysis...</td></tr>";
    try {
      const res = await fetch("/api/triage/network");
      const data = await res.json();
      tbody.innerHTML = "";

      document.getElementById("stat-malicious-count").innerText = `${data.malicious_count} C2 Beacon(s)`;

      data.flows.forEach(flow => {
        const isMal = flow.is_malicious;
        const badgeClass = isMal ? "badge-amber" : "badge";
        const tr = document.createElement("tr");
        if (isMal) tr.style.backgroundColor = "rgba(239, 68, 68, 0.08)";

        tr.innerHTML = `
          <td><code>${flow.flow_id}</code></td>
          <td>${flow.flow_details.packet_count}</td>
          <td>${flow.flow_details.mean_delta_sec}s</td>
          <td><code>${flow.flow_details.jitter_sec}s</code></td>
          <td><strong style="color: ${isMal ? '#EF4444' : '#10B981'}">${(flow.anomaly_score * 100).toFixed(1)}%</strong></td>
          <td><span class="badge ${badgeClass}">${flow.threat_type}</span></td>
          <td><small>${flow.mitre_technique || "None"}</small></td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan='7'>Error loading flows: ${err}</td></tr>`;
    }
  }

  // 3. Load Mobile Triage
  async function loadMobileTriage() {
    const tbody = document.getElementById("mobile-table-body");
    tbody.innerHTML = "<tr><td colspan='6'>Loading mobile triage...</td></tr>";
    try {
      const res = await fetch("/api/triage/mobile");
      const data = await res.json();
      tbody.innerHTML = "";

      document.getElementById("stat-mobile-flagged").innerText = `${data.flagged_count} Extortions`;

      data.messages.forEach(msg => {
        const isFlagged = msg.is_flagged;
        const tr = document.createElement("tr");
        if (isFlagged) tr.style.backgroundColor = "rgba(245, 158, 11, 0.08)";

        const upis = msg.entities.upi_vpas.length ? msg.entities.upi_vpas.join("<br/>") : "None";
        tr.innerHTML = `
          <td><code>${msg.sender}</code></td>
          <td><small>${msg.timestamp || 'N/A'}</small></td>
          <td>${msg.text}</td>
          <td><code style="color: #F59E0B">${upis}</code></td>
          <td><span class="badge ${isFlagged ? 'badge-amber' : 'badge'}">${msg.fraud_analysis.primary_category}</span></td>
          <td><strong style="color: ${isFlagged ? '#EF4444' : '#10B981'}">${(msg.fraud_analysis.fraud_score * 100).toFixed(0)}%</strong></td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan='6'>Error loading messages: ${err}</td></tr>`;
    }
  }

  // 4. Render Knowledge Graph with Cytoscape
  let cy = null;
  async function loadKnowledgeGraph() {
    try {
      const res = await fetch("/api/graph");
      const graphData = await res.json();

      const elements = [];
      graphData.elements.nodes.forEach(n => {
        let nodeColor = "#38BDF8";
        if (n.data.type === "c2_server") nodeColor = "#EF4444";
        if (n.data.type === "upi_vpa") nodeColor = "#F59E0B";
        if (n.data.type === "phone_number") nodeColor = "#10B981";

        elements.push({
          data: { ...n.data, color: nodeColor }
        });
      });

      graphData.elements.edges.forEach(e => {
        elements.push({ data: e.data });
      });

      if (!cy) {
        cy = cytoscape({
          container: document.getElementById("cy-container"),
          elements: elements,
          style: [
            {
              selector: "node",
              style: {
                "background-color": "data(color)",
                "label": "data(label)",
                "color": "#F8FAFC",
                "font-size": "11px",
                "text-valign": "bottom",
                "text-margin-y": "6px",
                "width": 34,
                "height": 34
              }
            },
            {
              selector: "edge",
              style: {
                "width": 2,
                "line-color": "#475569",
                "target-arrow-color": "#475569",
                "target-arrow-shape": "triangle",
                "curve-style": "bezier",
                "label": "data(label)",
                "font-size": "9px",
                "color": "#94A3B8"
              }
            }
          ],
          layout: {
            name: "cose",
            animate: false,
            padding: 30
          }
        });
      } else {
        cy.json({ elements: elements });
        cy.layout({ name: "cose", animate: false }).run();
      }
    } catch (err) {
      console.error("Error loading graph:", err);
    }
  }

  // 5. Execute DuckDB SQL Query
  const btnRunSql = document.getElementById("btn-run-sql");
  btnRunSql.addEventListener("click", async () => {
    const query_id = document.getElementById("sql-query-input").value;
    const labelTime = document.getElementById("query-exec-time");
    labelTime.innerText = "Executing...";

    try {
      const res = await fetch("/api/query/sql", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query_id, limit: 20 })
      });
      const data = await res.json();

      if (!res.ok || !data.success) {
        labelTime.innerText = "Query failed";
        alert("Query failed: " + (data.error || data.detail || "Invalid request."));
        return;
      }

      labelTime.innerText = `⚡ Completed in ${data.execution_ms} ms (${data.row_count} rows)`;

      const thead = document.getElementById("sql-results-head");
      const tbody = document.getElementById("sql-results-body");
      thead.innerHTML = "";
      tbody.innerHTML = "";

      if (data.columns && data.columns.length) {
        const headerTr = document.createElement("tr");
        data.columns.forEach(col => {
          const th = document.createElement("th");
          th.innerText = col;
          headerTr.appendChild(th);
        });
        thead.appendChild(headerTr);

        data.data.forEach(row => {
          const tr = document.createElement("tr");
          data.columns.forEach(col => {
            const td = document.createElement("td");
            td.innerText = row[col] !== null ? row[col] : "NULL";
            tr.appendChild(td);
          });
          tbody.appendChild(tr);
        });
      }
    } catch (err) {
      labelTime.innerText = "Request failed";
      alert("SQL execution failed: " + err);
    }
  });

  // 6. Generate BSA Section 63 Certificate
  const btnCert = document.getElementById("btn-generate-cert");
  btnCert.addEventListener("click", async () => {
    btnCert.innerText = "⏳ Generating Courtroom Certificate...";
    const case_id = document.getElementById("cert-case-id").value;
    const examiner_name = document.getElementById("cert-examiner").value;
    const agency_name = document.getElementById("cert-agency").value;

    try {
      const res = await fetch("/api/compliance/certificate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ case_id, examiner_name, agency_name })
      });
      const data = await res.json();
      btnCert.innerText = "✅ Certificate Issued";

      const container = document.getElementById("cert-download-container");
      container.innerHTML = `
        <div style="background: rgba(16, 185, 129, 0.15); border: 1px solid #10B981; padding: 12px; border-radius: 6px;">
          <p style="color: #10B981; font-weight: 600; margin-bottom: 6px;">
            Official BSA Section 63 Certificate Generated Successfully!
          </p>
          <a href="${data.pdf_download_url}" target="_blank" class="btn btn-emerald">
            📄 Download Official Section 63 PDF Certificate
          </a>
        </div>
      `;
    } catch (err) {
      alert("Certificate generation error: " + err);
      btnCert.innerText = "⚖️ Generate & Download Signed Section 63 PDF Certificate";
    }
  });

  // Trigger initial background load
  loadNetworkTriage();
  loadMobileTriage();
});
