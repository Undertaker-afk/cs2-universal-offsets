use crate::analysis::AnalysisResult;
use crate::signatures::SignatureReport;
use anyhow::Result;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub fn generate_reports(
    out_dir: &Path,
    analysis: &AnalysisResult,
    sigs: &Option<SignatureReport>,
    html: bool,
) -> Result<()> {
    // Generate JSON report
    let json = serde_json::to_string_pretty(analysis)?;
    fs::write(out_dir.join("report.json"), json)?;

    // Differential analysis logic
    let mut diff_content = String::new();
    let latest_report_path = Path::new("include/latest/report.json");
    if latest_report_path.exists() {
        if let Ok(latest_json) = fs::read_to_string(latest_report_path) {
            let latest_res: Result<AnalysisResult, _> = serde_json::from_str(&latest_json);
            if let Ok(latest) = latest_res {
                diff_content.push_str("<h2>Differential Analysis</h2>\n\n");
                for (module, (classes, _)) in &analysis.schemas {
                    if let Some((old_classes, _)) = latest.schemas.get(module) {
                        for class in classes {
                            if !old_classes.iter().any(|c| c.name == class.name) {
                                diff_content.push_str(&format!("<div class='diff-item new'>+ New Class: <code>{}</code> in {}</div>\n", class.name, module));
                            }
                        }
                    } else {
                        diff_content.push_str(&format!(
                            "<div class='diff-item new'>+ New Module: <code>{}</code></div>\n",
                            module
                        ));
                    }
                }
            }
        }
    }

    // Generate Markdown report
    let mut md = String::new();
    md.push_str("# CS2 Engine State Report\n\n");
    md.push_str(&format!(
        "- **Analysis Time**: {}\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    ));
    md.push_str(&format!(
        "- **Modules Scanned**: {}\n",
        analysis.schemas.len()
    ));
    md.push_str(&format!(
        "- **Classes Discovered**: {}\n",
        analysis
            .schemas
            .values()
            .map(|(c, _)| c.len())
            .sum::<usize>()
    ));
    if let Some(r) = sigs {
        md.push_str(&format!(
            "- **Signatures Validated**: {}/{} ({:.1}%)\n",
            r.found,
            r.total,
            (r.found as f32 / r.total as f32) * 100.0
        ));
    }
    md.push_str("\n---\n\n");
    md.push_str(
        &diff_content
            .replace("<h2>", "## ")
            .replace("</h2>", "")
            .replace("<code>", "`")
            .replace("</code>", "`")
            .replace("<div class='diff-item new'>", "- ")
            .replace("</div>", ""),
    );
    fs::write(out_dir.join("REPORT.md"), md)?;

    if html {
        // Collect additional metadata for the HTML report
        let mut module_meta = BTreeMap::new();
        let manifest_path = out_dir.join("manifest.json");
        if let Ok(m_json) = fs::read_to_string(manifest_path) {
            if let Ok(m_val) = serde_json::from_str::<serde_json::Value>(&m_json) {
                if let Some(modules) = m_val.get("modules") {
                    if let Some(m_obj) = modules.as_object() {
                        for (k, v) in m_obj {
                            module_meta.insert(k.clone(), v.clone());
                        }
                    }
                }
            }
        }

        let html_content = generate_beautiful_html(analysis, sigs, &diff_content, &module_meta);
        fs::write(out_dir.join("report.html"), html_content)?;
    }

    Ok(())
}

fn generate_beautiful_html(
    analysis: &AnalysisResult,
    sigs: &Option<SignatureReport>,
    diff: &str,
    module_meta: &BTreeMap<String, serde_json::Value>,
) -> String {
    let mut sig_rows = String::new();
    if let Some(report) = sigs {
        for hit in &report.hits {
            let status_class = if hit.found { "success" } else { "error" };
            let status_icon = if hit.found { "✓" } else { "✗" };
            let confidence = hit
                .confidence
                .map(|c| format!("{:.1}%", c * 100.0))
                .unwrap_or_else(|| "-".to_string());
            let rva = hit
                .rva
                .map(|r| format!("0x{:X}", r))
                .unwrap_or_else(|| "-".to_string());
            sig_rows.push_str(&format!(
                "<tr><td><span class='status-icon {}'>{}</span></td><td>{}</td><td>{}</td><td>{}</td><td><span class='confidence-badge' style='background: hsla({:.0}, 70%, 50%, 0.2); color: hsl({:.0}, 70%, 60%);'>{}</span></td><td><code>{}</code></td></tr>",
                status_class, status_icon, hit.module, hit.name, rva,
                hit.confidence.unwrap_or(0.0) * 120.0, hit.confidence.unwrap_or(0.0) * 120.0,
                confidence, hit.pattern
            ));
        }
    }

    let mut convar_rows = String::new();
    for (name, cv) in &analysis.convars {
        convar_rows.push_str(&format!(
            "<tr><td>{}</td><td><code>{:#X}</code></td><td>{}</td><td>{}</td></tr>",
            name,
            cv.flags,
            cv.description,
            cv.current_value.as_deref().unwrap_or("-")
        ));
    }

    let mut event_rows = String::new();
    for (name, event) in &analysis.game_events {
        let fields = event
            .fields
            .iter()
            .map(|f| format!("<code>{}</code>", f.name))
            .collect::<Vec<_>>()
            .join(", ");
        event_rows.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>", name, fields));
    }

    let mut interface_rows = String::new();
    for (module, ifaces) in &analysis.interfaces {
        for (name, offset) in ifaces {
            interface_rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td><code>{:#X}</code></td></tr>",
                module, name, offset
            ));
        }
    }

    let mut module_rows = String::new();
    for (name, meta) in module_meta {
        let base = meta.get("base").and_then(|v: &serde_json::Value| v.as_str()).unwrap_or("-");
        let size = meta.get("size").and_then(|v: &serde_json::Value| v.as_u64()).unwrap_or(0);
        let timestamp = meta.get("timestamp").and_then(|v: &serde_json::Value| v.as_u64()).unwrap_or(0);
        module_rows.push_str(&format!(
            "<tr><td>{}</td><td><code>{}</code></td><td>{:#X}</td><td><code>{:#X}</code></td></tr>",
            name, base, size, timestamp
        ));
    }

    let mut resource_sections = String::new();
    for (category, items) in &analysis.resources {
        resource_sections.push_str(&format!(
            "<div class='resource-group'><h3>{}</h3><div class='tag-cloud'>{}</div></div>",
            category,
            items
                .iter()
                .map(|i| format!("<span>{}</span>", i))
                .collect::<Vec<_>>()
                .join("")
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CS2 Engine Analysis Dashboard</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Plus+Jakarta+Sans:wght@400;600;700&display=swap');
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --surface-accent: #21262d;
            --border: #30363d;
            --primary: #58a6ff;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --success: #3fb950;
            --error: #f85149;
            --warning: #d29922;
            --cyan: #38f8f8;
            --magenta: #d670d6;
        }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
            margin: 0;
            padding: 0;
            line-height: 1.5;
        }}
        .header {{
            background: linear-gradient(180deg, var(--surface) 0%, var(--bg) 100%);
            border-bottom: 1px solid var(--border);
            padding: 60px 0;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 3em;
            color: var(--cyan);
            letter-spacing: -2px;
            font-weight: 800;
        }}
        .header p {{ color: var(--text-muted); margin-top: 15px; font-size: 1.1em; }}

        .container {{ max-width: 1400px; margin: 0 auto; padding: 0 60px 100px 60px; }}

        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 25px;
            margin-top: -40px;
            margin-bottom: 60px;
        }}
        .stat-card {{
            background: var(--surface);
            padding: 30px;
            border-radius: 16px;
            border: 1px solid var(--border);
            box-shadow: 0 8px 24px rgba(0,0,0,0.3);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        .stat-card:hover {{ transform: translateY(-5px); border-color: var(--primary); box-shadow: 0 12px 32px rgba(88, 166, 255, 0.15); }}
        .stat-card .label {{ color: var(--text-muted); font-size: 0.85em; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; }}
        .stat-card .value {{ font-size: 2.5em; font-weight: 800; color: var(--primary); margin-top: 8px; }}

        h2 {{
            font-size: 2em;
            margin-top: 80px;
            margin-bottom: 30px;
            display: flex;
            align-items: center;
            gap: 15px;
            font-weight: 700;
            color: var(--text);
        }}
        h2::before {{ content: ''; width: 6px; height: 1.2em; background: var(--cyan); border-radius: 3px; display: block; }}

        .section-box {{
            background: var(--surface);
            border-radius: 16px;
            border: 1px solid var(--border);
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: var(--surface-accent); color: var(--text-muted); font-weight: 600; text-align: left; padding: 18px 24px; border-bottom: 1px solid var(--border); font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px; }}
        td {{ padding: 18px 24px; border-bottom: 1px solid var(--border); font-size: 0.95em; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: rgba(88, 166, 255, 0.03); }}

        code {{
            font-family: 'JetBrains Mono', monospace;
            background: rgba(110, 118, 129, 0.2);
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.85em;
            color: #79c0ff;
        }}
        .status-icon {{ width: 24px; height: 24px; display: inline-flex; align-items: center; justify-content: center; border-radius: 50%; font-size: 0.8em; font-weight: 900; }}
        .status-icon.success {{ background: rgba(63, 185, 80, 0.15); color: var(--success); }}
        .status-icon.error {{ background: rgba(248, 81, 73, 0.15); color: var(--error); }}

        .confidence-badge {{
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }}

        .diff {{
            background: rgba(56, 248, 248, 0.03);
            border: 1px solid var(--cyan);
            border-radius: 16px;
            padding: 30px;
            margin: 40px 0;
        }}
        .diff h2 {{ margin-top: 0; color: var(--cyan); }}
        .diff-item {{ margin-bottom: 10px; font-family: 'JetBrains Mono', monospace; font-size: 0.9em; }}
        .diff-item.new {{ color: var(--success); }}

        .tag-cloud {{ display: flex; flex-wrap: wrap; gap: 8px; padding: 20px; }}
        .tag-cloud span {{
            background: var(--surface-accent);
            border: 1px solid var(--border);
            padding: 6px 14px;
            border-radius: 8px;
            font-size: 0.85em;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }}
        .resource-group h3 {{ margin: 20px 0 10px 20px; color: var(--magenta); font-size: 1.1em; }}

        ::-webkit-scrollbar {{ width: 10px; }}
        ::-webkit-scrollbar-track {{ background: var(--bg); }}
        ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 5px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: var(--text-muted); }}
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>Engine Insight Dashboard</h1>
            <p>Source 2 SDK Analysis Report • {}</p>
        </div>
    </div>

    <div class="container">
        <div class="stats">
            <div class="stat-card"><div class="label">Modules</div><div class="value">{}</div></div>
            <div class="stat-card"><div class="label">Classes</div><div class="value">{}</div></div>
            <div class="stat-card"><div class="label">Interfaces</div><div class="value">{}</div></div>
            <div class="stat-card"><div class="label">Signatures</div><div class="value">{}</div></div>
            <div class="stat-card"><div class="label">ConVars</div><div class="value">{}</div></div>
        </div>

        {}

        <h2>Signature Analysis</h2>
        <div class="section-box">
            <table>
                <thead><tr><th>Status</th><th>Module</th><th>Name</th><th>RVA</th><th>Confidence</th><th>Pattern / Needle</th></tr></thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <h2>Console Variables</h2>
        <div class="section-box">
            <table>
                <thead><tr><th>Name</th><th>Flags</th><th>Description</th><th>Current Value</th></tr></thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <h2>Event Definitions</h2>
        <div class="section-box">
            <table>
                <thead><tr><th>Event</th><th>Field Schema</th></tr></thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <h2>Interfaces</h2>
        <div class="section-box">
            <table>
                <thead><tr><th>Module</th><th>Interface</th><th>Offset</th></tr></thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <h2>Module Metadata</h2>
        <div class="section-box">
            <table>
                <thead><tr><th>Module</th><th>Base Address</th><th>Size</th><th>PE Timestamp</th></tr></thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <h2>Resource Map</h2>
        <div class="section-box">
            {}
        </div>
    </div>
</body>
</html>"#,
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        analysis.schemas.len(),
        analysis
            .schemas
            .values()
            .map(|(c, _)| c.len())
            .sum::<usize>(),
        analysis.interfaces.values().map(|i| i.len()).sum::<usize>(),
        sigs.as_ref()
            .map(|s| format!("{}/{}", s.found, s.total))
            .unwrap_or_else(|| "-".into()),
        analysis.convars.len(),
        if diff.is_empty() {
            "".to_string()
        } else {
            format!("<div class='diff'>{}</div>", diff)
        },
        sig_rows,
        convar_rows,
        event_rows,
        interface_rows,
        module_rows,
        resource_sections
    )
}
