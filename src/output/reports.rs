use anyhow::Result;
use std::fs;
use std::path::Path;
use crate::analysis::AnalysisResult;
use crate::signatures::SignatureReport;

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
                 diff_content.push_str("<h2>Changes from latest dump</h2>\n\n");
                 for (module, (classes, _)) in &analysis.schemas {
                     if let Some((old_classes, _)) = latest.schemas.get(module) {
                         for class in classes {
                             if !old_classes.iter().any(|c| c.name == class.name) {
                                 diff_content.push_str(&format!("<div class='diff-item'>• New Class: <code>{}</code> in {}</div>\n", class.name, module));
                             }
                         }
                     }
                 }
             }
        }
    }

    // Generate Markdown report
    let mut md = String::new();
    md.push_str("# CS2 SDK Dump Report\n\n");
    md.push_str(&format!("- **Timestamp**: {}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")));
    md.push_str(&format!("- **Modules**: {}\n", analysis.schemas.len()));
    md.push_str(&format!("- **Total classes**: {}\n", analysis.schemas.values().map(|(c, _)| c.len()).sum::<usize>()));
    if let Some(r) = sigs {
        md.push_str(&format!("- **Signatures**: {}/{} found\n", r.found, r.total));
    }
    md.push_str("\n---\n\n");
    md.push_str(&diff_content.replace("<br>", "\n").replace("<code>", "`").replace("</code>", "`").replace("<div class='diff-item'>", "- ").replace("</div>", ""));
    fs::write(out_dir.join("REPORT.md"), md)?;

    if html {
        let html_content = generate_beautiful_html(analysis, sigs, &diff_content);
        fs::write(out_dir.join("report.html"), html_content)?;
    }

    Ok(())
}

fn generate_beautiful_html(analysis: &AnalysisResult, sigs: &Option<SignatureReport>, diff: &str) -> String {
    let mut sig_rows = String::new();
    if let Some(report) = sigs {
        for hit in &report.hits {
            let status_class = if hit.found { "success" } else { "error" };
            let status_icon = if hit.found { "✓" } else { "✗" };
            let confidence = hit.confidence.map(|c| format!("{:.1}%", c * 100.0)).unwrap_or_else(|| "-".to_string());
            let rva = hit.rva.map(|r| format!("0x{:X}", r)).unwrap_or_else(|| "-".to_string());
            sig_rows.push_str(&format!(
                "<tr><td><span class='status-icon {}'>{}</span></td><td>{}</td><td>{}</td><td>{}</td><td><span class='confidence'>{}</span></td><td><code>{}</code></td></tr>",
                status_class, status_icon, hit.module, hit.name, rva, confidence, hit.pattern
            ));
        }
    }

    let mut convar_rows = String::new();
    for (name, cv) in &analysis.convars {
        convar_rows.push_str(&format!(
            "<tr><td>{}</td><td><code>{:#X}</code></td><td>{}</td></tr>",
            name, cv.flags, cv.description
        ));
    }

    let mut event_rows = String::new();
    for (name, event) in &analysis.game_events {
        let fields = event.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>().join(", ");
        event_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            name, fields
        ));
    }

    let mut resource_sections = String::new();
    for (category, items) in &analysis.resources {
        resource_sections.push_str(&format!(
            "<div class='resource-cat'><h3>{}</h3><ul>{}</ul></div>",
            category,
            items.iter().map(|i| format!("<li>{}</li>", i)).collect::<Vec<_>>().join("")
        ));
    }

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CS2 SDK Analysis Report</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=Fira+Code:wght@400;500&display=swap');
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --primary: #58a6ff;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --success: #3fb950;
            --error: #f85149;
            --warning: #d29922;
            --cyan: #38f8f8;
        }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            margin: 0;
            padding: 0;
            line-height: 1.5;
        }}
        .header {{
            background: var(--surface);
            border-bottom: 1px solid var(--border);
            padding: 40px 0;
            margin-bottom: 40px;
            text-align: center;
        }}
        .header h1 {{ margin: 0; font-size: 2.5em; color: var(--cyan); letter-spacing: -1px; }}
        .header p {{ color: var(--text-muted); margin-top: 10px; }}
        .container {{ max-width: 1300px; margin: 0 auto; padding: 0 40px 80px 40px; }}

        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 40px; }}
        .stat-card {{
            background: var(--surface);
            padding: 24px;
            border-radius: 12px;
            border: 1px solid var(--border);
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-2px); border-color: var(--primary); }}
        .stat-card .label {{ color: var(--text-muted); font-size: 0.9em; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }}
        .stat-card .value {{ font-size: 2.2em; font-weight: 700; color: var(--primary); margin-top: 5px; }}

        h2 {{ font-size: 1.8em; margin-top: 60px; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }}
        h2::before {{ content: ''; width: 4px; height: 1em; background: var(--cyan); border-radius: 2px; }}

        .table-container {{
            background: var(--surface);
            border-radius: 12px;
            border: 1px solid var(--border);
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 40px;
        }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: rgba(255,255,255,0.03); color: var(--text-muted); font-weight: 600; text-align: left; padding: 14px 20px; border-bottom: 1px solid var(--border); font-size: 0.85em; text-transform: uppercase; }}
        td {{ padding: 14px 20px; border-bottom: 1px solid var(--border); font-size: 0.95em; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: rgba(88, 166, 255, 0.05); }}

        code {{
            font-family: 'Fira Code', monospace;
            background: rgba(139, 148, 158, 0.15);
            padding: 3px 6px;
            border-radius: 6px;
            font-size: 0.9em;
            color: #d19a66;
        }}
        .status-icon {{ font-weight: bold; width: 24px; height: 24px; display: inline-flex; align-items: center; justify-content: center; border-radius: 50%; font-size: 0.8em; }}
        .status-icon.success {{ background: rgba(63, 185, 80, 0.15); color: var(--success); }}
        .status-icon.error {{ background: rgba(248, 81, 73, 0.15); color: var(--error); }}

        .confidence {{
            font-weight: 600;
            color: var(--warning);
        }}

        .diff {{
            background: rgba(56, 248, 248, 0.05);
            border: 1px solid var(--cyan);
            border-radius: 12px;
            padding: 24px;
            margin: 40px 0;
        }}
        .diff h2 {{ margin-top: 0; color: var(--cyan); }}
        .diff-item {{ margin-bottom: 8px; font-family: 'Fira Code', monospace; }}

        .resource-cat {{ margin-bottom: 20px; padding-left: 20px; border-left: 2px solid var(--border); }}
        .resource-cat h3 {{ color: var(--primary); font-size: 1.1em; }}
        .resource-cat ul {{ list-style-type: none; padding: 0; display: flex; flex-wrap: wrap; gap: 10px; }}
        .resource-cat li {{ background: var(--surface); border: 1px solid var(--border); padding: 5px 12px; border-radius: 20px; font-size: 0.85em; }}

        ::-webkit-scrollbar {{ width: 10px; }}
        ::-webkit-scrollbar-track {{ background: var(--bg); }}
        ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 5px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: var(--text-muted); }}
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>CS2 SDK Analysis Report</h1>
            <p>Generated by Universal Dumper v1.5 • {}</p>
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

        <h2>Signature Scan Results</h2>
        <div class="table-container">
            <table>
                <thead><tr><th>Status</th><th>Module</th><th>Name</th><th>RVA</th><th>Confidence</th><th>Pattern / Needle</th></tr></thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <h2>Console Variables (ConVars)</h2>
        <div class="table-container">
            <table>
                <thead><tr><th>Name</th><th>Flags</th><th>Description</th></tr></thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <h2>Game Events</h2>
        <div class="table-container">
            <table>
                <thead><tr><th>Event Name</th><th>Fields</th></tr></thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <h2>Engine Resources</h2>
        <div class="table-container" style="padding: 20px;">
            {}
        </div>
    </div>
</body>
</html>"#,
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
    analysis.schemas.len(),
    analysis.schemas.values().map(|(c, _)| c.len()).sum::<usize>(),
    analysis.interfaces.values().map(|i| i.len()).sum::<usize>(),
    sigs.as_ref().map(|s| format!("{}/{}", s.found, s.total)).unwrap_or_else(|| "-".into()),
    analysis.convars.len(),
    if diff.is_empty() { "".to_string() } else { format!("<div class='diff'>{}</div>", diff) },
    sig_rows,
    convar_rows,
    event_rows,
    resource_sections
    )
}
