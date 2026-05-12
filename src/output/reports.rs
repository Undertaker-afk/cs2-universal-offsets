use anyhow::Result;
use std::fs;
use std::path::Path;
use crate::analysis::AnalysisResult;
use crate::signatures::SignatureReport;

pub fn generate_reports(
    out_dir: &Path,
    analysis: &AnalysisResult,
    _sigs: &Option<SignatureReport>,
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
                 diff_content.push_str("## Changes from latest dump\n\n");
                 // Compare classes
                 for (module, (classes, _)) in &analysis.schemas {
                     if let Some((old_classes, _)) = latest.schemas.get(module) {
                         for class in classes {
                             if !old_classes.iter().any(|c| c.name == class.name) {
                                 diff_content.push_str(&format!("- New Class: `{}` in {}\n", class.name, module));
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
    md.push_str(&format!("- Modules: {}\n", analysis.schemas.len()));
    md.push_str(&format!("- Total classes: {}\n", analysis.schemas.values().map(|(c, _)| c.len()).sum::<usize>()));
    md.push_str("\n");
    md.push_str(&diff_content);
    fs::write(out_dir.join("REPORT.md"), md)?;

    if html {
        let html_content = format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>CS2 SDK Report</title>
    <style>
        body {{ font-family: sans-serif; margin: 40px; background: #1a1a1a; color: #eee; }}
        h1, h2 {{ color: #00bcd4; }}
        code {{ background: #333; padding: 2px 4px; border-radius: 4px; }}
        .module {{ border: 1px solid #444; padding: 10px; margin-bottom: 10px; }}
    </style>
</head>
<body>
    <h1>CS2 SDK Dump Report</h1>
    <p>Modules found: {}</p>
    {}
</body>
</html>"#, analysis.schemas.len(), diff_content.replace("\n", "<br>"));
        fs::write(out_dir.join("report.html"), html_content)?;
    }

    Ok(())
}
