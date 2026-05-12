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

    // Generate Markdown report
    let mut md = String::new();
    md.push_str("# CS2 SDK Dump Report\n\n");
    md.push_str(&format!("- Modules: {}\n", analysis.schemas.len()));
    // ... more detailed MD ...
    fs::write(out_dir.join("REPORT.md"), md)?;

    if html {
        let html_content = format!(r#"<!DOCTYPE html>
<html>
<head><title>CS2 SDK Report</title></head>
<body>
    <h1>CS2 SDK Dump Report</h1>
    <p>Modules found: {}</p>
</body>
</html>"#, analysis.schemas.len());
        fs::write(out_dir.join("report.html"), html_content)?;
    }

    Ok(())
}
