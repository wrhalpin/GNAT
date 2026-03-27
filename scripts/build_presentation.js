const pptxgen = require("pptxgenjs");
const path = require("path");

const OUT = process.argv[2] || "/mnt/user-data/outputs/GNAT-Presentation.pptx";

// ── Palette ──────────────────────────────────────────────────────────────
const C = {
  navy:      "0F2044",   // slide backgrounds (dark)
  navy2:     "162952",   // slightly lighter panels
  steel:     "1E4D8C",   // accent areas
  teal:      "0891B2",   // primary accent
  teal2:     "06B6D4",   // lighter teal
  mint:      "A5F3FC",   // highlight text on dark
  white:     "FFFFFF",
  offwhite:  "E8EFF8",
  muted:     "94A3B8",
  light_bg:  "F0F4FA",   // content slides background
  card_bg:   "EBF2FB",
  border:    "CBD5E1",
  green:     "10B981",
  amber:     "F59E0B",
  red:       "EF4444",
  charcoal:  "1E293B",
};

const makeShadow = () => ({
  type: "outer", blur: 5, offset: 2, angle: 135, color: "000000", opacity: 0.12
});

// ── Helpers ───────────────────────────────────────────────────────────────
function titleSlide(pres, title, sub) {
  const sl = pres.addSlide();
  sl.background = { color: C.navy };

  // Left accent bar
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 0.18, h: 5.625, fill: { color: C.teal }, line: { width: 0 }
  });

  // Title
  sl.addText(title, {
    x: 0.45, y: 1.6, w: 9.1, h: 1.4,
    fontSize: 42, fontFace: "Calibri", bold: true,
    color: C.white, align: "left", margin: 0
  });

  // Sub
  sl.addText(sub, {
    x: 0.45, y: 3.1, w: 9.1, h: 0.7,
    fontSize: 18, fontFace: "Calibri",
    color: C.mint, align: "left", margin: 0
  });

  // Decorative dots
  for (let i = 0; i < 5; i++) {
    sl.addShape(pres.shapes.OVAL, {
      x: 0.45 + i * 0.35, y: 4.5, w: 0.12, h: 0.12,
      fill: { color: i === 0 ? C.teal2 : C.steel }, line: { width: 0 }
    });
  }
  return sl;
}

function sectionDivider(pres, label, subtitle) {
  const sl = pres.addSlide();
  sl.background = { color: C.steel };

  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 0.18, h: 5.625, fill: { color: C.teal }, line: { width: 0 }
  });

  sl.addText(label, {
    x: 0.45, y: 1.9, w: 9.1, h: 1.2,
    fontSize: 36, fontFace: "Calibri", bold: true,
    color: C.white, align: "left", margin: 0
  });

  sl.addText(subtitle, {
    x: 0.45, y: 3.2, w: 9.1, h: 0.6,
    fontSize: 16, fontFace: "Calibri",
    color: C.mint, align: "left", margin: 0
  });

  return sl;
}

function contentSlide(pres, title) {
  const sl = pres.addSlide();
  sl.background = { color: C.light_bg };

  // Top bar
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 10, h: 0.72, fill: { color: C.navy }, line: { width: 0 }
  });
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0.72, w: 10, h: 0.06, fill: { color: C.teal }, line: { width: 0 }
  });

  sl.addText(title, {
    x: 0.4, y: 0.1, w: 9.2, h: 0.52,
    fontSize: 20, fontFace: "Calibri", bold: true,
    color: C.white, align: "left", margin: 0
  });

  return sl;
}

function card(sl, pres, x, y, w, h, headerColor, headerText, bodyItems) {
  // Card background
  sl.addShape(pres.shapes.RECTANGLE, {
    x, y, w, h, fill: { color: C.white },
    line: { color: C.border, width: 0.5 }, shadow: makeShadow()
  });
  // Card header
  sl.addShape(pres.shapes.RECTANGLE, {
    x, y, w, h: 0.38, fill: { color: headerColor }, line: { width: 0 }
  });
  sl.addText(headerText, {
    x: x + 0.12, y: y + 0.04, w: w - 0.24, h: 0.3,
    fontSize: 12, fontFace: "Calibri", bold: true,
    color: C.white, margin: 0
  });
  // Card body
  if (bodyItems && bodyItems.length) {
    sl.addText(bodyItems.map(t => ({ text: t, options: { bullet: true, breakLine: true } })),
      { x: x + 0.14, y: y + 0.48, w: w - 0.28, h: h - 0.58,
        fontSize: 10, fontFace: "Calibri", color: C.charcoal }
    );
  }
}

function statBox(sl, pres, x, y, w, h, value, label, color) {
  sl.addShape(pres.shapes.RECTANGLE, {
    x, y, w, h, fill: { color: C.white },
    line: { color: C.border, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape(pres.shapes.RECTANGLE, {
    x, y, w, h: 0.08, fill: { color }, line: { width: 0 }
  });
  sl.addText(value, {
    x: x + 0.08, y: y + 0.18, w: w - 0.16, h: 0.7,
    fontSize: 32, fontFace: "Calibri", bold: true,
    color, align: "center", margin: 0
  });
  sl.addText(label, {
    x: x + 0.08, y: y + 0.88, w: w - 0.16, h: 0.32,
    fontSize: 10, fontFace: "Calibri", color: C.muted, align: "center", margin: 0
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// BUILD DECK
// ═══════════════════════════════════════════════════════════════════════════
let pres = new pptxgen();
pres.layout = "LAYOUT_16x9";
pres.title  = "GNAT: Cybersecurity Threat Management Swiss Army Knife";
pres.author = "GNAT";

// ── Slide 1: Title ──────────────────────────────────────────────────────
{
  const sl = pres.addSlide();
  sl.background = { color: C.navy };

  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 0.22, h: 5.625, fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0.22, y: 4.9, w: 9.78, h: 0.08, fill: { color: C.teal }, line: { width: 0 }
  });

  sl.addText("GNAT", {
    x: 0.5, y: 0.7, w: 9, h: 1.0,
    fontSize: 52, fontFace: "Calibri", bold: true,
    color: C.white, align: "left", margin: 0
  });
  sl.addText("Cybersecurity Threat Management Swiss Army Knife", {
    x: 0.5, y: 1.75, w: 9, h: 0.8,
    fontSize: 22, fontFace: "Calibri",
    color: C.mint, align: "left", margin: 0
  });

  const pills = [
    ["15 Connectors", C.teal],
    ["STIX 2.1", C.steel],
    ["AI-Powered", C.teal2],
    ["Scheduled", C.steel],
    ["Multi-Format Reports", C.teal],
  ];
  pills.forEach(([label, col], i) => {
    const px = 0.5 + i * 1.85;
    sl.addShape(pres.shapes.RECTANGLE, {
      x: px, y: 2.85, w: 1.65, h: 0.36,
      fill: { color: col }, line: { width: 0 }
    });
    sl.addText(label, {
      x: px + 0.06, y: 2.87, w: 1.53, h: 0.32,
      fontSize: 10, fontFace: "Calibri", bold: true,
      color: C.white, align: "center", margin: 0
    });
  });

  sl.addText("Universal threat intelligence library — abstract, normalise, automate", {
    x: 0.5, y: 3.55, w: 9, h: 0.5,
    fontSize: 14, fontFace: "Calibri", italic: true,
    color: C.muted, align: "left", margin: 0
  });

  sl.addText("Version 1.0  |  Python 3.10+  |  STIX 2.1", {
    x: 0.5, y: 4.95, w: 9, h: 0.3,
    fontSize: 10, fontFace: "Calibri", color: C.muted, align: "left", margin: 0
  });
}

// ── Slide 2: The Problem ────────────────────────────────────────────────
{
  const sl = contentSlide(pres, "The Problem: Fragmented Threat Intelligence");

  sl.addText("Every platform is an island", {
    x: 0.4, y: 1.0, w: 9.2, h: 0.4,
    fontSize: 16, fontFace: "Calibri", bold: true, italic: true,
    color: C.steel, align: "left", margin: 0
  });

  const problems = [
    ["15 Different APIs", "Each platform has its own auth scheme, data model, and SDK. ThreatQ OAuth2 ≠ CrowdStrike OAuth2 ≠ VirusTotal API key."],
    ["No Shared Data Model", "An indicator in ThreatQ looks nothing like one in CrowdStrike or Splunk. Correlation requires manual mapping."],
    ["Custom Code Per Integration", "Every new source or destination means new scripts with no shared error handling, retry logic, or scheduling."],
    ["Fragile Automation", "Ad-hoc scripts break when APIs change. No tests, no versioning, no consistent patterns."],
  ];

  problems.forEach(([title, body], i) => {
    const col = i < 2 ? 0 : 1;
    const row = i % 2;
    const x = 0.35 + col * 4.7;
    const y = 1.6 + row * 1.7;
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 4.35, h: 1.5,
      fill: { color: C.white }, line: { color: C.border, width: 0.5 },
      shadow: makeShadow()
    });
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 0.1, h: 1.5, fill: { color: C.red }, line: { width: 0 }
    });
    sl.addText(title, {
      x: x + 0.2, y: y + 0.12, w: 4.05, h: 0.3,
      fontSize: 12, fontFace: "Calibri", bold: true, color: C.charcoal, margin: 0
    });
    sl.addText(body, {
      x: x + 0.2, y: y + 0.46, w: 4.05, h: 0.9,
      fontSize: 10, fontFace: "Calibri", color: C.muted, margin: 0
    });
  });
}

// ── Slide 3: The Solution ───────────────────────────────────────────────
{
  const sl = contentSlide(pres, "The Solution: One Library, Every Platform");

  // Left column — before
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0.35, y: 0.95, w: 4.1, h: 0.38,
    fill: { color: C.red }, line: { width: 0 }
  });
  sl.addText("WITHOUT GNAT", {
    x: 0.35, y: 0.95, w: 4.1, h: 0.38,
    fontSize: 12, fontFace: "Calibri", bold: true,
    color: C.white, align: "center", margin: 0
  });
  const withoutItems = [
    "ThreatQ SDK  →  custom code",
    "CrowdStrike API  →  custom code",
    "Splunk API  →  custom code",
    "VirusTotal API  →  custom code",
    "Netskope CE  →  custom code",
    "Each: own auth, errors, retries",
    "Each: own data model",
    "No shared testing or scheduling",
  ];
  sl.addText(withoutItems.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
    x: 0.5, y: 1.45, w: 3.8, h: 3.5,
    fontSize: 10, fontFace: "Calibri", color: C.charcoal, valign: "top"
  });

  // Arrow
  sl.addShape(pres.shapes.LINE, {
    x: 4.55, y: 3.2, w: 0.9, h: 0,
    line: { color: C.teal, width: 2.5, endArrowType: "triangle" }
  });
  sl.addText("GNAT", {
    x: 4.5, y: 3.35, w: 1.0, h: 0.25,
    fontSize: 9, fontFace: "Calibri", bold: true,
    color: C.teal, align: "center", margin: 0
  });

  // Right column — after
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 5.55, y: 0.95, w: 4.1, h: 0.38,
    fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("WITH GNAT", {
    x: 5.55, y: 0.95, w: 4.1, h: 0.38,
    fontSize: 12, fontFace: "Calibri", bold: true,
    color: C.white, align: "center", margin: 0
  });
  const withItems = [
    "SAKConfig  →  one config.ini",
    "SAKClient  →  one interface",
    "STIX 2.1 everywhere",
    "IngestPipeline  →  pull any source",
    "ExportPipeline  →  push to EDLs/CE",
    "FeedScheduler  →  all jobs, one place",
    "ReportGenerator  →  PDF/HTML/DOCX",
    "ResearchLibrary  →  shared knowledge",
  ];
  sl.addText(withItems.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
    x: 5.7, y: 1.45, w: 3.8, h: 3.5,
    fontSize: 10, fontFace: "Calibri", color: C.charcoal, valign: "top"
  });
}

// ── Slide 4: Architecture Overview ─────────────────────────────────────
{
  const sl = contentSlide(pres, "Architecture: The Middle Layer Model");

  // Layers
  const layers = [
    { label: "ANALYST / AUTOMATION LAYER", sub: "Workstations · SOAR · Scheduled jobs · CLI", col: C.navy2, textCol: C.white, y: 0.85 },
    { label: "GNAT CORE", sub: "Ingest · Export · Agents · Research Library · Reports · Visualization", col: C.steel, textCol: C.white, y: 1.52 },
    { label: "STIX 2.1 ORM + WORKSPACE", sub: "Indicator · ThreatActor · Vulnerability · AttackPattern · Relationship", col: C.teal, textCol: C.white, y: 2.19 },
    { label: "CONNECTOR LAYER (15 platforms)", sub: "ThreatQ · CrowdStrike · Splunk · RF · Netskope · VT · ShadowServer · Rapid7 · Nucleus · …", col: C.navy2, textCol: C.offwhite, y: 2.86 },
    { label: "EXTERNAL PLATFORMS", sub: "APIs, feeds, SIEMs, EDRs, vulnerability scanners, threat intel platforms", col: "6B7280", textCol: C.white, y: 3.53 },
  ];

  layers.forEach(({ label, sub, col, textCol, y }) => {
    sl.addShape(pres.shapes.RECTANGLE, {
      x: 0.35, y, w: 9.3, h: 0.57, fill: { color: col }, line: { width: 0 }
    });
    sl.addText(label, {
      x: 0.5, y: y + 0.05, w: 4.5, h: 0.22,
      fontSize: 10, fontFace: "Calibri", bold: true, color: textCol, margin: 0
    });
    sl.addText(sub, {
      x: 0.5, y: y + 0.28, w: 9.0, h: 0.2,
      fontSize: 9, fontFace: "Calibri", color: textCol === C.white ? C.mint : C.muted, margin: 0
    });
    // Arrow between layers
    if (y < 3.53) {
      sl.addShape(pres.shapes.LINE, {
        x: 4.85, y: y + 0.57, w: 0, h: 0.1,
        line: { color: C.teal, width: 1.5, endArrowType: "triangle" }
      });
    }
  });

  sl.addText("urllib3 / httpx transport — zero cloud dependencies", {
    x: 0.35, y: 4.25, w: 9.3, h: 0.3,
    fontSize: 10, fontFace: "Calibri", italic: true,
    color: C.muted, align: "center", margin: 0
  });
}

// ── Slide 5: Connectors ─────────────────────────────────────────────────
{
  const sl = contentSlide(pres, "15 Platform Connectors — One Interface");

  const connectors = [
    ["ThreatQ", "OAuth2 · Full CRUD", C.steel],
    ["CrowdStrike", "OAuth2 · Full CRUD", C.steel],
    ["Splunk", "Token · Search/KVStore", C.steel],
    ["Recorded Future", "Token · Alert API v3", C.navy2],
    ["Netskope", "Token · CE API", C.navy2],
    ["Proofpoint", "Basic auth", C.navy2],
    ["XSOAR", "API key · Incidents", C.steel],
    ["RiskRecon", "OAuth2 · Findings", C.navy2],
    ["Whistic", "API key · Vendor risk", C.navy2],
    ["Feedly", "Bearer · IOC/TTP feeds", C.steel],
    ["GreyMatter", "OAuth2 · Full CRUD", C.steel],
    ["VirusTotal", "API key · File/IP/URL", C.teal],
    ["ShadowServer", "API key · Scan/ASN", C.teal],
    ["Rapid7", "API key · Vuln/Asset", C.teal],
    ["Nucleus", "API key · Asset/Vuln", C.teal],
  ];

  const cols = 5;
  connectors.forEach(([name, detail, color], i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);
    const x = 0.35 + col * 1.87;
    const y = 1.0 + row * 1.3;
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 1.75, h: 1.1,
      fill: { color: C.white }, line: { color: C.border, width: 0.5 },
      shadow: makeShadow()
    });
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 1.75, h: 0.08, fill: { color }, line: { width: 0 }
    });
    sl.addText(name, {
      x: x + 0.08, y: y + 0.18, w: 1.59, h: 0.32,
      fontSize: 11, fontFace: "Calibri", bold: true,
      color: C.charcoal, align: "center", margin: 0
    });
    sl.addText(detail, {
      x: x + 0.06, y: y + 0.52, w: 1.63, h: 0.4,
      fontSize: 8.5, fontFace: "Calibri", color: C.muted, align: "center", margin: 0
    });
  });

  // Legend
  const legend = [[C.steel, "Established connectors"], [C.navy2, "Read/specialised"], [C.teal, "New — v1.0"]];
  legend.forEach(([col, label], i) => {
    sl.addShape(pres.shapes.RECTANGLE, {
      x: 0.35 + i * 3.0, y: 5.1, w: 0.18, h: 0.18, fill: { color: col }, line: { width: 0 }
    });
    sl.addText(label, {
      x: 0.6 + i * 3.0, y: 5.1, w: 2.5, h: 0.18,
      fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
    });
  });
}

// ── Slide 6: STIX 2.1 ORM ───────────────────────────────────────────────
{
  const sl = contentSlide(pres, "STIX 2.1 ORM — A Universal Data Contract");

  sl.addText("Every object from every connector normalises into the same STIX 2.1 types", {
    x: 0.4, y: 0.9, w: 9.2, h: 0.35,
    fontSize: 13, fontFace: "Calibri", italic: true,
    color: C.steel, align: "left", margin: 0
  });

  const types = [
    ["Indicator", "IOCs with STIX patterns\n[domain-name:value = '...']", C.teal],
    ["ThreatActor", "Actor profiles, aliases,\nmotivation, attribution", C.steel],
    ["Vulnerability", "CVEs, CVSS scores,\nexploited flag, products", C.amber],
    ["AttackPattern", "MITRE ATT&CK TTPs\nwith tactic mapping", C.green],
    ["Malware", "Malware families,\ncapabilities, types", C.red],
    ["Relationship", "Links between objects:\nindicates, uses, targets…", C.navy2],
  ];

  types.forEach(([name, detail, color], i) => {
    const col = i % 3;
    const row = Math.floor(i / 3);
    const x = 0.35 + col * 3.1;
    const y = 1.4 + row * 1.7;
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 2.9, h: 1.52,
      fill: { color: C.white }, line: { color: C.border, width: 0.5 },
      shadow: makeShadow()
    });
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 0.12, h: 1.52, fill: { color }, line: { width: 0 }
    });
    sl.addText(name, {
      x: x + 0.22, y: y + 0.15, w: 2.58, h: 0.32,
      fontSize: 13, fontFace: "Calibri", bold: true, color: C.charcoal, margin: 0
    });
    sl.addText(detail, {
      x: x + 0.22, y: y + 0.55, w: 2.58, h: 0.82,
      fontSize: 9.5, fontFace: "Calibri", color: C.muted, margin: 0
    });
  });
}

// ── Slide 7: Ingest + Export ─────────────────────────────────────────────
{
  const sl = contentSlide(pres, "Ingest + Export Pipelines");

  // Ingest
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0.35, y: 0.9, w: 4.4, h: 0.35,
    fill: { color: C.steel }, line: { width: 0 }
  });
  sl.addText("INGEST PIPELINE  (pull from platforms)", {
    x: 0.35, y: 0.9, w: 4.4, h: 0.35,
    fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });

  const ingestSteps = [
    ["SourceReader", "14 reader types\nTAXII · CSV · STIX · Syslog\nRSS · Email · Splunk · Elastic…", C.teal],
    ["RecordMapper", "12 mapper types\nFlatIOC · STIX · MISP · CEF\nCSV · NVD CVE · Feedly…", C.steel],
    ["Workspace", "STIX ORM objects\ndedup · confidence\nx_target_sectors tag", C.navy2],
  ];

  ingestSteps.forEach(([title, body, col], i) => {
    const x = 0.35 + i * 1.5;
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y: 1.35, w: 1.35, h: 1.85,
      fill: { color: C.white }, line: { color: col, width: 1.5 },
      shadow: makeShadow()
    });
    sl.addText(title, {
      x: x + 0.08, y: 1.45, w: 1.19, h: 0.28,
      fontSize: 10, fontFace: "Calibri", bold: true, color: col, margin: 0
    });
    sl.addText(body, {
      x: x + 0.08, y: 1.78, w: 1.19, h: 1.3,
      fontSize: 8.5, fontFace: "Calibri", color: C.muted, margin: 0
    });
    if (i < 2) {
      sl.addShape(pres.shapes.LINE, {
        x: x + 1.38, y: 2.27, w: 0.12, h: 0,
        line: { color: C.teal, width: 1.5, endArrowType: "triangle" }
      });
    }
  });

  // Export
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 5.25, y: 0.9, w: 4.4, h: 0.35,
    fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("EXPORT PIPELINE  (push to destinations)", {
    x: 5.25, y: 0.9, w: 4.4, h: 0.35,
    fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });

  const exportSteps = [
    ["ExportFilter", "TypeFilter · ConfidenceFilter\nTLPFilter · SectorFilter\nIOCTypeFilter · LimitFilter", C.teal],
    ["ExportTransform", "EDLTransform\nNetskopeCETransform\nSTIXBundle · CSV", C.steel],
    ["Delivery", "FileDelivery\nEDLServer (HTTP)\nPlatformDelivery\nMultiDelivery", C.navy2],
  ];

  exportSteps.forEach(([title, body, col], i) => {
    const x = 5.25 + i * 1.5;
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y: 1.35, w: 1.35, h: 1.85,
      fill: { color: C.white }, line: { color: col, width: 1.5 },
      shadow: makeShadow()
    });
    sl.addText(title, {
      x: x + 0.08, y: 1.45, w: 1.19, h: 0.28,
      fontSize: 10, fontFace: "Calibri", bold: true, color: col, margin: 0
    });
    sl.addText(body, {
      x: x + 0.08, y: 1.78, w: 1.19, h: 1.3,
      fontSize: 8.5, fontFace: "Calibri", color: C.muted, margin: 0
    });
    if (i < 2) {
      sl.addShape(pres.shapes.LINE, {
        x: x + 1.38, y: 2.27, w: 0.12, h: 0,
        line: { color: C.teal, width: 1.5, endArrowType: "triangle" }
      });
    }
  });

  // Use case row
  sl.addText("Real example: ThreatQ → GNAT → Netskope CE (FQDN + URL + SHA256 every 15 min) → Tenant lists → Palo Alto EDLs", {
    x: 0.35, y: 3.35, w: 9.3, h: 0.38,
    fontSize: 10.5, fontFace: "Calibri", italic: true,
    color: C.steel, align: "center", margin: 0
  });

  // Code snippet
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0.35, y: 3.85, w: 9.3, h: 1.4,
    fill: { color: C.charcoal }, line: { width: 0 }
  });
  sl.addText(
    "result = (ExportPipeline(\"tq-to-netskope\")\n" +
    "    .read_from(workspace)\n" +
    "    .filter_with(TypeFilter(\"indicator\")).filter_with(ConfidenceFilter(70))\n" +
    "    .transform_with(NetskopeCETransform(source_label=\"ThreatQ\", ioc_types=[\"domain\",\"url\",\"sha256\"]))\n" +
    "    .deliver_to(PlatformDelivery(netskope_client))).run()",
    {
      x: 0.5, y: 3.92, w: 9.1, h: 1.26,
      fontSize: 9, fontFace: "Consolas", color: C.mint, margin: 0
    }
  );
}

// ── Slide 8: Scheduling ──────────────────────────────────────────────────
{
  const sl = contentSlide(pres, "Scheduling — One Scheduler, All Jobs");

  // Stats row
  statBox(sl, pres, 0.35, 0.95, 2.15, 1.35, "FeedJob", "Declarative job type", C.teal);
  statBox(sl, pres, 2.65, 0.95, 2.15, 1.35, "Scheduler", "FeedScheduler threading", C.steel);
  statBox(sl, pres, 4.95, 0.95, 2.15, 1.35, "ExportJob", "Scheduled export", C.teal);
  statBox(sl, pres, 7.25, 0.95, 2.45, 1.35, "ReportJob", "Scheduled reports", C.steel);

  sl.addText("Every job type in GNAT extends FeedJob and runs in the same FeedScheduler", {
    x: 0.35, y: 2.42, w: 9.3, h: 0.3,
    fontSize: 10.5, fontFace: "Calibri", italic: true,
    color: C.steel, align: "center", margin: 0
  });

  // Feature list
  const features = [
    ["Drift-corrected timing", "Hourly jobs stay hourly even when runs take 5 min"],
    ["Overlap protection", "skip or queue policy — never two runs of the same job simultaneously"],
    ["ctx.last_success_iso", "Incremental ingestion: readers receive the last success timestamp automatically"],
    ["On-success / on-failure", "Callbacks for alerting, logging, and downstream triggers"],
    ["APScheduler / Celery adapters", "Export jobs to external schedulers for teams with existing infrastructure"],
    ["to_cron_lines()", "Generate crontab entries for simple server deployments"],
  ];

  features.forEach(([title, body], i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    const x = 0.35 + col * 4.7;
    const y = 2.88 + row * 0.72;
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 4.45, h: 0.6,
      fill: { color: C.white }, line: { color: C.border, width: 0.5 }
    });
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 0.08, h: 0.6, fill: { color: C.teal }, line: { width: 0 }
    });
    sl.addText(title, {
      x: x + 0.18, y: y + 0.06, w: 4.17, h: 0.22,
      fontSize: 10, fontFace: "Calibri", bold: true, color: C.charcoal, margin: 0
    });
    sl.addText(body, {
      x: x + 0.18, y: y + 0.3, w: 4.17, h: 0.22,
      fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
    });
  });
}

// ── Slide 9: AI Agents ───────────────────────────────────────────────────
{
  const sl = contentSlide(pres, "AI Agents — Claude-Powered Threat Research");

  const agents = [
    {
      title: "ResearchAgent", sub: "SourceReader",
      body: "Topic-driven: synthesise research on threat actors, CVEs, campaigns.\nFeed-driven: monitor sources for new threat content.\nUses Claude API with web_search tool.",
      color: C.teal
    },
    {
      title: "ParsingAgent", sub: "RecordMapper",
      body: "Extract structured STIX from any unstructured text.\nFlexible: IOCs + TTPs + actors + CVEs — whatever is present.\nAll output capped at confidence ≤ 60, tagged x_source_type=ai_extracted.",
      color: C.steel
    },
    {
      title: "CopilotReader", sub: "SourceReader",
      body: "Query Microsoft Copilot via DirectLine for M365 content.\nConfigured sources: SharePoint libraries, mailboxes, Teams channels.\nOutput feeds directly into ParsingAgent.",
      color: C.navy2
    },
  ];

  agents.forEach(({ title, sub, body, color }, i) => {
    const x = 0.35 + i * 3.1;
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y: 0.95, w: 2.9, h: 2.35,
      fill: { color: C.white }, line: { color: C.border, width: 0.5 },
      shadow: makeShadow()
    });
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y: 0.95, w: 2.9, h: 0.52, fill: { color }, line: { width: 0 }
    });
    sl.addText(title, {
      x: x + 0.12, y: 0.99, w: 2.66, h: 0.28,
      fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
    });
    sl.addText(sub, {
      x: x + 0.12, y: 1.27, w: 2.66, h: 0.18,
      fontSize: 9, fontFace: "Calibri", color: C.mint, italic: true, margin: 0
    });
    sl.addText(body, {
      x: x + 0.12, y: 1.62, w: 2.66, h: 1.55,
      fontSize: 9.5, fontFace: "Calibri", color: C.muted, margin: 0, valign: "top"
    });
  });

  // Trust model note
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0.35, y: 3.45, w: 9.3, h: 0.85,
    fill: { color: "FFF3CD" }, line: { color: C.amber, width: 1 }
  });
  sl.addText("⚠  AI Trust Model", {
    x: 0.55, y: 3.53, w: 3.0, h: 0.25,
    fontSize: 10, fontFace: "Calibri", bold: true, color: "92400E", margin: 0
  });
  sl.addText(
    "confidence_ceiling = 60 (configurable) prevents AI-extracted intel from reaching EDLs at high confidence without analyst review. " +
    "All AI objects tagged x_source_type='ai_extracted'. Export pipelines default to ConfidenceFilter(min=70), " +
    "which excludes AI intel until reviewed.",
    {
      x: 0.55, y: 3.77, w: 9.0, h: 0.45,
      fontSize: 9, fontFace: "Calibri", color: "78350F", margin: 0
    }
  );
}

// ── Slide 10: Research Library ───────────────────────────────────────────
{
  const sl = contentSlide(pres, "Research Library — Shared Team Knowledge Base");

  // Three tiers
  const tiers = [
    { label: "PERSONAL WORKSPACES", sub: "Analyst-owned · Active investigation", col: C.navy2, arrow: true },
    { label: "STAGING  (_ctmsak_staging)", sub: "lib.promote(ws, topic, researcher, note='…')  →  anyone can write, nothing auto-reads", col: C.steel, arrow: true },
    { label: "LIBRARY  (_ctmsak_library)", sub: "Curated · Read-only to analysts · Managed by CurationJob every 4h", col: C.teal, arrow: false },
  ];

  tiers.forEach(({ label, sub, col, arrow }, i) => {
    sl.addShape(pres.shapes.RECTANGLE, {
      x: 0.35, y: 0.95 + i * 1.05, w: 5.5, h: 0.85,
      fill: { color: col }, line: { width: 0 }
    });
    sl.addText(label, {
      x: 0.55, y: 1.02 + i * 1.05, w: 5.1, h: 0.28,
      fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0
    });
    sl.addText(sub, {
      x: 0.55, y: 1.32 + i * 1.05, w: 5.1, h: 0.38,
      fontSize: 9, fontFace: "Calibri", color: C.mint, margin: 0
    });
    if (arrow) {
      sl.addShape(pres.shapes.LINE, {
        x: 2.7, y: 1.8 + i * 1.05, w: 0, h: 0.2,
        line: { color: C.teal2, width: 2, endArrowType: "triangle" }
      });
    }
  });

  // TTL table
  sl.addText("TTL by Category", {
    x: 6.1, y: 0.92, w: 3.5, h: 0.28,
    fontSize: 11, fontFace: "Calibri", bold: true, color: C.charcoal, margin: 0
  });

  const ttl = [
    ["Category", "Default TTL", "Rationale"],
    ["indicator", "24 hours", "IOCs rotate quickly"],
    ["vulnerability", "72 hours", "Exploitability changes"],
    ["campaign", "14 days", "Evolves over weeks"],
    ["threat_actor", "30 days", "Slow-changing TTPs"],
    ["other", "7 days", "Conservative fallback"],
  ];
  sl.addTable(ttl, {
    x: 6.1, y: 1.28, w: 3.55, h: 2.2,
    border: { pt: 0.5, color: C.border },
    colW: [1.1, 0.95, 1.5],
    fontSize: 8.5, fontFace: "Calibri",
    fill: { color: C.white },
  });

  // Workflow note
  sl.addText(
    "Analyst checks lib.is_fresh(\"APT29\") before running ResearchAgent. " +
    "After review, promotes to staging with an optional analyst note. " +
    "CurationJob deduplicates (most recent wins) and promotes to library.",
    {
      x: 0.35, y: 4.3, w: 9.3, h: 0.7,
      fontSize: 9.5, fontFace: "Calibri", color: C.muted,
      fill: { color: C.card_bg }, margin: 0.08
    }
  );
}

// ── Slide 11: Report Generation ──────────────────────────────────────────
{
  const sl = contentSlide(pres, "Automated Report Generation");

  const reportTypes = [
    { name: "Daily Intel", interval: "06:00 daily", ai: "Assisted", audience: "SOC analysts / shift handoff", formats: "PDF · HTML · Markdown", color: C.teal },
    { name: "Trends", interval: "Weekly", ai: "Assisted", audience: "Team leads / analysts", formats: "PDF · HTML", color: C.steel },
    { name: "Yearly Intel", interval: "Annual / manual", ai: "Full", audience: "Management / compliance", formats: "PDF · DOCX", color: C.navy2 },
  ];

  reportTypes.forEach(({ name, interval, ai, audience, formats, color }, i) => {
    const x = 0.35 + i * 3.1;
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y: 0.95, w: 2.9, h: 2.7,
      fill: { color: C.white }, line: { color: C.border, width: 0.5 },
      shadow: makeShadow()
    });
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y: 0.95, w: 2.9, h: 0.45, fill: { color }, line: { width: 0 }
    });
    sl.addText(name, {
      x: x + 0.12, y: 0.99, w: 2.66, h: 0.35,
      fontSize: 14, fontFace: "Calibri", bold: true, color: C.white, margin: 0
    });
    const rows = [
      ["Schedule", interval], ["AI Mode", ai],
      ["Audience", audience], ["Formats", formats],
    ];
    rows.forEach(([label, value], j) => {
      sl.addText(label + ":", {
        x: x + 0.12, y: 1.52 + j * 0.46, w: 0.95, h: 0.26,
        fontSize: 9, fontFace: "Calibri", bold: true, color: C.muted, margin: 0
      });
      sl.addText(value, {
        x: x + 1.1, y: 1.52 + j * 0.46, w: 1.68, h: 0.26,
        fontSize: 9, fontFace: "Calibri", color: C.charcoal, margin: 0
      });
    });
  });

  // Pipeline
  sl.addText("Generation pipeline:", {
    x: 0.35, y: 3.78, w: 2.0, h: 0.3,
    fontSize: 10, fontFace: "Calibri", bold: true, color: C.charcoal, margin: 0
  });

  const pipeSteps = ["DataAggregator\n(no AI)", "ReportSynthesizer\n(one call/section)", "Renderers\nMD/HTML/PDF/DOCX", "Delivery\nEmail + SharePoint"];
  pipeSteps.forEach((step, i) => {
    const x = 0.35 + i * 2.35;
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y: 4.15, w: 2.05, h: 0.8,
      fill: { color: i % 2 === 0 ? C.teal : C.steel }, line: { width: 0 }
    });
    sl.addText(step, {
      x: x + 0.08, y: 4.2, w: 1.89, h: 0.7,
      fontSize: 9.5, fontFace: "Calibri", bold: true, color: C.white, align: "center", margin: 0
    });
    if (i < 3) {
      sl.addShape(pres.shapes.LINE, {
        x: x + 2.08, y: 4.55, w: 0.24, h: 0,
        line: { color: C.teal2, width: 1.5, endArrowType: "triangle" }
      });
    }
  });
}

// ── Slide 12: Sector Filtering ───────────────────────────────────────────
{
  const sl = contentSlide(pres, "Sector Targeting Intelligence");

  sl.addText("x_target_sectors — the canonical cross-platform sector field", {
    x: 0.4, y: 0.9, w: 9.2, h: 0.35,
    fontSize: 13, fontFace: "Calibri", italic: true,
    color: C.steel, align: "left", margin: 0
  });

  // Filter modes
  const modes = [
    { label: "any (default)", body: "Include objects tagged with at\nleast one listed sector.\nUntagged objects also pass\n(non-strict mode).", col: C.teal },
    { label: "all", body: "Require all listed sectors to\nbe present on the object.\nStrict: only tagged objects.", col: C.steel },
    { label: "strict=True", body: "Exclude untagged objects\nentirely. Only explicitly\ntagged objects are included.", col: C.navy2 },
  ];

  modes.forEach(({ label, body, col }, i) => {
    const x = 0.35 + i * 3.0;
    card(sl, pres, x, 1.4, 2.8, 2.0, col, label, []);
    sl.addText(body, {
      x: x + 0.12, y: 1.9, w: 2.56, h: 1.3,
      fontSize: 9.5, fontFace: "Calibri", color: C.muted, margin: 0, valign: "top"
    });
  });

  // Alias config
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0.35, y: 3.55, w: 9.3, h: 1.68,
    fill: { color: C.charcoal }, line: { width: 0 }
  });
  sl.addText(
    "[sector_aliases]\n" +
    "healthcare = Healthcare, Health, Medical, H-ISAC, Hospitals and Health Centers\n" +
    "financial  = Financial Services, Finance, Banking, FS-ISAC\n" +
    "energy     = Energy, Electric, Oil and Gas, E-ISAC\n\n" +
    "# SectorFilter expands aliases so 'health' matches 'Healthcare' from ThreatQ and 'Health' from RF",
    {
      x: 0.5, y: 3.62, w: 9.1, h: 1.54,
      fontSize: 9, fontFace: "Consolas", color: C.mint, margin: 0
    }
  );
}

// ── Slide 13: Deployment ─────────────────────────────────────────────────
{
  const sl = contentSlide(pres, "Deployment: Single Azure VM, Three Services");

  // VM box
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0.35, y: 0.88, w: 6.1, h: 4.38,
    fill: { color: C.white }, line: { color: C.border, width: 1 },
    shadow: makeShadow()
  });
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0.35, y: 0.88, w: 6.1, h: 0.38,
    fill: { color: C.navy2 }, line: { width: 0 }
  });
  sl.addText("Azure VM B2s  (2 vCPU · 4 GB · ~$50/month)", {
    x: 0.5, y: 0.92, w: 5.8, h: 0.3,
    fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });

  const services = [
    { name: "ctmsak-scheduler.service", desc: "FeedScheduler: ingest, export, AI research,\ncuration, and report jobs", col: C.teal },
    { name: "ctmsak-edl.service  :8080", desc: "EDLServer: serves indicator files to firewalls.\nIndependent — survives scheduler restart", col: C.steel },
    { name: "ctmsak-health.service  :8090", desc: "Health endpoint: GET /status → JSON\nAzure Monitor ping check", col: C.navy2 },
  ];

  services.forEach(({ name, desc, col }, i) => {
    const y = 1.4 + i * 1.1;
    sl.addShape(pres.shapes.RECTANGLE, {
      x: 0.5, y, w: 5.7, h: 0.9,
      fill: { color: C.light_bg }, line: { color: col, width: 1 }
    });
    sl.addShape(pres.shapes.RECTANGLE, {
      x: 0.5, y, w: 0.1, h: 0.9, fill: { color: col }, line: { width: 0 }
    });
    sl.addText(name, {
      x: 0.72, y: y + 0.08, w: 5.18, h: 0.24,
      fontSize: 10, fontFace: "Consolas", bold: true, color: C.charcoal, margin: 0
    });
    sl.addText(desc, {
      x: 0.72, y: y + 0.38, w: 5.18, h: 0.42,
      fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
    });
  });

  sl.addText("Storage: ~/.gnat/config.ini · workspaces/ · /var/reports/", {
    x: 0.5, y: 4.75, w: 5.7, h: 0.3,
    fontSize: 9, fontFace: "Calibri", italic: true, color: C.muted, margin: 0
  });

  // Right side: scaling path
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 6.6, y: 0.88, w: 3.05, h: 4.38,
    fill: { color: C.white }, line: { color: C.border, width: 0.5 },
    shadow: makeShadow()
  });
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 6.6, y: 0.88, w: 3.05, h: 0.38,
    fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("Scale-out path", {
    x: 6.75, y: 0.92, w: 2.75, h: 0.3,
    fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });

  const scalingItems = [
    ["100+ feeds", "AI jobs → Azure Container Instances"],
    ["EDL SLA < 5 min", "EDL server → dedicated B1s VM"],
    ["10+ analysts", "FlatFileStore → PostgreSQL (1 config change)"],
    ["Multi-tenant", "1 VM per tenant, shared codebase"],
  ];
  scalingItems.forEach(([trigger, action], i) => {
    const y = 1.42 + i * 0.88;
    sl.addText(trigger, {
      x: 6.75, y, w: 2.75, h: 0.24,
      fontSize: 9.5, fontFace: "Calibri", bold: true, color: C.charcoal, margin: 0
    });
    sl.addText(action, {
      x: 6.75, y: y + 0.26, w: 2.75, h: 0.4,
      fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
    });
    if (i < 3) {
      sl.addShape(pres.shapes.LINE, {
        x: 6.75, y: y + 0.72, w: 2.75, h: 0,
        line: { color: C.border, width: 0.5 }
      });
    }
  });
}

// ── Slide 14: Key Advantages ─────────────────────────────────────────────
{
  const sl = contentSlide(pres, "The Abstraction Advantage");

  const advantages = [
    {
      title: "Portability",
      body: "Switch from ThreatQ to a new TIP? Change one config line. The pipeline, scheduler, reports, and export jobs all work unchanged. Your automation is not locked to any platform.",
      col: C.teal,
    },
    {
      title: "Maintenance Simplicity",
      body: "API changes affect one connector file, not every script. Tests cover all 15 connectors uniformly. One library version number covers the entire integration stack.",
      col: C.steel,
    },
    {
      title: "Interface Consistency",
      body: "Every platform exposes get_object(), list_objects(), upsert_object(), to_stix(), from_stix(). Analysts learn one mental model once and it works everywhere.",
      col: C.teal,
    },
    {
      title: "Operational Coherence",
      body: "One scheduler, one health endpoint, one log stream. No more asking which of 15 scripts ran overnight and whether it worked. FeedScheduler.summary() answers all of that.",
      col: C.steel,
    },
    {
      title: "Incremental Adoption",
      body: "Each layer is independently useful. Start with connectors only. Add ingest. Add export. Add AI. Add reports. The stack is additive — you never have to replace working parts.",
      col: C.teal,
    },
    {
      title: "Test Coverage",
      body: "784 unit tests across 25 test files. Every connector, every pipeline stage, every renderer, every scheduler behaviour. Confidence in changes without regression fear.",
      col: C.steel,
    },
  ];

  advantages.forEach(({ title, body, col }, i) => {
    const c = i % 3;
    const r = Math.floor(i / 3);
    const x = 0.35 + c * 3.1;
    const y = 0.9 + r * 2.2;
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 2.9, h: 2.0,
      fill: { color: C.white }, line: { color: C.border, width: 0.5 },
      shadow: makeShadow()
    });
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 2.9, h: 0.42, fill: { color: col }, line: { width: 0 }
    });
    sl.addText(title, {
      x: x + 0.12, y: y + 0.08, w: 2.66, h: 0.28,
      fontSize: 12, fontFace: "Calibri", bold: true, color: C.white, margin: 0
    });
    sl.addText(body, {
      x: x + 0.12, y: y + 0.55, w: 2.66, h: 1.32,
      fontSize: 9.5, fontFace: "Calibri", color: C.muted, margin: 0
    });
  });
}

// ── Slide 15: Numbers ────────────────────────────────────────────────────
{
  const sl = contentSlide(pres, "By the Numbers");

  const stats = [
    ["15", "Platform\nConnectors", C.teal],
    ["784", "Unit\nTests", C.steel],
    ["96", "Source\nFiles", C.teal],
    ["~$50", "Monthly Azure\nVM Cost", C.steel],
    ["60", "AI Confidence\nCeiling (default)", C.amber],
    ["4 hrs", "Curation Job\nInterval", C.teal],
  ];

  stats.forEach(([value, label, col], i) => {
    const c = i % 3;
    const r = Math.floor(i / 3);
    const x = 0.55 + c * 3.0;
    const y = 1.0 + r * 2.1;
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 2.7, h: 1.8,
      fill: { color: C.white }, line: { color: C.border, width: 0.5 },
      shadow: makeShadow()
    });
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 2.7, h: 0.1, fill: { color: col }, line: { width: 0 }
    });
    sl.addText(value, {
      x: x + 0.12, y: y + 0.22, w: 2.46, h: 0.9,
      fontSize: 44, fontFace: "Calibri", bold: true,
      color: col, align: "center", margin: 0
    });
    sl.addText(label, {
      x: x + 0.12, y: y + 1.12, w: 2.46, h: 0.52,
      fontSize: 10, fontFace: "Calibri", color: C.muted, align: "center", margin: 0
    });
  });
}

// ── Slide 16: Implementation Path ────────────────────────────────────────
{
  const sl = contentSlide(pres, "Implementation Sequence");

  const phases = [
    { phase: "Phase 1", label: "Foundation", days: "Days 1-2", items: ["Install + configure config.ini", "Test connectivity: gnat ping", "First ingest dry-run"], col: C.teal },
    { phase: "Phase 2", label: "Ingest", days: "Days 3-5", items: ["All connector configs", "Primary ingest jobs (TQ, RF, CS)", "FeedScheduler running"], col: C.steel },
    { phase: "Phase 3", label: "Export", days: "Days 6-8", items: ["Netskope CE ExportJob (15 min)", "EDL files hourly", "Verify TQ → CE → firewall EDLs"], col: C.teal },
    { phase: "Phase 4", label: "Research", days: "Days 9-10", items: ["Configure [claude] in config.ini", "First ResearchAgent query", "CurationJob to scheduler"], col: C.steel },
    { phase: "Phase 5", label: "Reports", days: "Days 11-14", items: ["Daily report — review PDF/HTML", "Configure email delivery", "ReportJob at 06:00 daily"], col: C.teal },
    { phase: "Phase 6", label: "Rollout", days: "Ongoing", items: ["Analyst config templates", "Share EXAMPLES.md", "Library review process"], col: C.navy2 },
  ];

  // Timeline bar
  phases.forEach(({ phase, label, days, items, col }, i) => {
    const x = 0.35 + i * 1.6;

    // Top phase badge
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y: 0.9, w: 1.45, h: 0.55, fill: { color: col }, line: { width: 0 }
    });
    sl.addText(phase, {
      x: x + 0.05, y: 0.93, w: 1.35, h: 0.22,
      fontSize: 9, fontFace: "Calibri", bold: true, color: C.white, align: "center", margin: 0
    });
    sl.addText(days, {
      x: x + 0.05, y: 1.15, w: 1.35, h: 0.22,
      fontSize: 7.5, fontFace: "Calibri", color: C.mint, align: "center", margin: 0
    });

    // Content box
    sl.addShape(pres.shapes.RECTANGLE, {
      x, y: 1.55, w: 1.45, h: 3.5,
      fill: { color: C.white }, line: { color: C.border, width: 0.5 }
    });
    sl.addText(label, {
      x: x + 0.08, y: 1.65, w: 1.29, h: 0.28,
      fontSize: 11, fontFace: "Calibri", bold: true, color: col, align: "center", margin: 0
    });
    sl.addText(items.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
      x: x + 0.08, y: 2.02, w: 1.29, h: 2.9,
      fontSize: 8.5, fontFace: "Calibri", color: C.charcoal
    });

    // Connector arrow
    if (i < 5) {
      sl.addShape(pres.shapes.LINE, {
        x: x + 1.48, y: 1.17, w: 0.1, h: 0,
        line: { color: C.border, width: 1, endArrowType: "triangle" }
      });
    }
  });
}

// ── Slide 17: Pending + Roadmap ──────────────────────────────────────────
{
  const sl = contentSlide(pres, "Pending Items & Roadmap");

  // Pending (high priority)
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0.35, y: 0.88, w: 4.6, h: 0.35,
    fill: { color: C.red }, line: { width: 0 }
  });
  sl.addText("PENDING — VERIFY BEFORE PRODUCTION", {
    x: 0.35, y: 0.88, w: 4.6, h: 0.35,
    fontSize: 10, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });

  const pending = [
    "ThreatQ: verify x_target_sectors field names in STIX export (see PENDING_ITEMS.md §1)",
    "RecordedFuture, CrowdStrike, VT, ShadowServer, Nucleus: sector normalization",
    "DOCX renderer: npm install -g docx required on deployment host",
    "WorkspaceManager.default() method: verify or add to context/workspace.py",
    "Copilot DirectLine: test token refresh behavior in production Bot Framework setup",
  ];
  sl.addText(pending.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
    x: 0.5, y: 1.32, w: 4.3, h: 2.2,
    fontSize: 9.5, fontFace: "Calibri", color: C.charcoal
  });

  // Roadmap
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 5.2, y: 0.88, w: 4.45, h: 0.35,
    fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("ROADMAP — NEXT ADDITIONS", {
    x: 5.2, y: 0.88, w: 4.45, h: 0.35,
    fontSize: 10, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });

  const roadmap = [
    "CLI: gnat report run --config report.daily_healthcare",
    "SectorFilter: move to export/filters.py for use in both export and report layers",
    "CHANGELOG: versions 0.6.0 through 1.0.0",
    "Email body: use rendered HTML report as email body (not generic text)",
    "Yearly reports: calendar-anchored cron (0 6 1 1 *) vs 365-day interval",
    "Juno.build / Internet Computer: Rust-based serverless agent (future exploration)",
  ];
  sl.addText(roadmap.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
    x: 5.35, y: 1.32, w: 4.15, h: 2.2,
    fontSize: 9.5, fontFace: "Calibri", color: C.charcoal
  });

  // Bottom note
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0.35, y: 3.72, w: 9.3, h: 1.52,
    fill: { color: C.card_bg }, line: { color: C.border, width: 0.5 }
  });
  sl.addText("Reference Documents", {
    x: 0.55, y: 3.82, w: 3.0, h: 0.28,
    fontSize: 10, fontFace: "Calibri", bold: true, color: C.charcoal, margin: 0
  });
  const docs = [
    ["EXAMPLES.md", "907-line code snippet reference for all modules"],
    ["IMPLEMENTATION_PLAN.md", "Architecture, deployment, cost model, runbook"],
    ["PENDING_ITEMS.md", "Detailed action items with exact file locations"],
    ["ARCHITECTURE_DECISIONS.md", "18 sections covering every major design decision"],
  ];
  sl.addText(docs.map(([name, desc]) => ({ text: `${name}  —  ${desc}`, options: { bullet: true, breakLine: true } })), {
    x: 0.55, y: 4.15, w: 9.0, h: 1.0,
    fontSize: 9.5, fontFace: "Calibri", color: C.charcoal
  });
}

// ── Slide 18: Close ──────────────────────────────────────────────────────
{
  const sl = pres.addSlide();
  sl.background = { color: C.navy };

  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 0.22, h: 5.625, fill: { color: C.teal }, line: { width: 0 }
  });

  sl.addText("GNAT", {
    x: 0.5, y: 1.0, w: 9, h: 0.9,
    fontSize: 52, fontFace: "Calibri", bold: true,
    color: C.white, align: "left", margin: 0
  });
  sl.addText("One library. Every platform. Total control.", {
    x: 0.5, y: 2.0, w: 9, h: 0.55,
    fontSize: 20, fontFace: "Calibri", italic: true,
    color: C.mint, align: "left", margin: 0
  });

  const summary = [
    "15 connectors · STIX 2.1 · Ingest + Export pipelines",
    "AI agents (Claude + Copilot) · Research library · Report generation",
    "784 tests · ~$50/month Azure · Incremental adoption",
  ];
  sl.addText(summary.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
    x: 0.5, y: 2.75, w: 9, h: 1.2,
    fontSize: 14, fontFace: "Calibri", color: C.offwhite
  });

  sl.addShape(pres.shapes.LINE, {
    x: 0.5, y: 4.1, w: 8.5, h: 0,
    line: { color: C.teal, width: 1.5 }
  });
  sl.addText("Version 1.0  |  Python 3.10+  |  See EXAMPLES.md · IMPLEMENTATION_PLAN.md · PENDING_ITEMS.md", {
    x: 0.5, y: 4.25, w: 9, h: 0.3,
    fontSize: 10, fontFace: "Calibri", color: C.muted, margin: 0
  });
}

// ── Write ────────────────────────────────────────────────────────────────
pres.writeFile({ fileName: OUT }).then(() => {
  console.log("Written:", OUT);
}).catch(err => {
  console.error("ERROR:", err);
  process.exit(1);
});
