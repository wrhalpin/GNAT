const pptxgen = require("pptxgenjs");
const path = require("path");

const OUT = process.argv[2] || "/mnt/user-data/outputs/GNAT-Presentation.pptx";

// ── Palette ──────────────────────────────────────────────────────────────
const C = {
  navy:        "0F2044",   // slide backgrounds
  navy2:       "162952",   // panel / card backgrounds
  steel:       "1E4D8C",   // mid-blue accent
  steelLight:  "5B93D9",   // lighter blue for contrast on dark backgrounds
  teal:        "0891B2",   // primary accent
  teal2:       "06B6D4",   // lighter teal
  mint:        "A5F3FC",   // highlight text on dark
  white:       "FFFFFF",
  offwhite:    "E8EFF8",
  muted:       "94A3B8",
  charcoal:    "1E293B",   // code block backgrounds
  green:       "10B981",
  amber:       "F59E0B",
  red:         "EF4444",
};

const makeShadow = () => ({
  type: "outer", blur: 6, offset: 3, angle: 135, color: "000000", opacity: 0.30
});

// ── Helpers ───────────────────────────────────────────────────────────────
function contentSlide(pres, title) {
  const sl = pres.addSlide();
  sl.background = { color: C.navy };
  sl.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 10, h: 0.72, fill: { color: C.navy2 }, line: { width: 0 }
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

function darkCard(sl, x, y, w, h, accentColor, title, bodyText) {
  sl.addShape("rect", {
    x, y, w, h, fill: { color: C.navy2 },
    line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x, y, w, h: 0.08, fill: { color: accentColor }, line: { width: 0 }
  });
  if (title) {
    sl.addText(title, {
      x: x + 0.12, y: y + 0.14, w: w - 0.24, h: 0.28,
      fontSize: 11, fontFace: "Calibri", bold: true,
      color: C.white, align: "left", margin: 0
    });
  }
  if (bodyText) {
    sl.addText(bodyText, {
      x: x + 0.12, y: y + (title ? 0.46 : 0.16), w: w - 0.24, h: h - (title ? 0.56 : 0.26),
      fontSize: 9, fontFace: "Calibri", color: C.muted, align: "left", margin: 0, valign: "top"
    });
  }
}

function statBox(sl, x, y, w, h, value, label, color) {
  sl.addShape("rect", {
    x, y, w, h, fill: { color: C.navy2 },
    line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x, y, w, h: 0.08, fill: { color }, line: { width: 0 }
  });
  sl.addText(value, {
    x: x + 0.08, y: y + 0.18, w: w - 0.16, h: 0.7,
    fontSize: 30, fontFace: "Calibri", bold: true,
    color, align: "center", margin: 0
  });
  sl.addText(label, {
    x: x + 0.08, y: y + 0.88, w: w - 0.16, h: 0.38,
    fontSize: 9.5, fontFace: "Calibri", color: C.muted, align: "center", margin: 0
  });
}

function codeBlock(sl, x, y, w, h, text) {
  sl.addShape("rect", {
    x, y, w, h, fill: { color: C.charcoal }, line: { width: 0 }
  });
  sl.addText(text, {
    x: x + 0.14, y: y + 0.1, w: w - 0.28, h: h - 0.2,
    fontSize: 8.5, fontFace: "Consolas", color: C.mint, margin: 0, valign: "top"
  });
}

function arrow(sl, x, y, isVertical) {
  sl.addShape("line", {
    x, y, w: isVertical ? 0 : 0.5, h: isVertical ? 0.18 : 0,
    line: { color: C.teal, width: 1.5, endArrowType: "triangle" }
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// BUILD DECK
// ═══════════════════════════════════════════════════════════════════════════
let pres = new pptxgen();
pres.layout = "LAYOUT_16x9";
pres.title  = "GNAT: GNAT's Not Another TIP";
pres.author = "wrhalpin@gmail.com";

// ── Slide 1: Title ──────────────────────────────────────────────────────
{
  const sl = pres.addSlide();
  sl.background = { color: C.navy };

  sl.addShape("rect", {
    x: 0, y: 0, w: 0.22, h: 5.625, fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addShape("rect", {
    x: 0.22, y: 4.9, w: 9.78, h: 0.08, fill: { color: C.teal }, line: { width: 0 }
  });

  sl.addText("GNAT", {
    x: 0.5, y: 0.7, w: 9, h: 1.0,
    fontSize: 52, fontFace: "Calibri", bold: true,
    color: C.white, align: "left", margin: 0
  });
  sl.addText("GNAT's Not Another TIP", {
    x: 0.5, y: 1.75, w: 9, h: 0.8,
    fontSize: 22, fontFace: "Calibri",
    color: C.mint, align: "left", margin: 0
  });

  const pills = [
    ["99 Connectors", C.teal],
    ["STIX 2.1", C.steel],
    ["AI-Powered", C.teal2],
    ["Scheduled", C.steel],
    ["Multi-Format Reports", C.teal],
  ];
  pills.forEach(([label, col], i) => {
    const px = 0.5 + i * 1.85;
    sl.addShape("rect", {
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

  sl.addText("Version 1.5.0  ·  Python 3.9+  ·  STIX 2.1  ·  99 Platform Connectors  ·  2,000+ Tests", {
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
    color: C.teal2, align: "left", margin: 0
  });

  const problems = [
    ["Numerous Different APIs", "Each platform has its own auth scheme, data model, and SDK. ThreatQ OAuth2 \u2260 CrowdStrike OAuth2 \u2260 VirusTotal API key."],
    ["No Shared Data Model", "An indicator in ThreatQ looks nothing like one in CrowdStrike or Splunk. Correlation requires manual mapping."],
    ["Custom Code Per Integration", "Every new source or destination means new scripts with no shared error handling, retry logic, or scheduling."],
    ["Fragile Automation", "Ad-hoc scripts break when APIs change. No tests, no versioning, no consistent patterns."],
  ];

  problems.forEach(([title, body], i) => {
    const col = i < 2 ? 0 : 1;
    const row = i % 2;
    const x = 0.35 + col * 4.7;
    const y = 1.6 + row * 1.7;
    sl.addShape("rect", {
      x, y, w: 4.35, h: 1.5,
      fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
    });
    sl.addShape("rect", {
      x, y, w: 0.1, h: 1.5, fill: { color: C.red }, line: { width: 0 }
    });
    sl.addText(title, {
      x: x + 0.2, y: y + 0.12, w: 4.05, h: 0.3,
      fontSize: 12, fontFace: "Calibri", bold: true, color: C.white, margin: 0
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

  sl.addShape("rect", {
    x: 0.35, y: 0.95, w: 4.1, h: 0.38,
    fill: { color: C.red }, line: { width: 0 }
  });
  sl.addText("WITHOUT GNAT", {
    x: 0.35, y: 0.95, w: 4.1, h: 0.38,
    fontSize: 12, fontFace: "Calibri", bold: true,
    color: C.white, align: "center", margin: 0
  });
  const withoutItems = [
    "ThreatQ SDK  \u2192  custom code",
    "CrowdStrike API  \u2192  custom code",
    "Splunk API  \u2192  custom code",
    "VirusTotal API  \u2192  custom code",
    "Netskope CE  \u2192  custom code",
    "Each: own auth, errors, retries",
    "Each: own data model",
    "No shared testing or scheduling",
  ];
  sl.addText(withoutItems.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
    x: 0.5, y: 1.45, w: 3.8, h: 3.5,
    fontSize: 10, fontFace: "Calibri", color: C.offwhite, valign: "top"
  });

  arrow(sl, 4.55, 3.2, false);
  sl.addText("GNAT", {
    x: 4.5, y: 3.35, w: 1.0, h: 0.25,
    fontSize: 9, fontFace: "Calibri", bold: true,
    color: C.teal, align: "center", margin: 0
  });

  sl.addShape("rect", {
    x: 5.55, y: 0.95, w: 4.1, h: 0.38,
    fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("WITH GNAT", {
    x: 5.55, y: 0.95, w: 4.1, h: 0.38,
    fontSize: 12, fontFace: "Calibri", bold: true,
    color: C.white, align: "center", margin: 0
  });
  const withItems = [
    "GNATConfig  \u2192  one config.ini",
    "GNATClient  \u2192  one interface",
    "STIX 2.1 everywhere",
    "IngestPipeline  \u2192  pull any source",
    "ExportPipeline  \u2192  push to EDLs/CE",
    "FeedScheduler  \u2192  all jobs, one place",
    "ReportGenerator  \u2192  PDF/HTML/DOCX",
    "ResearchLibrary  \u2192  shared knowledge",
  ];
  sl.addText(withItems.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
    x: 5.7, y: 1.45, w: 3.8, h: 3.5,
    fontSize: 10, fontFace: "Calibri", color: C.offwhite, valign: "top"
  });
}

// ── Slide 4: Architecture ─────────────────────────────────────────────
{
  const sl = contentSlide(pres, "Architecture: The Middle Layer Model");

  const layers = [
    { label: "ANALYST / AUTOMATION LAYER", sub: "Workstations \u00b7 SOAR \u00b7 Scheduled jobs \u00b7 CLI \u00b7 TUI \u00b7 Web Dashboard", col: C.navy2, y: 0.85 },
    { label: "GNAT CORE", sub: "Ingest \u00b7 Export \u00b7 AI Agents \u00b7 Research Library \u00b7 Reports \u00b7 NLP \u00b7 TAXII 2.1 \u00b7 Solr Search", col: C.steel, y: 1.52 },
    { label: "STIX 2.1 ORM + WORKSPACE", sub: "Indicator \u00b7 ThreatActor \u00b7 Vulnerability \u00b7 AttackPattern \u00b7 Malware \u00b7 Relationship", col: C.teal, y: 2.19 },
    { label: "CONNECTOR LAYER (99 platforms)", sub: "ThreatQ \u00b7 CrowdStrike \u00b7 Splunk \u00b7 Elastic \u00b7 Wazuh \u00b7 QRadar \u00b7 Sentinel \u00b7 VirusTotal \u00b7 Mandiant \u00b7 Orca \u00b7 Wiz \u00b7 MISP \u00b7 ...", col: C.navy2, y: 2.86 },
    { label: "EXTERNAL PLATFORMS", sub: "TIPs \u00b7 SIEMs \u00b7 EDRs \u00b7 Vuln Scanners \u00b7 CNAPP/ASM \u00b7 SOAR \u00b7 NDR \u00b7 AI Assistants", col: "4B5563", y: 3.53 },
  ];

  layers.forEach(({ label, sub, col, y }) => {
    sl.addShape("rect", {
      x: 0.35, y, w: 9.3, h: 0.57, fill: { color: col }, line: { width: 0 }
    });
    sl.addText(label, {
      x: 0.5, y: y + 0.05, w: 4.5, h: 0.22,
      fontSize: 10, fontFace: "Calibri", bold: true, color: C.white, margin: 0
    });
    sl.addText(sub, {
      x: 0.5, y: y + 0.29, w: 9.0, h: 0.2,
      fontSize: 8.5, fontFace: "Calibri", color: C.mint, margin: 0
    });
    if (y < 3.53) {
      sl.addShape("line", {
        x: 4.85, y: y + 0.57, w: 0, h: 0.1,
        line: { color: C.teal, width: 1.5, endArrowType: "triangle" }
      });
    }
  });

  sl.addText("urllib3 / httpx transport  \u00b7  zero cloud dependencies  \u00b7  INI config  \u00b7  multi-tenant namespace isolation", {
    x: 0.35, y: 4.28, w: 9.3, h: 0.3,
    fontSize: 9.5, fontFace: "Calibri", italic: true,
    color: C.muted, align: "center", margin: 0
  });
}

// ── Slide 5: Connectors (category layout) ─────────────────────────────
{
  const sl = contentSlide(pres, "99 Platform Connectors \u2014 One Interface");

  const categories = [
    {
      label: "THREAT INTELLIGENCE",
      col: C.teal,
      items: "ThreatQ \u00b7 CrowdStrike \u00b7 Recorded Future \u00b7 AlienVault OTX \u00b7 VirusTotal \u00b7 ThreatConnect \u00b7 Mandiant \u00b7 MS Defender TI \u00b7 ThreatStream \u00b7 SOCRadar \u00b7 PulseDive \u00b7 FLARE \u00b7 Yeti \u00b7 CloudSEK \u00b7 Feedly \u00b7 MISP \u00b7 OpenCTI \u00b7 Group-IB \u00b7 Cyble Vision \u00b7 ZeroFox \u00b7 ShadowServer \u00b7 BitSight \u00b7 Flashpoint \u00b7 HudsonRock \u00b7 Intel 471 \u00b7 UpGuard \u00b7 Shodan \u00b7 GreyNoise \u00b7 CISA KEV \u00b7 OSINT Feed",
    },
    {
      label: "SIEM & LOG ANALYTICS",
      col: C.steelLight,
      items: "Splunk \u00b7 Elastic SIEM \u00b7 IBM QRadar \u00b7 Microsoft Sentinel \u00b7 Graylog \u00b7 OSSIM \u00b7 Security Onion \u00b7 Wazuh \u00b7 Google Chronicle \u00b7 LogRhythm \u00b7 Datadog",
    },
    {
      label: "SOAR & INCIDENT RESPONSE",
      col: C.teal,
      items: "Palo Alto XSOAR \u00b7 TheHive \u00b7 GreyMatter \u00b7 ServiceNow \u00b7 Jira \u00b7 Synapse \u00b7 FortiSOAR",
    },
    {
      label: "VULNERABILITY & CLOUD SECURITY",
      col: C.steelLight,
      items: "Rapid7 InsightVM/IDR \u00b7 Nucleus Security \u00b7 Tenable One \u00b7 Qualys VMDR \u00b7 Greenbone/OpenVAS \u00b7 DefectDojo \u00b7 Orca Security \u00b7 Wiz CNAPP \u00b7 Cortex Xpanse \u00b7 CyCognito \u00b7 RiskRecon \u00b7 Armis Centrix \u00b7 Axonius \u00b7 Prisma Cloud \u00b7 AWS Security Hub \u00b7 JupiterOne \u00b7 SecurityScorecard \u00b7 Censys",
    },
    {
      label: "NETWORK DETECTION & ENDPOINT",
      col: C.teal,
      items: "Snort IDS \u00b7 Suricata \u00b7 Zeek \u00b7 SentinelOne \u00b7 Stellar Cyber \u00b7 Netskope \u00b7 ControlUp DEX \u00b7 Whistic \u00b7 Proofpoint \u00b7 Darktrace \u00b7 ExtraHop \u00b7 Lansweeper \u00b7 Vectra AI \u00b7 Sophos \u00b7 Trellix \u00b7 Carbon Black \u00b7 Tanium \u00b7 Trend Micro Vision One \u00b7 Cisco Umbrella \u00b7 Cortex XDR \u00b7 FortiEDR \u00b7 FortiSIEM",
    },
    {
      label: "OT/ICS & INDUSTRY",
      col: C.steelLight,
      items: "Dragos Platform \u00b7 Claroty \u00b7 Nozomi Networks \u00b7 Cribl Stream",
    },
    {
      label: "AI ASSISTANTS",
      col: C.teal2,
      items: "Microsoft Copilot for Security \u00b7 OpenAI ChatGPT \u00b7 Google Gemini \u00b7 Grok AI \u00b7 Discord",
    },
    {
      label: "ITSM & TICKETING",
      col: C.amber,
      items: "ServiceNow SecOps \u00b7 Atlassian Jira",
    },
  ];

  // 2 columns x 4 rows
  const colW = 4.55, rowH = 1.12, startX = 0.2, startY = 0.88, gap = 0.1;

  categories.forEach(({ label, col, items }, i) => {
    const c = i % 2;
    const r = Math.floor(i / 2);
    const x = startX + c * (colW + gap);
    const y = startY + r * (rowH + gap);

    sl.addShape("rect", {
      x, y, w: colW, h: rowH,
      fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
    });
    sl.addShape("rect", {
      x, y, w: colW, h: 0.06, fill: { color: col }, line: { width: 0 }
    });
    sl.addText(label, {
      x: x + 0.12, y: y + 0.1, w: colW - 0.24, h: 0.22,
      fontSize: 8.5, fontFace: "Calibri", bold: true, color: col, margin: 0
    });
    sl.addText(items, {
      x: x + 0.12, y: y + 0.35, w: colW - 0.24, h: rowH - 0.45,
      fontSize: 8, fontFace: "Calibri", color: C.muted, margin: 0, valign: "top"
    });
  });

  // Footer
  sl.addText("Every connector: authenticate \u00b7 health_check \u00b7 get/list/upsert/delete_object \u00b7 to_stix() \u00b7 from_stix()  \u2014  one uniform contract", {
    x: 0.2, y: 5.32, w: 9.6, h: 0.22,
    fontSize: 8.5, fontFace: "Calibri", italic: true, color: C.muted, align: "center", margin: 0
  });
}

// ── Slide 6: STIX 2.1 ORM ───────────────────────────────────────────────
{
  const sl = contentSlide(pres, "STIX 2.1 ORM \u2014 A Universal Data Contract");

  sl.addText("Every object from every connector normalises into the same STIX 2.1 types", {
    x: 0.4, y: 0.9, w: 9.2, h: 0.35,
    fontSize: 13, fontFace: "Calibri", italic: true,
    color: C.teal2, align: "left", margin: 0
  });

  const types = [
    ["Indicator", "IOCs with STIX patterns\n[domain-name:value = '...']", C.teal],
    ["ThreatActor", "Actor profiles, aliases,\nmotivation, attribution", C.steel],
    ["Vulnerability", "CVEs, CVSS scores,\nexploited flag, products", C.amber],
    ["AttackPattern", "MITRE ATT&CK TTPs\nwith tactic mapping", C.green],
    ["Malware", "Malware families,\ncapabilities, kill-chain", C.red],
    ["Relationship", "Links: indicates \u00b7 uses \u00b7 targets\nBidirectional STIX graph", C.teal2],
  ];

  types.forEach(([name, detail, color], i) => {
    const col = i % 3;
    const row = Math.floor(i / 3);
    const x = 0.35 + col * 3.1;
    const y = 1.4 + row * 1.7;
    sl.addShape("rect", {
      x, y, w: 2.9, h: 1.52,
      fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
    });
    sl.addShape("rect", {
      x, y, w: 0.12, h: 1.52, fill: { color }, line: { width: 0 }
    });
    sl.addText(name, {
      x: x + 0.22, y: y + 0.15, w: 2.58, h: 0.32,
      fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
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

  // Ingest header
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.4, h: 0.35,
    fill: { color: C.steel }, line: { width: 0 }
  });
  sl.addText("INGEST PIPELINE  (pull from platforms)", {
    x: 0.35, y: 0.9, w: 4.4, h: 0.35,
    fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });

  const ingestSteps = [
    ["SourceReader", "14 reader types\nTAXII \u00b7 CSV \u00b7 STIX \u00b7 Syslog\nRSS \u00b7 Email \u00b7 Splunk \u00b7 Elastic\u2026", C.teal],
    ["RecordMapper", "12 mapper types\nFlatIOC \u00b7 STIX \u00b7 MISP \u00b7 CEF\nCSV \u00b7 NVD CVE \u00b7 Feedly\u2026", C.steel],
    ["Workspace", "STIX ORM objects\ndedup \u00b7 confidence\nx_target_sectors tag", C.navy2],
  ];

  ingestSteps.forEach(([title, body, col], i) => {
    const x = 0.35 + i * 1.5;
    sl.addShape("rect", {
      x, y: 1.35, w: 1.35, h: 1.85,
      fill: { color: C.navy2 }, line: { color: col, width: 1.5 }, shadow: makeShadow()
    });
    sl.addText(title, {
      x: x + 0.08, y: 1.45, w: 1.19, h: 0.28,
      fontSize: 10, fontFace: "Calibri", bold: true, color: col, margin: 0
    });
    sl.addText(body, {
      x: x + 0.08, y: 1.78, w: 1.19, h: 1.3,
      fontSize: 8.5, fontFace: "Calibri", color: C.muted, margin: 0
    });
  });

  // Export header
  sl.addShape("rect", {
    x: 5.25, y: 0.9, w: 4.4, h: 0.35,
    fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("EXPORT PIPELINE  (push to destinations)", {
    x: 5.25, y: 0.9, w: 4.4, h: 0.35,
    fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });

  const exportSteps = [
    ["ExportFilter", "TypeFilter \u00b7 ConfidenceFilter\nTLPFilter \u00b7 SectorFilter\nIOCTypeFilter \u00b7 LimitFilter", C.teal],
    ["ExportTransform", "EDLTransform\nNetskopeCETransform\nSTIXBundle \u00b7 CSV", C.steel],
    ["Delivery", "FileDelivery\nEDLServer (HTTP)\nPlatformDelivery\nMultiDelivery", C.navy2],
  ];

  exportSteps.forEach(([title, body, col], i) => {
    const x = 5.25 + i * 1.5;
    sl.addShape("rect", {
      x, y: 1.35, w: 1.35, h: 1.85,
      fill: { color: C.navy2 }, line: { color: col, width: 1.5 }, shadow: makeShadow()
    });
    sl.addText(title, {
      x: x + 0.08, y: 1.45, w: 1.19, h: 0.28,
      fontSize: 10, fontFace: "Calibri", bold: true, color: col, margin: 0
    });
    sl.addText(body, {
      x: x + 0.08, y: 1.78, w: 1.19, h: 1.3,
      fontSize: 8.5, fontFace: "Calibri", color: C.muted, margin: 0
    });
  });

  sl.addText("Real example: ThreatQ \u2192 GNAT \u2192 Netskope CE (FQDN + URL + SHA256 every 15 min) \u2192 Tenant lists \u2192 Palo Alto EDLs", {
    x: 0.35, y: 3.35, w: 9.3, h: 0.38,
    fontSize: 10.5, fontFace: "Calibri", italic: true,
    color: C.teal2, align: "center", margin: 0
  });

  codeBlock(sl, 0.35, 3.85, 9.3, 1.38,
    "result = (ExportPipeline(\"tq-to-netskope\")\n" +
    "    .read_from(workspace)\n" +
    "    .filter_with(TypeFilter(\"indicator\")).filter_with(ConfidenceFilter(70))\n" +
    "    .transform_with(NetskopeCETransform(source_label=\"ThreatQ\", ioc_types=[\"domain\",\"url\",\"sha256\"]))\n" +
    "    .deliver_to(PlatformDelivery(netskope_client))).run()"
  );
}

// ── Slide 8: Scheduling ──────────────────────────────────────────────────
{
  const sl = contentSlide(pres, "Scheduling \u2014 One Scheduler, All Jobs");

  statBox(sl, 0.35, 0.95, 2.15, 1.35, "FeedJob", "Declarative job type", C.teal);
  statBox(sl, 2.65, 0.95, 2.15, 1.35, "Scheduler", "FeedScheduler threading", C.steel);
  statBox(sl, 4.95, 0.95, 2.15, 1.35, "ExportJob", "Scheduled export", C.teal);
  statBox(sl, 7.25, 0.95, 2.45, 1.35, "ReportJob", "Scheduled reports", C.steel);

  sl.addText("Every job type extends FeedJob and runs in the same FeedScheduler", {
    x: 0.35, y: 2.42, w: 9.3, h: 0.3,
    fontSize: 10.5, fontFace: "Calibri", italic: true,
    color: C.teal2, align: "center", margin: 0
  });

  const features = [
    ["Drift-corrected timing", "Hourly jobs stay hourly even when runs take 5 min"],
    ["Overlap protection", "skip or queue policy \u2014 never two runs of the same job simultaneously"],
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
    sl.addShape("rect", {
      x, y, w: 4.45, h: 0.6,
      fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }
    });
    sl.addShape("rect", {
      x, y, w: 0.08, h: 0.6, fill: { color: C.teal }, line: { width: 0 }
    });
    sl.addText(title, {
      x: x + 0.18, y: y + 0.06, w: 4.17, h: 0.22,
      fontSize: 10, fontFace: "Calibri", bold: true, color: C.white, margin: 0
    });
    sl.addText(body, {
      x: x + 0.18, y: y + 0.3, w: 4.17, h: 0.22,
      fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
    });
  });
}

// ── Slide 9: AI Agents ───────────────────────────────────────────────────
{
  const sl = contentSlide(pres, "AI Agents \u2014 Multi-LLM Threat Research");

  const agents = [
    {
      title: "ResearchAgent", sub: "SourceReader",
      body: "Topic-driven: synthesise research on threat actors, CVEs, campaigns.\nFeed-driven: monitor sources for new threat content.\nBacked by LLMClient (Claude / OpenAI / Grok / Gemini).",
      color: C.teal
    },
    {
      title: "ParsingAgent", sub: "RecordMapper",
      body: "Extract structured STIX from any unstructured text.\nFlexible: IOCs + TTPs + actors + CVEs \u2014 whatever is present.\nAll output capped at confidence \u2264 60, tagged x_source_type=ai_extracted.",
      color: C.steel
    },
    {
      title: "LLMClient", sub: "Unified Multi-LLM Facade",
      body: "Single interface for Claude, OpenAI, Grok (xAI), and Gemini.\nAutomatic provider fallback on errors or rate limits.\nConfigured via [claude] / [openai] / [grok] / [gemini] INI sections.\nUsed by ResearchAgent, ParsingAgent, and ReportDraftingAssistant.",
      color: C.teal2
    },
  ];

  agents.forEach(({ title, sub, body, color }, i) => {
    const x = 0.35 + i * 3.1;
    sl.addShape("rect", {
      x, y: 0.95, w: 2.9, h: 2.35,
      fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
    });
    sl.addShape("rect", {
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

  // Workflow engine banner
  sl.addShape("rect", {
    x: 0.35, y: 3.38, w: 9.3, h: 0.52,
    fill: { color: C.navy2 }, line: { color: C.teal, width: 1 }
  });
  sl.addText("\u26f6  WorkflowEngine \u2014 Sequential DAG Orchestration (v1.4+)", {
    x: 0.55, y: 3.44, w: 5.0, h: 0.22,
    fontSize: 9.5, fontFace: "Calibri", bold: true, color: C.teal, margin: 0
  });
  sl.addText("Pre-built: PhishingTriage \u00b7 IncidentResponse \u00b7 Custom DAGs with on_success / on_failure routing \u00b7 cycle detection \u00b7 elapsed timing", {
    x: 0.55, y: 3.64, w: 9.0, h: 0.2,
    fontSize: 8.5, fontFace: "Calibri", color: C.muted, margin: 0
  });

  // Trust model
  sl.addShape("rect", {
    x: 0.35, y: 4.0, w: 9.3, h: 0.78,
    fill: { color: C.navy2 }, line: { color: C.amber, width: 1 }
  });
  sl.addText("\u26a0  AI Trust Model \u00b7 CopilotReader", {
    x: 0.55, y: 4.07, w: 4.5, h: 0.25,
    fontSize: 10, fontFace: "Calibri", bold: true, color: C.amber, margin: 0
  });
  sl.addText(
    "confidence_ceiling = 60 (configurable) prevents AI-extracted intel from reaching EDLs without analyst review. " +
    "All AI objects tagged x_source_type='ai_extracted'. Export pipelines default to ConfidenceFilter(min=70), " +
    "which excludes AI intel until promoted. CopilotReader queries Microsoft Copilot via DirectLine (SharePoint, mailboxes, Teams) " +
    "and feeds output directly into ParsingAgent.",
    {
      x: 0.55, y: 4.3, w: 9.0, h: 0.42,
      fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
    }
  );
}

// ── Slide 10: NLP Query Interface ────────────────────────────────────────
{
  const sl = contentSlide(pres, "Natural Language Query Interface");

  // Left: engine
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 2.55,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 0.38, fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("NLPQueryEngine", {
    x: 0.47, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });

  const backends = [
    ["BuiltinParser", "Rule-based extraction \u2014 zero extra\ndependencies. Regex + keyword rules\nextract entities, IOC types, time\nranges, and platform filters."],
    ["ClaudeParser", "Claude API structured extraction.\nReturns the same QuerySpec as\nthe builtin backend. Configured\nvia [nlp] backend = claude."],
  ];
  backends.forEach(([name, body], i) => {
    const y = 1.42 + i * 0.95;
    sl.addShape("rect", {
      x: 0.48, y, w: 4.28, h: 0.82,
      fill: { color: C.steel }, line: { width: 0 }
    });
    sl.addText(name, {
      x: 0.6, y: y + 0.06, w: 4.04, h: 0.22,
      fontSize: 10, fontFace: "Calibri", bold: true, color: C.white, margin: 0
    });
    sl.addText(body, {
      x: 0.6, y: y + 0.3, w: 4.04, h: 0.46,
      fontSize: 8.5, fontFace: "Calibri", color: C.mint, margin: 0
    });
  });

  sl.addText("Configure via [nlp] section in gnat.ini \u00b7 backend = builtin | claude \u00b7 CLI: gnat nlq \"...\"", {
    x: 0.47, y: 3.33, w: 4.31, h: 0.22,
    fontSize: 8, fontFace: "Calibri", color: C.muted, italic: true, margin: 0
  });

  // Right: QuerySpec
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 2.55,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 0.38, fill: { color: C.steel }, line: { width: 0 }
  });
  sl.addText("QuerySpec (internal dataclass)", {
    x: 5.22, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  codeBlock(sl, 5.22, 1.38, 4.3, 1.95,
    "@dataclass\nclass QuerySpec:\n    entities:   list[str]        # APT-128, Cobalt Strike...\n    ioc_types:  list[str]        # ip, domain, hash...\n    since:      datetime | None\n    until:      datetime | None\n    platforms:  list[str]        # connectors to query\n    limit:      int"
  );

  // Bottom code
  codeBlock(sl, 0.35, 3.65, 9.3, 0.9,
    "results = client.natural_language_query(\n" +
    "    \"Get all IPs associated with Lazarus Group in the last 30 days\"\n" +
    ")  # \u2192 list[STIXBase] dispatched to all configured connectors"
  );
}

// ── Slide 11: Research Library ───────────────────────────────────────────
{
  const sl = contentSlide(pres, "Research Library \u2014 Shared Team Knowledge Base");

  const tiers = [
    { label: "PERSONAL WORKSPACES", sub: "Analyst-owned \u00b7 Active investigation", col: C.navy2 },
    { label: "STAGING  (_gnat_staging)", sub: "lib.promote(ws, topic, researcher, note='...')  \u2014  anyone can write, nothing auto-promotes", col: C.steel },
    { label: "LIBRARY  (_gnat_library)", sub: "Curated \u00b7 Read-only to analysts \u00b7 CurationJob every 4h \u00b7 deduplication \u00b7 TTL enforcement", col: C.teal },
  ];

  tiers.forEach(({ label, sub, col }, i) => {
    sl.addShape("rect", {
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
  });

  // Arrows between tiers (Personal → Staging → Library)
  [0, 1].forEach(i => {
    arrow(sl, 3.1, 0.95 + i * 1.05 + 0.85 + 0.01, true);
  });

  sl.addText("TTL by Category", {
    x: 6.1, y: 0.92, w: 3.5, h: 0.28,
    fontSize: 11, fontFace: "Calibri", bold: true, color: C.offwhite, margin: 0
  });

  const ttl = [
    [
      { text: "Category", options: { fill: { color: C.teal }, color: C.white, bold: true } },
      { text: "Default TTL", options: { fill: { color: C.teal }, color: C.white, bold: true } },
      { text: "Rationale", options: { fill: { color: C.teal }, color: C.white, bold: true } },
    ],
    ["indicator", "24 hours", "IOCs rotate quickly"],
    ["vulnerability", "72 hours", "Exploitability changes"],
    ["campaign", "14 days", "Evolves over weeks"],
    ["threat_actor", "30 days", "Slow-changing TTPs"],
    ["other", "7 days", "Conservative fallback"],
  ];
  sl.addTable(ttl, {
    x: 6.1, y: 1.28, w: 3.55, h: 2.2,
    border: { pt: 0.5, color: C.steel },
    colW: [1.1, 0.95, 1.5],
    fontSize: 8.5, fontFace: "Calibri",
    fill: { color: C.navy2 },
    color: C.offwhite,
  });

  sl.addText(
    "Analyst checks lib.is_fresh(\"APT29\") before running ResearchAgent. " +
    "After review, promotes to staging with an analyst note. " +
    "CurationJob deduplicates and promotes to library.",
    {
      x: 0.35, y: 4.28, w: 9.3, h: 0.72,
      fontSize: 9.5, fontFace: "Calibri", color: C.muted,
      fill: { color: C.navy2 }, margin: 0.08
    }
  );
}

// ── Slide 12: Report Generation ──────────────────────────────────────────
{
  const sl = contentSlide(pres, "Automated Report Generation");

  const reportTypes = [
    { name: "Daily Intel", interval: "06:00 daily", ai: "Assisted", audience: "SOC analysts / shift handoff", formats: "PDF \u00b7 HTML \u00b7 Markdown", color: C.teal },
    { name: "Trends", interval: "Weekly", ai: "Assisted", audience: "Team leads / analysts", formats: "PDF \u00b7 HTML", color: C.steel },
    { name: "Yearly Intel", interval: "Annual / manual", ai: "Full", audience: "Management / compliance", formats: "PDF \u00b7 DOCX", color: C.navy2 },
  ];

  reportTypes.forEach(({ name, interval, ai, audience, formats, color }, i) => {
    const x = 0.35 + i * 3.1;
    sl.addShape("rect", {
      x, y: 0.95, w: 2.9, h: 2.7,
      fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
    });
    sl.addShape("rect", {
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
        fontSize: 9, fontFace: "Calibri", color: C.offwhite, margin: 0
      });
    });
  });

  sl.addText("Generation pipeline:", {
    x: 0.35, y: 3.78, w: 2.0, h: 0.3,
    fontSize: 10, fontFace: "Calibri", bold: true, color: C.offwhite, margin: 0
  });

  const pipeSteps = ["DataAggregator\n(no AI)", "ReportSynthesizer\n(one call/section)", "Renderers\nMD/HTML/PDF/DOCX", "Delivery\nEmail + SharePoint"];
  pipeSteps.forEach((step, i) => {
    const x = 0.35 + i * 2.35;
    sl.addShape("rect", {
      x, y: 4.15, w: 2.05, h: 0.8,
      fill: { color: i % 2 === 0 ? C.teal : C.steel }, line: { width: 0 }
    });
    sl.addText(step, {
      x: x + 0.08, y: 4.2, w: 1.89, h: 0.7,
      fontSize: 9.5, fontFace: "Calibri", bold: true, color: C.white, align: "center", margin: 0
    });
  });

  // Arrows between pipeline steps
  [0, 1, 2].forEach(i => {
    sl.addShape("line", {
      x: 0.35 + i * 2.35 + 2.07, y: 4.55, w: 0.26, h: 0,
      line: { color: C.teal, width: 1.5, endArrowType: "triangle" }
    });
  });
}

// ── Slide 13: Sector Filtering ───────────────────────────────────────────
{
  const sl = contentSlide(pres, "Sector Targeting Intelligence");

  sl.addText("x_target_sectors \u2014 canonical cross-platform sector field, normalized from all connectors", {
    x: 0.4, y: 0.9, w: 9.2, h: 0.35,
    fontSize: 13, fontFace: "Calibri", italic: true,
    color: C.teal2, align: "left", margin: 0
  });

  const modes = [
    { label: "any (default)", body: "Include objects tagged with at\nleast one listed sector.\nUntagged objects also pass\n(non-strict mode).", col: C.teal },
    { label: "all", body: "Require all listed sectors to\nbe present on the object.\nStrict: only tagged objects.", col: C.steel },
    { label: "strict=True", body: "Exclude untagged objects\nentirely. Only explicitly\ntagged objects are included.", col: C.navy2 },
  ];

  modes.forEach(({ label, body, col }, i) => {
    const x = 0.35 + i * 3.0;
    sl.addShape("rect", {
      x, y: 1.4, w: 2.8, h: 2.0,
      fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
    });
    sl.addShape("rect", {
      x, y: 1.4, w: 2.8, h: 0.38, fill: { color: col }, line: { width: 0 }
    });
    sl.addText(label, {
      x: x + 0.12, y: 1.44, w: 2.56, h: 0.3,
      fontSize: 12, fontFace: "Calibri", bold: true, color: C.white, margin: 0
    });
    sl.addText(body, {
      x: x + 0.12, y: 1.9, w: 2.56, h: 1.3,
      fontSize: 9.5, fontFace: "Calibri", color: C.muted, margin: 0, valign: "top"
    });
  });

  codeBlock(sl, 0.35, 3.55, 9.3, 1.68,
    "[sector_aliases]\n" +
    "healthcare = Healthcare, Health, Medical, H-ISAC, Hospitals and Health Centers\n" +
    "financial  = Financial Services, Finance, Banking, FS-ISAC\n" +
    "energy     = Energy, Electric, Oil and Gas, E-ISAC\n\n" +
    "# SectorFilter expands aliases so 'health' matches 'Healthcare' from ThreatQ and 'Health' from RF"
  );
}

// ── Slide 14: Search Sidecar ─────────────────────────────────────────────
{
  const sl = contentSlide(pres, "Search Sidecar \u2014 Solr Full-Text Search");

  sl.addText("Every STIX object indexed in Solr 9.x \u2014 search across all connectors simultaneously", {
    x: 0.4, y: 0.9, w: 9.2, h: 0.35,
    fontSize: 13, fontFace: "Calibri", italic: true,
    color: C.teal2, align: "left", margin: 0
  });

  const components = [
    { label: "GNATIndexer", sub: "gnat/search/index.py", body: "Add/update/delete Solr documents. Batch indexing with configurable batch_size. Field-mapped from STIX objects.", col: C.teal },
    { label: "SearchMixin", sub: "gnat/search/mixin.py", body: "Drop-in connector mixin. Auto-indexes on upsert_object() calls. Zero code change to existing connectors.", col: C.steel },
    { label: "ORM Integration", sub: "gnat/search/orm_with_mixin.py", body: "SearchMixin-enhanced STIX objects. Transparent to existing ORM code.", col: C.navy2 },
    { label: "Pipeline Patch", sub: "gnat/search/pipeline_patch.py", body: "Patches IngestPipeline to route records through Solr indexer post-map.", col: C.steel },
    { label: "Library Patch", sub: "gnat/search/library_patch.py", body: "ResearchLibrary search-backed lookups. Cross-source correlation at query time.", col: C.navy2 },
    { label: "Solr Schema", sub: "solr_schema_gnat.xml", body: "Solr 9.x schema for GNAT fields: type, value, confidence, x_target_sectors, tlp, source, timestamp.", col: C.teal },
  ];

  components.forEach(({ label, sub, body, col }, i) => {
    const c = i % 3;
    const r = Math.floor(i / 3);
    const x = 0.3 + c * 3.15;
    const y = 1.45 + r * 1.95;
    sl.addShape("rect", {
      x, y, w: 3.0, h: 1.75,
      fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
    });
    sl.addShape("rect", {
      x, y, w: 3.0, h: 0.08, fill: { color: col }, line: { width: 0 }
    });
    sl.addText(label, {
      x: x + 0.1, y: y + 0.15, w: 2.8, h: 0.3,
      fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0
    });
    sl.addText(sub, {
      x: x + 0.1, y: y + 0.45, w: 2.8, h: 0.22,
      fontSize: 8.5, fontFace: "Calibri", italic: true, color: C.muted, margin: 0
    });
    sl.addText(body, {
      x: x + 0.1, y: y + 0.7, w: 2.8, h: 0.95,
      fontSize: 9, fontFace: "Calibri", color: C.offwhite, margin: 0
    });
  });

  sl.addShape("rect", {
    x: 0.3, y: 5.1, w: 9.4, h: 0.38,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }
  });
  sl.addText("Configure via [search] in gnat.ini  \u00b7  solr_url = http://localhost:8983/solr/gnat  \u00b7  enabled = true  \u00b7  Grafana dashboards via gnat viz serve --with-solr", {
    x: 0.4, y: 5.14, w: 9.2, h: 0.3,
    fontSize: 8.5, fontFace: "Calibri", color: C.muted, align: "center", margin: 0
  });
}

// ── Slide 15: TAXII 2.1 + STIX Validator ────────────────────────────────
{
  const sl = contentSlide(pres, "TAXII 2.1 Server & STIX Pattern Validator");

  // Left: TAXII
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 4.42,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 0.42, fill: { color: C.steel }, line: { width: 0 }
  });
  sl.addText("TAXII 2.1 Server \u2014 Full Read + Write", {
    x: 0.47, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText("Each GNAT workspace is exposed as a TAXII 2.1 collection. Full protocol compliance including write endpoints.", {
    x: 0.47, y: 1.4, w: 4.31, h: 0.38,
    fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
  });

  const endpoints = [
    "GET  /taxii2/  \u2014  Discovery",
    "GET  /taxii2/roots/gnat/collections/  \u2014  List",
    "GET  /taxii2/.../objects/  \u2014  Paginated bundle",
    "POST /taxii2/.../objects/  \u2014  Ingest bundle (WRITE_TAXII permission)",
    "DELETE /taxii2/.../objects/{id}  \u2014  Soft-delete by STIX ID",
    "GET  /taxii2/.../manifest/  \u2014  Object manifest",
    "GET  /taxii2/.../objects/{oid}/versions/",
  ];
  sl.addText(endpoints.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
    x: 0.47, y: 1.85, w: 4.31, h: 2.05,
    fontSize: 8.5, fontFace: "Calibri", color: C.offwhite
  });

  codeBlock(sl, 0.47, 4.0, 4.31, 0.48,
    "gnat taxii --port 8090 --api-key s3cr3t\ngnat taxii --title \"Acme TAXII\" --port 9000"
  );
  sl.addText("Requires gnat[serve]  \u00b7  56 unit tests  \u00b7  TLP:AMBER + RED collections allow write", {
    x: 0.47, y: 4.55, w: 4.31, h: 0.22,
    fontSize: 8, fontFace: "Calibri", color: C.muted, italic: true, margin: 0
  });

  // Right: STIX Validator
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 4.42,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 0.42, fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("STIX 2.1 Pattern Validator", {
    x: 5.22, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText("Two-tier validator. Tier 1: pure-Python recursive descent (zero deps). Tier 2: stix2-patterns ANTLR grammar.", {
    x: 5.22, y: 1.4, w: 4.31, h: 0.46,
    fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
  });

  codeBlock(sl, 5.22, 1.94, 4.31, 1.45,
    "from gnat.stix import validate_pattern, PatternValidationError\n\n" +
    "result = validate_pattern(\"[ipv4-addr:value = '1.2.3.4']\")\nassert result.valid\n\n" +
    "# ORM opt-in validation\nIndicator(pattern=\"[domain-name:value = 'evil.com']\", validate=True)"
  );

  sl.addText("CLI:", {
    x: 5.22, y: 3.46, w: 0.5, h: 0.22,
    fontSize: 9, fontFace: "Calibri", bold: true, color: C.muted, margin: 0
  });
  codeBlock(sl, 5.22, 3.68, 4.31, 0.72,
    "gnat validate pattern \"[ipv4-addr:value = '1.2.3.4']\"\ngnat validate bundle indicators.json --strict"
  );
  sl.addText("Requires gnat[stix-validate] for tier 2  \u00b7  87 unit tests", {
    x: 5.22, y: 4.47, w: 4.31, h: 0.22,
    fontSize: 8, fontFace: "Calibri", color: C.muted, italic: true, margin: 0
  });
}

// ── Slide 16: Connector Capabilities + Health Monitor ───────────────────
{
  const sl = contentSlide(pres, "Connector Capability Reflection & Health Monitoring");

  // Left: Capabilities
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 4.42,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 0.42, fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("Capability Reflection", {
    x: 0.47, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText("Introspect any connector's methods at runtime. Safe guarded dispatch prevents unintended writes.", {
    x: 0.47, y: 1.4, w: 4.31, h: 0.46,
    fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
  });
  codeBlock(sl, 0.47, 1.93, 4.31, 1.45,
    "caps = client.capabilities()\n# [{name, signature, doc, type:\n#   'auth|read|write|helper',\n#   platform_specific: bool}, ...]\n\n" +
    "# Guarded dispatch\nclient.call(\"list_objects\", stix_type=\"indicator\")\nclient.call(\"upsert\", obj, allow_write=True)"
  );
  sl.addText("CLI:", {
    x: 0.47, y: 3.45, w: 0.5, h: 0.22,
    fontSize: 9, fontFace: "Calibri", bold: true, color: C.muted, margin: 0
  });
  codeBlock(sl, 0.47, 3.68, 4.31, 0.72,
    "gnat client capabilities --platform threatq\ngnat client call --platform splunk --method list_objects"
  );
  sl.addText("31 unit tests", {
    x: 0.47, y: 4.47, w: 4.31, h: 0.22,
    fontSize: 8, fontFace: "Calibri", color: C.muted, italic: true, margin: 0
  });

  // Right: Health Monitor
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 4.42,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 0.42, fill: { color: C.steel }, line: { width: 0 }
  });
  sl.addText("Connector Health + Drift Monitor", {
    x: 5.22, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });

  const healthItems = [
    "ConnectorHealthJob \u2014 FeedJob subclass, periodic health checks",
    "Calls health_check() on all configured connectors",
    "SchemaSnapshot: samples list_objects(limit=1) and stores field fingerprint",
    "DriftReport: alerts when changed fields exceed drift_threshold (default 20%)",
    "Slack webhook or email alerts on drift detection",
    "gnat health check  /  gnat health baseline  CLI subcommands",
  ];
  sl.addText(healthItems.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
    x: 5.22, y: 1.42, w: 4.31, h: 2.45,
    fontSize: 9, fontFace: "Calibri", color: C.offwhite
  });

  codeBlock(sl, 5.22, 3.95, 4.31, 0.72,
    "[health_monitor]\nenabled          = true\ninterval_minutes = 60\nalert_webhook    = https://hooks.slack.com/...\ndrift_threshold  = 0.2"
  );
  sl.addText("74 unit tests", {
    x: 5.22, y: 4.74, w: 4.31, h: 0.22,
    fontSize: 8, fontFace: "Calibri", color: C.muted, italic: true, margin: 0
  });
}

// ── Slide 17: Terminal UI + Web Dashboard ────────────────────────────────
{
  const sl = contentSlide(pres, "Terminal UI & Web Dashboard");

  // Left: TUI
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 4.42,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 0.42, fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("Terminal UI (Textual)", {
    x: 0.47, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText("Works over SSH \u2014 no browser, no display server required. Modern TUI built on Textual.", {
    x: 0.47, y: 1.4, w: 4.31, h: 0.46,
    fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
  });

  const screens = [
    ["F1  Query", "NLP search bar + scrollable STIX results table"],
    ["F2  Library", "Research Library browser \u00b7 promote (Ctrl+P) / reject (Ctrl+X)"],
    ["F3  Scheduler", "Live job status \u00b7 manual trigger with Ctrl+T"],
    ["F4  Reports", "PDF/HTML/DOCX browser \u00b7 open in browser (Ctrl+O)"],
    ["F5  Health", "Connector health monitor \u00b7 drift detection \u00b7 Ctrl+R refresh"],
    ["F6  Review", "AI Intel Review Queue \u00b7 Approve/Reject/Modify with confidence override"],
  ];
  screens.forEach(([name, desc], i) => {
    const y = 1.94 + i * 0.44;
    sl.addShape("rect", {
      x: 0.47, y, w: 4.28, h: 0.38,
      fill: { color: i < 4 ? C.steel : C.teal }, line: { width: 0 }
    });
    sl.addText(name, {
      x: 0.6, y: y + 0.06, w: 1.2, h: 0.22,
      fontSize: 9, fontFace: "Calibri", bold: true, color: C.white, margin: 0
    });
    sl.addText(desc, {
      x: 1.85, y: y + 0.06, w: 2.8, h: 0.28,
      fontSize: 8, fontFace: "Calibri", color: C.mint, margin: 0, valign: "middle"
    });
  });

  codeBlock(sl, 0.47, 4.66, 4.31, 0.38,
    "gnat tui           # launch dashboard\ngnat tui review    # start on review screen"
  );
  sl.addText("pip install \"gnat[tui]\"  \u00b7  F1\u2013F6 screens  \u00b7  38 unit tests", {
    x: 0.47, y: 5.1, w: 4.31, h: 0.22,
    fontSize: 8, fontFace: "Calibri", color: C.muted, italic: true, margin: 0
  });

  // Right: Web
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 4.42,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 0.42, fill: { color: C.steel }, line: { width: 0 }
  });
  sl.addText("Web Dashboard (FastAPI)", {
    x: 5.22, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText("Browser-based dashboard for server deployments. X-Api-Key auth, rate-limited 100 req/min.", {
    x: 5.22, y: 1.4, w: 4.31, h: 0.46,
    fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
  });

  const routes = [
    ["GET/POST /api/library", "Research Library search, promote, reject"],
    ["GET /api/reports", "List reports; serve HTML inline"],
    ["GET/POST /api/scheduler/jobs", "Job status + manual trigger"],
    ["GET /health", "Unauthenticated liveness check"],
    ["GET /", "Single-page dashboard (dark, no build step)"],
  ];
  routes.forEach(([route, desc], i) => {
    const y = 1.94 + i * 0.58;
    sl.addText(route, {
      x: 5.22, y: y, w: 4.28, h: 0.22,
      fontSize: 8.5, fontFace: "Consolas", bold: true, color: C.teal2, margin: 0
    });
    sl.addText(desc, {
      x: 5.22, y: y + 0.22, w: 4.28, h: 0.22,
      fontSize: 8.5, fontFace: "Calibri", color: C.muted, margin: 0
    });
  });

  codeBlock(sl, 5.22, 4.85, 4.31, 0.35,
    "gnat serve --port 8088 --api-key $(openssl rand -hex 16)"
  );
  sl.addText("pip install \"gnat[serve]\"  \u00b7  Bind 127.0.0.1 by default  \u00b7  54 unit tests", {
    x: 5.22, y: 5.26, w: 4.31, h: 0.18,
    fontSize: 8, fontFace: "Calibri", color: C.muted, italic: true, margin: 0
  });
}

// ── Slide 18: XSOAR Pack + Contribution ─────────────────────────────────
{
  const sl = contentSlide(pres, "XSOAR Content Pack Generator & Contribution Pipeline");

  // Left: XSOAR
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 4.42,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 0.42, fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("XSOAR Content Pack Generator", {
    x: 0.47, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 12, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText("Introspects any registered connector via capabilities() and generates a valid XSOAR 6 content pack zip.", {
    x: 0.47, y: 1.4, w: 4.31, h: 0.46,
    fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
  });

  const packItems = [
    "pack_metadata.json",
    "Integrations/<Name>/<Name>.yml  \u2014  XSOAR command defs",
    "Integrations/<Name>/<Name>.py  \u2014  Python bridge",
    "ReleaseNotes/<ver>.md",
    "Write methods flagged dangerous: true",
    "Auth type auto-detected from constructor",
  ];
  sl.addText(packItems.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
    x: 0.47, y: 1.94, w: 4.31, h: 2.15,
    fontSize: 9, fontFace: "Calibri", color: C.offwhite
  });

  codeBlock(sl, 0.47, 4.15, 4.31, 0.72,
    "gnat codegen xsoar --connector threatq --output ./packs/\ngnat codegen openapi --spec api.yaml --target myplatform"
  );
  sl.addText("40 unit tests", {
    x: 0.47, y: 4.94, w: 4.31, h: 0.22,
    fontSize: 8, fontFace: "Calibri", color: C.muted, italic: true, margin: 0
  });

  // Right: Contribution
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 4.42,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 0.42, fill: { color: C.steel }, line: { width: 0 }
  });
  sl.addText("Upstream Contribution Pipeline", {
    x: 5.22, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 12, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText("Packages a connector as a draft GitHub PR through a 7-step compliance gate.", {
    x: 5.22, y: 1.4, w: 4.31, h: 0.46,
    fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
  });

  const steps = [
    "1. Enabled guard (opt-in only)",
    "2. Connector exists in CLIENT_REGISTRY",
    "3. ComplianceMatrix: all 8 methods + test file",
    "4. Full test suite \u2014 aborts on failure",
    "5. Branch: contribute/{platform}-{timestamp}",
    "6. Commit + push to fork",
    "7. Draft PR via GitHub REST API",
  ];
  sl.addText(steps.map(t => ({ text: t, options: { bullet: false, breakLine: true } })), {
    x: 5.22, y: 1.94, w: 4.31, h: 2.2,
    fontSize: 9, fontFace: "Calibri", color: C.offwhite
  });

  codeBlock(sl, 5.22, 4.22, 4.31, 0.6,
    "gnat contribute --connector myplatform --message \"Add...\"\ngnat contribute --connector myplatform --dry-run"
  );
  sl.addText("draft_pr = true is hardcoded \u2014 always requires human review  \u00b7  47 unit tests", {
    x: 5.22, y: 4.89, w: 4.31, h: 0.26,
    fontSize: 8, fontFace: "Calibri", color: C.muted, italic: true, margin: 0
  });
}

// ── Slide 19: Docker & Containerization ─────────────────────────────────
{
  const sl = contentSlide(pres, "Docker & Containerization");

  // Left: services
  sl.addShape("rect", {
    x: 0.35, y: 0.88, w: 5.85, h: 4.38,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 1 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 0.35, y: 0.88, w: 5.85, h: 0.38,
    fill: { color: C.steel }, line: { width: 0 }
  });
  sl.addText("docker-compose.yml  \u2014  Production Stack", {
    x: 0.5, y: 0.92, w: 5.55, h: 0.3,
    fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });

  const services = [
    { name: "gnat-scheduler", port: "\u2014", desc: "FeedScheduler: ingest, export, AI research,\ncuration, and report jobs", col: C.teal },
    { name: "gnat-edl  :8080", port: "8080", desc: "EDL server: serves indicator files to\nfirewalls. Survives scheduler restart.", col: C.steel },
    { name: "gnat-monitor  :8090", port: "8090", desc: "Health endpoint: GET /status \u2192 JSON\nAzure Monitor / Grafana ping check.", col: C.navy2 },
    { name: "solr (profile: search)  :8983", port: "8983", desc: "Solr search index for GNAT sidecar.", col: C.teal },
    { name: "grafana (profile: monitoring)  :3000", port: "3000", desc: "Grafana dashboards for Solr + GNAT data.", col: C.steel },
  ];

  services.forEach(({ name, desc, col }, i) => {
    const y = 1.38 + i * 0.72;
    sl.addShape("rect", {
      x: 0.5, y, w: 5.55, h: 0.62,
      fill: { color: C.charcoal }, line: { color: col, width: 0.5 }
    });
    sl.addShape("rect", {
      x: 0.5, y, w: 0.08, h: 0.62, fill: { color: col }, line: { width: 0 }
    });
    sl.addText(name, {
      x: 0.7, y: y + 0.06, w: 5.15, h: 0.2,
      fontSize: 8.5, fontFace: "Consolas", bold: true, color: C.white, margin: 0
    });
    sl.addText(desc, {
      x: 0.7, y: y + 0.3, w: 5.15, h: 0.28,
      fontSize: 8, fontFace: "Calibri", color: C.muted, margin: 0
    });
  });

  sl.addText("Named volume: gnat-workspace  \u00b7  .env.example \u2192 .env  \u00b7  make docker-build / docker-up / docker-logs", {
    x: 0.5, y: 5.0, w: 5.55, h: 0.22,
    fontSize: 8, fontFace: "Calibri", italic: true, color: C.muted, margin: 0
  });

  // Right: DevContainer + Test Harness
  sl.addShape("rect", {
    x: 6.35, y: 0.88, w: 3.3, h: 2.05,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 6.35, y: 0.88, w: 3.3, h: 0.38, fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("VS Code DevContainer", {
    x: 6.47, y: 0.92, w: 3.06, h: 0.3,
    fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText(".devcontainer/devcontainer.json\nRust toolchain + Docker-in-Docker\nRuff extension\nGitHub Codespaces ready", {
    x: 6.47, y: 1.34, w: 3.06, h: 1.38,
    fontSize: 9, fontFace: "Calibri", color: C.offwhite, margin: 0
  });

  sl.addShape("rect", {
    x: 6.35, y: 3.08, w: 3.3, h: 2.18,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 6.35, y: 3.08, w: 3.3, h: 0.38, fill: { color: C.steel }, line: { width: 0 }
  });
  sl.addText("Integration Test Harness", {
    x: 6.47, y: 3.12, w: 3.06, h: 0.3,
    fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText("Elasticsearch 8.13.4 + Solr 9.6\nNon-conflicting ports (19200, 18983)\n@pytest.mark.docker marker\n20 TAXII + 14 Elastic + 14 Solr tests\nmake test-docker  (up \u2192 run \u2192 down)", {
    x: 6.47, y: 3.54, w: 3.06, h: 1.56,
    fontSize: 9, fontFace: "Calibri", color: C.offwhite, margin: 0
  });
}

// ── Slide 20: Multi-Tenant Architecture ─────────────────────────────────
{
  const sl = contentSlide(pres, "Multi-Tenant Workspace Isolation");

  sl.addText("Transparent namespace prefixing \u2014 no schema migration \u2014 works with SQLite and FlatFile stores", {
    x: 0.4, y: 0.9, w: 9.2, h: 0.35,
    fontSize: 12, fontFace: "Calibri", italic: true,
    color: C.teal2, align: "left", margin: 0
  });

  codeBlock(sl, 0.35, 1.35, 6.0, 2.55,
    "from gnat.context import WorkspaceManager\n\nmanager = WorkspaceManager.default()\n\n" +
    "acme = manager.for_tenant(\"acme\")\nws   = acme.create(\"apt28-investigation\")\n# stored as: \"acme::apt28-investigation\"\n\n" +
    "beta = manager.for_tenant(\"beta\")\nws2  = beta.create(\"apt28-investigation\")\n# stored as: \"beta::apt28-investigation\"  (no collision)"
  );

  // Right: tenant info
  sl.addShape("rect", {
    x: 6.55, y: 1.35, w: 3.1, h: 2.55,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 6.55, y: 1.35, w: 3.1, h: 0.38, fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("TenantRegistry", {
    x: 6.67, y: 1.39, w: 2.86, h: 0.28,
    fontSize: 12, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  const tenantFeatures = [
    "Existing workspaces \u2192 \"default\" tenant",
    "per-tenant config_path in INI",
    "list() scoped to tenant namespace",
    "WorkspaceManager.for_tenant(id)",
    "63 unit tests",
  ];
  sl.addText(tenantFeatures.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
    x: 6.67, y: 1.82, w: 2.86, h: 1.9,
    fontSize: 9, fontFace: "Calibri", color: C.offwhite
  });

  sl.addText("CLI:", {
    x: 0.4, y: 4.0, w: 0.5, h: 0.22,
    fontSize: 9.5, fontFace: "Calibri", bold: true, color: C.offwhite, margin: 0
  });
  codeBlock(sl, 0.35, 4.25, 9.3, 0.92,
    "gnat tenant list\ngnat tenant create acme --display-name \"Acme Corp\" --config /etc/gnat/acme.ini\ngnat tenant workspaces acme\ngnat tenant delete acme --yes"
  );
}

// ── Slide 21: Deployment ──────────────────────────────────────────────────
{
  const sl = contentSlide(pres, "Deployment: Single Azure VM, Three Services");

  sl.addShape("rect", {
    x: 0.35, y: 0.88, w: 6.1, h: 4.38,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 1 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 0.35, y: 0.88, w: 6.1, h: 0.38,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0 }
  });
  sl.addShape("rect", {
    x: 0.35, y: 0.88, w: 6.1, h: 0.38,
    fill: { color: C.steel }, line: { width: 0 }
  });
  sl.addText("Azure VM B2s  (2 vCPU \u00b7 4 GB \u00b7 ~$50/month)", {
    x: 0.5, y: 0.92, w: 5.8, h: 0.3,
    fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });

  const services = [
    { name: "gnat-scheduler.service", desc: "FeedScheduler: ingest, export, AI research,\ncuration, and report jobs", col: C.teal },
    { name: "gnat-edl.service  :8080", desc: "EDLServer: serves indicator files to firewalls.\nIndependent \u2014 survives scheduler restart", col: C.steel },
    { name: "gnat-health.service  :8090", desc: "Health endpoint: GET /status \u2192 JSON\nAzure Monitor / Grafana ping check", col: C.navy2 },
  ];

  services.forEach(({ name, desc, col }, i) => {
    const y = 1.4 + i * 1.1;
    sl.addShape("rect", {
      x: 0.5, y, w: 5.7, h: 0.9,
      fill: { color: C.charcoal }, line: { color: col, width: 1 }
    });
    sl.addShape("rect", {
      x: 0.5, y, w: 0.1, h: 0.9, fill: { color: col }, line: { width: 0 }
    });
    sl.addText(name, {
      x: 0.72, y: y + 0.08, w: 5.18, h: 0.24,
      fontSize: 10, fontFace: "Consolas", bold: true, color: C.white, margin: 0
    });
    sl.addText(desc, {
      x: 0.72, y: y + 0.38, w: 5.18, h: 0.42,
      fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
    });
  });

  sl.addText("Storage: ~/.gnat/config.ini  \u00b7  workspaces/  \u00b7  /var/reports/", {
    x: 0.5, y: 4.78, w: 5.7, h: 0.3,
    fontSize: 9, fontFace: "Calibri", italic: true, color: C.muted, margin: 0
  });

  sl.addShape("rect", {
    x: 6.6, y: 0.88, w: 3.05, h: 4.38,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 6.6, y: 0.88, w: 3.05, h: 0.38,
    fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("Scale-out path", {
    x: 6.75, y: 0.92, w: 2.75, h: 0.3,
    fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });

  const scalingItems = [
    ["100+ feeds", "AI jobs \u2192 Azure Container Instances"],
    ["EDL SLA < 5 min", "EDL server \u2192 dedicated B1s VM"],
    ["10+ analysts", "FlatFileStore \u2192 PostgreSQL (1 config change)"],
    ["Multi-tenant", "1 workspace namespace per tenant, shared codebase"],
  ];
  scalingItems.forEach(([trigger, action], i) => {
    const y = 1.42 + i * 0.88;
    sl.addText(trigger, {
      x: 6.75, y, w: 2.75, h: 0.24,
      fontSize: 9.5, fontFace: "Calibri", bold: true, color: C.offwhite, margin: 0
    });
    sl.addText(action, {
      x: 6.75, y: y + 0.26, w: 2.75, h: 0.4,
      fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
    });
    if (i < 3) {
      sl.addShape("line", {
        x: 6.75, y: y + 0.72, w: 2.75, h: 0,
        line: { color: C.steel, width: 0.5 }
      });
    }
  });
}

// ── Slide 22: Database Migrations + Plugin System ─────────────────────────
{
  const sl = contentSlide(pres, "Database Migrations & Plugin System (v1.4+)");

  // Left: Alembic Migrations
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 4.42,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 0.42, fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("Database Migrations (Alembic)", {
    x: 0.47, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText("Alembic 1.13 schema management. URL resolved: GNAT_DB_URL \u2192 [database] INI \u2192 default.", {
    x: 0.47, y: 1.4, w: 4.31, h: 0.42,
    fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
  });

  const migrations = [
    ["0001_init_all_tables", "investigations, reports, workspaces,\nworkspace_objects, enrichment_log, context_globals"],
    ["0002_add_lineage_events", "lineage_events table \u00b7 composite index on (object_id, timestamp)"],
    ["0003_add_metrics_events", "metrics_events table \u00b7 index on (metric_type, timestamp)"],
  ];
  migrations.forEach(([name, desc], i) => {
    const y = 1.92 + i * 0.72;
    sl.addShape("rect", { x: 0.47, y, w: 4.28, h: 0.62, fill: { color: C.steel }, line: { width: 0 } });
    sl.addText(name, { x: 0.59, y: y + 0.06, w: 4.04, h: 0.22, fontSize: 9, fontFace: "Consolas", bold: true, color: C.mint, margin: 0 });
    sl.addText(desc, { x: 0.59, y: y + 0.3, w: 4.04, h: 0.28, fontSize: 8.5, fontFace: "Calibri", color: C.offwhite, margin: 0 });
  });

  codeBlock(sl, 0.47, 4.1, 4.31, 0.55,
    "gnat-db upgrade head    # apply all migrations\ngnat-db current         # show current revision\ngnat-db history         # show migration history"
  );
  sl.addText("pip install \"gnat[migrations]\"  \u00b7  get_combined_metadata() for Alembic auto-detect", {
    x: 0.47, y: 4.72, w: 4.31, h: 0.22,
    fontSize: 8, fontFace: "Calibri", color: C.muted, italic: true, margin: 0
  });

  // Right: Plugin System
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 4.42,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 0.42, fill: { color: C.steel }, line: { width: 0 }
  });
  sl.addText("Plugin System (gnat.plugins)", {
    x: 5.22, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText("Extensible plugin architecture with entry_points discovery, filesystem scanning, and HookBus pub/sub.", {
    x: 5.22, y: 1.4, w: 4.31, h: 0.46,
    fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
  });

  const pluginItems = [
    ["GNATPlugin ABC", "name / version / capabilities / register(registry)"],
    ["PluginCapability", "CONNECTOR \u00b7 READER \u00b7 MAPPER \u00b7 AGENT \u00b7 REPORTER \u00b7 HOOK"],
    ["HookBus", "Thread-safe pub/sub \u00b7 14 built-in KNOWN_EVENTS\nasync handlers \u00b7 exceptions never propagate"],
    ["PluginRegistry", "load/unload/get/list \u00b7 entry_points discovery\nGNAT_PLUGIN_DIRS env var \u00b7 wraps existing registries"],
  ];
  pluginItems.forEach(([name, desc], i) => {
    const y = 1.96 + i * 0.62;
    sl.addShape("rect", { x: 5.22, y, w: 4.28, h: 0.54, fill: { color: C.charcoal }, line: { color: C.steel, width: 0.5 } });
    sl.addText(name, { x: 5.34, y: y + 0.04, w: 4.04, h: 0.22, fontSize: 9.5, fontFace: "Calibri", bold: true, color: C.teal2, margin: 0 });
    sl.addText(desc, { x: 5.34, y: y + 0.26, w: 4.04, h: 0.24, fontSize: 8.5, fontFace: "Calibri", color: C.muted, margin: 0 });
  });

  codeBlock(sl, 5.22, 4.4, 4.31, 0.45,
    "[plugins]\ndirs = /opt/gnat/plugins\n# or declare in pyproject.toml entry-points: gnat.plugins"
  );
}

// ── Slide 23: Policy Engine (RBAC) + STIX Object Validator ────────────────
{
  const sl = contentSlide(pres, "Policy Engine (RBAC) & STIX Object Validator (v1.4+)");

  // Left: Policy Engine
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 4.42,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 0.42, fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("Policy Engine \u2014 RBAC", {
    x: 0.47, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText("Role-based access control orthogonal to TLP labels. Static permission matrix. FastAPI-native Depends.", {
    x: 0.47, y: 1.4, w: 4.31, h: 0.46,
    fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
  });

  const roles = [
    ["VIEWER", "READ_OBJECTS, READ_REPORTS, QUERY_NLP"],
    ["ANALYST", "+ WRITE_OBJECTS, ENRICH, PROMOTE_INTEL"],
    ["OPERATOR", "+ MANAGE_SCHEDULES, WRITE_TAXII, EXPORT"],
    ["ADMIN", "+ MANAGE_KEYS, MANAGE_TENANTS (all perms)"],
  ];
  roles.forEach(([role, perms], i) => {
    const y = 2.0 + i * 0.56;
    sl.addShape("rect", { x: 0.47, y, w: 4.28, h: 0.48, fill: { color: C.charcoal }, line: { color: C.steel, width: 0.5 } });
    sl.addText(role, { x: 0.59, y: y + 0.04, w: 1.1, h: 0.22, fontSize: 9.5, fontFace: "Calibri", bold: true, color: C.teal2, margin: 0 });
    sl.addText(perms, { x: 1.72, y: y + 0.06, w: 2.94, h: 0.34, fontSize: 8, fontFace: "Calibri", color: C.offwhite, margin: 0 });
  });

  sl.addShape("rect", { x: 0.47, y: 4.28, w: 4.28, h: 0.42, fill: { color: C.navy2 }, line: { color: C.amber, width: 1 } });
  sl.addText("\u26a0  Audit Middleware: every API request emits api_request HookBus event + structured log. APIKey.role field.", {
    x: 0.59, y: 4.34, w: 4.04, h: 0.3,
    fontSize: 8, fontFace: "Calibri", color: C.amber, margin: 0
  });
  codeBlock(sl, 0.47, 4.78, 4.31, 0.4,
    "engine.require(Permission.WRITE_TAXII, key_store)  # FastAPI Depends"
  );

  // Right: STIX Object Validator
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 4.42,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 0.42, fill: { color: C.steel }, line: { width: 0 }
  });
  sl.addText("STIX Object Validator", {
    x: 5.22, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText("STIXObjectValidator validates required properties, vocabularies, confidence, refs, and ID format.", {
    x: 5.22, y: 1.4, w: 4.31, h: 0.46,
    fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
  });

  const typeGroups = [
    ["SDO  (19 types)", "indicator, malware, threat-actor, campaign, attack-pattern, course-of-action, identity, intrusion-set, tool, vulnerability, report, observed-data, note, opinion, relationship, sighting, infrastructure, malware-analysis, location"],
    ["SCO  (16 types)", "ipv4-addr, ipv6-addr, domain-name, url, file, process, network-traffic, email-message, windows-registry-key, user-account, software, autonomous-system, directory, email-addr, mac-addr, mutex"],
    ["SRO  (2 types)", "relationship, sighting — validates source/target ref format and relationship_type"],
    ["Meta (4 types)", "bundle, marking-definition, language-content, extension-definition"],
  ];
  typeGroups.forEach(([group, desc], i) => {
    const y = 1.96 + i * 0.78;
    sl.addShape("rect", { x: 5.22, y, w: 4.28, h: 0.7, fill: { color: C.charcoal }, line: { color: C.steel, width: 0.5 } });
    sl.addText(group, { x: 5.34, y: y + 0.04, w: 4.04, h: 0.22, fontSize: 9.5, fontFace: "Calibri", bold: true, color: C.teal2, margin: 0 });
    sl.addText(desc, { x: 5.34, y: y + 0.26, w: 4.04, h: 0.4, fontSize: 7.5, fontFace: "Calibri", color: C.muted, margin: 0, valign: "top" });
  });
  codeBlock(sl, 5.22, 5.1, 4.31, 0.18,
    "from gnat.stix.object_validator import STIXObjectValidator"
  );
}

// ── Slide 24: Agent Orchestration — Workflow DAG Engine ───────────────────
{
  const sl = contentSlide(pres, "Agent Orchestration \u2014 Workflow DAG Engine (v1.4+)");

  // Top banner
  sl.addShape("rect", { x: 0.35, y: 0.9, w: 9.3, h: 0.46, fill: { color: C.navy2 }, line: { color: C.teal, width: 1 } });
  sl.addText("gnat.agents.workflow  \u00b7  Sequential DAG executor with success/failure routing, cycle detection, and elapsed timing", {
    x: 0.55, y: 1.0, w: 9.0, h: 0.26,
    fontSize: 9.5, fontFace: "Calibri", color: C.mint, margin: 0
  });

  // Core classes
  const classes = [
    ["WorkflowStep", "name, fn, on_success, on_failure\nCallable step with optional routing"],
    ["WorkflowContext", "investigation, enriched_objects, gaps, draft,\nerrors, metadata — shared state across all steps"],
    ["Workflow", "steps dict + entry_point\nRun: .execute(ctx) \u2192 WorkflowResult"],
    ["WorkflowResult", "success, steps_run, errors, elapsed_ms\nFull execution trace"],
  ];
  classes.forEach(({ 0: name, 1: desc }, i) => {
    const x = 0.35 + i * 2.35;
    darkCard(sl, x, 1.47, 2.2, 1.5, C.teal, name, desc);
  });

  // Step factories
  sl.addText("Built-in Step Factories:", {
    x: 0.47, y: 3.1, w: 3.0, h: 0.26,
    fontSize: 10, fontFace: "Calibri", bold: true, color: C.offwhite, margin: 0
  });
  const factories = ["enrich_step", "correlate_step", "gap_detect_step", "draft_report_step", "transition_step", "fn_step"];
  factories.forEach((f, i) => {
    sl.addShape("rect", { x: 0.35 + i * 1.56, y: 3.4, w: 1.46, h: 0.3, fill: { color: C.steel }, line: { width: 0 } });
    sl.addText(f, { x: 0.47 + i * 1.56, y: 3.44, w: 1.22, h: 0.22, fontSize: 8.5, fontFace: "Consolas", color: C.mint, margin: 0 });
  });

  // Pre-built workflows
  sl.addText("Pre-built Workflows:", {
    x: 0.47, y: 3.85, w: 3.0, h: 0.26,
    fontSize: 10, fontFace: "Calibri", bold: true, color: C.offwhite, margin: 0
  });

  const prebuilt = [
    ["PhishingTriage", "enrich \u2192 correlate \u2192 gap_detect \u2192 draft_report \u2192 transition(IN_PROGRESS)"],
    ["IncidentResponse", "enrich \u2192 correlate \u2192 gap_detect \u2192 draft_report \u2192 transition(REVIEW)"],
  ];
  prebuilt.forEach(([name, flow], i) => {
    const y = 4.18 + i * 0.52;
    sl.addShape("rect", { x: 0.35, y, w: 9.3, h: 0.44, fill: { color: C.charcoal }, line: { color: C.teal, width: 0.5 } });
    sl.addText(name, { x: 0.47, y: y + 0.06, w: 1.6, h: 0.28, fontSize: 10, fontFace: "Calibri", bold: true, color: C.teal2, margin: 0 });
    sl.addText(flow, { x: 2.12, y: y + 0.1, w: 7.4, h: 0.24, fontSize: 9, fontFace: "Calibri", color: C.offwhite, margin: 0 });
  });

  codeBlock(sl, 0.35, 5.28, 9.3, 0.3,
    "from gnat.agents.workflows.phishing_triage import build_phishing_triage_workflow\nresult = build_phishing_triage_workflow(enricher, correlator, detector, drafter, svc).execute(ctx)"
  );
}

// ── Slide 25: Data Lineage + Analyst Metrics ──────────────────────────────
{
  const sl = contentSlide(pres, "Data Lineage & Analyst Metrics (v1.4+)");

  // Left: Data Lineage
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 4.42,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 0.35, y: 0.9, w: 4.55, h: 0.42, fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("Data Lineage (gnat.lineage)", {
    x: 0.47, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText("Append-only event log. Zero new runtime dependencies. Optional deployment.", {
    x: 0.47, y: 1.4, w: 4.31, h: 0.38,
    fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
  });

  const lineageItems = [
    ["LineageEventType", "INGESTED \u00b7 ENRICHED \u00b7 NORMALIZED\nLINKED \u00b7 EXPORTED \u00b7 REPORTED \u00b7 DELETED"],
    ["LineageEvent", "UUID4 id \u00b7 timestamp \u00b7 object_id\nactor \u00b7 source \u00b7 metadata dict (immutable)"],
    ["LineageStore", "SQLAlchemy-backed lineage_events table\nappend / query / query_by_type / count()"],
    ["LineageTracker", "Convenience wrapper: record_ingested()\nrecord_enriched() \u2026 store=None \u2192 no-op"],
  ];
  lineageItems.forEach(([name, desc], i) => {
    const y = 1.9 + i * 0.68;
    sl.addShape("rect", { x: 0.47, y, w: 4.28, h: 0.6, fill: { color: C.charcoal }, line: { color: C.steel, width: 0.5 } });
    sl.addText(name, { x: 0.59, y: y + 0.04, w: 4.04, h: 0.22, fontSize: 9.5, fontFace: "Calibri", bold: true, color: C.teal2, margin: 0 });
    sl.addText(desc, { x: 0.59, y: y + 0.26, w: 4.04, h: 0.3, fontSize: 8.5, fontFace: "Calibri", color: C.muted, margin: 0 });
  });
  codeBlock(sl, 0.47, 4.64, 4.31, 0.38,
    "tracker.record_ingested(\"indicator--abc\", actor=\"feed_scheduler\")\nstore.query(\"indicator--abc\")  # full audit trail"
  );
  sl.addText("ADR-0038: append-only log \u00b7 no runtime deps \u00b7 optional deployment", {
    x: 0.47, y: 5.08, w: 4.31, h: 0.18,
    fontSize: 7.5, fontFace: "Calibri", color: C.muted, italic: true, margin: 0
  });

  // Right: Analyst Metrics
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 4.42,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", {
    x: 5.1, y: 0.9, w: 4.55, h: 0.42, fill: { color: C.steel }, line: { width: 0 }
  });
  sl.addText("Analyst Metrics (gnat.metrics)", {
    x: 5.22, y: 0.94, w: 4.31, h: 0.3,
    fontSize: 13, fontFace: "Calibri", bold: true, color: C.white, margin: 0
  });
  sl.addText("Thread-safe ring-buffer collector with structured aggregation by type and time window.", {
    x: 5.22, y: 1.4, w: 4.31, h: 0.38,
    fontSize: 9, fontFace: "Calibri", color: C.muted, margin: 0
  });

  const metricTypes = [
    "INVESTIGATION_CREATED \u00b7 INVESTIGATION_CLOSED",
    "ENRICHMENT_ATTEMPTED \u00b7 ENRICHMENT_SUCCESS",
    "REPORT_PUBLISHED \u00b7 GAP_DETECTED",
    "FALSE_POSITIVE_FLAGGED \u00b7 ANALYST_OVERRIDE \u00b7 INTEL_PROMOTED",
  ];
  sl.addText(metricTypes.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
    x: 5.22, y: 1.88, w: 4.31, h: 1.08,
    fontSize: 9, fontFace: "Calibri", color: C.offwhite
  });

  const aggs = [
    ["investigation_summary(days)", "Status breakdown + close rate for period"],
    ["enrichment_effectiveness(platform, days)", "Hit rate + avg per-platform confidence"],
    ["gap_frequency(days)", "Gap detection rate over the window"],
    ["false_positive_rate(days)", "FP:total ratio for the window"],
  ];
  aggs.forEach(([method, desc], i) => {
    const y = 3.06 + i * 0.56;
    sl.addShape("rect", { x: 5.22, y, w: 4.28, h: 0.48, fill: { color: C.charcoal }, line: { color: C.steel, width: 0.5 } });
    sl.addText(method, { x: 5.34, y: y + 0.04, w: 4.04, h: 0.2, fontSize: 8.5, fontFace: "Consolas", color: C.teal2, margin: 0 });
    sl.addText(desc, { x: 5.34, y: y + 0.26, w: 4.04, h: 0.18, fontSize: 8, fontFace: "Calibri", color: C.muted, margin: 0 });
  });
  codeBlock(sl, 5.22, 5.32, 4.31, 0.24,
    "collector.record(MetricType.REPORT_PUBLISHED, 1)  # anywhere in pipeline"
  );
}

// ── Slide 26: AI Intel Review Queue ──────────────────────────────────────
{
  const sl = contentSlide(pres, "AI Intel Review Queue (v1.4+)");

  // Top description
  sl.addShape("rect", { x: 0.35, y: 0.9, w: 9.3, h: 0.44, fill: { color: C.navy2 }, line: { color: C.teal, width: 1 } });
  sl.addText("Human-in-the-loop gate between AI-extracted intel and the analyst-verified workspace. Analysts approve, modify, or reject before promotion.", {
    x: 0.55, y: 0.99, w: 9.0, h: 0.26,
    fontSize: 9.5, fontFace: "Calibri", color: C.mint, margin: 0
  });

  // Lifecycle flow
  const flow = ["PENDING", "\u2192", "APPROVED", "\u2192", "PROMOTED", "", "REJECTED", "", "MODIFIED"];
  const flowColors = [C.amber, C.muted, C.green, C.muted, C.teal2, "", C.red, "", C.steel];
  flow.forEach((step, i) => {
    const x = 0.42 + i * 1.04;
    if (step === "\u2192" || step === "") {
      if (step === "\u2192") sl.addText(step, { x, y: 1.46, w: 0.6, h: 0.28, fontSize: 14, fontFace: "Calibri", color: C.muted, align: "center", margin: 0 });
      return;
    }
    sl.addShape("rect", { x, y: 1.42, w: 0.92, h: 0.3, fill: { color: flowColors[i] }, line: { width: 0 } });
    sl.addText(step, { x: x + 0.04, y: 1.44, w: 0.84, h: 0.26, fontSize: 9, fontFace: "Calibri", bold: true, color: C.white, align: "center", margin: 0 });
  });

  // Left: ReviewService methods
  sl.addShape("rect", {
    x: 0.35, y: 1.84, w: 4.55, h: 3.4,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", { x: 0.35, y: 1.84, w: 4.55, h: 0.36, fill: { color: C.teal }, line: { width: 0 } });
  sl.addText("ReviewService Methods", { x: 0.47, y: 1.88, w: 4.31, h: 0.28, fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0 });

  const methods = [
    ["submit(stix_id, stix_type, stix_data, ...)", "Queue AI-extracted intel for review (PENDING)"],
    ["approve(id, reviewer, notes, confidence)", "Set APPROVED + optional confidence override (0-100)"],
    ["reject(id, reviewer, reason)", "Set REJECTED with reason"],
    ["modify(id, reviewer, modified_properties)", "Capture analyst property overrides (MODIFIED)"],
    ["promote(id, reviewer, workspace_manager)", "Merge overrides + x_source_type=analyst_verified"],
    ["bulk_approve(ids) / bulk_reject(ids)", "Batch operations with full validation"],
    ["stats()", "Per-status breakdown + total count"],
  ];
  methods.forEach(([sig, desc], i) => {
    const y = 2.28 + i * 0.4;
    sl.addText(sig, { x: 0.47, y, w: 4.28, h: 0.2, fontSize: 8, fontFace: "Consolas", color: C.teal2, margin: 0 });
    sl.addText(desc, { x: 0.47, y: y + 0.2, w: 4.28, h: 0.16, fontSize: 7.5, fontFace: "Calibri", color: C.muted, margin: 0 });
  });

  // Right: REST + CLI + TUI
  sl.addShape("rect", {
    x: 5.1, y: 1.84, w: 4.55, h: 3.4,
    fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
  });
  sl.addShape("rect", { x: 5.1, y: 1.84, w: 4.55, h: 0.36, fill: { color: C.steel }, line: { width: 0 } });
  sl.addText("REST API  \u00b7  CLI  \u00b7  TUI", { x: 5.22, y: 1.88, w: 4.31, h: 0.28, fontSize: 11, fontFace: "Calibri", bold: true, color: C.white, margin: 0 });

  const restEndpoints = [
    "GET  /api/review  \u2014  list (status + type + submitter filters)",
    "POST /api/review  \u2014  submit new item",
    "GET  /api/review/stats  \u2014  per-status counts",
    "GET  /api/review/{id}  \u2014  item detail",
    "POST /api/review/{id}/approve  \u2014  approve",
    "POST /api/review/{id}/reject   \u2014  reject",
    "POST /api/review/{id}/modify   \u2014  set overrides",
    "POST /api/review/{id}/promote  \u2014  promote to workspace",
  ];
  sl.addText(restEndpoints.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
    x: 5.22, y: 2.28, w: 4.31, h: 2.0,
    fontSize: 8, fontFace: "Consolas", color: C.offwhite
  });

  codeBlock(sl, 5.22, 4.34, 4.31, 0.56,
    "gnat review list --status pending --type indicator\ngnat review approve <id> --by alice --confidence 85\ngnat review stats"
  );

  sl.addShape("rect", { x: 5.22, y: 4.96, w: 4.28, h: 0.22, fill: { color: C.charcoal }, line: { width: 0 } });
  sl.addText("TUI: F6  ReviewScreen  \u00b7  Approve/Reject/Modify with confidence input  \u00b7  Ctrl+A bulk approve", {
    x: 5.34, y: 4.98, w: 4.04, h: 0.18,
    fontSize: 7.5, fontFace: "Calibri", color: C.teal2, margin: 0
  });
}

// ── Slide 27: Key Advantages ─────────────────────────────────────────────
{
  const sl = contentSlide(pres, "The Abstraction Advantage");

  const advantages = [
    { title: "Portability", body: "Switch from ThreatQ to a new TIP? Change one config line. The pipeline, scheduler, reports, and export jobs all work unchanged. Your automation is not locked to any platform.", col: C.teal },
    { title: "Maintenance Simplicity", body: "API changes affect one connector file, not every script. Tests cover all connectors uniformly. One library version number covers the entire integration stack.", col: C.steel },
    { title: "Interface Consistency", body: "Every platform exposes get_object(), list_objects(), upsert_object(), to_stix(), from_stix(). Analysts learn one mental model once and it works across 99 platforms.", col: C.teal },
    { title: "Operational Coherence", body: "One scheduler, one health endpoint, one log stream. No more asking which of 15 scripts ran overnight and whether it worked. FeedScheduler.summary() answers all of that.", col: C.steel },
    { title: "Incremental Adoption", body: "Each layer is independently useful. Start with connectors only. Add ingest. Add export. Add AI. Add reports. The stack is additive \u2014 you never have to replace working parts.", col: C.teal },
    { title: "Test Coverage", body: "2,000+ unit tests across 30+ test files. Every connector, every pipeline stage, every renderer, every scheduler, every new v1.4/1.5 module. Confidence in changes without regression fear.", col: C.steel },
  ];

  advantages.forEach(({ title, body, col }, i) => {
    const c = i % 3;
    const r = Math.floor(i / 3);
    const x = 0.35 + c * 3.1;
    const y = 0.9 + r * 2.2;
    sl.addShape("rect", {
      x, y, w: 2.9, h: 2.0,
      fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
    });
    sl.addShape("rect", {
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

// ── Slide 28: Code Safety, CI & Security ────────────────────────────────
{
  const sl = contentSlide(pres, "Code Safety, CI & Developer Security");

  const panels = [
    {
      title: "GitHub Actions CI",
      col: C.steel,
      body: "pylint workflow on every push\nPython 3.9 / 3.10 / 3.11 / 3.12 matrix\nFails build on any lint error\nBadge on README signals status",
    },
    {
      title: "GitHub Copilot",
      col: C.teal,
      body: "AI-assisted code review on pull requests\nInline suggestions during authoring\nPattern detection across codebase\nAll AI code still gates through CI",
    },
    {
      title: "Ruff + mypy",
      col: C.teal2,
      body: "Ruff: E, F, W, I, UP, B, C4, SIM rules\nLine length 100, Python 3.9 target\nmypy: warn_return_any, strict configs\nmake check = lint + typecheck gate",
    },
    {
      title: "pytest + Coverage",
      col: C.green,
      body: "2,000+ unit tests across 30+ files\n70% minimum coverage enforced\nfail_under = 70 in pyproject.toml\nDocker integration harness (ES + Solr)",
    },
    {
      title: "Dependabot",
      col: C.steel,
      body: "Automated dependency update PRs\nOne PR per dependency for audit trail\nPinned versions reviewed before merge\nCovers Python + GitHub Actions deps",
    },
    {
      title: "Snyk + Secret Scanning",
      col: C.amber,
      body: "Snyk: dependency vulnerability scanning\nCode security analysis in pipeline\nGitHub secret scanning: blocks known\npatterns before they reach history",
    },
  ];

  panels.forEach(({ title, col, body }, i) => {
    const c = i % 3;
    const r = Math.floor(i / 3);
    const x = 0.32 + c * 3.15;
    const y = 0.9 + r * 2.22;
    sl.addShape("rect", {
      x, y, w: 2.98, h: 2.02,
      fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
    });
    sl.addShape("rect", {
      x, y, w: 2.98, h: 0.44, fill: { color: col }, line: { width: 0 }
    });
    sl.addText(title, {
      x: x + 0.12, y: y + 0.08, w: 2.74, h: 0.28,
      fontSize: 12, fontFace: "Calibri", bold: true, color: C.white, margin: 0
    });
    sl.addText(body, {
      x: x + 0.12, y: y + 0.54, w: 2.74, h: 1.36,
      fontSize: 9.5, fontFace: "Calibri", color: C.muted, margin: 0, valign: "top"
    });
  });

  // Footer: additional security practices
  sl.addShape("rect", {
    x: 0.32, y: 5.3, w: 9.38, h: 0.2,
    fill: { color: C.navy2 }, line: { color: C.teal, width: 0.5 }
  });
  sl.addText(
    "AI confidence ceiling \u2014 draft PRs only \u2014 localhost binding by default \u2014 call() write guard \u2014 no credentials in source \u2014 HMAC constant-time key validation",
    {
      x: 0.44, y: 5.32, w: 9.14, h: 0.18,
      fontSize: 7.5, fontFace: "Calibri", color: C.muted, align: "center", margin: 0
    }
  );
}

// ── Slide 29: By the Numbers ─────────────────────────────────────────────
{
  const sl = contentSlide(pres, "By the Numbers");

  const stats = [
    ["99", "Platform\nConnectors", C.teal],
    ["2,000+", "Unit\nTests", C.steel],
    ["200+", "Source\nFiles", C.teal],
    ["~$50", "Monthly Azure\nVM Cost", C.steel],
    ["60", "AI Confidence\nCeiling (default)", C.amber],
    ["5", "New v1.5\nModules", C.teal],
  ];

  stats.forEach(([value, label, col], i) => {
    const c = i % 3;
    const r = Math.floor(i / 3);
    const x = 0.55 + c * 3.0;
    const y = 1.0 + r * 2.1;
    sl.addShape("rect", {
      x, y, w: 2.7, h: 1.8,
      fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }, shadow: makeShadow()
    });
    sl.addShape("rect", {
      x, y, w: 2.7, h: 0.1, fill: { color: col }, line: { width: 0 }
    });
    sl.addText(value, {
      x: x + 0.12, y: y + 0.2, w: 2.46, h: 0.88,
      fontSize: 42, fontFace: "Calibri", bold: true,
      color: col, align: "center", margin: 0
    });
    sl.addText(label, {
      x: x + 0.12, y: y + 1.1, w: 2.46, h: 0.54,
      fontSize: 10, fontFace: "Calibri", color: C.muted, align: "center", margin: 0
    });
  });
}

// ── Slide 30: Implementation Path ────────────────────────────────────────
{
  const sl = contentSlide(pres, "Implementation Sequence");

  const phases = [
    { phase: "Phase 1", label: "Foundation", days: "Days 1-2", items: ["Install + configure config.ini", "Test connectivity: gnat ping", "First ingest dry-run"], col: C.teal },
    { phase: "Phase 2", label: "Ingest", days: "Days 3-5", items: ["All connector configs", "Primary ingest jobs (TQ, RF, CS)", "FeedScheduler running"], col: C.steel },
    { phase: "Phase 3", label: "Export", days: "Days 6-8", items: ["Netskope CE ExportJob (15 min)", "EDL files hourly", "Verify TQ \u2192 CE \u2192 firewall EDLs"], col: C.teal },
    { phase: "Phase 4", label: "Research", days: "Days 9-10", items: ["Configure [claude] in config.ini", "First ResearchAgent query", "CurationJob to scheduler"], col: C.steel },
    { phase: "Phase 5", label: "Reports", days: "Days 11-14", items: ["Daily report \u2014 review PDF/HTML", "Configure email delivery", "ReportJob at 06:00 daily"], col: C.teal },
    { phase: "Phase 6", label: "Rollout", days: "Ongoing", items: ["Analyst config templates", "Share EXAMPLES.md", "Library review process"], col: C.navy2 },
  ];

  phases.forEach(({ phase, label, days, items, col }, i) => {
    const x = 0.35 + i * 1.6;
    sl.addShape("rect", {
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
    sl.addShape("rect", {
      x, y: 1.55, w: 1.45, h: 3.5,
      fill: { color: C.navy2 }, line: { color: C.steel, width: 0.5 }
    });
    sl.addText(label, {
      x: x + 0.08, y: 1.65, w: 1.29, h: 0.28,
      fontSize: 11, fontFace: "Calibri", bold: true, color: col, align: "center", margin: 0
    });
    sl.addText(items.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
      x: x + 0.08, y: 2.02, w: 1.29, h: 2.9,
      fontSize: 8.5, fontFace: "Calibri", color: C.offwhite
    });
  });
}

// ── Slide 31: All Roadmap Complete ───────────────────────────────────────
{
  const sl = contentSlide(pres, "All Roadmap Items \u2014 Complete");

  sl.addText("\u2713  Every pending item and roadmap addition has shipped through v1.5.0", {
    x: 0.4, y: 0.9, w: 9.2, h: 0.35,
    fontSize: 13, fontFace: "Calibri", italic: true,
    color: C.green, align: "left", margin: 0
  });

  const col1 = [
    ["\u2705", "x_target_sectors normalized across all connectors"],
    ["\u2705", "DOCX renderer \u2014 pure Python (python-docx)"],
    ["\u2705", "WorkspaceManager.default() method"],
    ["\u2705", "Copilot DirectLine token refresh"],
    ["\u2705", "CLI: gnat report run / gnat report list"],
    ["\u2705", "SectorFilter in gnat.export.filters"],
    ["\u2705", "Email body: rendered HTML content"],
    ["\u2705", "NLP Query Interface (builtin + Claude)"],
    ["\u2705", "Client Capability Reflection + safe dispatch"],
    ["\u2705", "Connectors Batch 2 \u2014 11 new platforms (v1.0)"],
    ["\u2705", "XSOAR Content Pack Generator"],
    ["\u2705", "Docker containerization (3-service stack)"],
    ["\u2705", "Database Migrations (Alembic + gnat-db CLI)"],
    ["\u2705", "Plugin System (PluginRegistry + HookBus + 14 events)"],
    ["\u2705", "WorkflowEngine DAG (PhishingTriage \u00b7 IncidentResponse)"],
  ];

  const col2 = [
    ["\u2705", "Terminal UI (Textual, SSH-safe, F1\u2013F6 screens)"],
    ["\u2705", "Web Dashboard (FastAPI, X-Api-Key, rate-limited)"],
    ["\u2705", "Connector Health + Drift Monitoring"],
    ["\u2705", "Upstream Contribution Pipeline (7-step gate)"],
    ["\u2705", "TAXII 2.1 Server (full read + write protocol)"],
    ["\u2705", "STIX 2.1 Pattern Validator (two-tier)"],
    ["\u2705", "Multi-Tenant Workspace Isolation"],
    ["\u2705", "Docker Integration Test Harness"],
    ["\u2705", "13 new connectors v1.1 \u2014 25 in v1.2 \u2014 9 in v1.3"],
    ["\u2705", "99 connectors total in CLIENT_REGISTRY"],
    ["\u2705", "LLMClient: Claude \u00b7 OpenAI \u00b7 Grok \u00b7 Gemini (v1.3)"],
    ["\u2705", "Policy Engine (RBAC \u00b7 Permission matrix \u00b7 audit hook)"],
    ["\u2705", "Data Lineage tracking (append-only event log)"],
    ["\u2705", "Analyst Metrics (ring-buffer \u00b7 9 metric types)"],
    ["\u2705", "AI Intel Review Queue (submit \u2192 approve \u2192 promote)"],
  ];

  const renderCol = (items, x) => {
    items.forEach(([check, text], i) => {
      const y = 1.35 + i * 0.27;
      sl.addShape("rect", {
        x, y, w: 4.45, h: 0.24,
        fill: { color: i % 2 === 0 ? C.navy2 : C.charcoal }, line: { width: 0 }
      });
      sl.addText(check, {
        x: x + 0.08, y: y + 0.02, w: 0.28, h: 0.2,
        fontSize: 9.5, fontFace: "Calibri", color: C.green, margin: 0
      });
      sl.addText(text, {
        x: x + 0.38, y: y + 0.03, w: 4.0, h: 0.18,
        fontSize: 8, fontFace: "Calibri", color: C.offwhite, margin: 0
      });
    });
  };

  renderCol(col1, 0.35);
  renderCol(col2, 5.17);

  sl.addShape("rect", {
    x: 0.35, y: 5.29, w: 9.3, h: 0.22,
    fill: { color: C.teal }, line: { width: 0 }
  });
  sl.addText("Reference: EXAMPLES.md  \u00b7  IMPLEMENTATION_PLAN.md  \u00b7  ARCHITECTURE_DECISIONS.md  \u00b7  CHANGELOG.md", {
    x: 0.47, y: 5.31, w: 9.16, h: 0.18,
    fontSize: 8, fontFace: "Calibri", bold: true, color: C.white, align: "center", margin: 0
  });
}

// ── Slide 32: Close ──────────────────────────────────────────────────────
{
  const sl = pres.addSlide();
  sl.background = { color: C.navy };

  sl.addShape("rect", {
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
    "99 connectors \u00b7 STIX 2.1 ORM \u00b7 Ingest + Export pipelines",
    "AI agents (LLMClient: Claude \u00b7 OpenAI \u00b7 Grok \u00b7 Gemini) \u00b7 WorkflowEngine DAG \u00b7 NLP queries \u00b7 Research library",
    "TAXII 2.1 read+write \u00b7 STIX validator \u00b7 Policy RBAC \u00b7 Plugins \u00b7 Lineage \u00b7 Metrics \u00b7 Review Queue",
    "2,000+ tests \u00b7 ~$50/month Azure \u00b7 Incremental adoption \u00b7 Contribution pipeline",
  ];
  sl.addText(summary.map(t => ({ text: t, options: { bullet: true, breakLine: true } })), {
    x: 0.5, y: 2.72, w: 9, h: 1.45,
    fontSize: 13, fontFace: "Calibri", color: C.offwhite
  });

  sl.addShape("line", {
    x: 0.5, y: 4.25, w: 8.5, h: 0,
    line: { color: C.teal, width: 1.5 }
  });
  sl.addText("Version 1.5.0  |  Python 3.9+  |  Apache 2.0  |  EXAMPLES.md \u00b7 IMPLEMENTATION_PLAN.md \u00b7 README.md", {
    x: 0.5, y: 4.4, w: 9, h: 0.3,
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
