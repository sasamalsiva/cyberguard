/*
 * ============================================================
 * CYBERGUARD — PDF REPORT EXPORT
 * ============================================================
 *
 * Renders an analysis result as a standalone, branded PDF that a
 * reviewer can forward to someone who never saw the dashboard.
 *
 * jsPDF is vendored under vendor/jspdf.umd.min.js rather than
 * loaded from a CDN so that exporting still works when the venue
 * has no internet. The report is built with vector primitives
 * only, so no image embedding is required.
 * ============================================================
 */


const CG_PDF = (() => {

    const PAGE = {
        width: 210,
        height: 297,
        margin: 16
    };

    const COLORS = {
        ink: [15, 23, 42],
        body: [51, 65, 85],
        muted: [100, 116, 139],
        line: [226, 232, 240],
        high: [220, 38, 38],
        highBg: [254, 226, 226],
        medium: [180, 83, 9],
        mediumBg: [254, 243, 199],
        low: [22, 128, 61],
        lowBg: [220, 252, 231],
        accent: [37, 99, 235]
    };

    const riskPalette = level => {
        const key = String(level || "").toUpperCase();

        if (key === "HIGH") {
            return { text: COLORS.high, bg: COLORS.highBg };
        }

        if (key === "MEDIUM") {
            return { text: COLORS.medium, bg: COLORS.mediumBg };
        }

        return { text: COLORS.low, bg: COLORS.lowBg };
    };

    const stamp = () => {
        const now = new Date();

        const two = value => String(value).padStart(2, "0");

        return `${now.getFullYear()}-${two(now.getMonth() + 1)}-${two(now.getDate())} ` +
               `${two(now.getHours())}:${two(now.getMinutes())}`;
    };

    const safeFilePart = value =>
        String(value || "")
            .trim()
            .replace(/[^a-z0-9]+/gi, "-")
            .replace(/^-+|-+$/g, "")
            .toLowerCase() || "report";


    /* --------------------------------------------------------
     * LAYOUT PRIMITIVES
     *
     * jsPDF has no flow layout, so text is measured up front and
     * the cursor advances by the real wrapped height. This keeps
     * long evidence lists from overlapping the footer.
     * ------------------------------------------------------ */

    function createLayout(doc) {

        let y = PAGE.margin;

        const usableWidth = () => PAGE.width - PAGE.margin * 2;

        const remaining = () => PAGE.height - 22 - y;

        function newPage() {
            doc.addPage();
            y = PAGE.margin;
            drawHeaderBand();
        }

        function ensure(space) {
            if (y + space > PAGE.height - 22) {
                newPage();
                return true;
            }

            return false;
        }

        function drawHeaderBand() {
            doc.setFillColor(37, 99, 235);
            doc.rect(0, 0, PAGE.width, 3, "F");

            doc.setFillColor(15, 23, 42);
            doc.rect(0, 3, PAGE.width, 15, "F");
        }

        function text(value, options = {}) {
            const {
                size = 9,
                style = "normal",
                color = COLORS.body,
                gap = 3,
                indent = 0,
                maxLines = 40
            } = options;

            doc.setFont("helvetica", style);
            doc.setFontSize(size);
            doc.setTextColor(...color);

            const lines = doc.splitTextToSize(
                String(value ?? ""),
                Math.max(10, usableWidth() - indent)
            );

            const shown = lines.slice(0, maxLines);

            if (lines.length > maxLines) {
                shown[maxLines - 1] = `${shown[maxLines - 1]}...`;
            }

            shown.forEach(line => {
                ensure(size * 1.45);
                doc.text(line, PAGE.margin + indent, y);
                y += size * 1.45;
            });

            y += gap;
        }

        function wrap(value, options = {}) {
            const { size = 9, color = COLORS.body, indent = 0, gap = 2, style = "normal" } = options;

            doc.setFont("helvetica", style);
            doc.setFontSize(size);
            doc.setTextColor(...color);

            const lines = doc.splitTextToSize(
                String(value ?? ""),
                Math.max(10, usableWidth() - indent - 10)
            );

            lines.forEach(line => {
                ensure(size * 1.4);
                doc.text(line, PAGE.margin + indent + 10, y);
                y += size * 1.4;
            });

            y += gap;
        }

        function rule(gap = 5) {
            ensure(4);
            doc.setDrawColor(...COLORS.line);
            doc.setLineWidth(0.4);
            doc.line(PAGE.margin, y, PAGE.width - PAGE.margin, y);
            y += gap;
        }

        function sectionTitle(title) {
            ensure(20);

            doc.setFont("helvetica", "bold");
            doc.setFontSize(11);
            doc.setTextColor(...COLORS.ink);

            doc.text(
                String(title).toUpperCase(),
                PAGE.margin,
                y
            );

            y += 5;

            doc.setDrawColor(...COLORS.accent);
            doc.setLineWidth(1);
            doc.line(PAGE.margin, y - 2, PAGE.margin + 22, y - 2);

            y += 4;
        }

        function statRow(stats) {
            ensure(22);

            const count = stats.length;

            const gap = 4;

            const boxWidth = (usableWidth() - gap * (count - 1)) / count;

            const top = y;

            stats.forEach((stat, index) => {
                const x = PAGE.margin + index * (boxWidth + gap);

                const palette = stat.risk
                    ? riskPalette(stat.risk)
                    : { text: COLORS.ink, bg: [241, 245, 249] };

                doc.setFillColor(...palette.bg);
                doc.setDrawColor(...COLORS.line);
                doc.setLineWidth(0.3);

                doc.roundedRect(
                    x,
                    top,
                    boxWidth,
                    19,
                    1.6,
                    1.6,
                    "FD"
                );

                doc.setFont("helvetica", "bold");
                doc.setFontSize(7);
                doc.setTextColor(...COLORS.muted);

                doc.text(
                    String(stat.label).toUpperCase(),
                    x + 4,
                    top + 7
                );

                doc.setFontSize(14);
                doc.setTextColor(...palette.text);

                doc.text(
                    String(stat.value),
                    x + 4,
                    top + 15.5
                );
            });

            y = top + 19 + 6;
        }

        function badge(label, palette) {
            doc.setFont("helvetica", "bold");
            doc.setFontSize(8);

            const width = doc.getTextWidth(String(label)) + 8;

            doc.setFillColor(...palette.bg);
            doc.setDrawColor(...palette.text);
            doc.setLineWidth(0.3);

            doc.roundedRect(
                PAGE.margin,
                y - 4.6,
                width,
                7.4,
                1.4,
                1.4,
                "FD"
            );

            doc.setTextColor(...palette.text);
            doc.text(String(label), PAGE.margin + 4, y);

            y += 9.5;

            return width;
        }

        function drawFooter(pageNumber, totalPages) {
            doc.setDrawColor(...COLORS.line);
            doc.setLineWidth(0.4);

            doc.line(
                PAGE.margin,
                PAGE.height - 16,
                PAGE.width - PAGE.margin,
                PAGE.height - 16
            );

            doc.setFont("helvetica", "normal");
            doc.setFontSize(7);
            doc.setTextColor(...COLORS.muted);

            doc.text(
                "CyberGuard — Organisation Security Platform",
                PAGE.margin,
                PAGE.height - 10
            );

            doc.text(
                `Page ${pageNumber} of ${totalPages}`,
                PAGE.width - PAGE.margin,
                PAGE.height - 10,
                { align: "right" }
            );
        }

        return {
            get y() { return y; },
            set y(value) { y = value; },
            text,
            wrap,
            rule,
            sectionTitle,
            statRow,
            badge,
            ensure,
            newPage,
            drawHeaderBand,
            drawFooter,
            remaining
        };
    }


    /* --------------------------------------------------------
     * REPORT HEADER
     * ------------------------------------------------------ */

    function drawMasthead(doc, layout, config) {
        layout.drawHeaderBand();

        doc.setFont("helvetica", "bold");
        doc.setFontSize(17);
        doc.setTextColor(255, 255, 255);

        doc.text("CYBERGUARD", PAGE.margin, 14);

        doc.setFont("helvetica", "normal");
        doc.setFontSize(8);
        doc.setTextColor(191, 219, 254);

        doc.text(
            "ORGANISATION SECURITY",
            PAGE.margin + 64,
            14
        );

        layout.y = 26;

        layout.text(config.title, {
            size: 16,
            style: "bold",
            color: COLORS.ink,
            gap: 2
        });

        layout.text(config.subtitle, {
            size: 9,
            color: COLORS.body,
            gap: 3
        });

        layout.text(
            `Generated ${stamp()}  •  ${config.organisation}`,
            { size: 7.5, color: COLORS.muted, gap: 4 }
        );

        layout.rule(6);
    }


    /* --------------------------------------------------------
     * SHARED SECTIONS
     * ------------------------------------------------------ */

    function drawSummary(doc, layout, summary, fields) {
        layout.sectionTitle("Summary");

        layout.statRow([
            { label: fields.analyzed, value: summary.analyzed ?? 0 },
            { label: fields.flagged, value: summary.flagged ?? 0 },
            { label: "High", value: summary.high ?? 0, risk: "HIGH" },
            { label: "Medium", value: summary.medium ?? 0, risk: "MEDIUM" },
            { label: "Low", value: summary.low ?? 0, risk: "LOW" }
        ]);

        layout.text(
            `Detection events: ${summary.detections ?? 0}  •  ` +
            `Detector types: ${summary.detectorTypes ?? 0}`,
            { size: 8, color: COLORS.muted, gap: 6 }
        );
    }

    function drawFindings(doc, layout, findings, config) {
        layout.sectionTitle(config.findingsTitle);

        if (!findings.length) {

            layout.text(
                config.emptyMessage,
                { size: 9, color: COLORS.muted }
            );

            return;
        }

        findings.forEach((finding, index) => {

            layout.ensure(34);

            const palette = riskPalette(finding.riskLevel);

            // Risk colour rail
            doc.setFillColor(...palette.text);
            doc.rect(
                PAGE.margin,
                layout.y - 4,
                1.6,
                9,
                "F"
            );

            doc.setFont("helvetica", "bold");
            doc.setFontSize(9.5);
            doc.setTextColor(...COLORS.ink);

            doc.text(
                `${index + 1}. ${finding.title}`,
                PAGE.margin + 5,
                layout.y + 1
            );

            const scoreText = `RISK ${finding.riskScore}  •  ${String(finding.riskLevel).toUpperCase()}`;

            doc.setFontSize(8);
            doc.setTextColor(...palette.text);

            doc.text(
                scoreText,
                PAGE.width - PAGE.margin,
                layout.y + 1,
                { align: "right" }
            );

            layout.y += 6;

            if (finding.subtitle) {
                layout.text(
                    finding.subtitle,
                    { size: 8, color: COLORS.muted, indent: 5, gap: 3, maxLines: 2 }
                );
            }

            // Detector chips
            (finding.detectors || []).forEach(detector => {

                layout.ensure(10);

                doc.setFont("helvetica", "bold");
                doc.setFontSize(7.5);

                const label = String(detector);

                const width = doc.getTextWidth(label) + 8;

                const boxWidth = PAGE.width - PAGE.margin * 2 - 6;

                if (width > boxWidth) {
                    layout.wrap(label, { size: 7.5, indent: 5, gap: 2 });
                    return;
                }

                doc.setFillColor(239, 246, 255);
                doc.setDrawColor(147, 197, 253);
                doc.setLineWidth(0.3);

                doc.roundedRect(
                    PAGE.margin + 5,
                    layout.y - 4.4,
                    width,
                    7.2,
                    1.4,
                    1.4,
                    "FD"
                );

                doc.setTextColor(30, 64, 175);
                doc.text(label, PAGE.margin + 9, layout.y);

                layout.y += 9.6;
            });

            layout.y += 1;

            // Evidence
            (finding.reasons || []).forEach(reason => {

                layout.ensure(12);

                doc.setFillColor(148, 163, 184);
                doc.circle(PAGE.margin + 6.5, layout.y - 1.2, 0.7, "F");

                layout.wrap(reason, {
                    size: 8.5,
                    indent: 5,
                    gap: 2,
                    color: COLORS.body
                });
            });

            layout.rule(6);
        });
    }

    function drawNarrative(doc, layout, meaning, recommendation) {
        layout.sectionTitle("Assessment");

        if (meaning) {
            layout.text(
                "WHAT THIS MEANS",
                { size: 7.5, style: "bold", color: COLORS.muted, gap: 2 }
            );

            layout.wrap(meaning, { size: 9, gap: 6 });
        }

        if (recommendation) {
            layout.text(
                "RECOMMENDED ACTION",
                { size: 7.5, style: "bold", color: COLORS.muted, gap: 2 }
            );

            layout.wrap(recommendation, { size: 9, gap: 6 });
        }
    }

    function drawCampaigns(doc, layout, campaigns) {
        if (!campaigns || !campaigns.length) return;

        layout.sectionTitle("Campaign signals");

        campaigns.forEach(campaign => {

            layout.ensure(16);

            const count = campaign.message_count ?? 0;

            const threats = String(campaign.threats || "")
                .split(",")
                .map(item => item.trim())
                .filter(Boolean);

            layout.text(
                `${campaign.campaign_key ?? "Unknown sender"} — ` +
                `${count} message${count === 1 ? "" : "s"}`,
                { size: 9, style: "bold", color: COLORS.ink, gap: 1 }
            );

            if (threats.length) {
                layout.text(
                    `Detectors: ${threats.join(", ")}`,
                    { size: 8, color: COLORS.muted, gap: 4, maxLines: 3 }
                );
            }
        });
    }

    function drawMethodology(doc, layout, config) {

        layout.ensure(40);

        layout.sectionTitle("Methodology");

        layout.wrap(
            `${config.inputSummary} Scoring combines weighted detector ` +
            "contributions with bonuses for evidence volume, repeated " +
            "evidence and agreement between detectors. A high-risk " +
            "verdict is an indicator for investigation, not an automatic " +
            "finding of malice.",
            { size: 8.5, gap: 5 }
        );

        layout.rule(4);

        doc.setFont("helvetica", "normal");
        doc.setFontSize(7);
        doc.setTextColor(...COLORS.muted);

        layout.wrap(
            "CyberGuard analyses telemetry supplied by the organisation. " +
            "It does not require attack labels; detections and risk are " +
            "derived from the supplied data.",
            { size: 7, color: COLORS.muted, gap: 0 }
        );
    }


    /* --------------------------------------------------------
     * ACCOUNT TAKEOVER REPORT
     * ------------------------------------------------------ */

    function buildAccountTakeoverReport(result, options = {}) {

        const doc = new window.jspdf.jsPDF({
            unit: "mm",
            format: "a4"
        });

        const summary = result?.summary || {};

        const accounts = Array.isArray(result?.accounts)
            ? result.accounts
            : [];

        const layout = createLayout(doc);

        drawMasthead(doc, layout, {
            title: "Account Takeover Assessment",
            subtitle:
                "Behavioural analysis of authentication and session telemetry",
            organisation: options.organisation || "Organisation"
        });

        drawSummary(doc, layout, {
            analyzed: summary.users_analyzed,
            flagged: summary.accounts_flagged,
            high: summary.high_risk,
            medium: summary.medium_risk,
            low: summary.low_risk,
            detections: summary.detection_events,
            detectorTypes: summary.detector_types
        }, {
            analyzed: "Users analysed",
            flagged: "Accounts flagged"
        });

        drawFindings(doc, layout, accounts.map(account => ({
            title: account.user_id || "Unknown account",
            subtitle: null,
            riskLevel: account.risk_level,
            riskScore: account.risk_score ?? 0,
            detectors: account.detectors_triggered,
            reasons: account.reasons
        })), {
            findingsTitle: "Account risk assessments",
            emptyMessage:
                "No accounts were flagged by the takeover engine."
        });

        drawNarrative(
            doc,
            layout,
            options.meaning,
            options.recommendation
        );

        drawMethodology(doc, layout, {
            inputSummary:
                "The engine evaluates six indicators: multiple failed " +
                "logins, password spraying, unusual login locations, " +
                "unknown devices, suspicious session activity and sudden " +
                "changes in account behaviour."
        });

        const total = doc.getNumberOfPages();

        for (let page = 1; page <= total; page++) {
            doc.setPage(page);
            layout.drawFooter(page, total);
        }

        return doc;
    }


    /* --------------------------------------------------------
     * DIGITAL IMPERSONATION REPORT
     * ------------------------------------------------------ */

    function buildImpersonationReport(result, options = {}) {

        const doc = new window.jspdf.jsPDF({
            unit: "mm",
            format: "a4"
        });

        const summary = result?.summary || {};

        const messages = Array.isArray(result?.messages)
            ? result.messages
            : [];

        const layout = createLayout(doc);

        drawMasthead(doc, layout, {
            title: "Digital Impersonation Assessment",
            subtitle:
                "Analysis of reported messages and social content",
            organisation: options.organisation || "Organisation"
        });

        drawSummary(doc, layout, {
            analyzed: summary.messages_analyzed,
            flagged: summary.messages_flagged,
            high: summary.high_risk,
            medium: summary.medium_risk,
            low: summary.low_risk,
            detections: summary.detection_events,
            detectorTypes: summary.detector_types
        }, {
            analyzed: "Messages analysed",
            flagged: "Messages flagged"
        });

        drawFindings(doc, layout, messages.map(message => {

            const claimed =
                message.claimed_identity ||
                message.claimed_organisation ||
                message.sender_name ||
                "Unattributed message";

            const channel = message.channel
                ? String(message.channel).toUpperCase()
                : "MESSAGE";

            const excerpt = message.message_text
                ? `"${String(message.message_text).slice(0, 220)}"`
                : null;

            return {
                title: claimed,
                subtitle:
                    `${channel} • ${message.message_id || "unlabelled"}` +
                    (excerpt ? `\n${excerpt}` : ""),
                riskLevel: message.risk_level,
                riskScore: message.risk_score ?? 0,
                detectors: message.detectors_triggered,
                reasons: message.reasons
            };
        }), {
            findingsTitle: "Message risk assessments",
            emptyMessage:
                "No messages were flagged by the impersonation engine."
        });

        drawCampaigns(doc, layout, result?.campaigns);

        drawNarrative(
            doc,
            layout,
            options.meaning,
            options.recommendation
        );

        drawMethodology(doc, layout, {
            inputSummary:
                "The engine evaluates six indicators: authority " +
                "impersonation, executive impersonation, brand " +
                "impersonation, urgency and pressure tactics, " +
                "threatening language, and credential harvesting behind " +
                "a trusted identity."
        });

        const total = doc.getNumberOfPages();

        for (let page = 1; page <= total; page++) {
            doc.setPage(page);
            layout.drawFooter(page, total);
        }

        return doc;
    }


    /* --------------------------------------------------------
     * DOWNLOAD
     * ------------------------------------------------------ */

    function save(doc, filename) {

        doc.save(
            `cyberguard-${safeFilePart(filename)}.pdf`
        );
    }

    return {
        buildAccountTakeoverReport,
        buildImpersonationReport,
        save,
        safeFilePart,
        riskPalette
    };

})();


/* ============================================================
   UI BINDING
   ============================================================ */

function initializePdfExport() {

    const buttons = [
        {
            element: $("#exportTakeoverPdf"),
            build: (result, options) =>
                CG_PDF.buildAccountTakeoverReport(result, options),
            name: () => `account-takeover-${state.takeoverEvents?.length ?? 0}-events`
        },
        {
            element: $("#exportImpersonationPdf"),
            build: (result, options) =>
                CG_PDF.buildImpersonationReport(result, options),
            name: () => `impersonation-${state.impersonationMessages?.length ?? 0}-messages`
        }
    ];

    buttons.forEach(config => {

        const button = config.element;

        if (!button) return;

        button.addEventListener("click", () => {

            if (!window.jspdf) {

                showToast(
                    "Export unavailable",
                    "The PDF library did not load. Reload the page and try again.",
                    "error"
                );

                return;
            }

            const lastResult = window.lastCyberGuardResult;

            if (!lastResult) {

                showToast(
                    "Nothing to export",
                    "Run an analysis before exporting a report.",
                    "error"
                );

                return;
            }

            if (button.dataset.module !== lastResult.type) {
                return;
            }

            button.classList.add("exporting");
            button.disabled = true;

            showLoading(
                "Preparing PDF report",
                "CyberGuard is laying out the findings for download."
            );

            // Defer so the spinner paints before the synchronous
            // PDF layout blocks the main thread.
            setTimeout(() => {

                try {

                    const doc = config.build(
                        lastResult.result,
                        {
                            organisation:
                                state.organisation || "Organisation",
                            meaning: lastResult.meaning,
                            recommendation:
                                lastResult.recommendation
                        }
                    );

                    CG_PDF.save(
                        doc,
                        config.name()
                    );

                    showToast(
                        "Report exported",
                        "The PDF report has been downloaded.",
                        "success"
                    );

                } catch (error) {

                    console.error(
                        "[CyberGuard] PDF export failed:",
                        error
                    );

                    showToast(
                        "Export failed",
                        getErrorMessage(error),
                        "error"
                    );

                } finally {

                    button.classList.remove("exporting");
                    button.disabled = false;

                    hideLoading();
                }

            }, 60);
        });
    });
}

function setPdfExportReady(moduleType, isReady) {

    const buttonId = moduleType === "account_takeover"
        ? "#exportTakeoverPdf"
        : "#exportImpersonationPdf";

    const button = $(buttonId);

    if (!button) return;

    button.disabled = !isReady;
    button.dataset.module = moduleType;
}