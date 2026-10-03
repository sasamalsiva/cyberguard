import pandas as pd


# ============================================================
# RISK LEVEL THRESHOLDS
# ============================================================

LOW_THRESHOLD = 30
HIGH_THRESHOLD = 70


# ============================================================
# DETECTOR BASE WEIGHTS
# ============================================================

DETECTOR_WEIGHTS = {
    "Authority Impersonation": 24,
    "Executive Impersonation": 20,
    "Brand Impersonation": 18,
    "Urgency & Pressure Tactics": 16,
    "Threatening Or Extortion Language": 20,
    "Credential Harvesting Via Impersonation": 26
}


# ============================================================
# HELPERS
# ============================================================

def safe_int(value, default=0):

    try:
        if pd.isna(value):
            return default

        return int(float(value))

    except Exception:
        return default


def normalise_detection(
    dataframe,
    threat_name
):

    if dataframe is None:
        return pd.DataFrame()

    if not isinstance(
        dataframe,
        pd.DataFrame
    ):
        return pd.DataFrame()

    if dataframe.empty:
        return pd.DataFrame()

    df = dataframe.copy()

    if "message_id" not in df.columns:
        return pd.DataFrame()

    df["threat"] = threat_name

    return df


# ============================================================
# INDIVIDUAL DETECTOR SCORE
# ============================================================

def calculate_detector_score(
    threat,
    detection
):

    base_score = DETECTOR_WEIGHTS.get(
        threat,
        10
    )

    evidence_bonus = 0

    # --------------------------------------------------------
    # AUTHORITY IMPERSONATION
    # --------------------------------------------------------

    if threat == "Authority Impersonation":

        signals = safe_int(
            detection.get(
                "authority_signals",
                0
            )
        )

        if signals >= 5:
            evidence_bonus += 12

        elif signals >= 3:
            evidence_bonus += 8

        elif signals >= 2:
            evidence_bonus += 4

    # --------------------------------------------------------
    # EXECUTIVE IMPERSONATION
    # --------------------------------------------------------

    elif threat == "Executive Impersonation":

        signals = safe_int(
            detection.get(
                "executive_signals",
                0
            )
        )

        if signals >= 3:
            evidence_bonus += 10

        elif signals >= 2:
            evidence_bonus += 6

        elif signals >= 1:
            evidence_bonus += 3

    # --------------------------------------------------------
    # BRAND IMPERSONATION
    # --------------------------------------------------------

    elif threat == "Brand Impersonation":

        signals = safe_int(
            detection.get(
                "brand_signals",
                0
            )
        )

        if signals >= 3:
            evidence_bonus += 8

        elif signals >= 2:
            evidence_bonus += 5

        # A lookalike sender domain is strong evidence on
        # its own because the claimed affiliation does not
        # appear in the actual sending infrastructure. A
        # domain that merely exists proves nothing, so the
        # bonus is gated on the detector's own lookalike
        # finding rather than on domain presence.

        reason_text = str(
            detection.get(
                "reasons",
                ""
            )
        )

        if "carries no part" in reason_text:
            evidence_bonus += 5

    # --------------------------------------------------------
    # URGENCY & PRESSURE
    # --------------------------------------------------------

    elif threat == "Urgency & Pressure Tactics":

        signals = safe_int(
            detection.get(
                "urgency_signals",
                0
            )
        )

        if signals >= 4:
            evidence_bonus += 10

        elif signals >= 2:
            evidence_bonus += 6

        elif signals >= 1:
            evidence_bonus += 3

    # --------------------------------------------------------
    # THREATENING LANGUAGE
    # --------------------------------------------------------

    elif threat == "Threatening Or Extortion Language":

        signals = safe_int(
            detection.get(
                "threat_signals",
                0
            )
        )

        if signals >= 3:
            evidence_bonus += 12

        elif signals >= 2:
            evidence_bonus += 7

        elif signals >= 1:
            evidence_bonus += 3

    # --------------------------------------------------------
    # CREDENTIAL HARVESTING
    # --------------------------------------------------------

    elif threat == "Credential Harvesting Via Impersonation":

        credentials = safe_int(
            detection.get(
                "credential_signals",
                0
            )
        )

        redirects = safe_int(
            detection.get(
                "redirect_signals",
                0
            )
        )

        if credentials >= 2:
            evidence_bonus += 10

        elif credentials >= 1:
            evidence_bonus += 6

        # Sending a victim to an attacker-controlled link is
        # the highest-value credential theft path, so a
        # redirect outranks the raw keyword count.

        if redirects >= 1:
            evidence_bonus += 10

    return base_score + evidence_bonus


# ============================================================
# REPETITION BONUS
# ============================================================

def calculate_repetition_bonus(
    count
):

    if count >= 5:
        return 8

    if count >= 3:
        return 5

    if count >= 2:
        return 3

    return 0


# ============================================================
# CORRELATION BONUS
#
# Impersonation attempts are far more dangerous when a
# message combines identity, pressure and a request for
# secrets. These combinations are scored explicitly.
# ============================================================

def calculate_correlation_bonus(
    threats
):

    bonus = 0

    reasons = []

    threat_set = set(threats)

    # --------------------------------------------------------
    # IDENTITY + PRESSURE
    # --------------------------------------------------------

    identity_threats = {
        "Authority Impersonation",
        "Executive Impersonation",
        "Brand Impersonation"
    }

    pressure_threats = {
        "Urgency & Pressure Tactics",
        "Threatening Or Extortion Language"
    }

    has_identity = bool(
        threat_set & identity_threats
    )

    has_pressure = bool(
        threat_set & pressure_threats
    )

    has_credentials = (
        "Credential Harvesting Via Impersonation"
        in threat_set
    )

    if has_identity and has_pressure:

        bonus += 8

        reasons.append(
            "Trusted identity combined with pressure tactics"
        )

    # --------------------------------------------------------
    # CREDENTIAL REQUEST = HIGHEST RISK COMBINATION
    # --------------------------------------------------------

    if has_credentials and has_identity:

        bonus += 12

        reasons.append(
            "Credential request delivered through a claimed "
            "trusted identity"
        )

    if has_credentials and has_pressure:

        bonus += 8

        reasons.append(
            "Credential request paired with threats or urgency "
            "to prevent verification"
        )

    # --------------------------------------------------------
    # FULL ATTACK CHAIN
    # --------------------------------------------------------

    if has_credentials and has_identity and has_pressure:

        bonus += 10

        reasons.append(
            "Complete impersonation attack chain: identity, "
            "pressure and credential request"
        )

    # --------------------------------------------------------
    # EXECUTIVE + FINANCIAL DATA
    # --------------------------------------------------------

    if (
        "Executive Impersonation" in threat_set
        and has_credentials
    ):

        bonus += 6

        reasons.append(
            "Executive impersonation combined with a "
            "credential request"
        )

    return bonus, reasons


# ============================================================
# BUILD RISK REPORT
# ============================================================

def build_risk_report(
    authority_results,
    executive_results,
    brand_results,
    urgency_results,
    threat_results,
    credential_results
):

    # ========================================================
    # NORMALISE ALL DETECTORS
    # ========================================================

    detector_frames = [

        normalise_detection(
            authority_results,
            "Authority Impersonation"
        ),

        normalise_detection(
            executive_results,
            "Executive Impersonation"
        ),

        normalise_detection(
            brand_results,
            "Brand Impersonation"
        ),

        normalise_detection(
            urgency_results,
            "Urgency & Pressure Tactics"
        ),

        normalise_detection(
            threat_results,
            "Threatening Or Extortion Language"
        ),

        normalise_detection(
            credential_results,
            "Credential Harvesting Via Impersonation"
        )
    ]

    detector_frames = [
        df
        for df in detector_frames
        if not df.empty
    ]

    # ========================================================
    # NOTHING DETECTED
    # ========================================================

    if not detector_frames:

        return (

            pd.DataFrame(
                columns=[
                    "message_id",
                    "risk_score",
                    "risk_level",
                    "detector_count",
                    "detectors_triggered",
                    "reasons"
                ]
            ),

            pd.DataFrame()
        )

    # ========================================================
    # COMBINE DETECTIONS
    # ========================================================

    combined = pd.concat(
        detector_frames,
        ignore_index=True,
        sort=False
    )

    reports = []

    detection_details = []

    for message_id, message_events in combined.groupby(
        "message_id"
    ):

        # ====================================================
        # COUNT DETECTOR OCCURRENCES
        # ====================================================

        detector_counts = (
            message_events[
                "threat"
            ]
            .value_counts()
            .to_dict()
        )

        unique_detections = (
            message_events
            .drop_duplicates(
                subset=["threat"]
            )
        )

        threats = (
            unique_detections[
                "threat"
            ]
            .tolist()
        )

        detector_scores = []

        evidence_reasons = []

        for _, detection in (
            unique_detections.iterrows()
        ):

            threat = detection[
                "threat"
            ]

            score_data = (
                calculate_detector_score(
                    threat,
                    detection
                )
            )

            detector_scores.append(
                score_data
            )

            # ================================================
            # HUMAN-READABLE EVIDENCE
            # ================================================

            if threat == "Authority Impersonation":

                signals = safe_int(
                    detection.get(
                        "authority_signals",
                        0
                    )
                )

                evidence_reasons.append(
                    f"Message impersonates an authority or "
                    f"regulator ({signals} indicator(s))"
                )

            elif threat == "Executive Impersonation":

                role = str(
                    detection.get(
                        "claimed_role",
                        "senior role"
                    )
                )

                evidence_reasons.append(
                    f"Sender claims a senior role: {role}"
                )

            elif threat == "Brand Impersonation":

                organisation = str(
                    detection.get(
                        "claimed_organisation",
                        "unknown organisation"
                    )
                )

                evidence_reasons.append(
                    f"Message impersonates organisation: "
                    f"{organisation}"
                )

                domain = str(
                    detection.get(
                        "sender_domain",
                        ""
                    )
                ).strip()

                if (
                    domain
                    and "carries no part"
                    in str(
                        detection.get(
                            "reasons",
                            ""
                        )
                    )
                ):
                    evidence_reasons.append(
                        f"Sending domain does not match the "
                        f"claimed organisation: {domain}"
                    )

            elif threat == "Urgency & Pressure Tactics":

                signals = safe_int(
                    detection.get(
                        "urgency_signals",
                        0
                    )
                )

                evidence_reasons.append(
                    f"High-pressure language used to force action "
                    f"({signals} indicator(s))"
                )

            elif threat == "Threatening Or Extortion Language":

                signals = safe_int(
                    detection.get(
                        "threat_signals",
                        0
                    )
                )

                evidence_reasons.append(
                    f"Threatening or coercive language detected "
                    f"({signals} indicator(s))"
                )

            elif threat == "Credential Harvesting Via Impersonation":

                credentials = safe_int(
                    detection.get(
                        "credential_signals",
                        0
                    )
                )

                evidence_reasons.append(
                    f"Sensitive information requested from the "
                    f"recipient ({credentials} credential indicator(s))"
                )

        # ====================================================
        # BASE SCORE
        # ====================================================

        base_score = sum(
            detector_scores
        )

        # ====================================================
        # CORRELATION BONUS
        # ====================================================

        (
            correlation_bonus,
            correlation_reasons
        ) = calculate_correlation_bonus(
            threats
        )

        # ====================================================
        # DIMINISHING RETURNS
        # ====================================================

        sorted_scores = sorted(
            detector_scores,
            reverse=True
        )

        weighted_score = 0

        for index, score in enumerate(
            sorted_scores
        ):

            if index == 0:
                multiplier = 1.00

            elif index == 1:
                multiplier = 0.85

            elif index == 2:
                multiplier = 0.70

            elif index == 3:
                multiplier = 0.50

            elif index == 4:
                multiplier = 0.35

            else:
                multiplier = 0.20

            weighted_score += (
                score *
                multiplier
            )

        # ====================================================
        # REPETITION BONUS
        # ====================================================

        repetition_bonus = 0

        for threat, count in (
            detector_counts.items()
        ):

            bonus = calculate_repetition_bonus(
                count
            )

            repetition_bonus += bonus

            if bonus > 0:

                evidence_reasons.append(
                    f"{threat} detected {count} times; "
                    f"repeated evidence adds {bonus} risk points"
                )

        # ====================================================
        # COMBINE SCORE
        # ====================================================

        raw_score = (
            weighted_score
            + correlation_bonus
            + repetition_bonus
        )

        # ====================================================
        # STRONG EVIDENCE ADJUSTMENT
        # ====================================================

        strong_signals = 0

        if (
            "Authority Impersonation"
            in threats
        ):
            strong_signals += 1

        if (
            "Credential Harvesting Via Impersonation"
            in threats
        ):
            strong_signals += 1

        if (
            "Threatening Or Extortion Language"
            in threats
        ):
            strong_signals += 1

        if strong_signals >= 3:

            raw_score += 8

            evidence_reasons.append(
                "Multiple strong impersonation signals detected"
            )

        # ====================================================
        # CAP SCORE
        # ====================================================

        risk_score = min(
            int(raw_score),
            100
        )

        # ====================================================
        # RISK LEVEL
        # ====================================================

        if risk_score >= HIGH_THRESHOLD:
            risk_level = "HIGH"

        elif risk_score >= LOW_THRESHOLD:
            risk_level = "MEDIUM"

        else:
            risk_level = "LOW"

        reports.append({

            "message_id": str(message_id),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "detector_count": len(threats),
            "detectors_triggered":
                ", ".join(threats),
            "reasons":
                " | ".join(
                    evidence_reasons
                    + correlation_reasons
                )
        })

        # ====================================================
        # TECHNICAL DETECTION DETAILS
        # ====================================================

        for _, detection in message_events.iterrows():

            detection_details.append(
                detection.to_dict()
            )

    # ========================================================
    # RETURN DATAFRAMES
    # ========================================================

    return (

        pd.DataFrame(reports),

        pd.DataFrame(
            detection_details
        )
    )
