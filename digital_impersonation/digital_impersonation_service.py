import pandas as pd

from .digital_impersonation_engine import (
    detect_authority_impersonation,
    detect_executive_impersonation,
    detect_brand_impersonation,
    detect_urgency_manipulation,
    detect_threat_language,
    detect_credential_harvesting,
    summarise_campaigns,
    ensure_message_id
)

from .risk_engine import build_risk_report


# ============================================================
# DIGITAL IMPERSONATION SERVICE
# ============================================================
#
# This file is the single entry point for the entire
# Digital Impersonation Detection module.
#
# It connects:
#
# CSV / reported messages
#      ↓
# 6 detectors
#      ↓
# Risk Engine
#      ↓
# Structured result
#
# The frontend calls this service without needing to know
# how the detectors work.
# ============================================================


def analyze_digital_impersonation(
    messages
):
    """
    Run the complete Digital Impersonation Detection pipeline.

    Parameters
    ----------
    messages : pandas.DataFrame
        Reported impersonation messages.

    Returns
    -------
    dict
        Structured Digital Impersonation analysis result.
    """

    # ========================================================
    # VALIDATE MESSAGES
    # ========================================================

    if messages is None:

        raise ValueError(
            "Messages data cannot be None."
        )

    if not isinstance(
        messages,
        pd.DataFrame
    ):

        raise TypeError(
            "Messages must be a pandas DataFrame."
        )

    if messages.empty:

        return {
            "summary": {
                "messages_analyzed": 0,
                "messages_flagged": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "detection_events": 0,
                "detector_types": 6
            },
            "messages": [],
            "detections": [],
            "campaigns": []
        }


    # ========================================================
    # COPY INPUT
    # ========================================================

    messages = messages.copy()


    # ========================================================
    # SYNTHESISE MESSAGE IDENTIFIERS
    #
    # message_id is the grouping key for both the risk engine
    # and the source-message lookup below, so it is guaranteed
    # here. Doing it once means the detectors and this lookup
    # always agree, even when the CSV omits the column.
    # ========================================================

    messages = ensure_message_id(messages)


    # ========================================================
    # DETECTOR 1
    # AUTHORITY IMPERSONATION
    # ========================================================

    authority_results = (
        detect_authority_impersonation(
            messages
        )
    )


    # ========================================================
    # DETECTOR 2
    # EXECUTIVE / SENIOR AUTHORITY IMPERSONATION
    # ========================================================

    executive_results = (
        detect_executive_impersonation(
            messages
        )
    )


    # ========================================================
    # DETECTOR 3
    # BRAND / ORGANISATION IMPERSONATION
    # ========================================================

    brand_results = (
        detect_brand_impersonation(
            messages
        )
    )


    # ========================================================
    # DETECTOR 4
    # URGENCY & PRESSURE TACTICS
    # ========================================================

    urgency_results = (
        detect_urgency_manipulation(
            messages
        )
    )


    # ========================================================
    # DETECTOR 5
    # THREATENING / EXTORTION LANGUAGE
    # ========================================================

    threat_results = (
        detect_threat_language(
            messages
        )
    )


    # ========================================================
    # DETECTOR 6
    # CREDENTIAL HARVESTING VIA IMPERSONATION
    # ========================================================

    credential_results = (
        detect_credential_harvesting(
            messages
        )
    )


    # ========================================================
    # RISK ENGINE
    # ========================================================

    risk_report, detection_details = (
        build_risk_report(

            authority_results,

            executive_results,

            brand_results,

            urgency_results,

            threat_results,

            credential_results
        )
    )


    # ========================================================
    # SUMMARY
    # ========================================================

    messages_analyzed = (
        messages["message_id"]
        .nunique()
        if "message_id" in messages.columns
        else len(messages)
    )


    messages_flagged = (
        len(risk_report)
        if not risk_report.empty
        else 0
    )


    if risk_report.empty:

        high_risk = 0
        medium_risk = 0
        low_risk = 0

    else:

        high_risk = int(
            (
                risk_report["risk_level"]
                == "HIGH"
            ).sum()
        )

        medium_risk = int(
            (
                risk_report["risk_level"]
                == "MEDIUM"
            ).sum()
        )

        low_risk = int(
            (
                risk_report["risk_level"]
                == "LOW"
            ).sum()
        )


    detection_events = (
        len(detection_details)
        if not detection_details.empty
        else 0
    )


    # ========================================================
    # CONVERT MESSAGE REPORT TO JSON-SAFE RECORDS
    # ========================================================

    report_records = []

    if not risk_report.empty:

        for _, row in risk_report.iterrows():

            record = {}

            for column, value in row.items():

                if pd.isna(value):

                    record[column] = None

                elif isinstance(
                    value,
                    (pd.Timestamp,)
                ):

                    record[column] = (
                        value.isoformat()
                    )

                elif hasattr(
                    value,
                    "item"
                ):

                    record[column] = (
                        value.item()
                    )

                else:

                    record[column] = value


            # ------------------------------------------------
            # Convert detector string into a list
            # ------------------------------------------------

            detector_text = record.get(
                "detectors_triggered",
                ""
            )


            if detector_text:

                record[
                    "detectors_triggered"
                ] = [
                    detector.strip()
                    for detector in
                    str(
                        detector_text
                    ).split(",")
                    if detector.strip()
                ]

            else:

                record[
                    "detectors_triggered"
                ] = []


            # ------------------------------------------------
            # Convert reasons into a list
            # ------------------------------------------------

            reason_text = record.get(
                "reasons",
                ""
            )


            if reason_text:

                record[
                    "reasons"
                ] = [
                    reason.strip()
                    for reason in
                    str(
                        reason_text
                    ).split("|")
                    if reason.strip()
                ]

            else:

                record[
                    "reasons"
                ] = []


            # ------------------------------------------------
            # Attach the original reported message so the
            # dashboard can show what was actually sent
            # ------------------------------------------------

            message_id = record.get(
                "message_id"
            )

            source = messages[
                messages["message_id"].astype(str)
                == str(message_id)
            ]

            if not source.empty:

                source_row = source.iloc[0]

                for column in (
                    "channel",
                    "sender_domain",
                    "claimed_identity",
                    "claimed_role",
                    "claimed_organisation",
                    "message_text",
                    "context"
                ):

                    if column in source_row.index:

                        value = source_row[column]

                        if pd.isna(value):

                            record[column] = None

                        else:

                            record[column] = value


            report_records.append(
                record
            )


    # ========================================================
    # CONVERT TECHNICAL DETECTIONS
    # ========================================================

    detections = []

    if not detection_details.empty:

        for _, row in detection_details.iterrows():

            detection = {}

            for column, value in row.items():

                if pd.isna(value):

                    detection[column] = None

                elif isinstance(
                    value,
                    (pd.Timestamp,)
                ):

                    detection[column] = (
                        value.isoformat()
                    )

                elif hasattr(
                    value,
                    "item"
                ):

                    detection[column] = (
                        value.item()
                    )

                else:

                    detection[column] = value


            detections.append(
                detection
            )


    # ========================================================
    # CAMPAIGN AGGREGATION
    # ========================================================

    campaign_frame = summarise_campaigns(
        [

            (
                authority_results,
                "Authority Impersonation"
            ),

            (
                executive_results,
                "Executive Impersonation"
            ),

            (
                brand_results,
                "Brand Impersonation"
            ),

            (
                urgency_results,
                "Urgency & Pressure Tactics"
            ),

            (
                threat_results,
                "Threatening Or Extortion Language"
            ),

            (
                credential_results,
                "Credential Harvesting Via Impersonation"
            )
        ]
    )


    campaigns = []

    if not campaign_frame.empty:

        for _, row in campaign_frame.iterrows():

            campaign = {}

            for column, value in row.items():

                if pd.isna(value):

                    campaign[column] = None

                elif hasattr(
                    value,
                    "item"
                ):

                    campaign[column] = (
                        value.item()
                    )

                else:

                    campaign[column] = value


            campaigns.append(
                campaign
            )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    result = {

        "summary": {

            "messages_analyzed":
                messages_analyzed,

            "messages_flagged":
                messages_flagged,

            "high_risk":
                high_risk,

            "medium_risk":
                medium_risk,

            "low_risk":
                low_risk,

            "detection_events":
                detection_events,

            "detector_types":
                6
        },


        "messages":
            report_records,

        "detections":
            detections,

        "campaigns":
            campaigns
    }


    return result
