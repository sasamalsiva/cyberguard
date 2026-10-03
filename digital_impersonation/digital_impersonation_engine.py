import re

import pandas as pd


# ============================================================
# CYBERGUARD
# DIGITAL IMPERSONATION DETECTION ENGINE
#
# Six detectors run over reported impersonation messages
# (SMS, email, chat, social comment, QR, caller notes).
#
# The module never requires an "is_impersonation" label:
# it derives every verdict from the message content, the
# claimed identity, the channel and the reporting context.
# ============================================================


# ============================================================
# INPUT SAFETY HELPERS
# ============================================================

def _prepare_messages(
    messages,
    required_columns=None,
    optional_columns=None
):

    if messages is None or not isinstance(
        messages,
        pd.DataFrame
    ):
        return None, list(required_columns or [])

    messages = messages.copy()

    required_columns = list(required_columns or [])
    optional_columns = list(optional_columns or [])

    missing_required = [
        column
        for column in required_columns
        if column not in messages.columns
    ]

    if missing_required:
        return None, missing_required

    for column in optional_columns:
        if column not in messages.columns:
            messages[column] = ""

    return messages, []


def _empty_result(columns):
    return pd.DataFrame(columns=columns)


def ensure_message_id(messages):
    """
    Guarantee a message_id column.

    message_id is the grouping key for the risk engine, so a
    CSV that omits the column entirely must still be analysed
    rather than silently returning zero detections. Identifiers
    are synthesised from the row position.
    """

    if (
        "message_id" in messages.columns
        and messages["message_id"].notna().any()
    ):
        # Fill only the gaps so a partially populated column
        # does not produce colliding identifiers.
        messages["message_id"] = messages[
            "message_id"
        ].fillna("")

        missing = (
            messages["message_id"]
            .astype(str)
            .str.strip() == ""
        )

        if missing.any():
            messages.loc[missing, "message_id"] = [
                f"message_{index}"
                for index in messages.index[missing]
            ]

        return messages

    messages["message_id"] = [
        f"message_{index}"
        for index in range(len(messages))
    ]

    return messages


def _text_of(row, column):
    """Read a message field as a lowercase string, never None."""

    if column not in row:
        return ""

    value = row[column]

    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass

    return str(value).strip().lower()


# ============================================================
# LEARNED VOCABULARIES
#
# Kept as data rather than code so the engine stays auditable
# and the lists can be tuned without touching detector logic.
# ============================================================

AUTHORITY_KEYWORDS = {
    "police", "cbi", "ed", "income tax", "it department",
    "government", "govt", "government of india", "court",
    "judge", "summon", "notice", "traffic", "cyber cell",
    "nda", "supreme court", "high court", "district court",
    "aadhaar", "pan card", "election commission",
    "tax department", "customs", "fraud department", "bank official",
    # Institutional staff titles are authority claims in their
    # own right, independent of the institution named.
    "officer", "official", "inspector", "commissioner",
    "magistrate", "ombudsman", "superintendent", "sheriff",
    "collector", "tehsildar", "warden", "prosecutor"
}


FINANCIAL_KEYWORDS = {
    "bank", "sbi", "hdfc", "icici", "axis bank", "kotak",
    "punjab national", "bank of baroda", "canara bank",
    "upi", "net banking", "netbanking", "atm", "debit card",
    "credit card", "kyc", "kyc update", "account closure",
    "account freeze", "payment gateway", "merchant", "transaction"
}


EXECUTIVE_KEYWORDS = {
    "ceo", "cfo", "cto", "coo", "md", "managing director",
    "director", "chairman", "chairperson", "founder", "owner",
    "hr", "human resources", "finance department", "accounts department",
    "payroll", "admin", "administrator", "ceo office", "board",
    "vice president", "vp", "head of department", "hod", "principal",
    "dean", "registrar", "vice chancellor", "trustee"
}


URGENCY_KEYWORDS = {
    "urgent", "immediately", "right now", "within 24 hours",
    "within 2 hours", "asap", "final warning", "last warning",
    "expire", "expiring", "suspended", "suspension", "pending",
    "legal action", "arrest", "penalty", "fine", "blocked",
    "deactivate", "deactivation", "failure to comply", "act now",
    "before midnight", "today itself", "no time", "hurry"
}


THREAT_KEYWORDS = {
    "arrest", "warrant", "prosecut", "court notice", "legal action",
    "jail", "police station", "crime branch", "fraud case",
    "money laundering", "drug", "money laundering case", "case registered",
    "complaint filed", "notice under", "section 138", "ndr",
    "secrecy", "confidential", "classified", "penalty proceedings",
    "attachment", "property attached", "freeze order"
}


CREDENTIAL_KEYWORDS = {
    "otp", "one time password", "verification code", "pin",
    "cvv", "atm pin", "password", "passcode", "login credentials",
    "share your password", "card number", "account number and otp",
    "confirm your otp", "send the code", "verify your identity with otp",
    "bank credentials", "net banking password", "seed phrase",
    "private key", "security code"
}


REDIRECT_KEYWORDS = {
    "click here", "click the link", "link below", "http", "https",
    "www.", "scan the qr", "scan this qr", "open the link",
    "download the app", "install the app", "update your browser",
    "verify now", "click the blue link", "bit.ly", "tinyurl",
    "form fill", "fill the form", "submit details"
}


# ============================================================
# VERIFICATION BLOCKING
#
# Instructions that stop a victim from checking the identity
# of the sender. Matched on word boundaries so "do not tell"
# does not fire inside a longer word.
# ============================================================

VERIFICATION_BLOCKING_KEYWORDS = {
    "do not tell", "don't tell",
    "do not inform", "don't inform",
    "do not call", "don't call",
    "do not discuss", "don't discuss",
    "do not share", "don't share",
    "do not verify", "don't verify",
    "keep this secret",
    "keep it confidential",
    "confidential",
    "secretly"
}


INTERNAL_CODENAME_KEYWORDS = {
    "payroll update", "vendor change", "invoice", "purchase order",
    "tender", "rfq", "quotation", "advance payment", "salary revision",
    "transfer the amount", "bank details change", "account change",
    "new account number", "ifs code change", "beneficiary change",
    "confidential project", "board meeting", "acquisition",
    "merger", "funding round", "due diligence"
}


# ============================================================
# COMPILED MATCHERS
# ============================================================

URL_PATTERN = re.compile(
    r"(https?://|www\.)\S+|"
    r"\b\S+\.(com|net|org|in|co\.in|edu|gov|gov\.in|"
    r"ac\.in|edu\.in|biz|xyz|top|info|ru|uk)\b",
    re.IGNORECASE
)


# ============================================================
# KEYWORD MATCHERS
#
# Vocabularies above are written as ordinary words and short
# tokens such as "ed", "md" or "atm". Plain substring matching
# would match those inside unrelated words ("need", "cancelled",
# "debarred"), so every vocabulary is compiled once into a
# word-boundary pattern.
#
# Lookarounds are used rather than \b so that keywords ending in
# punctuation (for example "www.") still match at the end of a
# string.
# ============================================================

def _compile_keywords(keywords):
    """Compile a keyword vocabulary into one word-boundary pattern."""

    alternatives = "|".join(
        re.escape(keyword)
        for keyword in sorted(
            keywords,
            key=len,
            reverse=True
        )
    )

    return re.compile(
        r"(?<!\w)(?:" + alternatives + r")(?!\w)",
        re.IGNORECASE
    )


AUTHORITY_PATTERN = _compile_keywords(
    AUTHORITY_KEYWORDS
)

FINANCIAL_PATTERN = _compile_keywords(
    FINANCIAL_KEYWORDS
)

EXECUTIVE_PATTERN = _compile_keywords(
    EXECUTIVE_KEYWORDS
)

URGENCY_PATTERN = _compile_keywords(
    URGENCY_KEYWORDS
)

THREAT_PATTERN = _compile_keywords(
    THREAT_KEYWORDS
)

CREDENTIAL_PATTERN = _compile_keywords(
    CREDENTIAL_KEYWORDS
)

REDIRECT_PATTERN = _compile_keywords(
    REDIRECT_KEYWORDS
)

INTERNAL_CODENAME_PATTERN = _compile_keywords(
    INTERNAL_CODENAME_KEYWORDS
)

VERIFICATION_BLOCKING_PATTERN = _compile_keywords(
    VERIFICATION_BLOCKING_KEYWORDS
)


def _count_matches(text, pattern):
    """
    Count distinct keywords from a compiled vocabulary.

    Longest alternatives are ordered first, so a message that
    contains "one time password" is counted once rather than
    once per overlapping fragment.
    """

    if not text:
        return 0

    if pattern is None:
        return 0

    matched = set()

    for match in pattern.finditer(text):

        matched.add(
            match.group(0).lower()
        )

    return len(matched)


def _combined_text(row):
    """
    Build the searchable text for a message.

    Combines the body with the claimed identity so an
    impersonation described only in the identity field
    (for example claimed_role = "police officer")
    is still detected.
    """

    fields = [
        "message_text",
        "claimed_identity",
        "claimed_role",
        "claimed_organisation",
        "context"
    ]

    parts = [
        _text_of(row, field)
        for field in fields
    ]

    return " ".join(
        part for part in parts
        if part
    )


# ============================================================
# DETECTOR 1: AUTHORITY IMPERSONATION
# ============================================================

def detect_authority_impersonation(messages):
    """
    Catches messages that present themselves as a government,
    police, judicial or regulatory authority.
    """

    messages, missing_columns = _prepare_messages(
        messages,
        required_columns=[],
        optional_columns=[
            "message_id",
            "message_text",
            "claimed_identity",
            "claimed_role",
            "claimed_organisation",
            "channel",
            "timestamp"
        ]
    )

    if messages is None:
        return _empty_result([
            "message_id",
            "authority_signals",
            "claimed_identity",
            "channel",
            "timestamp",
            "reasons",
            "risk"
        ])

    messages = ensure_message_id(messages)

    records = []

    for _, row in messages.iterrows():

        text = _combined_text(row)

        authority_hits = _count_matches(
            text,
            AUTHORITY_PATTERN
        )

        if authority_hits < 1:
            continue

        financial_hits = _count_matches(
            text,
            FINANCIAL_PATTERN
        )

        # ====================================================
        # BUILD REASONS
        # ====================================================

        reasons = [
            f"Message presents as an authority: "
            f"{authority_hits} authority indicator(s) matched"
        ]

        if financial_hits:
            reasons.append(
                f"Authority claim combined with banking context "
                f"({financial_hits} financial indicator(s))"
            )

        risk = "HIGH" if authority_hits >= 3 else "MEDIUM"

        records.append({

            "message_id": row.get("message_id"),
            "authority_signals": authority_hits,
            "claimed_identity":
                row.get("claimed_identity", ""),
            "channel": row.get("channel", ""),
            "timestamp": row.get("timestamp", ""),
            "reasons": " | ".join(reasons),
            "risk": risk
        })

    if not records:
        return _empty_result([
            "message_id",
            "authority_signals",
            "claimed_identity",
            "channel",
            "timestamp",
            "reasons",
            "risk"
        ])

    return pd.DataFrame(records)


# ============================================================
# DETECTOR 2: EXECUTIVE / SENIOR AUTHORITY REQUEST
# ============================================================

def detect_executive_impersonation(messages):
    """
    Catches a sender claiming to be a senior leader, admin,
    finance or payroll authority inside the organisation.
    """

    messages, missing_columns = _prepare_messages(
        messages,
        required_columns=[],
        optional_columns=[
            "message_id",
            "message_text",
            "claimed_identity",
            "claimed_role",
            "claimed_organisation",
            "channel",
            "timestamp"
        ]
    )

    if messages is None:
        return _empty_result([
            "message_id",
            "executive_signals",
            "claimed_role",
            "channel",
            "timestamp",
            "reasons",
            "risk"
        ])

    messages = ensure_message_id(messages)

    records = []

    for _, row in messages.iterrows():

        text = _combined_text(row)

        executive_hits = _count_matches(
            text,
            EXECUTIVE_PATTERN
        )

        codename_hits = _count_matches(
            text,
            INTERNAL_CODENAME_PATTERN
        )

        if executive_hits < 1:
            continue

        reasons = [
            f"Sender claims a senior authority role: "
            f"{executive_hits} role indicator(s) matched"
        ]

        if codename_hits:
            reasons.append(
                f"Executive claim paired with sensitive internal "
                f"topic ({codename_hits} internal signal(s))"
            )

        risk = "HIGH" if codename_hits >= 1 else "MEDIUM"

        records.append({

            "message_id": row.get("message_id"),
            "executive_signals": executive_hits,
            "claimed_role": row.get("claimed_role", ""),
            "channel": row.get("channel", ""),
            "timestamp": row.get("timestamp", ""),
            "reasons": " | ".join(reasons),
            "risk": risk
        })

    if not records:
        return _empty_result([
            "message_id",
            "executive_signals",
            "claimed_role",
            "channel",
            "timestamp",
            "reasons",
            "risk"
        ])

    return pd.DataFrame(records)


# ============================================================
# DETECTOR 3: BRAND / ORGANISATION IMPERSONATION
# ============================================================

def detect_brand_impersonation(messages):
    """
    Catches messages impersonating a bank, brand, institution
    or commercial organisation through claimed affiliation
    or a lookalike sender identity.
    """

    messages, missing_columns = _prepare_messages(
        messages,
        required_columns=[],
        optional_columns=[
            "message_id",
            "message_text",
            "claimed_identity",
            "claimed_organisation",
            "sender_name",
            "sender_domain",
            "channel",
            "timestamp"
        ]
    )

    if messages is None:
        return _empty_result([
            "message_id",
            "brand_signals",
            "claimed_organisation",
            "sender_domain",
            "channel",
            "timestamp",
            "reasons",
            "risk"
        ])

    messages = ensure_message_id(messages)

    records = []

    for _, row in messages.iterrows():

        text = _combined_text(row)

        organisation = _text_of(
            row,
            "claimed_organisation"
        )

        sender_domain = _text_of(
            row,
            "sender_domain"
        )

        financial_hits = _count_matches(
            text,
            FINANCIAL_PATTERN
        )

        # ====================================================
        # LOOKALIKE DOMAIN
        #
        # A genuine affiliation is expected to appear in the
        # sending domain ("acme-corp.com" for "Acme
        # Corporation"). A domain that carries no token of
        # the claimed organisation is treated as a lookalike,
        # but only when the message also leans on a brand or
        # financial identity. Merely naming an organisation
        # in a normal internal email is not impersonation.
        # ====================================================

        lookalike = False

        if (
            sender_domain
            and "." in sender_domain
            and organisation
        ):

            domain_tokens = set(
                re.findall(
                    r"[a-z0-9]+",
                    sender_domain.lower()
                )
            )

            organisation_tokens = [
                token
                for token in re.findall(
                    r"[a-z0-9]+",
                    organisation.lower()
                )
                if len(token) > 2
            ]

            shared = (
                domain_tokens
                & set(organisation_tokens)
            )

            if not shared:
                lookalike = True

        if financial_hits < 1 and not lookalike:
            continue

        reasons = []

        if financial_hits:
            reasons.append(
                f"Message claims a financial or brand identity: "
                f"{financial_hits} brand indicator(s) matched"
            )

        if lookalike:
            reasons.append(
                f"Sender domain '{sender_domain}' carries no "
                f"part of the claimed organisation "
                f"'{organisation}'"
            )

        risk = "HIGH" if lookalike else "MEDIUM"

        records.append({

            "message_id": row.get("message_id"),
            "brand_signals": financial_hits,
            "claimed_organisation":
                row.get("claimed_organisation", ""),
            "sender_domain":
                row.get("sender_domain", ""),
            "channel": row.get("channel", ""),
            "timestamp": row.get("timestamp", ""),
            "reasons": " | ".join(reasons),
            "risk": risk
        })

    if not records:
        return _empty_result([
            "message_id",
            "brand_signals",
            "claimed_organisation",
            "sender_domain",
            "channel",
            "timestamp",
            "reasons",
            "risk"
        ])

    return pd.DataFrame(records)


# ============================================================
# DETECTOR 4: URGENCY & PRESSURE TACTICS
# ============================================================

def detect_urgency_manipulation(messages):
    """
    Catches coercive time pressure used to stop a victim
    from verifying the identity of the sender.
    """

    messages, missing_columns = _prepare_messages(
        messages,
        required_columns=[],
        optional_columns=[
            "message_id",
            "message_text",
            "claimed_identity",
            "context",
            "channel",
            "timestamp"
        ]
    )

    if messages is None:
        return _empty_result([
            "message_id",
            "urgency_signals",
            "channel",
            "timestamp",
            "reasons",
            "risk"
        ])

    messages = ensure_message_id(messages)

    records = []

    for _, row in messages.iterrows():

        text = _combined_text(row)

        urgency_hits = _count_matches(
            text,
            URGENCY_PATTERN
        )

        if urgency_hits < 1:
            continue

        # ====================================================
        # VERIFICATION BLOCKING
        #
        # Explicit instructions not to contact or verify
        # the sender raise the severity of the pressure.
        # ====================================================

        blocking = _count_matches(
            text,
            VERIFICATION_BLOCKING_PATTERN
        )

        reasons = [
            f"High-pressure language used: "
            f"{urgency_hits} urgency indicator(s) matched"
        ]

        if blocking:
            reasons.append(
                f"Sender pressures secrecy and blocks verification "
                f"({blocking} blocking instruction(s))"
            )

        risk = (
            "HIGH"
            if urgency_hits >= 2 or blocking
            else "MEDIUM"
        )

        records.append({

            "message_id": row.get("message_id"),
            "urgency_signals": urgency_hits,
            "channel": row.get("channel", ""),
            "timestamp": row.get("timestamp", ""),
            "reasons": " | ".join(reasons),
            "risk": risk
        })

    if not records:
        return _empty_result([
            "message_id",
            "urgency_signals",
            "channel",
            "timestamp",
            "reasons",
            "risk"
        ])

    return pd.DataFrame(records)


# ============================================================
# DETECTOR 5: THREATENING OR EXTORTION LANGUAGE
# ============================================================

def detect_threat_language(messages):
    """
    Catches legal, policing or financial threat used to make
    a victim comply without verifying the sender.
    """

    messages, missing_columns = _prepare_messages(
        messages,
        required_columns=[],
        optional_columns=[
            "message_id",
            "message_text",
            "claimed_identity",
            "context",
            "channel",
            "timestamp"
        ]
    )

    if messages is None:
        return _empty_result([
            "message_id",
            "threat_signals",
            "channel",
            "timestamp",
            "reasons",
            "risk"
        ])

    messages = ensure_message_id(messages)

    records = []

    for _, row in messages.iterrows():

        text = _combined_text(row)

        threat_hits = _count_matches(
            text,
            THREAT_PATTERN
        )

        if threat_hits < 1:
            continue

        reasons = [
            f"Threatening or coercive language detected: "
            f"{threat_hits} threat indicator(s) matched"
        ]

        risk = "HIGH" if threat_hits >= 2 else "MEDIUM"

        records.append({

            "message_id": row.get("message_id"),
            "threat_signals": threat_hits,
            "channel": row.get("channel", ""),
            "timestamp": row.get("timestamp", ""),
            "reasons": " | ".join(reasons),
            "risk": risk
        })

    if not records:
        return _empty_result([
            "message_id",
            "threat_signals",
            "channel",
            "timestamp",
            "reasons",
            "risk"
        ])

    return pd.DataFrame(records)


# ============================================================
# DETECTOR 6: CREDENTIAL HARVESTING VIA IMPERSONATION
# ============================================================

def detect_credential_harvesting(messages):
    """
    Catches a message that combines a claim of trusted identity
    with a request for secrets: OTP, PIN, password, card
    details, or redirection to a link or QR code.
    """

    messages, missing_columns = _prepare_messages(
        messages,
        required_columns=[],
        optional_columns=[
            "message_id",
            "message_text",
            "claimed_identity",
            "claimed_organisation",
            "sender_domain",
            "channel",
            "timestamp"
        ]
    )

    if messages is None:
        return _empty_result([
            "message_id",
            "credential_signals",
            "redirect_signals",
            "channel",
            "timestamp",
            "reasons",
            "risk"
        ])

    messages = ensure_message_id(messages)

    records = []

    for _, row in messages.iterrows():

        text = _combined_text(row)

        credential_hits = _count_matches(
            text,
            CREDENTIAL_PATTERN
        )

        redirect_hits = _count_matches(
            text,
            REDIRECT_PATTERN
        )

        # ====================================================
        # URL / QR REDIRECTION
        # ====================================================

        if URL_PATTERN.search(text):
            redirect_hits += 1

        if credential_hits < 1:
            continue

        # ====================================================
        # A credential request is only reported when it is
        # paired with some social-engineering pressure,
        # otherwise it is a support request rather than
        # an impersonation attempt.
        # ====================================================

        pressure = _count_matches(
            text,
            AUTHORITY_PATTERN
        ) + _count_matches(
            text,
            EXECUTIVE_PATTERN
        ) + _count_matches(
            text,
            URGENCY_PATTERN
        ) + _count_matches(
            text,
            THREAT_PATTERN
        )

        if pressure < 1 and redirect_hits < 1:
            continue

        reasons = [
            f"Sensitive information requested: "
            f"{credential_hits} credential indicator(s) matched"
        ]

        if redirect_hits:
            reasons.append(
                f"Request routed to an external link or QR code "
                f"({redirect_hits} redirect indicator(s))"
            )

        if pressure:
            reasons.append(
                f"Credential request paired with identity pressure "
                f"({pressure} pressure signal(s))"
            )

        risk = (
            "HIGH"
            if redirect_hits >= 1 or credential_hits >= 2
            else "MEDIUM"
        )

        records.append({

            "message_id": row.get("message_id"),
            "credential_signals": credential_hits,
            "redirect_signals": redirect_hits,
            "channel": row.get("channel", ""),
            "timestamp": row.get("timestamp", ""),
            "reasons": " | ".join(reasons),
            "risk": risk
        })

    if not records:
        return _empty_result([
            "message_id",
            "credential_signals",
            "redirect_signals",
            "channel",
            "timestamp",
            "reasons",
            "risk"
        ])

    return pd.DataFrame(records)


# ============================================================
# CAMPAIGN AGGREGATION
# ============================================================

def summarise_campaigns(
    detector_frames
):
    """
    Group detections by sender domain so a single campaign
    spreading across several messages is visible in the
    report.

    `detector_frames` is a list of
    (dataframe, threat_name) tuples. The threat name is
    attached here because the raw detector output does not
    carry it.
    """

    labelled = []

    for frame, threat_name in (
        detector_frames or []
    ):

        if frame is None or frame.empty:
            continue

        if "message_id" not in frame.columns:
            continue

        labelled_frame = frame.copy()

        labelled_frame["threat"] = threat_name

        labelled.append(
            labelled_frame
        )

    combined = pd.concat(
        labelled,
        ignore_index=True,
        sort=False
    ) if labelled else pd.DataFrame()

    if combined.empty:
        return pd.DataFrame(
            columns=[
                "campaign_key",
                "message_count",
                "threats"
            ]
        )

    if "sender_domain" not in combined.columns:
        return pd.DataFrame(
            columns=[
                "campaign_key",
                "message_count",
                "threats"
            ]
        )

    if "threat" not in combined.columns:
        return pd.DataFrame(
            columns=[
                "campaign_key",
                "message_count",
                "threats"
            ]
        )

    domains = combined.dropna(
        subset=["sender_domain"]
    )

    domains = domains[
        domains["sender_domain"]
        .astype(str)
        .str.strip() != ""
    ]

    if domains.empty:
        return pd.DataFrame(
            columns=[
                "campaign_key",
                "message_count",
                "threats"
            ]
        )

    campaigns = []

    for domain, group in domains.groupby(
        "sender_domain"
    ):

        campaigns.append({
            "campaign_key": str(domain),
            "message_count": int(
                group["message_id"]
                .nunique()
            ),
            "threats": ", ".join(
                sorted(
                    set(group["threat"])
                )
            )
        })

    return pd.DataFrame(campaigns)


# ============================================================
# CLI ENTRY POINT
# ============================================================

if __name__ == "__main__":

    sample = pd.DataFrame([

        {
            "message_id": "msg001",
            "timestamp": "2026-10-03T09:00:00",
            "channel": "sms",
            "sender_domain": "",
            "claimed_identity": "Delhi Police Cyber Cell",
            "claimed_role": "police officer",
            "claimed_organisation": "Delhi Police",
            "message_text": (
                "URGENT: a case has been registered against you. "
                "Your account will be frozen within 24 hours. "
                "Do not tell anyone about this notice."
            ),
            "context": "employee received on personal number"
        },

        {
            "message_id": "msg002",
            "timestamp": "2026-10-03T10:00:00",
            "channel": "email",
            "sender_domain": "hdfc-netbanking-secure.xyz",
            "claimed_identity": "HDFC Bank KYC Desk",
            "claimed_role": "bank official",
            "claimed_organisation": "HDFC Bank",
            "message_text": (
                "Your account will be suspended today. "
                "Click here to update KYC and confirm your OTP "
                "and net banking password."
            ),
            "context": "vendor received an email invoice scam"
        }
    ])

    print("=" * 60)
    print(" DIGITAL IMPERSONATION DETECTION ENGINE")
    print("=" * 60)

    authority = detect_authority_impersonation(
        sample
    )

    executive = detect_executive_impersonation(
        sample
    )

    brand = detect_brand_impersonation(
        sample
    )

    urgency = detect_urgency_manipulation(
        sample
    )

    threat = detect_threat_language(
        sample
    )

    credential = detect_credential_harvesting(
        sample
    )

    print(
        "\n[1] Authority impersonation :",
        len(authority)
    )

    print(
        "\n[2] Executive impersonation  :",
        len(executive)
    )

    print(
        "\n[3] Brand impersonation      :",
        len(brand)
    )

    print(
        "\n[4] Urgency manipulation      :",
        len(urgency)
    )

    print(
        "\n[5] Threat language           :",
        len(threat)
    )

    print(
        "\n[6] Credential harvesting     :",
        len(credential)
    )

    print(
        "\nAll six detectors executed."
    )
