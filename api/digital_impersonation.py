import pandas as pd

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any, Dict, List

from digital_impersonation.digital_impersonation_service import (
    analyze_digital_impersonation
)


app = FastAPI(
    title="CyberGuard Digital Impersonation API"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


# ============================================================
# REQUEST MODEL
# ============================================================

class DigitalImpersonationRequest(BaseModel):

    messages: List[Dict[str, Any]]


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
@app.get("/api/digital_impersonation")
def health_check():

    return {
        "success": True,
        "service": "CyberGuard Digital Impersonation Detection",
        "status": "online",
        "detectors": 6
    }


# ============================================================
# DIGITAL IMPERSONATION ANALYSIS
# ============================================================

@app.post("/")
@app.post("/api/digital_impersonation")
def analyze_digital_impersonation_api(
    request: DigitalImpersonationRequest
):

    if not request.messages:

        raise HTTPException(
            status_code=400,
            detail="No impersonation messages supplied."
        )

    try:

        # ----------------------------------------------------
        # Convert frontend JSON array into a DataFrame
        # ----------------------------------------------------

        messages_df = pd.DataFrame(
            request.messages
        )


        # ----------------------------------------------------
        # Run the CyberGuard impersonation engine
        # ----------------------------------------------------

        result = analyze_digital_impersonation(
            messages=messages_df
        )


        # ----------------------------------------------------
        # Convert pandas / timestamps / numpy values
        # into JSON-safe values
        # ----------------------------------------------------

        def make_json_safe(value):

            if isinstance(
                value,
                dict
            ):

                return {
                    str(key):
                    make_json_safe(val)

                    for key, val
                    in value.items()
                }


            if isinstance(
                value,
                list
            ):

                return [
                    make_json_safe(item)
                    for item in value
                ]


            if isinstance(
                value,
                tuple
            ):

                return [
                    make_json_safe(item)
                    for item in value
                ]


            if isinstance(
                value,
                pd.Timestamp
            ):

                return value.isoformat()


            try:

                if pd.isna(value):
                    return None

            except Exception:

                pass


            if hasattr(
                value,
                "item"
            ):

                try:

                    return value.item()

                except Exception:

                    pass


            return value


        return {
            "success": True,
            "type": "digital_impersonation",
            "result": make_json_safe(result)
        }


    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


    except TypeError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


    except Exception as error:

        print(
            "Digital Impersonation API error:",
            repr(error)
        )

        raise HTTPException(
            status_code=500,
            detail="Digital impersonation analysis failed."
        )
