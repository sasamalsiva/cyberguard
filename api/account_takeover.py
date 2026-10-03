import pandas as pd

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any, Dict, List, Optional

from account_takeover.account_takeover_service import (
    analyze_account_takeover
)


app = FastAPI(
    title="CyberGuard Account Takeover API"
)


# ============================================================
# CORS
# ============================================================
#
# The frontend is commonly served from a different origin than
# this API (e.g. static hosting plus a serverless backend).
# Without CORS the browser blocks every analysis request.
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

class AccountTakeoverRequest(BaseModel):

    events: List[Dict[str, Any]]

    profiles: Optional[
        List[Dict[str, Any]]
    ] = None


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
@app.get("/api/account_takeover")
def health_check():

    return {
        "success": True,
        "service": "CyberGuard Account Takeover Detection",
        "status": "online",
        "detectors": 6
    }


# ============================================================
# ACCOUNT TAKEOVER ANALYSIS
# ============================================================

@app.post("/")
@app.post("/api/account_takeover")
def analyze_account_takeover_api(
    request: AccountTakeoverRequest
):

    if not request.events:

        raise HTTPException(
            status_code=400,
            detail="No event telemetry supplied."
        )

    try:

        # ----------------------------------------------------
        # Convert frontend JSON arrays into DataFrames
        # ----------------------------------------------------

        events_df = pd.DataFrame(
            request.events
        )


        if request.profiles:

            profiles_df = pd.DataFrame(
                request.profiles
            )

        else:

            profiles_df = None


        # ----------------------------------------------------
        # Run the existing CyberGuard engine
        # ----------------------------------------------------

        result = analyze_account_takeover(
            events=events_df,
            profiles=profiles_df
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
            "type": "account_takeover",
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
            "Account Takeover API error:",
            repr(error)
        )

        raise HTTPException(
            status_code=500,
            detail="Account takeover analysis failed."
        )
