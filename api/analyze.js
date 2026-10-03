import { Client, handle_file } from "@gradio/client";
import fs from "fs/promises";
import os from "os";
import path from "path";
import crypto from "crypto";

const SPACE_ID = "saswatpatra/cyberguard_phishing";

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store"
        }
    });
}

/*
 * The Space is public, so a token is optional: connecting
 * anonymously keeps the deployed demo working out of the box.
 * HF_TOKEN is only required when the Space is switched to
 * private or gated, or when the anonymous rate limit bites.
 */

async function getClient() {
    const token = process.env.HF_TOKEN;

    if (!token) {
        return await Client.connect(SPACE_ID);
    }

    return await Client.connect(SPACE_ID, {
        token: token
    });
}

/*
 * Bad input from the caller must surface as 400, not as a
 * generic 500 "analysis failed": a missing message is a user
 * error, not a server fault.
 */

class BadRequestError extends Error {
    constructor(message) {
        super(message);
        this.name = "BadRequestError";
        this.statusCode = 400;
    }
}

async function analyzeMessage(client, message) {
    if (typeof message !== "string" || !message.trim()) {
        throw new BadRequestError("Message is required.");
    }

    const result = await client.predict("/analyze_message", {
        message: message.trim()
    });

    return result.data;
}

async function analyzeWebsite(client, url) {
    if (typeof url !== "string" || !url.trim()) {
        throw new BadRequestError("Website URL is required.");
    }

    const result = await client.predict("/analyze_website", {
        url: url.trim()
    });

    return result.data;
}

async function analyzeQR(client, imageData, fileName = "qr-image.png") {
    if (typeof imageData !== "string" || !imageData) {
        throw new BadRequestError("QR image is required.");
    }

    /*
     * Expected format:
     * data:image/png;base64,....
     */

    let base64Data = imageData;

    if (imageData.includes(",")) {
        base64Data = imageData.split(",")[1];
    }

    const imageBuffer = Buffer.from(base64Data, "base64");

    if (!imageBuffer.length) {
        throw new BadRequestError("Invalid QR image data.");
    }

    const safeName = path.basename(fileName).replace(/[^a-zA-Z0-9._-]/g, "_");

    const tempPath = path.join(
        os.tmpdir(),
        `${crypto.randomUUID()}-${safeName}`
    );

    try {
        await fs.writeFile(tempPath, imageBuffer);

        const result = await client.predict("/scan_qr", {
            image: handle_file(tempPath)
        });

        return result.data;
    } finally {
        try {
            await fs.unlink(tempPath);
        } catch {
            // Ignore cleanup errors.
        }
    }
}

async function handleRequest(request) {
    if (request.method === "OPTIONS") {
        return new Response(null, {
            status: 204,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            }
        });
    }

    if (request.method !== "POST") {
        return jsonResponse(
            {
                success: false,
                error: "Method not allowed. Use POST."
            },
            405
        );
    }

    try {
        const body = await request.json();

        if (!body || typeof body !== "object") {
            return jsonResponse(
                {
                    success: false,
                    error: "Invalid request body."
                },
                400
            );
        }

        const type = body.type;

        if (!type) {
            return jsonResponse(
                {
                    success: false,
                    error: "Missing analysis type."
                },
                400
            );
        }

        const client = await getClient();

        let result;

        switch (type) {
            case "message":
                result = await analyzeMessage(
                    client,
                    body.message
                );
                break;

            case "website":
                result = await analyzeWebsite(
                    client,
                    body.url
                );
                break;

            case "qr":
                result = await analyzeQR(
                    client,
                    body.image,
                    body.fileName || "qr-image.png"
                );
                break;

            default:
                return jsonResponse(
                    {
                        success: false,
                        error: "Unknown analysis type."
                    },
                    400
                );
        }

        return jsonResponse({
            success: true,
            type: type,
            result: result
        });

    } catch (error) {
        const isBadRequest = error instanceof BadRequestError;

        if (!isBadRequest) {
            console.error("CyberGuard API error:", error);
        }

        return jsonResponse(
            {
                success: false,
                error: isBadRequest
                    ? error.message
                    : "Analysis request failed.",
                details:
                    !isBadRequest && process.env.NODE_ENV === "development"
                        ? String(error.message || error)
                        : undefined
            },
            isBadRequest ? 400 : 500
        );
    }
}

/*
 * Adapter so the handler works on every common serverless target:
 *
 * - Cloudflare Workers / edge runtimes call the default export
 *   with a single web Request.
 * - Vercel / Node serverless functions call it with (req, res).
 *
 * Previously the file only supported the Worker calling
 * convention, which broke when deployed to Vercel even with a
 * valid HF_TOKEN configured.
 */

async function readNodeBody(req) {
    if (req.body !== undefined && req.body !== null) {
        if (typeof req.body === "string") {
            return req.body;
        }

        try {
            return JSON.stringify(req.body);
        } catch {
            return undefined;
        }
    }

    const chunks = [];

    for await (const chunk of req) {
        chunks.push(Buffer.from(chunk));
    }

    return chunks.length ? Buffer.concat(chunks).toString("utf8") : undefined;
}

export default async function handler(req, res) {
    const isNodeStyle =
        res &&
        typeof res.status === "function" &&
        typeof res.setHeader === "function";

    if (isNodeStyle) {
        try {
            const method = String(req.method || "GET").toUpperCase();
            const url = new URL(req.url || "/", "http://localhost");

            const body =
                method === "GET" || method === "HEAD"
                    ? undefined
                    : await readNodeBody(req);

            const request = new Request(url, {
                method,
                headers: {
                    "content-type":
                        req.headers["content-type"] || "application/json"
                },
                body
            });

            const response = await handleRequest(request);
            const text = await response.text();

            if (typeof response.headers.forEach === "function") {
                response.headers.forEach((value, key) => {
                    try {
                        res.setHeader(key, value);
                    } catch {
                        // Some headers are reserved; ignore failures.
                    }
                });
            }

            res.status(response.status).send(text);
        } catch (error) {
            console.error("CyberGuard API adapter error:", error);

            res.status(500).json({
                success: false,
                error: "Analysis request failed."
            });
        }

        return;
    }

    return handleRequest(req);
}
