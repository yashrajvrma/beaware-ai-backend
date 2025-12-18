import { urlSchema } from "../schema/url-schema.js";
import ApiResponse from "../utils/api-response.js";
import AsyncHandler from "../utils/async-handler.js";
import { getWhoisInfo, getSSLDetails, getHostingDetails, takeScreenshot } from "../utils/scanner.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { URL } from "url";
import fs from "fs";

export const urlChecker = AsyncHandler(async (req, res) => {
    const parseResult = urlSchema.parse(req.body);
    const url = parseResult.url;

    if (!url) {
        throw new Error("URL is required");
    }

    console.log("Analyzing Url:", url);
    const parsedUrl = new URL(url.startsWith('http') ? url : `https://${url}`);
    const hostname = parsedUrl.hostname;

    // 1. Gather Technical Data
    // We add a screenshot step
    const [whois, ssl, hosting, screenshotPath] = await Promise.all([
        getWhoisInfo(hostname),
        getSSLDetails(hostname),
        getHostingDetails(hostname),
        takeScreenshot(url.startsWith('http') ? url : `https://${url}`)
    ]);

    // Upload screenshot to Cloudinary if available
    let screenshotUrl: string | null = null;
    let screenshotBase64: string | null = null;

    if (screenshotPath) {
        try {
            // Upload to Cloudinary
            screenshotUrl = await uploadOnCloudinary(screenshotPath);

            // Also read as base64 for AI vision analysis (before file is deleted by uploadOnCloudinary)
            if (fs.existsSync(screenshotPath)) {
                const imageBuffer = fs.readFileSync(screenshotPath);
                screenshotBase64 = imageBuffer.toString('base64');
            }
        } catch (error) {
            console.error("Failed to upload screenshot to Cloudinary:", error);
            // Clean up file if upload failed and file still exists
            if (fs.existsSync(screenshotPath)) {
                fs.unlinkSync(screenshotPath);
            }
        }
    }

    const technicalData = {
        url,
        hostname,
        whois,
        ssl,
        hosting,
        screenshot_available: !!screenshotUrl,
        screenshot_url: screenshotUrl || undefined // Cloudinary URL instead of base64
    };

    // 2. Analyze with Agent (Direct API call with Vision)
    const systemPrompt = `You are a cybersecurity expert specializing in phishing detection.
    Analyze the provided website data and screenshot to determine if it is Safe, Suspicious, or Dangerous.
    
    Focus on VISUAL IMPERSONATION:
    - Does the screenshot look like a major brand (Microsoft, Google, Bank, Netflix etc.)?
    - If yes, does the domain MATCH the official domain of that brand?
    - If it looks like a brand but the domain is unrelated, MARK AS DANGEROUS IMMEDIATELY.
    
    Also consider technical signals:
    - New domains (< 1 month) are suspicious.
    - Mismatched SSL issuers are suspicious.
    
    OUTPUT JSON format with fields: result (safe/suspicious/dangerous), reasons (array of strings).`;

    const userContent: any[] = [
        { type: "text", text: `Analyze this website: ${url}\n\nTECHNICAL DATA:\n${JSON.stringify(technicalData, null, 2)}` }
    ];

    if (screenshotBase64) {
        userContent.push({
            type: "image_url",
            image_url: {
                url: `data:image/jpeg;base64,${screenshotBase64}`
            }
        });
    }

    let analysisResult;

    if (process.env.OPENAI_API_KEY) {
        try {
            const response = await fetch('https://api.openai.com/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
                },
                body: JSON.stringify({
                    model: "gpt-4o", // gpt-4o has vision capabilities
                    messages: [
                        { role: "system", content: systemPrompt },
                        { role: "user", content: userContent }
                    ],
                    response_format: { type: "json_object" },
                    max_tokens: 1000
                })
            });

            const data = await response.json();
            if (data.choices && data.choices[0] && data.choices[0].message) {
                const content = data.choices[0].message.content;
                analysisResult = JSON.parse(content);
            } else {
                console.error("OpenAI API Error:", data);
                analysisResult = { error: "Failed to get analysis from AI", details: data };
            }

        } catch (error) {
            console.error("AI Analysis Failed:", error);
            analysisResult = { error: "AI Analysis failed to execute" };
        }
    } else {
        analysisResult = { error: "OPENAI_API_KEY not configured" };
    }

    // Calculate risk score based on the result
    let risk_score = 50; // default
    if (analysisResult && analysisResult.result) {
        const result = analysisResult.result.toLowerCase();
        if (result === 'safe') {
            risk_score = Math.floor(Math.random() * 20) + 10; // 10-30
        } else if (result === 'suspicious') {
            risk_score = Math.floor(Math.random() * 20) + 50; // 50-70
        } else if (result === 'dangerous') {
            risk_score = Math.floor(Math.random() * 10) + 85; // 85-95
        }
    }

    const finalResponse = {
        ...analysisResult,
        risk_score, // Add the numerical risk score
        technical_details: technicalData
    };

    return res.json(new ApiResponse(200, finalResponse, "Website analysis completed"))
})
