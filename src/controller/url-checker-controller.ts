import { urlSchema } from "../schema/url-schema.js";
import ApiResponse from "../utils/api-response.js";
import AsyncHandler from "../utils/async-handler.js";

export const urlChecker = AsyncHandler(async (req, res) => {
    const { url } = urlSchema.parse(req.body)

    console.log("Url is", url)

    return res.json(new ApiResponse(200, url))
})