import { ZodError } from "zod";
import ApiError from "../utils/api-error.js";
const errorHandler = (err, req, res, next) => {
    if (err instanceof ApiError) {
        res.status(err.statusCode || 500).json({
            success: false,
            message: err.message,
            errors: err.errors || [],
        });
    }
    else if (err instanceof ZodError) {
        // Print the first error message from Zod errors
        const firstErrorMessage = err.message.length > 0 ? err.message[0] : "Validation error";
        res.status(400).json({
            success: false,
            message: firstErrorMessage,
            errors: err.issues.map((e) => ({
                path: e.path.join("."), // Join path array to a string if needed
                message: e.message,
            })),
        });
    }
    else {
        res.status(500).json({
            success: false,
            message: err.message || "Internal Server Error",
        });
    }
};
export default errorHandler;
//# sourceMappingURL=error-middleware.js.map