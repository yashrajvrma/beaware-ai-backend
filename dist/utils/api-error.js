class ApiError extends Error {
    statusCode;
    data;
    success;
    errors;
    constructor(statusCode, message = "Something went wrong", errors = [], data = null, stack = "") {
        super(message);
        this.statusCode = statusCode;
        this.data = data; // Assign the data here
        this.success = false;
        this.errors = errors;
        if (stack) {
            this.stack = stack;
        }
        else {
            Error.captureStackTrace(this, this.constructor);
        }
    }
}
export default ApiError;
//# sourceMappingURL=api-error.js.map