class ApiError extends Error {
    statusCode: number;
    data: any;
    success: boolean;
    errors: string[];

    constructor(
        statusCode: number,
        message: string = "Something went wrong",
        errors: string[] = [],
        data: any = null,
        stack: string = ""
    ) {
        super(message);
        this.statusCode = statusCode;
        this.data = data; // Assign the data here
        this.success = false;
        this.errors = errors;

        if (stack) {
            this.stack = stack;
        } else {
            Error.captureStackTrace(this, this.constructor);
        }
    }
}

export default ApiError;