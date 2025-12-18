declare class ApiError extends Error {
    statusCode: number;
    data: any;
    success: boolean;
    errors: string[];
    constructor(statusCode: number, message?: string, errors?: string[], data?: any, stack?: string);
}
export default ApiError;
//# sourceMappingURL=api-error.d.ts.map