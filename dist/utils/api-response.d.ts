declare class ApiResponse<T> {
    statusCode: number;
    data: T;
    message: string;
    success: boolean;
    constructor(statusCode: number, data: T, message?: string);
}
export default ApiResponse;
//# sourceMappingURL=api-response.d.ts.map