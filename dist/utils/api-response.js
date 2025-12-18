class ApiResponse {
    statusCode;
    data;
    message;
    success;
    constructor(statusCode, data, message = "success") {
        this.statusCode = statusCode;
        this.data = data;
        this.message = message;
        this.success = statusCode < 400;
    }
}
export default ApiResponse;
//# sourceMappingURL=api-response.js.map