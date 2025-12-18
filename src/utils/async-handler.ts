import type { Request, Response, NextFunction } from "express";

// Adjust handler to accept Promise<Response> or Response.
type RequestHandler = (
    req: Request,
    res: Response,
    next: NextFunction
) =>
    | Promise<Response<any, Record<string, any>>>
    | Response<any, Record<string, any>>
    | Promise<void>
    | void;

const AsyncHandler = (requestHandler: RequestHandler) => {
    return (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(requestHandler(req, res, next)).catch(next);
    };
};

export default AsyncHandler;