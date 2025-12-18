import type { Request, Response, NextFunction } from "express";
type RequestHandler = (req: Request, res: Response, next: NextFunction) => Promise<Response<any, Record<string, any>>> | Response<any, Record<string, any>> | Promise<void> | void;
declare const AsyncHandler: (requestHandler: RequestHandler) => (req: Request, res: Response, next: NextFunction) => void;
export default AsyncHandler;
//# sourceMappingURL=async-handler.d.ts.map