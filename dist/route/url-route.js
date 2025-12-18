import { Router } from "express";
import { urlChecker } from "../controller/url-checker-controller.js";
const router = Router();
router.route("/check").post(urlChecker);
export default router;
//# sourceMappingURL=url-route.js.map