import { Router } from "express";
import { urlChecker } from "../controller/url-checker-controller.js";

const router: Router = Router()

router.route("/check").post(urlChecker)

export default router;