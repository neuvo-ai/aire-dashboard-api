import express from "express";

const router = express.Router();
import logger from "../logger";
import { Bot } from "../models/bot";

router.get("/", async (req: express.Request, res: express.Response) => {
	try {
		const botList = await Bot.find({ public: true, status: "deployed" }).limit(3000).select("name desc url projectId");
		res.status(200).json({ botList });
	} catch (e) {
		logger.error(e.message);
		return res.status(500).json({
			success: false,
			error: "GeneralError"
		});
	}
});

export default router;