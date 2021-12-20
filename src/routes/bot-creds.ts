import express from "express";
import { param, body, validationResult, matchedData } from "express-validator";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const guard = require("express-jwt-permissions")();

const router = express.Router();
import logger from "../logger";
import _ from "lodash";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { Types } from "mongoose";
import { AuditLog } from "../models/audit";
import { Bot } from "../models/bot";

router.get("/:id", guard.check("admin"), [
	param("id", "Invalid ID").isMongoId()
], async (req: express.Request, res: express.Response) => {
	const errors = validationResult(req);
	const values = matchedData(req);

	if (!errors.isEmpty()) {
		return res.status(400).json({
			error: "ValidatingError",
			message: "Validating parameters failed",
			errors: _.uniqWith(errors.array(), _.isEqual)
		});
	}

	try {
		const bot = await Bot.findOne({_id: new Types.ObjectId(values.id), status: { "$ne": "deleted" }});
		if(bot === undefined || bot === null) {
			return res.status(404).json({
				error: "NotFound",
				message: "Bot was not found",
				success: false
			});
		}
		const botName = bot.name;
		const dbUsers = bot.credentials.server.databases;
		const botfrontUsers = bot.credentials.server.botfront;
		for(const user of dbUsers) {
			user.password = "";
		}
		for(const user of botfrontUsers) {
			user.password = "";
		}
		res.status(200).json({dbUsers, botfrontUsers, botName, data: bot, success: true});
	} catch (e) {
		logger.error(e.message);
		return res.status(500).json({
			success: false,
			error: "GeneralError"
		});
	}
});

router.get("/status/:id", guard.check("admin"), [
	param("id", "Invalid ID").isMongoId()
], async (req: express.Request, res: express.Response) => {
	const errors = validationResult(req);
	const values = matchedData(req);

	if (!errors.isEmpty()) {
		return res.status(400).json({
			error: "ValidatingError",
			message: "Validating parameters failed",
			errors: _.uniqWith(errors.array(), _.isEqual)
		});
	}

	try {
		const bot = await Bot.findById(new Types.ObjectId(values.id));

		if(bot !== undefined) {
			return res.status(200).json({ status: bot.status, success: true });
		}

		res.status(200).json({ success: false });
	} catch (e) {
		logger.error(e.message);
		return res.status(500).json({
			success: false,
			error: "GeneralError"
		});
	}
});

router.post("/save-creds/:id", guard.check("admin"), [
	param("id", "invalid id").isMongoId(),
	body("botData.tombstoned", "invalid boolean").optional().isBoolean(),
	body("botData.desc", "invalid string").optional().isString(),
	body("botData.projectId", "invalid string").isString(),
	body("botData.public", "invalid boolean").optional().isBoolean(),
	body("botData.credentials.server.botfront", "invalid array").optional().isArray(),
	body("botData.credentials.server.botfront.*.name", "invalid string").optional({ checkFalsy: true }).isString(),
	body("botData.credentials.server.botfront.*.password", "invalid string").optional({ checkFalsy: true }).isString(),
], async (req: express.Request, res: express.Response) => {
	const errors = validationResult(req);
	const values = matchedData(req);

	if (!errors.isEmpty()) {
		return res.status(400).json({
			success: false,
			error: "ValidatingError",
			message: "Validating parameters failed",
			errors: _.uniqWith(errors.array(), _.isEqual)
		});
	}

	try {
		let hasSaltData = false;
		let isModified = false;
		const bot = await Bot.findById(new Types.ObjectId(values.id));

		if(bot.status !== "deployed" && bot.status !== "errored" && bot.status !== "removing") {
			return res.status(200).json({ success: false });
		}

		if(bot === undefined) {
			return res.status(404).json({
				error: "NotFound",
				message: "Bot was not found",
				success: false
			});
		}

		if(values.botData.desc !== undefined && values.botData.desc !== bot.desc) {
			bot.desc = values.botData.desc;
			isModified = true;
		}

		if(values.botData.projectId !== undefined && values.botData.projectId !== bot.projectId) {
			bot.projectId = values.botData.projectId;
			isModified = true;
		}

		if(values.botData.public !== undefined && values.botData.public !== bot.public ) {
			bot.public = values.botData.public;
			isModified = true;
		}
		// Do botfront user pass
		for (const bfUser of values.botData.credentials.server.botfront) {
			const index = bot.credentials.server.botfront.findIndex((element: any) => element.name === bfUser.name);
			if (index !== -1) {
				// Modifying an existing user
				if(bfUser !== undefined && bfUser.password !== "") {
					bot.credentials.server.botfront[index].password = await saltPassword(bfUser.password);
					hasSaltData = true;
					isModified = true;
				}
			}
		}

		// Save
		if(isModified){
			bot.updatedAt = new Date();
			await bot.save();
			void AuditLog({
				type: "bot-update-success",
				adminId: res.locals.user._id,
				target: "self",
			}, req);
			// We only want to call salt-api if data that was modified applies to salt
			if(hasSaltData === true) {
				// Call saltstack endpoint with id of bot
				// axios.get(`/{{orchestrate}}/${encodeURIComponent(newBot._id)}`)
			}
			return res.status(200).json({ success: true });
		} else {
			return res.status(200).json({ success: false });
		}
	} catch (e) {
		logger.error(e.message);
		return res.status(500).json({
			success: false,
			error: "GeneralError"
		});
	}
});

const saltPassword = async (password: string) => {
	const saltRounds = 10;
	const sha256pass = crypto.createHash("sha256").update(password).digest("hex");

	const hash = await bcrypt.hash(sha256pass, saltRounds);

	return hash;
};

export default router;
