import express from "express";
import { param, body, validationResult, matchedData } from "express-validator";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const guard = require("express-jwt-permissions")();
import bcrypt from "bcrypt";
import crypto from "crypto";

const router = express.Router();
import logger from "../logger";
import _ from "lodash";
import { Types } from "mongoose";
import { AuditLog } from "../models/audit";
import { Bot } from "../models/bot";
import slugify from "slugify";
import axios from "axios";

router.post("/add", guard.check("admin"), [
	body("name", "Invalid string").isString(),
	body("desc", "Invalid string").isString(),
	body("email", "Invalid email").isEmail()
], async (req: express.Request | any, res: express.Response) => {
	const errors = validationResult(req);
	const bodyValues = matchedData(req);

	if (!errors.isEmpty()) {
		return res.status(400).json({
			error: "ValidatingError",
			message: "Validating parameters failed",
			errors: _.uniqWith(errors.array(), _.isEqual)
		});
	}

	try {
		const bot = new Bot();

		bot.name = bodyValues.name;
		bot.desc = bodyValues.desc;
		bot.projectId = "pW2WEr9JJoWauvFge"; // Default botfront project id, this can be overwritten by user in dashboard bot edit page
		bot.public = true;
		bot.slug = botSlug(bodyValues.name);
		bot.createdBy = new Types.ObjectId(req.user._id);
		bot.url = `https://${bot.slug}-jamk.neuvo.ai`;

		// We need to add passwords for bot database
		const rndPass = Math.random().toString(36).slice(-10);
		bot.credentials.server.databases.push({name: "botfront", password: rndPass});
		const userPassword = Math.random().toString(36).slice(-10);
		bot.credentials.server.botfront.push({name: bodyValues.email, password: await saltPassword(userPassword) });

		const newBot = await bot.save();
		if(newBot === undefined) {
			void AuditLog({
				type: "bot-create-failed",
				adminId: res.locals.user._id,
				target: "self",
			}, req);
			return res.status(200).json({ success: false });
		} else {
			// Add code to poke orchestration-api that a new minion has been created in the database with the _id
			await axios.post(`/orchestrate/${encodeURIComponent(newBot._id)}`);
			void AuditLog({
				type: "bot-create-success",
				adminId: res.locals.user._id,
				target: "self",
			}, req);
			return res.status(200).json({ success: true, password: userPassword });
		}
	} catch (e) {
		logger.error(e.message);
		return res.status(500).json({ success: false, error: "BotAddError" });
	}
});

router.delete("/:id", guard.check("admin"), [
	param("id", "Invalid id format").isMongoId()
], async (req: express.Request | any, res: express.Response) => {
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
		// Mark bot for removal
		const bot = await Bot.findById(new Types.ObjectId(values.id));
		// We need to check bot status is in a rested creation state (deployed or errored)
		if(bot.status !== "deployed" && bot.status !== "errored" && bot.status !== "removing") {
			// do not remove bot mid creation
			return res.status(200).json({ success: false });
		}
		bot.status = "removing";
		bot.removedAt = new Date().toISOString();
		bot.tombstoned = true;
		bot.logs.push({ log: "bot-marked-delete", json: { actionByUser: req.user._id } });
		bot.save();
		// Add code to poke orchestration-api with id of the tombstoned bot
		// axios.get(`/{{orchestrate}}/${encodeURIComponent(newBot._id)}`);
		void AuditLog({
			type: "bot-remove-flagged",
			adminId: res.locals.user._id,
			target: "self",
		}, req);
		return res.status(200).json({ success: true });
	} catch (e) {
		logger.error("Error marking bot for removal");
		logger.error(e?.message);
		return res.status(500).json({ success: false, error: "BotDeleteError" });
	}
});

router.get("/bot-status", guard.check("admin"), async (req: express.Request, res: express.Response) => {
	try {
		void AuditLog({
			type: "bot-get-status",
			adminId: res.locals.user._id,
			target: "self",
		}, req);
		const bots = await Bot.find({status: { "$ne": "deleted" } }).sort("-createdAt").limit(3000).select("_id status");

		return res.status(200).json({
			success: true,
			bots
		});
	} catch(e) {
		logger.error(e.message);
		return res.status(500).json({
			success: false,
			error: "GeneralError"
		});
	}
});
 /*
// This is for updating dash only fields that do not affect the deployed bot
router.post("/update", guard.check("admin"), [
	param("id", "Invalid id format").isMongoId(),
	param("name", "Invalid string").optional().isString(),
	param("desc", "Invalid string").optional().isString()
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
		if (values.name === undefined && values.desc === undefined) {
			// Return, there is nothing to update (This should be checked before posting update from dashboard)
			return res.status(200).json({ success: false });
		}

		const bot = await Bot.findById(Types.ObjectId(values.id));
		if(values.name !== undefined) {
			bot.name = values.name;
		}
		if(values.desc !== undefined) {
			bot.desc = values.desc;
		}

		const updatedBot = await bot.save();
		if(updatedBot === bot) {
			void AuditLog({
				type: "bot-update-success",
				adminId: res.locals.user._id,
				target: "self",
			}, req);
			return res.status(200).json({ success: true });
		} else {
			void AuditLog({
				type: "bot-update-failed",
				adminId: res.locals.user._id,
				target: "self",
			}, req);
			return res.status(200).json({ success: false });
		}
	} catch (e) {
		logger.error(e.message);
		return res.status(500).json({ success: false, error: "BotUpdateError" });
	}
});
*/
router.get("/", guard.check("admin"), async (req: express.Request, res: express.Response) => {
	try {
		void AuditLog({
			type: "bot-get",
			adminId: res.locals.user._id,
			target: "self",
		}, req);
		const bots = await Bot.find({status: { "$ne": "deleted" } }).sort("-createdAt").limit(3000).select("_id name desc status createdAt updatedAt");
		return res.json({
			success: true,
			bots
		});
	} catch (e) {
		logger.error(e.message);
		return res.status(500).json({
			success: false,
			error: "GeneralError"
		});
	}
});

function botSlug(name: string): string {
	return slugify(name, {
		replacement: "-", // replace spaces with replacement character, defaults to `-`
		lower: true, // convert to lower case, defaults to `false`
		strict: false, // strip special characters except replacement, defaults to `false`
		locale: "fi", // language code of the locale to use
		trim: true, // trim leading and trailing replacement chars, defaults to `true`
	});
}

const saltPassword = async (password: string) => {
	const saltRounds = 10;
	const sha256pass = crypto.createHash("sha256").update(password).digest("hex");

	const hash = await bcrypt.hash(sha256pass, saltRounds);

	return hash;
};

export default router;
