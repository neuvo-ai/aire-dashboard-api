import express from "express";
import { param, body, validationResult, matchedData } from "express-validator";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const guard = require("express-jwt-permissions")();

const router = express.Router();
import logger from "../logger";
import _ from "lodash";
import { Types } from "mongoose";
import { AuditLog } from "../models/audit";
import { Admin } from "../models/admin";

router.post("/add", guard.check("super"), [
	body("email", "Invalid email format").isEmail(),
	body("permissions", "Invalid permission format").isArray()
], async (req: express.Request, res: express.Response) => {
	const errors = validationResult(req);
	const bodyValues = matchedData(req);

	if (!errors.isEmpty()) {
		return res.status(400).json({
			error: "ValidatingError",
			message: "Validating parameters failed",
			errors: _.uniqWith(errors.array(), _.isEqual)
		});
	}

	if (bodyValues.permissions.includes("super") && !res.locals.user.permissions.includes("super")) {
		return res.status(403).json({
			error: "InvalidPermissions",
			message: "Not allowed",
			errors: _.uniqWith(errors.array(), _.isEqual)
		});
	}

	try {
		let password = "";
		let successResult = true;
		// Check if email address is already in the database
		let admin = await Admin.findOne({"email": bodyValues.email});

		if(admin && admin.email !== undefined) {
			// Account already exists
			successResult = false;
		} else {
			// This is a new account
			password = "CHANGE-" + Math.random().toString(36).slice(-10);
			const data = {
				email: bodyValues.email,
				password,
				permissions: bodyValues.permissions
			};
			admin = new Admin(data);
			await admin.save();
		}
		if (successResult === true) {
			void AuditLog({
				type: "admin-created",
				adminId: res.locals.user._id,
				target: "admin",
				targetId: admin._id,
			}, req);
		}
		return res.status(200).json({ success: successResult, password });

	} catch (e) {
		logger.error(e.message);
		return res.status(404).json({ error: "AdminAddError" });
	}
});

router.delete("/:id", guard.check("super"), [
	param("id", "Invalid id format").isMongoId()
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
		const admin = await Admin.findOne({ _id: new Types.ObjectId(values.id) });

		admin.remove();
		void AuditLog({
			type: "admin-deleted",
			adminId: res.locals.user._id,
			target: "admin",
			targetId: values.id,
		}, req);
		return res.status(200).json({ success: true });
	} catch (e) {
		logger.error("Error removing user");
		logger.error(e?.message);
		return res.status(404).json({ error: "AdminDeleteError" });
	}
});

router.post("/reset/:id", guard.check("super"), [
	param("id", "Invalid id format").isMongoId()
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
		const admin = await Admin.findOne({ _id: new Types.ObjectId(values.id) });

		void AuditLog({
			type: "admin-password-reset",
			adminId: res.locals.user._id,
			target: "admin",
			targetId: admin._id,
		}, req);

		const password = "CHANGE-" + Math.random().toString(36).slice(-10);
		admin.password = password;
		await admin.save();
		return res.status(200).json({ success: true, password });
	} catch (e) {
		logger.error(e.message);
		return res.status(404).json({ error: "AdminUpdateError" });
	}
});

router.post("/permissions/:id", guard.check("super"), [
	param("id", "Invalid id format").isMongoId(),
	body("permissions").isArray()
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

	if ( values.permissions.includes("super") && !res.locals.user.permissions.includes("super")) {
		return res.status(403).json({
			error: "InvalidPermissions",
			message: "Not allowed",
			errors: _.uniqWith(errors.array(), _.isEqual)
		});
	}

	try {
		void AuditLog({
			type: "admin-permissions",
			adminId: res.locals.user._id,
			target: "admin",
			targetId: values.id,
		}, req);

		const admin = await Admin.findOne({ _id: new Types.ObjectId(values.id) });

		admin.permissions = values.permissions;
		await admin.save();
		return res.status(200).json({ success: true });
	} catch (e) {
		logger.error(e.message);
		return res.status(404).json({ error: "AdminUpdateError" });
	}
});

router.get("/", guard.check("super"), async (req: express.Request, res: express.Response) => {
	try {
		void AuditLog({
			type: "admin-get",
			adminId: res.locals.user._id,
			target: "self",
		}, req);
		const admins = await Admin.find().sort("-createdAt").limit(3000).select("_id email createdAt updatedAt permissions");
		return res.json({
			success: true,
			admins
		});
	} catch (e) {
		logger.error(e.message);
		return res.status(500).json({
			error: "GeneralError"
		});
	}
});

export default router;
