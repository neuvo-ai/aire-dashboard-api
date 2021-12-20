import express from "express";
import { query, validationResult, matchedData } from "express-validator";

const router = express.Router();
import logger from "../logger";
import _ from "lodash";
import { Audit } from "../models/audit";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const guard = require("express-jwt-permissions")();

router.get("/audits", guard.check("super"), [
	query("limit", "Invalid value").isNumeric({ no_symbols: true }).custom(value => (value <= 10000))
], (req: express.Request, res: express.Response) => {
	const errors = validationResult(req);
	const values = matchedData(req);

	if (!errors.isEmpty()) {
		return res.status(400).json({
			error: "ValidatingError",
			message: "Validating parameters failed",
			errors: _.uniqWith(errors.array(), _.isEqual)
		});
	}
	// Auditing needs overhaul
	Audit.aggregate([
		{
			"$sort": {
				"createdAt": -1
		  	}
		}, {
		  	"$limit": parseInt(values.limit, 10)
		}, {
		  	"$lookup": {
				"from": "admins",
				"localField": "adminId",
				"foreignField": "_id",
				"as": "admin"
		  	}
		}, {
		  	"$unwind": {
				"path": "$admin",
				"preserveNullAndEmptyArrays": true
		  	}
		}, {
		  	"$lookup": {
				"from": "admins",
				"localField": "targetId",
				"foreignField": "_id",
				"as": "targetAdmin"
		  	}
		}, {
		  	"$unwind": {
				"path": "$targetAdmin",
				"preserveNullAndEmptyArrays": true
		  	}
		}, {
		  	"$addFields": {
				"admin": "$admin.email",
				"targetValue": {
			  		"$switch": {
						"branches": [
				  			{
								"case": {
					  				"$eq": [
										"$target", "admin"
					  				]
								},
								"then": "$targetAdmin.email"
				  			}
						],
						"default": ""
			  		}
				}
		  	}
		}, {
		  	"$unset": [
				"targetAdmin"
		  	]
		}
	]).then((documents: any) => {
		return res.status(200).json(documents);
	}).catch((err: any) => {
		logger.error("Error fetching audits");
		logger.error(err?.message);
		return res.status(500).send("Error");
	});
});

export default router;
