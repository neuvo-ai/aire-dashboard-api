import express from "express";
import bots from "./routes/bots";
import botcreds from "./routes/bot-creds";
import admin from "./routes/admin";
import audits from "./routes/audits";
import botlist from "./routes/botlist";

const app = express();

app.disable("x-powered-by");

app.use((err: express.Errback, req: express.Request, res: express.Response, next: express.NextFunction) => {
	res.status(500);
	res.json({ error: err });
	next();
});

app.use("/bots", bots);
app.use("/bot-creds", botcreds);
app.use("/admin", admin);
app.use("/audits", audits);
app.use("/public", botlist);

export default app;