// api/quote.js
import { spawn } from "child_process";

export default async function handler(req, res) {
  const symbols = req.query.symbols || "AAPL,MSFT";
  const py = spawn("python3", ["api/quote.py", symbols]);

  let data = "";
  py.stdout.on("data", (chunk) => (data += chunk));
  py.on("close", () => res.status(200).send(data));
}
