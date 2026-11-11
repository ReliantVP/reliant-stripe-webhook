const crypto = require("node:crypto");

module.exports.config = { api: { bodyParser: false } };

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  if (process.env.STRIPE_SANDBOX_ENABLED !== "true") {
    return res.status(503).json({ error: "Sandbox disabled" });
  }
  const secret = process.env.STRIPE_SANDBOX_WEBHOOK_SECRET || "";
  if (!secret.startsWith("whsec_")) {
    return res.status(503).json({ error: "Sandbox signing secret not configured" });
  }
  const header = String(req.headers["stripe-signature"] || "");
  const fields = header.split(",").map(part => part.trim());
  const timestamp = fields.find(part => part.startsWith("t="))?.slice(2);
  const signatures = fields.filter(part => part.startsWith("v1=")).map(part => part.slice(3));
  if (!timestamp || !/^\d+$/.test(timestamp) || Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) {
    return res.status(400).json({ error: "Invalid Stripe signature" });
  }
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  const payload = Buffer.concat(chunks);
  const expected = crypto.createHmac("sha256", secret).update(timestamp + ".").update(payload).digest();
  const verified = signatures.some(value => {
    if (!/^[0-9a-f]{64}$/i.test(value)) return false;
    const received = Buffer.from(value, "hex");
    return received.length === expected.length && crypto.timingSafeEqual(received, expected);
  });
  if (!verified) return res.status(400).json({ error: "Invalid Stripe signature" });

  let event;
  try { event = JSON.parse(payload.toString("utf8")); }
  catch { return res.status(400).json({ error: "Invalid event JSON" }); }
  if (!event.id || !event.type || event.livemode !== false) {
    return res.status(400).json({ error: "Expected sandbox Stripe event" });
  }
  const session = event.data?.object || {};
  if (event.type === "checkout.session.completed" || event.type === "checkout.session.async_payment_succeeded") {
    if (session.mode !== "payment" ||
        session.metadata?.reliant_mode !== "internal_sandbox_test_no_coverage" ||
        session.metadata?.contract_issuance !== "disabled" ||
        session.amount_total !== 100 || session.currency !== "usd") {
      console.info("Ignored unmatched sandbox session", { eventId: event.id, type: event.type });
      return res.status(200).json({ received: true, ignored: true });
    }
    if (session.payment_status !== "paid") {
      console.info("Sandbox session not yet paid", { eventId: event.id, sessionId: session.id });
      return res.status(200).json({ received: true, paymentVerified: false });
    }
    console.info("Verified Reliant sandbox payment", {
      eventId: event.id, sessionId: session.id, amountCents: 100,
      currency: "usd", coverageIssued: false
    });
    return res.status(200).json({ received: true, paymentVerified: true, coverageIssued: false });
  }
  return res.status(200).json({ received: true });
};
module.exports.config = { api: { bodyParser: false } };
