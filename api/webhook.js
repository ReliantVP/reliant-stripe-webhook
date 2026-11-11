const crypto = require("node:crypto");

async function recordEvent(record) {
  const url = process.env.SUPABASE_URL || "";
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
  if (!/^https:\/\/[^/]+\.supabase\.co\/?$/.test(url) || !key) {
    throw new Error("Supabase sandbox ledger is not configured");
  }
  const response = await fetch(url.replace(/\/$/, "") + "/rest/v1/reliant_stripe_sandbox_events?on_conflict=stripe_event_id", {
    method: "POST",
    headers: {
      "apikey": key,
      "Authorization": "Bearer " + key,
      "Content-Type": "application/json",
      "Prefer": "resolution=ignore-duplicates,return=minimal"
    },
    body: JSON.stringify(record),
    signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) {
    console.error("Stripe sandbox ledger write failed", { status: response.status });
    throw new Error("Sandbox ledger write failed");
  }
}



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
    const matched = session.mode === "payment" &&
      session.metadata?.reliant_mode === "internal_sandbox_test_no_coverage" &&
      session.metadata?.contract_issuance === "disabled" &&
      session.amount_total === 100 && session.currency === "usd";
    const paymentStatus = !matched ? "ignored" : session.payment_status === "paid" ? "paid" : "unpaid";
    try {
      await recordEvent({
        stripe_event_id: event.id,
        stripe_session_id: typeof session.id === "string" ? session.id : null,
        event_type: event.type,
        payment_status: paymentStatus,
        amount_cents: Number.isInteger(session.amount_total) ? session.amount_total : null,
        currency: typeof session.currency === "string" ? session.currency : null,
        sandbox_reference: typeof session.metadata?.sandbox_reference === "string" ? session.metadata.sandbox_reference : null,
        coverage_tier: typeof session.metadata?.coverage_tier === "string" ? session.metadata.coverage_tier : null,
        vehicle_label: typeof session.metadata?.vehicle_label === "string" ? session.metadata.vehicle_label : null,
        quote_term_months: /^\\d+$/.test(session.metadata?.quote_term_months || "") ? Number(session.metadata.quote_term_months) : null,
        quote_term_miles: /^\\d+$/.test(session.metadata?.quote_term_miles || "") ? Number(session.metadata.quote_term_miles) : null,
        quoted_retail_cents: /^\\d+$/.test(session.metadata?.quoted_retail_cents || "") ? Number(session.metadata.quoted_retail_cents) : null,
        coverage_issued: false
      });
    } catch (error) {
      console.error("Sandbox payment event not acknowledged because persistence failed", { eventId: event.id });
      return res.status(503).json({ error: "Payment event storage unavailable" });
    }
    console.info("Recorded Stripe sandbox event", { eventId: event.id, sessionId: session.id, paymentStatus, coverageIssued: false });
    return res.status(200).json({ received: true, paymentVerified: paymentStatus === "paid", coverageIssued: false });
  }
  return res.status(200).json({ received: true });
};
module.exports.config = { api: { bodyParser: false } };
