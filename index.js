import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import fetch from "node-fetch";
import crypto from "crypto";
import admin from "firebase-admin";

import serviceAccount from "./serviceAccount.json" assert { type: "json" };

const app = express();
app.use(cors());
app.use(bodyParser.json());

// 🔥 Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();

const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET;

// ✅ Generate 10-digit User ID
function generateUserId() {
  return Math.floor(1000000000 + Math.random() * 9000000000).toString();
}

//
// ========== AUTH ==========
//

// ✅ Register User
app.post("/register", async (req, res) => {
  try {
    const { fullName, email, password, accountNumber, bankName, bankCode, country, age, pin, nin } = req.body;

    if (age < 18) return res.status(400).json({ error: "Must be 18 or older" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedPin = await bcrypt.hash(pin, 10);

    const userId = generateUserId();
    const uid = uuidv4();

    await db.collection("users").doc(uid).set({
      uid,
      userId,
      fullName,
      email,
      password: hashedPassword,
      accountNumber,
      bankName,
      bankCode,
      country,
      age,
      pin: hashedPin,
      nin,
      balance: 0,
      createdAt: Date.now(),
    });

    res.json({ message: "User registered", userId, uid });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const snap = await db.collection("users").where("email", "==", email).get();

    if (snap.empty) return res.status(404).json({ error: "User not found" });

    const user = snap.docs[0].data();
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    res.json({ message: "Login successful", uid: user.uid, userId: user.userId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

//
// ========== DEPOSIT ==========
//

// ✅ Deposit (initiate Paystack Checkout)
app.post("/deposit", async (req, res) => {
  try {
    const { uid, amount } = req.body;
    const fee = amount * 0.01; // 1%
    const netAmount = amount - fee;

    const user = (await db.collection("users").doc(uid).get()).data();
    if (!user) return res.status(404).json({ error: "User not found" });

    // Create Paystack payment
    const response = await fetch("https://api.paystack.co/transaction/initialize", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: user.email,
        amount: amount * 100, // kobo/cents
        currency: "NGN", // 👈 default, change dynamically later if needed
      }),
    });

    const data = await response.json();
    if (!data.status) throw new Error(data.message);

    res.json({ authorizationUrl: data.data.authorization_url, fee, netAmount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

//
// ========== WITHDRAW ==========
//

// ✅ Withdraw with Paystack Payout
app.post("/withdraw", async (req, res) => {
  try {
    const { uid, amount, pin } = req.body;
    const fee = amount * 0.05; // 5%
    const total = amount + fee;

    const ref = db.collection("users").doc(uid);
    const user = (await ref.get()).data();

    if (!user) return res.status(404).json({ error: "User not found" });

    const pinValid = await bcrypt.compare(pin, user.pin);
    if (!pinValid) return res.status(401).json({ error: "Invalid PIN" });
    if (user.balance < total) return res.status(400).json({ error: "Insufficient balance" });

    // 1️⃣ Create transfer recipient
    const recipientRes = await fetch("https://api.paystack.co/transferrecipient", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        type: "nuban",
        name: user.fullName,
        account_number: user.accountNumber,
        bank_code: user.bankCode,
        currency: "NGN", // adjust for country if needed
      }),
    });

    const recipientData = await recipientRes.json();
    if (!recipientData.status) throw new Error(recipientData.message);

    const recipientCode = recipientData.data.recipient_code;

    // 2️⃣ Initiate transfer
    const transferRes = await fetch("https://api.paystack.co/transfer", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        source: "balance",
        amount: amount * 100, // kobo/cents
        recipient: recipientCode,
        reason: "Hitcoin Withdrawal",
      }),
    });

    const transferData = await transferRes.json();
    if (!transferData.status) throw new Error(transferData.message);

    // 3️⃣ Deduct balance
    await ref.update({ balance: user.balance - total });

    // 4️⃣ Log transaction
    await db.collection("transactions").add({
      uid,
      type: "withdraw",
      amount,
      fee,
      status: "pending",
      paystackRef: transferData.data.reference,
      timestamp: Date.now(),
    });

    res.json({ message: "Withdrawal initiated", fee, remaining: user.balance - total });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

//
// ========== TRANSFER ==========
//

// ✅ Transfer coins between users
app.post("/transfer", async (req, res) => {
  try {
    const { fromUid, toUserId, amount, pin } = req.body;
    const fee = amount * 0.07; // 7%
    const total = amount + fee;

    const fromRef = db.collection("users").doc(fromUid);
    const fromUser = (await fromRef.get()).data();

    if (!fromUser) return res.status(404).json({ error: "Sender not found" });

    const pinValid = await bcrypt.compare(pin, fromUser.pin);
    if (!pinValid) return res.status(401).json({ error: "Invalid PIN" });
    if (fromUser.balance < total) return res.status(400).json({ error: "Insufficient balance" });

    const snap = await db.collection("users").where("userId", "==", toUserId).get();
    if (snap.empty) return res.status(404).json({ error: "Recipient not found" });

    const toRef = snap.docs[0].ref;
    const toUser = snap.docs[0].data();

    // Deduct + credit
    await fromRef.update({ balance: fromUser.balance - total });
    await toRef.update({ balance: toUser.balance + amount });

    await db.collection("transactions").add({
      from: fromUser.userId,
      to: toUser.userId,
      type: "transfer",
      amount,
      fee,
      timestamp: Date.now(),
    });

    res.json({ message: "Transfer successful", fee, remaining: fromUser.balance - total });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

//
// ========== TRANSACTIONS ==========
//

// ✅ Get user transactions
app.get("/transactions/:uid", async (req, res) => {
  try {
    const { uid } = req.params;
    const snap = await db.collection("transactions").where("uid", "==", uid).get();

    const txs = snap.docs.map(doc => doc.data());
    res.json(txs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

//
// ========== BANKS API ==========
//

// ✅ Get banks for any Paystack-supported country
let cachedBanks = {};
let lastFetched = {};

app.get("/banks", async (req, res) => {
  try {
    const country = req.query.country || "NG"; // Default Nigeria
    const now = Date.now();

    if (cachedBanks[country] && now - lastFetched[country] < 24 * 60 * 60 * 1000) {
      return res.json(cachedBanks[country]);
    }

    const response = await fetch(`https://api.paystack.co/bank?country=${country}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` },
    });

    const data = await response.json();
    if (!data.status) throw new Error("Failed to fetch banks");

    cachedBanks[country] = data.data.map(bank => ({
      name: bank.name,
      code: bank.code,
    }));
    lastFetched[country] = now;

    res.json(cachedBanks[country]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

//
// ========== WEBHOOK ==========
//

// ✅ Paystack Webhook
app.post("/paystack/webhook", async (req, res) => {
  try {
    const hash = crypto
      .createHmac("sha512", PAYSTACK_SECRET)
      .update(JSON.stringify(req.body))
      .digest("hex");

    if (hash !== req.headers["x-paystack-signature"]) {
      return res.status(401).send("Invalid signature");
    }

    const event = req.body.event;

    // 🔹 Deposit confirmation
    if (event === "charge.success") {
      const { reference, amount, customer } = req.body.data;

      const snap = await db.collection("users").where("email", "==", customer.email).get();
      if (!snap.empty) {
        const userRef = snap.docs[0].ref;
        const user = snap.docs[0].data();

        await userRef.update({ balance: user.balance + amount / 100 });
        await db.collection("transactions").add({
          uid: user.uid,
          type: "deposit",
          amount: amount / 100,
          fee: amount * 0.01,
          status: "success",
          paystackRef: reference,
          timestamp: Date.now(),
        });
      }
    }

    // 🔹 Withdrawal success
    if (event === "transfer.success") {
      const { reference } = req.body.data;

      const snap = await db.collection("transactions").where("paystackRef", "==", reference).get();
      if (!snap.empty) {
        const txRef = snap.docs[0].ref;
        await txRef.update({ status: "success" });
      }
    }

    // 🔹 Withdrawal failed
    if (event === "transfer.failed") {
      const { reference } = req.body.data;

      const snap = await db.collection("transactions").where("paystackRef", "==", reference).get();
      if (!snap.empty) {
        const tx = snap.docs[0].data();
        const userRef = db.collection("users").doc(tx.uid);
        const user = (await userRef.get()).data();

        // Refund
        await userRef.update({ balance: user.balance + tx.amount + tx.fee });
        await snap.docs[0].ref.update({ status: "failed" });
      }
    }

    res.sendStatus(200);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

//
// ========== START SERVER ==========
//

app.listen(4000, () => console.log("🚀 Backend running on http://localhost:4000"));
