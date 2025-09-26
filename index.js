import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import crypto from "crypto";
import { buffer } from "micro";
import fetch from "node-fetch";
import { initializeApp } from "firebase/app";
import { getFirestore, doc, setDoc, getDoc, updateDoc, runTransaction, collection, query, where, getDocs } from "firebase/firestore";

// --- Firebase Setup ---
const firebaseConfig = {
  apiKey: process.env.FB_API_KEY,
  authDomain: process.env.FB_AUTH_DOMAIN,
  projectId: process.env.FB_PROJECT_ID,
  storageBucket: process.env.FB_STORAGE_BUCKET,
  messagingSenderId: process.env.FB_MSG_SENDER,
  appId: process.env.FB_APP_ID,
};
const appFB = initializeApp(firebaseConfig);
const db = getFirestore(appFB);

// --- Helpers ---
function generateUserId() {
  return Math.floor(1000000000 + Math.random() * 9000000000).toString(); // 10-digit
}
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET;
const PAYSTACK_BASE = "https://api.paystack.co";

// --- API Handler ---
export default async function handler(req, res) {
  const { method, url } = req;

  try {
    // --- REGISTER ---
    if (method === "POST" && url.includes("/register")) {
      const { uid, email, pin, bankName, accountNumber } = req.body;
      if (!uid || !email || !pin || !bankName || !accountNumber) {
        return res.status(400).json({ error: "Missing fields" });
      }

      const userId = generateUserId();
      const pinHash = await bcrypt.hash(pin, 10);

      await setDoc(doc(db, "users", uid), {
        userId,
        email,
        balance: 0,
        pinHash,
        bankName,
        accountNumber,
        createdAt: new Date(),
      });

      return res.json({ message: "User created", userId });
    }

    // --- BALANCE ---
    if (method === "GET" && url.includes("/balance")) {
      const { uid } = req.query;
      const snapshot = await getDoc(doc(db, "users", uid));
      if (!snapshot.exists()) return res.status(404).json({ error: "User not found" });
      return res.json({ balance: snapshot.data().balance, userId: snapshot.data().userId });
    }

    // --- TRANSFER ---
    if (method === "POST" && url.includes("/transfer")) {
      const { senderUid, recipientUserId, amount, pin } = req.body;
      await runTransaction(db, async (transaction) => {
        const senderRef = doc(db, "users", senderUid);
        const senderDoc = await transaction.get(senderRef);
        if (!senderDoc.exists()) throw "Sender not found";
        const senderData = senderDoc.data();

        const validPin = await bcrypt.compare(pin, senderData.pinHash);
        if (!validPin) throw "Invalid PIN";
        if (senderData.balance < amount) throw "Insufficient balance";

        const q = query(collection(db, "users"), where("userId", "==", recipientUserId));
        const recSnap = await getDocs(q);
        if (recSnap.empty) throw "Recipient not found";

        const recipientRef = recSnap.docs[0].ref;
        const recipientData = recSnap.docs[0].data();

        transaction.update(senderRef, { balance: senderData.balance - amount });
        transaction.update(recipientRef, { balance: recipientData.balance + amount });

        const txnRef = doc(db, "transactions", uuidv4());
        transaction.set(txnRef, {
          fromUserId: senderData.userId,
          toUserId: recipientUserId,
          amount,
          type: "transfer",
          status: "success",
          timestamp: new Date(),
        });
      });
      return res.json({ message: "Transfer successful" });
    }

    // --- DEPOSIT INIT ---
    if (method === "POST" && url.includes("/deposit")) {
      const { uid, amount } = req.body;
      const userDoc = await getDoc(doc(db, "users", uid));
      if (!userDoc.exists()) return res.status(404).json({ error: "User not found" });
      const user = userDoc.data();

      const response = await fetch(`${PAYSTACK_BASE}/transaction/initialize`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: user.email,
          amount: amount * 100, // Paystack expects kobo
          metadata: { uid },
        }),
      });
      const data = await response.json();
      return res.json(data);
    }

    // --- WITHDRAW ---
    if (method === "POST" && url.includes("/withdraw")) {
      const { uid, amount, pin } = req.body;
      const userRef = doc(db, "users", uid);
      const userDoc = await getDoc(userRef);
      if (!userDoc.exists()) return res.status(404).json({ error: "User not found" });
      const user = userDoc.data();

      const validPin = await bcrypt.compare(pin, user.pinHash);
      if (!validPin) return res.status(401).json({ error: "Invalid PIN" });
      if (user.balance < amount) return res.status(400).json({ error: "Insufficient balance" });

      // Call Paystack transfer
      const response = await fetch(`${PAYSTACK_BASE}/transfer`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          source: "balance",
          amount: amount * 100,
          recipient: {
            type: "nuban",
            name: user.email,
            bank_code: user.bankName, // You must map to Paystack bank codes
            account_number: user.accountNumber,
          },
          reason: "Hitcoin Withdrawal",
          metadata: { uid },
        }),
      });

      const data = await response.json();
      return res.json(data);
    }

    // --- TRANSACTIONS ---
    if (method === "GET" && url.includes("/transactions")) {
      const { userId } = req.query;
      const q1 = query(collection(db, "transactions"), where("fromUserId", "==", userId));
      const q2 = query(collection(db, "transactions"), where("toUserId", "==", userId));

      const [sentSnap, receivedSnap] = await Promise.all([getDocs(q1), getDocs(q2)]);
      const transactions = [];
      sentSnap.forEach((doc) => transactions.push(doc.data()));
      receivedSnap.forEach((doc) => transactions.push(doc.data()));

      return res.json({ transactions });
    }

    // --- PAYSTACK WEBHOOK ---
    if (method === "POST" && url.includes("/paystack/webhook")) {
      const rawBody = await buffer(req);
      const signature = req.headers["x-paystack-signature"];
      const hash = crypto.createHmac("sha512", PAYSTACK_SECRET).update(rawBody).digest("hex");
      if (hash !== signature) return res.status(401).json({ error: "Invalid signature" });

      const event = JSON.parse(rawBody.toString());

      if (event.event === "charge.success") {
        const { amount, metadata } = event.data;
        const uid = metadata.uid;

        await runTransaction(db, async (transaction) => {
          const userRef = doc(db, "users", uid);
          const userDoc = await transaction.get(userRef);
          if (!userDoc.exists()) throw "User not found";
          const user = userDoc.data();

          transaction.update(userRef, { balance: user.balance + amount / 100 });

          const txnRef = doc(db, "transactions", uuidv4());
          transaction.set(txnRef, {
            fromUserId: "TREASURY",
            toUserId: user.userId,
            amount: amount / 100,
            type: "deposit",
            status: "success",
            timestamp: new Date(),
          });
        });
      }

      if (event.event === "transfer.success") {
        const { amount, metadata } = event.data;
        const uid = metadata.uid;

        await runTransaction(db, async (transaction) => {
          const userRef = doc(db, "users", uid);
          const userDoc = await transaction.get(userRef);
          if (!userDoc.exists()) throw "User not found";
          const user = userDoc.data();

          transaction.update(userRef, { balance: user.balance - amount / 100 });

          const txnRef = doc(db, "transactions", uuidv4());
          transaction.set(txnRef, {
            fromUserId: user.userId,
            toUserId: "TREASURY",
            amount: amount / 100,
            type: "withdraw",
            status: "success",
            timestamp: new Date(),
          });
        });
      }

      return res.json({ status: "Webhook received" });
    }

    return res.status(404).json({ error: "Not found" });
  } catch (err) {
    return res.status(400).json({ error: err.toString() });
  }
}

// --- Next.js API Config ---
export const config = {
  api: {
    bodyParser: false, // required for Paystack raw body
  },
};
