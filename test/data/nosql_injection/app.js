const express = require("express");
const { MongoClient } = require("mongodb");

const MONGO_URL = process.env.MONGO_URL || "mongodb://nosql-injection-test-mongo:27017";
const DB_NAME = "testdb";
const PORT = 3000;

async function connectWithRetry() {
  for (;;) {
    try {
      const client = new MongoClient(MONGO_URL, { serverSelectionTimeoutMS: 2000 });
      await client.connect();
      await client.db(DB_NAME).command({ ping: 1 });
      return client;
    } catch (err) {
      console.log("Waiting for MongoDB:", err.message);
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
}

async function seed(db) {
  const items = db.collection("items");
  if ((await items.countDocuments()) === 0) {
    await items.insertMany([
      { q: "first post", title: "First", content: "hello world", id: 1 },
      { q: "second post", title: "Second", content: "another entry", id: 2 },
    ]);
  }
  const users = db.collection("users");
  if ((await users.countDocuments()) === 0) {
    await users.insertMany([
      { username: "admin", password: "s3cret" },
      { username: "alice", password: "password123" },
    ]);
  }
}

function pageHtml(count) {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>NoSQL Injection Test App</title></head>
<body>
<h1>Item search</h1>
<form method="get" action="/">
  <input name="q" placeholder="search text">
  <input name="id" placeholder="item id">
  <button type="submit">Search</button>
</form>
<form method="post" action="/api/login">
  <input name="username" placeholder="username">
  <input name="password" placeholder="password">
  <button type="submit">Log in</button>
</form>
<p>${count} item(s) found.</p>
<ul>
  <li><a href="/not_vuln?id=1">safe endpoint</a></li>
  <li><a href="/noisy">verbose endpoint</a></li>
  <li><a href="/blind?q=first">error-swallowing endpoint</a></li>
</ul>
</body>
</html>`;
}

async function main() {
  const client = await connectWithRetry();
  const db = client.db(DB_NAME);
  await seed(db);

  const app = express();
  app.use(express.json());

  app.get("/", async (req, res) => {
    try {
      const results = await db.collection("items").find(req.query).toArray();
      res.type("html").send(pageHtml(results.length));
    } catch (err) {
      res.status(500).type("text/plain").send(String(err));
    }
  });

  app.post("/", async (req, res) => {
    try {
      const results = await db.collection("items").find(req.body || {}).toArray();
      res.type("application/json").send(JSON.stringify({ count: results.length }));
    } catch (err) {
      res.status(500).type("text/plain").send(String(err));
    }
  });

  app.post("/api/login", async (req, res) => {
    try {
      const user = await db.collection("users").findOne(req.body || {});
      res.type("application/json").send(JSON.stringify({ authenticated: Boolean(user) }));
    } catch (err) {
      res.status(500).type("text/plain").send(String(err));
    }
  });

  app.get("/blind", async (req, res) => {
    try {
      const results = await db.collection("items").find(req.query).toArray();
      res.type("application/json").send(JSON.stringify(results));
    } catch (err) {
      res.type("application/json").send("[]");
    }
  });

  app.get("/not_vuln", async (req, res) => {
    const filter = {};
    for (const key of Object.keys(req.query)) {
      filter[key] = String(req.query[key]);
    }
    const results = await db.collection("items").find(filter).toArray();
    res.type("application/json").send(JSON.stringify({ count: results.length }));
  });

  app.get("/noisy", (req, res) => {
    res.type("html").send("<p>Status errmsg: none. Last CastError: none. ValidationError: none.</p>");
  });

  app.listen(PORT, () => console.log(`listening on ${PORT}`));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
