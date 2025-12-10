import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";
dotenv.config();

// --------------------------------------------------
// CONFIG
// --------------------------------------------------
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "superSecretKey";

// --------------------------------------------------
// DATABASE CONNECTION
// --------------------------------------------------
const client = new MongoClient(process.env.MONGO_URI);

let Users, Clubs, Memberships, Events, Registrations, Payments;

async function dbConnect() {
  try {
    await client.connect();
    const db = client.db("clubsphereDB");

    Users = db.collection("users");
    Clubs = db.collection("clubs");
    Memberships = db.collection("memberships");
    Events = db.collection("events");
    Registrations = db.collection("registrations");
    Payments = db.collection("payments");

    console.log("MongoDB Connected Successfully!");
  } catch (err) {
    console.log("MongoDB Connection Failed:", err);
  }
}
dbConnect();

// --------------------------------------------------
// JWT MIDDLEWARE
// --------------------------------------------------
function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;

  const users = req.body;
  console.log(users);

  if (!authHeader)
    return res.status(401).json({ message: "Unauthorized: No token provided" });

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
}

// --------------------------------------------------
// ROLE MIDDLEWARE
// --------------------------------------------------
function verifyRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role)
      return res.status(403).json({ message: "Access denied" });
    next();
  };
}

// --------------------------------------------------
// AUTH API
// --------------------------------------------------
app.post("/api/auth/jwt", (req, res) => {
  const { email, name, role, photoURL } = req.body;

  const token = jwt.sign(
    { email, name, role: role || "member", photoURL },
    JWT_SECRET,
    { expiresIn: "1d" }
  );

  return res.json({ token });
});

// Save user to database (without authentication)
app.post("/api/users", async (req, res) => {
  try {
    const { email, name, password } = req.body;

    // Check if user already exists
    const existingUser = await Users.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists" });
    }

    // Create new user
    const newUser = {
      email,
      name,
      password,
      role: "member",
      createdAt: new Date(),
    };

    await Users.insertOne(newUser);
    res.status(201).json({ message: "User created successfully", email });
  } catch (err) {
    res.status(500).json({ message: "Error creating user", error: err });
  }
});

// Get User Role
app.get("/api/getRole/:email", verifyJWT, async (req, res) => {
  const userEmail = req.params.email;

  if (req.user.email !== userEmail) {
    return res.status(500).send("Unauthorized Access");
  }

  try {
    const user = await Users.findOne({ email: userEmail });
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Error creating user", error: err });
  }
});

// --------------------------------------------------
// USERS API
// --------------------------------------------------

// Admin – Get all users
app.get("/api/users", verifyJWT, verifyRole("admin"), async (req, res) => {
  try {
    const users = await Users.find().toArray();
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: "Error fetching users", error: err });
  }
});

// Admin – Update user role
app.patch(
  "/api/users/role/:email",
  verifyJWT,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const { role } = req.body;
      await Users.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { role } }
      );
      res.json({ message: "Role updated" });
    } catch (err) {
      res.status(500).json({ message: "Error updating role", error: err });
    }
  }
);

// Logged-in user info
app.get("/", async (req, res) => {
  res.send("user ok");
});

app.get("/api/users/me", verifyJWT, async (req, res) => {
  try {
    const user = await Users.findOne({ email: req.user.email });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: "Error fetching user", error: err });
  }
});

// --------------------------------------------------
// CLUB API
// --------------------------------------------------

// Create Club
app.post("/api/clubs", verifyJWT, async (req, res) => {
  const decoded_email = req.user.email;
  const creatorEmail = req.body.managerEmail;
  console.log(decoded_email, creatorEmail);

  if (decoded_email !== creatorEmail) {
    res.status(403).json({ message: "Unauthorized email" });
  }

  try {
    const clubData = {
      ...req.body,
      status: "pending",
      managerEmail: req.user.email,
      createdAt: new Date(),
    };

    await Clubs.insertOne(clubData);
    res.json({ message: "Club created, waiting for admin approval" });
  } catch (err) {
    res.status(500).json({ message: "Error creating club", error: err });
  }
});

// Public – List Approved Clubs
app.get("/api/clubs", async (req, res) => {
  try {
    const clubs = await Clubs.find({ status: "approved" }).toArray();
    res.json(clubs);
  } catch (err) {
    res.status(500).json({ message: "Error fetching clubs", error: err });
  }
});

// Get club details
app.get("/api/clubs/:id", async (req, res) => {
  try {
    const club = await Clubs.findOne({ _id: new ObjectId(req.params.id) });
    if (!club) {
      return res.status(404).json({ message: "Club not found" });
    }
    res.json(club);
  } catch (err) {
    res.status(500).json({ message: "Error fetching club", error: err });
  }
});

// Admin – Approve club
app.patch(
  "/api/clubs/approve/:id",
  verifyJWT,
  verifyRole("admin"),
  async (req, res) => {
    try {
      await Clubs.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { status: "approved" } }
      );

      res.json({ message: "Club approved!" });
    } catch (err) {
      res.status(500).json({ message: "Error approving club", error: err });
    }
  }
);

// Admin – Reject club
app.patch(
  "/api/clubs/reject/:id",
  verifyJWT,
  verifyRole("admin"),
  async (req, res) => {
    try {
      await Clubs.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { status: "rejected" } }
      );

      res.json({ message: "Club rejected!" });
    } catch (err) {
      res.status(500).json({ message: "Error rejecting club", error: err });
    }
  }
);

// Manager – Update Club
app.patch("/api/clubs/:id", verifyJWT, async (req, res) => {
  try {
    const club = await Clubs.findOne({ _id: new ObjectId(req.params.id) });

    if (!club) {
      return res.status(404).json({ message: "Club not found" });
    }

    if (club.managerEmail !== req.user.email)
      return res.status(403).json({ message: "Not your club" });

    await Clubs.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: req.body }
    );

    res.json({ message: "Club updated" });
  } catch (err) {
    res.status(500).json({ message: "Error updating club", error: err });
  }
});

// --------------------------------------------------
// MEMBERSHIP API
// --------------------------------------------------
app.post("/api/memberships", verifyJWT, async (req, res) => {
  try {
    const membership = {
      ...req.body,
      userEmail: req.user.email,
      status: "active",
      joinedAt: new Date(),
    };

    await Memberships.insertOne(membership);
    res.json({ message: "Membership added" });
  } catch (err) {
    res.status(500).json({ message: "Error adding membership", error: err });
  }
});

app.get("/api/memberships/user", verifyJWT, async (req, res) => {
  try {
    const memberships = await Memberships.find({
      userEmail: req.user.email,
    }).toArray();

    res.json(memberships);
  } catch (err) {
    res.status(500).json({ message: "Error fetching memberships", error: err });
  }
});

// --------------------------------------------------
// EVENTS API
// --------------------------------------------------
app.post("/api/events", verifyJWT, async (req, res) => {
  try {
    const event = {
      ...req.body,
      createdAt: new Date(),
    };

    await Events.insertOne(event);
    res.json({ message: "Event created!" });
  } catch (err) {
    res.status(500).json({ message: "Error creating event", error: err });
  }
});

app.get("/api/events", async (req, res) => {
  try {
    const events = await Events.find().toArray();
    res.json(events);
  } catch (err) {
    res.status(500).json({ message: "Error fetching events", error: err });
  }
});

app.get("/api/events/:id", async (req, res) => {
  try {
    const event = await Events.findOne({ _id: new ObjectId(req.params.id) });
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }
    res.json(event);
  } catch (err) {
    res.status(500).json({ message: "Error fetching event", error: err });
  }
});

// --------------------------------------------------
// EVENT REGISTRATION
// --------------------------------------------------
app.post("/api/registrations", verifyJWT, async (req, res) => {
  try {
    const reg = {
      ...req.body,
      userEmail: req.user.email,
      registeredAt: new Date(),
      status: "registered",
    };

    await Registrations.insertOne(reg);
    res.json({ message: "Event registration completed!" });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error registering for event", error: err });
  }
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
