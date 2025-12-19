import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";
dotenv.config();
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET);
import admin from "firebase-admin";

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
    // await client.connect();
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

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// --------------------------------------------------
// JWT MIDDLEWARE
// --------------------------------------------------
function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;

  const users = req.body;

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
// FIREBASE TOKEN VERIFICATION MIDDLEWARE
// --------------------------------------------------
async function verifyFirebaseToken(req, res, next) {
  try {
    if (!firebaseInitialized) {
      // Fall back to JWT verification
      return verifyJWT(req, res, next);
    }

    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ message: "Unauthorized: No Firebase token provided" });
    }

    const idToken = authHeader.split("Bearer ")[1];

    // Verify Firebase token
    const decodedToken = await admin.auth().verifyIdToken(idToken);

    // Get user from database or create if doesn't exist
    let user = await Users.findOne({ email: decodedToken.email });

    if (!user) {
      // Auto-create user from Firebase data
      const newUser = {
        email: decodedToken.email,
        name: decodedToken.name || "User",
        photoURL: decodedToken.picture || "",
        role: "member",
        createdAt: new Date(),
      };

      await Users.insertOne(newUser);
      user = newUser;
    }

    req.user = {
      email: user.email,
      name: user.name,
      role: user.role,
      photoURL: user.photoURL,
      uid: decodedToken.uid,
    };

    next();
  } catch (error) {
    console.error("Firebase token verification error:", error);
    // Fall back to JWT verification
    return verifyJWT(req, res, next);
  }
}

// --------------------------------------------------
// ROLE MIDDLEWARE
// --------------------------------------------------
function verifyRole(role) {
  return (req, res, next) => {
    const user = req.user;

    if (req.user.role !== role)
      return res.status(403).json({ message: "Access denied" });
    next();
  };
}

// --------------------------------------------------
// PAYMENT INTEGRATION
// --------------------------------------------------

const YOUR_DOMAIN = process.env.BASE_DOMAIN || "http://localhost:5173";

app.post("/api/create-checkout-session", verifyJWT, async (req, res) => {
  const { clubName, email, cost, clubId, description } = req.body;
  const amount = parseInt(cost) * 100;
  const session = await stripe.checkout.sessions.create({
    line_items: [
      {
        price_data: {
          currency: "usd",
          unit_amount: amount,
          product_data: {
            name: clubName,
            description: description,
          },
        },
        quantity: 1,
      },
    ],
    customer_email: email,
    mode: "payment",
    metadata: {
      productId: clubId,
      type: "membership",
    },
    success_url: `${YOUR_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${YOUR_DOMAIN}/dashboard/payment-cancel`,
  });

  res.send(session.url);
});

// Event Payment Checkout Session
app.post("/api/create-event-checkout-session", verifyJWT, async (req, res) => {
  const { eventTitle, email, fee, eventId, description } = req.body;
  const amount = parseInt(fee) * 100;
  const session = await stripe.checkout.sessions.create({
    line_items: [
      {
        price_data: {
          currency: "usd",
          unit_amount: amount,
          product_data: {
            name: eventTitle,
            description: description,
          },
        },
        quantity: 1,
      },
    ],
    customer_email: email,
    mode: "payment",
    metadata: {
      productId: eventId,
      type: "event",
    },
    success_url: `${YOUR_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${YOUR_DOMAIN}/dashboard/payment-cancel`,
  });

  res.send(session.url);
});

app.patch("/api/payment/verify", verifyJWT, async (req, res) => {
  try {
    const { session_id } = req.query;

    if (!session_id) {
      return res.status(400).json({ message: "Session ID required" });
    }

    const session = await stripe.checkout.sessions.retrieve(session_id);

    // 2️⃣ Ensure payment is successful
    if (session.payment_status !== "paid") {
      return res.status(400).json({ message: "Payment not completed" });
    }

    const productId = session.metadata.productId;
    const paymentType = session.metadata.type || "membership";

    if (paymentType === "membership") {
      // Handle membership payment
      const clubId = productId;

      // 3️⃣ Prevent duplicate membership
      const existingMembership = await Memberships.findOne({
        userEmail: req.user.email,
        clubId: new ObjectId(clubId),
        status: "active",
      });

      if (existingMembership) {
        return res.json({
          message: "Membership already exists",
          membership: existingMembership,
        });
      }

      // 4️⃣ Create membership
      const membershipDoc = {
        userEmail: req.user.email,
        clubId: new ObjectId(clubId),
        status: "active",
        paymentId: session.payment_intent,
        paymentType: "paid",
        joinedAt: new Date(),
        expiresAt: null,
      };

      await Memberships.insertOne(membershipDoc);

      // 5️⃣ Save payment history
      await Payments.insertOne({
        userEmail: req.user.email,
        amount: session.amount_total / 100,
        type: "membership",
        clubId: new ObjectId(clubId),
        stripePaymentIntentId: session.payment_intent,
        status: "paid",
        createdAt: new Date(),
      });

      res.json({
        message: "Payment verified & membership activated",
        membership: membershipDoc,
      });
    } else if (paymentType === "event") {
      // Handle event payment
      const eventId = productId;

      // Check if already registered
      const existingRegistration = await Registrations.findOne({
        userEmail: req.user.email,
        eventId: new ObjectId(eventId),
        status: "registered",
      });

      if (existingRegistration) {
        return res.json({
          message: "Already registered for this event",
          registration: existingRegistration,
        });
      }

      // Create event registration
      const registrationDoc = {
        userEmail: req.user.email,
        eventId: new ObjectId(eventId),
        status: "registered",
        paymentId: session.payment_intent,
        paymentType: "paid",
        registeredAt: new Date(),
      };

      await Registrations.insertOne(registrationDoc);

      // Save payment history
      await Payments.insertOne({
        userEmail: req.user.email,
        amount: session.amount_total / 100,
        type: "event",
        eventId: new ObjectId(eventId),
        stripePaymentIntentId: session.payment_intent,
        status: "paid",
        createdAt: new Date(),
      });

      res.json({
        message: "Payment verified & event registration completed",
        registration: registrationDoc,
      });
    } else {
      return res.status(400).json({ message: "Unknown payment type" });
    }
  } catch (err) {
    res
      .status(500)
      .json({ message: "Payment verification failed", error: err });
  }
});
app.get("/api/payment-user/:id", verifyJWT, async (req, res) => {
  try {
    const email = req.user.email;
    const clubId = req.params.id;

    const result = await Payments.findOne({
      userEmail: email,
      clubId: new ObjectId(clubId),
    });

    if (!result) {
      return res.status(404).json({ message: "No payment found" });
    }

    res.json(result);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/payment-users/:clubId", async (req, res) => {
  const clubId = req.params.clubId;
  const query = { clubId: new ObjectId(clubId) };

  const totalUsers = await Payments.countDocuments(query);

  res.json({ totalUsers });
});

// --------------------------------------------------
// AUTH API
// --------------------------------------------------
app.post("/api/auth/jwt", async (req, res) => {
  try {
    const { email, name, photoURL } = req.body;

    // Check if user exists, if not create them
    let user = await Users.findOne({ email });

    if (!user) {
      // Auto-create user from Firebase data
      const newUser = {
        email,
        name: name || "User",
        photoURL: photoURL || "",
        role: "member",
        createdAt: new Date(),
      };

      await Users.insertOne(newUser);
      user = newUser;
    }

    const token = jwt.sign(
      {
        email: user.email,
        name: user.name,
        role: user.role,
        photoURL: user.photoURL,
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({ token });
  } catch (err) {
    console.error("JWT generation error:", err);
    return res
      .status(500)
      .json({ message: "Error generating token", error: err });
  }
});

// Save user to database (without authentication) - for manual registration
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
      password, // Note: In production, this should be hashed
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
  "/api/users/update-role/:id",
  verifyJWT,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const { role } = req.body;
      const id = req.params.id;
      if (!id) return res.status(400).json({ message: "Missing id parameter" });

      const result = await Users.updateOne(
        { _id: new ObjectId(id) },
        { $set: { role } }
      );
      if (result.matchedCount === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json({ message: "Role updated" });
    } catch (err) {
      res.status(500).json({ message: "Error updating role", error: err });
    }
  }
);
// Update Member Role Api
const updateUser = async (req, res, next) => {
  try {
    const email = req.user?.email;
    if (!email) return next();

    // 1. Get current user from DB
    const user = await Users.findOne({ email });

    if (!user) {
      return next();
    }

    // 2. Prevent overwriting admin role
    if (user.role === "admin") {
      return next();
    }

    // 3. If user is already manager, do not update
    if (user.role === "manager") {
      return next();
    }

    // 4. If user is member, upgrade to manager
    if (user.role === "member") {
      await Users.updateOne({ email }, { $set: { role: "manager" } });

      req.user.role = "manager";
    }

    next();
  } catch (error) {
    next(error);
  }
};
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

// DELETE User
app.delete("/api/users/:id", async (req, res) => {
  try {
    const result = await Users.deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ message: "User Deleted Successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error fetching user", error: err });
  }
});

// --------------------------------------------------
// CLUB API
// --------------------------------------------------

// Create Club
app.post("/api/clubs", verifyJWT, updateUser, async (req, res) => {
  const decoded_email = req.user.email;
  const creatorEmail = req.body.managerEmail;

  if (decoded_email !== creatorEmail) {
    return res.status(403).json({ message: "Unauthorized email" });
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

app.get("/api/clubs/:email", verifyJWT, async (req, res) => {
  if (req.user.email !== req.params.email) {
    return res.status(403).json({ message: "Unauthorized access!" });
  }
  try {
    const { search, status } = req.query;
    let query = { managerEmail: req.params.email };

    // Add status filter if provided
    if (status && status !== "all") {
      query.status = status;
    }

    // Add search filter if provided
    if (search) {
      query.$or = [
        { clubName: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
        { category: { $regex: search, $options: "i" } },
      ];
    }

    const clubs = await Clubs.find(query).toArray();
    res.json(clubs);
  } catch (err) {
    res.status(500).json({ message: "Error fetching clubs", error: err });
  }
});
// Public – List Approved Clubs with search/filter/sorting
app.get("/api/clubs", async (req, res) => {
  try {
    const {
      search,
      category,
      sortBy = "createdAt",
      sortOrder = "desc",
      page = 1,
      limit = 10,
    } = req.query;
    let query = { status: "approved" };

    // Add search filter
    if (search) {
      query.$or = [
        { clubName: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
        { category: { $regex: search, $options: "i" } },
      ];
    }

    // Add category filter
    if (category && category !== "all") {
      query.category = category;
    }

    // Build sort object
    const sortOptions = {};
    sortOptions[sortBy] = sortOrder === "asc" ? 1 : -1;

    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const clubs = await Clubs.find(query)
      .sort(sortOptions)
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    const total = await Clubs.countDocuments(query);

    res.json({
      clubs,
      total,
      page: parseInt(page),
      limit: parseInt(limit),
      totalPages: Math.ceil(total / parseInt(limit)),
    });
  } catch (err) {
    res.status(500).json({ message: "Error fetching clubs", error: err });
  }
});
app.get("/api/manager/club-stats", async (req, res) => {
  const stats = await Payments.aggregate([
    {
      $group: {
        _id: "$clubId",
        totalUsers: { $sum: 1 },
      },
    },
  ]).toArray();

  res.json(stats);
});

app.get(
  "/api/clubs/pending/:email",
  verifyJWT,
  verifyRole("admin"),
  async (req, res) => {
    if (req.params.email !== req.user.email) {
      return res.status(500).json({ message: "Unauthorized Access" });
    }
    const query = {
      email: email,
    };
    try {
      const pendingClub = await Clubs.find(query);
      res.json(pendingClub);
    } catch (error) {
      res.status(500).json({ message: "Error fetching clubs", error: err });
    }
  }
);

app.get(
  "/api/clubs/approved",
  verifyJWT,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const result = await Clubs.find({ status: "approved" }).toArray();
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Error fetching clubs", error: err });
    }
  }
);

app.get(
  "/api/clubs/pending/:role/:email",
  verifyJWT,
  verifyRole("admin"),
  async (req, res) => {
    if (req.params.email !== req.user.email) {
      return res.status(500).json({ message: "Unauthorized Access" });
    }
    if (req.params.role !== "admin") {
      return res.status(500).json({ message: "Unauthorized Access" });
    }
    const query = {
      status: "pending",
    };
    try {
      const pendingClub = await Clubs.find(query).toArray();
      res.json(pendingClub);
    } catch (error) {
      res.status(500).json({ message: "Error fetching clubs", error: err });
    }
  }
);

// Get club details
app.get("/api/club-details/:id", async (req, res) => {
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
app.patch("/api/clubs/approve/:id", verifyJWT, async (req, res) => {
  try {
    await Clubs.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status: "approved" } }
    );

    res.json({ message: "Club approved!" });
  } catch (err) {
    res.status(500).json({ message: "Error approving club", error: err });
  }
});

// Admin – Reject club
app.patch(
  "/api/clubs/reject/:id",
  verifyJWT,

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
app.patch("/api/club/:id", verifyJWT, async (req, res) => {
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
    const {
      search,
      clubId,
      sortBy = "date",
      sortOrder = "asc",
      page = 1,
      limit = 10,
    } = req.query;
    let query = {};

    // Add search filter
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
        { location: { $regex: search, $options: "i" } },
      ];
    }

    // Add club filter
    if (clubId) {
      query.clubId = clubId;
    }

    // Build sort object
    const sortOptions = {};
    if (sortBy === "date") {
      sortOptions.date = sortOrder === "asc" ? 1 : -1;
    } else if (sortBy === "fee") {
      sortOptions.fee = sortOrder === "asc" ? 1 : -1;
    } else if (sortBy === "createdAt") {
      sortOptions.createdAt = sortOrder === "asc" ? 1 : -1;
    }

    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const events = await Events.find(query)
      .sort(sortOptions)
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    const total = await Events.countDocuments(query);

    res.json({
      events,
      total,
      page: parseInt(page),
      limit: parseInt(limit),
      totalPages: Math.ceil(total / parseInt(limit)),
    });
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

app.get("/api/club-events/:clubId", async (req, res) => {
  const clubId = req.params.clubId;
  try {
    const event = await Events.find({ clubId: clubId }).toArray();
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
    const { eventId } = req.body;

    // Check if event exists and get its details
    const event = await Events.findOne({ _id: new ObjectId(eventId) });
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Check if already registered
    const existingRegistration = await Registrations.findOne({
      userEmail: req.user.email,
      eventId: new ObjectId(eventId),
    });

    if (existingRegistration) {
      return res
        .status(409)
        .json({ message: "Already registered for this event" });
    }

    // If event has a fee, require payment
    if (event.fee && event.fee > 0) {
      return res.status(402).json({
        message: "Payment required for this event",
        requiresPayment: true,
        event: {
          id: event._id,
          title: event.title,
          fee: event.fee,
          description: event.description,
        },
      });
    }

    // Free event - register directly
    const reg = {
      eventId: new ObjectId(eventId),
      userEmail: req.user.email,
      registeredAt: new Date(),
      status: "registered",
      paymentType: "free",
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
// DASHBOARD ANALYTICS
// --------------------------------------------------
app.get("/api/analytics/dashboard", verifyJWT, async (req, res) => {
  try {
    const userEmail = req.user.email;
    const userRole = req.user.role;

    let analytics = {};

    if (userRole === "admin") {
      // Admin analytics
      const totalUsers = await Users.countDocuments();
      const totalClubs = await Clubs.countDocuments();
      const approvedClubs = await Clubs.countDocuments({ status: "approved" });
      const pendingClubs = await Clubs.countDocuments({ status: "pending" });
      const totalEvents = await Events.countDocuments();
      const totalPayments = await Payments.aggregate([
        { $group: { _id: null, total: { $sum: "$amount" } } },
      ]).toArray();

      const monthlyRevenue = await Payments.aggregate([
        {
          $group: {
            _id: {
              year: { $year: "$createdAt" },
              month: { $month: "$createdAt" },
            },
            revenue: { $sum: "$amount" },
            count: { $sum: 1 },
          },
        },
        { $sort: { "_id.year": -1, "_id.month": -1 } },
        { $limit: 12 },
      ]).toArray();

      analytics = {
        totalUsers,
        totalClubs,
        approvedClubs,
        pendingClubs,
        totalEvents,
        totalRevenue: totalPayments[0]?.total || 0,
        monthlyRevenue,
      };
    } else if (userRole === "manager") {
      // Manager analytics
      const userClubs = await Clubs.find({ managerEmail: userEmail }).toArray();
      const clubIds = userClubs.map((club) => club._id);

      const clubMemberships = await Memberships.countDocuments({
        clubId: { $in: clubIds },
        status: "active",
      });

      const clubEvents = await Events.find({
        clubId: { $in: clubIds },
      }).toArray();
      const eventIds = clubEvents.map((event) => event._id);

      const eventRegistrations = await Registrations.countDocuments({
        eventId: { $in: eventIds },
      });

      const clubRevenue = await Payments.aggregate([
        { $match: { clubId: { $in: clubIds } } },
        { $group: { _id: null, total: { $sum: "$amount" } } },
      ]).toArray();

      analytics = {
        myClubs: userClubs.length,
        totalMembers: clubMemberships,
        totalEvents: clubEvents.length,
        totalRegistrations: eventRegistrations,
        totalRevenue: clubRevenue[0]?.total || 0,
      };
    } else {
      // Member analytics
      const userMemberships = await Memberships.countDocuments({
        userEmail: userEmail,
        status: "active",
      });

      const userRegistrations = await Registrations.countDocuments({
        userEmail: userEmail,
      });

      const userPayments = await Payments.aggregate([
        { $match: { userEmail: userEmail } },
        { $group: { _id: null, total: { $sum: "$amount" } } },
      ]).toArray();

      analytics = {
        myMemberships: userMemberships,
        myRegistrations: userRegistrations,
        totalSpent: userPayments[0]?.total || 0,
      };
    }

    res.json(analytics);
  } catch (err) {
    res.status(500).json({ message: "Error fetching analytics", error: err });
  }
});
