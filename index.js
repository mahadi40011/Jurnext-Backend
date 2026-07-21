require("dotenv").config();
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
const port = process.env.PORT || 3000;
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf-8",
);
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();

// middleware
app.use(
  cors({
    origin: [process.env.CLIENT_DOMAIN, process.env.DEVELOPMENT_URL],
    credentials: true,
    optionsSuccessStatus: 200,
  }),
);
app.use(express.json());

// jwt middlewares
const verifyJWT = async (req, res, next) => {
  const token = req?.headers?.authorization?.split(" ")[1];
  if (!token) return res.status(401).send({ message: "Unauthorized Access!" });
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;
    next();
  } catch (err) {
    console.log(err);
    return res.status(401).send({ message: "Unauthorized Access!", err });
  }
};

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    const db = client.db("Jurnext-1");
    const usersCollection = db.collection("Users");
    const ticketsCollection = db.collection("Tickets");
    const bookedTicketsCollection = db.collection("Booked_Tickets");
    const paymentsCollection = db.collection("Payments");

    // Dynamic Verify Role Middleware
    const verifyRole = (requiredRole) => {
      return async (req, res, next) => {
        try {
          const email = req.tokenEmail;
          const user = await usersCollection.findOne({ email });

          if (!user) {
            return res.status(404).send({ message: "User not found" });
          }

          if (user?.role !== requiredRole) {
            return res.status(403).send({
              message: `${
                requiredRole.charAt(0).toUpperCase() + requiredRole.slice(1)
              } Access Only, You are ${user?.role}`,
            });
          }

          next();
        } catch (error) {
          res.status(500).send({ message: "Internal Server Error", error });
        }
      };
    };

    // save or update user in database
    app.post("/user", async (req, res) => {
      const userData = req.body;

      userData.created_at = new Date().toISOString();
      userData.last_loggedIn = new Date().toISOString();
      userData.role = "customer";

      const query = { email: userData.email };
      const alreadyExist = await usersCollection.findOne(query);

      if (alreadyExist) {
        const result = await usersCollection.updateOne(query, {
          $set: {
            last_loggedIn: new Date().toISOString(),
          },
        });
        return res.send(result);
      }

      const result = await usersCollection.insertOne(userData);
      res.send(result);
    });

    //get all users from database [Admin only]
    app.get("/users", verifyJWT, verifyRole("admin"), async (req, res) => {
      const adminEmail = req.tokenEmail;
      const result = await usersCollection
        .find({ email: { $ne: adminEmail } })
        .toArray();
      res.send(result);
    });

    //update user role [admin only]
    app.patch(
      "/update-role",
      verifyJWT,
      verifyRole("admin"),
      async (req, res) => {
        try {
          const { id, role } = req.body;

          if (!id) {
            return res.status(400).send({ message: "User ID is required" });
          }

          const filter = { _id: new ObjectId(id) };
          const updateDoc = { $set: { role: role } };

          const result = await usersCollection.updateOne(filter, updateDoc);
          res.send(result);
        } catch (err) {
          res
            .status(500)
            .send({ message: "Failed to update role", error: err.message });
        }
      },
    );

    //get a user role [common access]
    app.get("/user/role", verifyJWT, async (req, res) => {
      const result = await usersCollection.findOne({ email: req.tokenEmail });
      res.send({ role: result.role });
    });

    //make a vendor fraud [admin only]
    app.patch(
      "/users/mark-fraud/:id",
      verifyJWT,
      verifyRole("admin"),
      async (req, res) => {
        const id = req.params.id;

        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              fraud: true,
            },
          },
        );
        res.send(result);
      },
    );

    //remove fraud field to the vendor [admin only]
    app.patch(
      "/users/unmark-fraud/:id",
      verifyJWT,
      verifyRole("admin"),
      async (req, res) => {
        const id = req.params.id;

        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $unset: {
              fraud: "",
            },
          },
        );
        res.send(result);
      },
    );

    //Update advertise status and filter <= 6 tickets for advertise [admin only]
    app.patch(
      "/advertise-ticket/:id",
      verifyJWT,
      verifyRole("admin"),
      async (req, res) => {
        const { id } = req.params;
        const { advertise } = req.body;

        const advertisedCount = await ticketsCollection.countDocuments({
          advertise: true,
        });

        if (advertisedCount >= 6 && advertise === true) {
          return res.status(400).send({
            message: "Limit reached! You cannot advertise more than 6 tickets.",
          });
        }

        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: { advertise },
        };

        const result = await ticketsCollection.updateOne(filter, updateDoc);
        res.send(result);
      },
    );

    //get advertise tickets from database [common access]
    app.get("/advertise-tickets", async (req, res) => {
      const result = await ticketsCollection
        .find({ advertise: true })
        .toArray();
      res.send(result);
    });

    //get latest tickets for home page
    app.get("/latest-tickets", async (req, res) => {
      const result = await ticketsCollection
        .find()
        .sort({ _id: -1 })
        .limit(8)
        .toArray();
      res.send(result);
    });

    //send 1 data to database [vendor Only]
    app.post("/tickets", verifyJWT, verifyRole("vendor"), async (req, res) => {
      try {
        const ticketData = req.body;
        const email = req.tokenEmail;

        const user = await usersCollection.findOne({ email });

        if (user && user.fraud === true) {
          return res.send({
            message: "You are marked as a fraud! You cannot add new tickets.",
          });
        }

        const result = await ticketsCollection.insertOne(ticketData);
        res.send(result);
      } catch (error) {
        console.error("Error adding ticket:", error);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // Get all approved tickets with search & filter [common access]
    app.get("/approved-tickets", async (req, res) => {
      try {
        const { from, to, date, operator, busType, maxPrice } = req.query;

        const query = { status: "approved" };

        if (operator) {
          query.operator = {
            $regex: operator,
            $options: "i",
          };
        }

        if (from) {
          query.from = {
            $regex: `^${from}$`,
            $options: "i",
          };
        }

        if (to) {
          query.to = {
            $regex: `^${to}$`,
            $options: "i",
          };
        }

        if (date) {
          query.date = date;
        }

        if (busType) {
          query.busType = busType;
        }

        if (maxPrice) {
          query.price = {
            $lte: Number(maxPrice),
          };
        }

        const result = await ticketsCollection.find(query).toArray();

        res.send(result);
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Error fetching tickets",
        });
      }
    });

    //get all ticket Data from Database [Admin only]
    app.get("/tickets", verifyJWT, verifyRole("admin"), async (req, res) => {
      const result = await ticketsCollection.find().toArray();
      res.send(result);
    });

    // update the ticket status by Admin [Admin only]
    app.patch(
      "/tickets/:id",
      verifyJWT,
      verifyRole("admin"),
      async (req, res) => {
        const id = req.params.id;
        const { status } = req.body;

        try {
          const query = { _id: new ObjectId(id) };
          const updateDoc = {
            $set: {
              status: status,
            },
          };

          const result = await ticketsCollection.updateOne(query, updateDoc);

          if (result.modifiedCount > 0) {
            res.send(result);
          } else {
            res.status(404).send({ message: "Status update failed" });
          }
        } catch (error) {
          res.status(500).send({ message: "Internal Server Error" });
        }
      },
    );

    //get 1 ticket Data from Database [common access]
    app.get("/tickets/:id", async (req, res) => {
      const { id } = req.params;
      const result = await ticketsCollection.findOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    //send 1 data to database [common access]
    app.post("/book-ticket", async (req, res) => {
      const ticketBookingData = req.body;
      const result = await bookedTicketsCollection.insertOne(ticketBookingData);
      res.send(result);
    });

    //get all booked ticket data from database [customer only]
    app.get(
      "/booked-tickets",
      verifyJWT,
      verifyRole("customer"),
      async (req, res) => {
        const email = req.tokenEmail;

        try {
          const result = await bookedTicketsCollection
            .aggregate([
              {
                $match: { "customer.email": email },
              },
              {
                $addFields: {
                  convertedTicketID: { $toObjectId: "$ticketID" },
                },
              },
              {
                $lookup: {
                  from: "Tickets",
                  localField: "convertedTicketID",
                  foreignField: "_id",
                  as: "ticketDetails",
                },
              },
              {
                $unwind: "$ticketDetails",
              },
              {
                $project: {
                  convertedTicketID: 0,
                  vendor: 0,
                  customer: 0,
                  "ticketDetails.perks": 0,
                  "ticketDetails.quantity": 0,
                  "ticketDetails.vendor": 0,
                  "ticketDetails._id": 0,
                },
              },
            ])
            .toArray();

          res.send(result);
        } catch (error) {
          console.error("Aggregation Error:", error);
          res
            .status(500)
            .send({ message: "Failed to fetch booked tickets with details." });
        }
      },
    );

    //get all payment data from database [customer only]
    app.get(
      "/transactions",
      verifyJWT,
      verifyRole("customer"),
      async (req, res) => {
        try {
          const email = req.tokenEmail;
          const result = await paymentsCollection
            .find({ "customer.email": email })
            .project({
              transactionId: 1,
              operator: 1,
              amount: 1,
              date: 1,
            })
            .toArray();

          res.send(result);
        } catch (error) {
          res
            .status(500)
            .send({ message: "Error fetching transactions", error });
        }
      },
    );

    //get all added ticket of a vendor, verify vendor using email [vendor only]
    app.get(
      "/added-tickets",
      verifyJWT,
      verifyRole("vendor"),
      async (req, res) => {
        const email = req.tokenEmail;
        const result = await ticketsCollection
          .find({ "vendor.email": email })
          .toArray();
        res.send(result);
      },
    );

    //get all booking request data for a verified vendor [vendor only]
    app.get(
      "/requested-booking",
      verifyJWT,
      verifyRole("vendor"),
      async (req, res) => {
        const email = req.tokenEmail;
        const result = await bookedTicketsCollection
          .aggregate([
            { $match: { "vendor.email": email } },
            {
              $addFields: {
                convertedID: { $toObjectId: "$ticketID" },
              },
            },
            {
              $lookup: {
                from: "Tickets",
                localField: "convertedID",
                foreignField: "_id",
                as: "joinedTicket",
              },
            },
            { $unwind: "$joinedTicket" },
            {
              $project: {
                _id: 1,
                customer: 1,
                vendor: 1,
                status: 1,
                quantity: 1,
                ticketPrice: "$joinedTicket.price",
                operatorName: "$joinedTicket.operator",
              },
            },
          ])
          .toArray();
        res.send(result);
      },
    );

    // update the booked ticket status by a verified vendor [vendor only]
    app.patch(
      "/booking-status/:id",
      verifyJWT,
      verifyRole("vendor"),
      async (req, res) => {
        const id = req.params.id;
        const { status } = req.body;

        try {
          const query = { _id: new ObjectId(id) };
          const updateDoc = {
            $set: {
              status: status,
            },
          };

          const result = await bookedTicketsCollection.updateOne(
            query,
            updateDoc,
          );

          if (result.modifiedCount > 0) {
            res.send(result);
          } else {
            res.status(404).send({ message: "Status update failed" });
          }
        } catch (error) {
          res.status(500).send({ message: "Internal Server Error" });
        }
      },
    );

    // Update a ticket details [vendor only]
    app.patch(
      "/tickets/:id",
      verifyJWT,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const id = req.params.id;
          const updatedData = req.body;
          const email = req.tokenEmail;

          const query = { _id: new ObjectId(id) };
          const ticket = await ticketsCollection.findOne(query);

          if (!ticket) {
            return res.status(404).send({ message: "Ticket not found!" });
          }

          if (ticket.vendor.email !== email) {
            return res.status(403).send({
              message: "You are not authorized to update this ticket!",
            });
          }

          const updateDoc = {
            $set: {
              ...updatedData,
              updatedAt: new Date(),
            },
          };

          const result = await ticketsCollection.updateOne(query, updateDoc);
          res.send(result);
        } catch (error) {
          console.error("Update Error:", error);
          res.status(500).send({ message: "Internal server error" });
        }
      },
    );

    //delete a ticket [vendor only]
    app.delete(
      "/tickets/:id",
      verifyJWT,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const id = req.params.id;
          const email = req.tokenEmail;

          const query = { _id: new ObjectId(id) };

          if (ticket.vendor.email !== email) {
            return res.status(403).send({
              message: "Unauthorized! You can only delete your own tickets.",
            });
          }

          const result = await ticketsCollection.deleteOne(query);
          res.send(result);
        } catch (error) {
          console.error("Delete Error:", error);
          res.status(500).send({ message: "Internal server error" });
        }
      },
    );

    //get all Revenue data for a vendor [vendor only]
    app.get(
      "/total-revenue",
      verifyJWT,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const email = req.tokenEmail;

          const paymentStats = await paymentsCollection
            .aggregate([
              {
                $match: { "vendor.email": email },
              },
              {
                $group: {
                  _id: null,
                  totalRevenue: { $sum: "$amount" },
                  totalSold: { $sum: "$quantity" },
                },
              },
            ])
            .toArray();

          const stats =
            paymentStats.length > 0
              ? paymentStats[0]
              : { totalRevenue: 0, totalSold: 0 };

          const totalTicketsCount = await ticketsCollection.countDocuments({
            "vendor.email": email,
          });

          res.send({
            revenue: stats.totalRevenue,
            sold: stats.totalSold,
            tickets: totalTicketsCount,
          });
        } catch (error) {
          console.error("Revenue Error:", error);
          res.status(500).send({ message: "Internal Server Error", error });
        }
      },
    );

    //Payment endPint
    app.post("/create-checkout-session", async (req, res) => {
      const paymentInfo = req.body;

      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: "bdt",
              product_data: {
                name: paymentInfo?.operator,
                images: [paymentInfo?.image],
              },
              unit_amount: paymentInfo?.price * 100,
            },
            quantity: paymentInfo?.quantity,
          },
        ],
        customer_email: paymentInfo?.customer?.email,
        mode: "payment",
        metadata: {
          ticketID: paymentInfo?.ticketID,
          customer_name: paymentInfo?.customer?.name,
          customer_email: paymentInfo?.customer?.email,
          quantity: paymentInfo?.quantity,
          bookingId: paymentInfo?.bookingId,
        },
        success_url: `${process.env.CLIENT_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.CLIENT_DOMAIN}/dashboard/booked-tickets`,
      });
      res.send({ url: session.url });
    });

    //payment-success and this data save to paymentsCollection
    app.post("/payment-success", async (req, res) => {
      const { sessionId } = req.body;
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      const soldQuantity = Number(session?.metadata?.quantity);

      const ticket = await ticketsCollection.findOne({
        _id: new ObjectId(session?.metadata?.ticketID),
      });

      const existingPayment = await paymentsCollection.findOne({
        transactionId: session?.payment_intent,
      });

      if ((sessionId.status = "complete" && ticket && !existingPayment)) {
        // payment Information
        const paymentInfo = {
          transactionId: session.payment_intent,
          ticketId: session.metadata.ticketID,
          customer: {
            email: session.metadata.customer_email,
            name: session.metadata.customer_name,
          },
          vendor: ticket.vendor,
          operator: ticket.operator,
          quantity: soldQuantity,
          amount: session.amount_total / 100,
          date: new Date().toISOString(),
        };

        const result = await paymentsCollection.insertOne(paymentInfo);

        await ticketsCollection.updateOne(
          {
            _id: new ObjectId(session?.metadata?.ticketID),
            quantity: { $gte: soldQuantity },
          },
          {
            $inc: { quantity: -soldQuantity },
          },
        );

        await bookedTicketsCollection.updateOne(
          { _id: new ObjectId(session?.metadata?.bookingId) },
          { $set: { status: "Paid" } },
        );

        return res.send({
          transactionId: session.payment_intent,
          paymentId: result.insertedId,
        });
      }
      res.send({
        transactionId: session.payment_intent,
      });
    });

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    // console.log(
    //   "Pinged your deployment. You successfully connected to MongoDB!"
    // );
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello from Server..");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
