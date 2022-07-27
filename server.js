const express = require("express");
const cors = require("cors");
const mongodb = require("mongodb");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodeMailer = require("nodemailer");
const socket = require("socket.io");
const auth = require("./auth");

dotenv.config();
const app = express();

let transporter = nodeMailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.eMail,
    pass: process.env.passWord,
  },
});

var time = new Date();

var date = [
  time.getDate().toString().padStart(2, 0),
  time.getMonth().toString().padStart(2, 0),
  time.getFullYear().toString(),
].join("/");
date = new Date();
var currentTime = time.toLocaleString("en-US", {
  hour: "numeric",
  hour12: true,
  minute: "numeric",
});
const client = mongodb.MongoClient;

app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
  res.json({ message: `server started at PORT : ${process.env.PORT} ` });
});
app.get("/home", (req, res) => {
  res.json({ message: `server started at PORT : ${process.env.PORT} ` });
});

const hashPassword = async (password) => {
  let salt = await bcrypt.genSalt(10);
  let pass = await bcrypt.hash(password, salt);
  return pass;
};

app.post("/register", async (req, res) => {
  try {
    var connection = await client.connect(process.env.MONGO_URL);
    let isUserExist = await connection
      .db("ChatApp")
      .collection("users")
      .findOne({ email: req.body.email });
    if (isUserExist) {
      res.status(409).send({ message: "user already exist" });
    } else {
      const otp = Math.floor(100000 + Math.random() * 900000);
      await transporter.sendMail({
        from: process.env.eMail,
        to: `${req.body.email}`,
        subject: "OTP verification for ChatApp",
        text: ` ${otp} This is your otp`,
        html: `<p>your OTP is <b>${otp}</b></p>`,
      });
      let pass = await hashPassword(req.body.password);
      req.body.password = pass;
      req.body.status = "pending";
      req.body.otp = otp;

      await connection.db("ChatApp").collection("users").insertOne(req.body);
      res.send({ message: "OTP sent through Email" });
    }
    await connection.close();
  } catch (error) {
    res.send({ message: error.message });
  }
});

app.post("/validate/:email", async (req, res) => {
  try {
    let connection = await client.connect(process.env.MONGO_URL);
    let user = await connection
      .db("ChatApp")
      .collection("users")
      .findOne({ email: req.params.email });
    if (user.otp) {
      if (user.otp == req.body.otp) {
        let data = await connection
          .db("ChatApp")
          .collection("users")
          .updateOne(
            { email: req.params.email },
            { $unset: { otp: 1, status: 1 } }
          );

        await transporter.sendMail({
          from: process.env.email,
          to: `${req.params.email}`,
          subject: "OTP verification successful",
          html: `<p>Thankyou for created an account in our app 😊, Happy chatting</p>`,
        });

        let token = jwt.sign({ id: user._id }, process.env.SECRET_KEY);

        res.json({
          message: "email validation successful",
          token: token,
          id: user._id,
        });
      } else {
        res.status(401).send({ message: "OTP not match" });
      }
    } else {
      res.status(409).send({ message: "user account already verified" });
    }
    await connection.close();
  } catch (err) {
    res.status(401).send({ message: err.message });
    console.log("146 : failed");
  }
});

app.post("/resetPassword", async (req, res) => {
  try {
    let connection = await client.connect(process.env.MONGO_URL);
    let isUserExist = await connection
      .db("ChatApp")
      .collection("users")
      .findOne({ email: req.body.email });
    if (isUserExist) {
      const otp = Math.floor(100000 + Math.random() * 900000);
      let mail = await transporter.sendMail({
        from: process.env.email,
        to: `${req.body.email}`,
        subject: "Reset Password",
        html: `<p><b>${otp}</b> - this is the OTP to reset your Beintouch account password</p>`,
      });

      await connection
        .db("ChatApp")
        .collection("users")
        .updateOne({ email: isUserExist.email }, { $set: { otp: otp } });
      res.send({ message: "OTP sent" });
    } else {
      res.status(401).json({ message: "user not found" });
    }
    await connection.close();
  } catch (err) {
    res.send(err.msg);
  }
});

app.post("/changePassword/:id", async (req, res) => {
  try {
    let connecion = await client.connect(process.env.MONGO_URL);
    let user = await connecion
      .db("ChatApp")
      .collection("users")
      .findOne({ _id: mongodb.ObjectId(req.params.id) });
    let isPasswordMatch = await bcrypt.compare(
      req.body.oldPassword,
      user.password
    );
    if (isPasswordMatch) {
      let password = await hashPassword(req.body.newPassword);
      await connecion
        .db("ChatApp")
        .collection("users")
        .updateOne(
          { _id: mongodb.ObjectId(req.params.id) },
          { $set: { password: password } }
        );
      res.send({ message: "Password changed successfully" });
    } else {
      res.status(401).send({ message: "password not match" });
    }
  } catch (error) {
    res.status(401).send({ message: error.message });
  }
});
app.post("/changeUsername/:id", async (req, res) => {
  try {
    let connection = await client.connect(process.env.MONGO_URL);
    let user = await connection
      .db("ChatApp")
      .collection("users")
      .updateOne(
        { _id: mongodb.ObjectId(req.params.id) },
        { $set: { name: req.body.name } }
      );
    res.send({ message: "username updated successfully" });
    await connection.close();
  } catch (error) {
    res.status(401).send({ message: error.message });
  }
});

app.post("/setNewPassword/:email", async (req, res) => {
  try {
    let connection = await client.connect(process.env.MONGO_URL);
    let user = await connection
      .db("ChatApp")
      .collection("users")
      .findOne({ email: req.params.email });
    if (user.forgotPassword) {
      let token = jwt.sign({ id: user._id }, process.env.SECRET_KEY);
      let pass = await hashPassword(req.body.password);
      await connection
        .db("ChatApp")
        .collection("users")
        .updateOne(
          { email: req.params.email },
          {
            $set: { password: pass, online: true },
            $unset: { forgotPassword: 1 },
          }
        );
      let mail = await transporter.sendMail({
        from: process.env.email,
        to: `${user.email}`,
        subject: "Password changed succesfully",
        html: `<p>your account password has been changed successfully</p>`,
      });

      res.json({
        message: "user logged in successfully",
        token: token,
        id: user._id,
      });
    } else {
      res.status(403).send({ message: "prohibited" });
    }
    await connection.close();
  } catch (error) {
    res.send(error.message);
  }
});

app.post("/resetPassword/otp/:email", async (req, res) => {
  try {
    let connection = await client.connect(process.env.MONGO_URL);
    let user = await connection
      .db("ChatApp")
      .collection("users")
      .findOne({ email: req.params.email });
    if (user.otp == req.body.otp) {
      await connection
        .db("ChatApp")
        .collection("users")
        .updateOne(
          { email: user.email },
          { $set: { forgotPassword: true }, $unset: { otp: 1 } }
        );

      res.send({ message: "OTP matched" });
    } else {
      res.status(401).send({ message: "OTP not match" });
    }
    await connection.close();
  } catch (error) {
    res.send({ message: error.msg });
  }
});

app.post("/login", async (req, res) => {
  try {
    let connection = await client.connect(process.env.MONGO_URL);
    let isUserExist = await connection
      .db("ChatApp")
      .collection("users")
      .findOne({ email: req.body.email });
    if (isUserExist) {
      let isPasswordMatch = await bcrypt.compare(
        req.body.password,
        isUserExist.password
      );

      if (isPasswordMatch) {
        if (isUserExist.status === "pending") {
          // email again-----
          const otp = Math.floor(100000 + Math.random() * 900000);
          let mail = await transporter.sendMail({
            from: process.env.email,
            to: `${req.body.email}`,
            subject: "OTP re-verification for ChatApp",
            text: ` ${otp} This is your otp`,
            html: `<p>your OTP is <b>${otp}</b></p>`,
          });

          await connection
            .db("ChatApp")
            .collection("users")
            .updateOne({ email: isUserExist.email }, { $set: { otp: otp } });

          res.status(409).send({ message: "Verify your email to login" });
        } else {
          if (!isUserExist.profilePicture) {
            res
              .status(410)
              .send({ message: "please upload your profile picture" });
          } else {
            let token = jwt.sign(
              { id: isUserExist._id },
              process.env.SECRET_KEY
            );
            await connection
              .db("ChatApp")
              .collection("users")
              .updateOne(
                { email: isUserExist.email },
                { $set: { online: true } }
              );

            res.json({
              message: "user logged in successfully",
              token: token,
              id: isUserExist._id,
            });
          }
        }
      } else {
        res.status(401).json({ message: "Invalid credentials" });
      }

      // --------------------
    } else {
      res.status(401).json({ message: "invalid credentials" });
    }
    await connection.close();
  } catch (error) {
    res.json({ message: error.message });
  }
});

app.post("/uploadProfilePicture/:email", async (req, res) => {
  try {
    let { imageURL } = req.body;
    let connection = await client.connect(process.env.MONGO_URL);

    let user = await connection
      .db("ChatApp")
      .collection("users")
      .findOne({ email: req.params.email });

    await connection
      .db("ChatApp")
      .collection("users")
      .updateOne(
        { email: user.email },
        { $set: { profilePicture: imageURL, online: true } }
      );

    let token = jwt.sign({ id: user._id }, process.env.SECRET_KEY);

    res.json({
      message: "user logged in successfully",
      token: token,
      id: user._id,
    });
    await connection.close();
  } catch (error) {
    res.send({ message: error.message });
  }
});

app.get("/user/:id", auth, async (req, res) => {
  try {
    let connection = await client.connect(process.env.MONGO_URL);
    let data = await connection
      .db("ChatApp")
      .collection("users")
      .findOne({ _id: mongodb.ObjectId(req.params.id) });
    res.send(data);
    await connection.close();
  } catch (err) {
    res.send({ message: err.message });
  }
});

app.post("/getAllUsers", async (req, res) => {
  try {
    let connection = await client.connect(process.env.MONGO_URL);
    let users = await connection
      .db("ChatApp")
      .collection("users")
      .find(
        {
          _id: { $ne: mongodb.ObjectId(req.body.id) },
          status: { $ne: "pending" },
        },
        {
          email: 0,
          age: 0,
          number: 0,
          password: 0,
        }
      )
      .toArray();
    res.send(users);
    await connection.close();
  } catch (error) {
    console.log("398 new", error.message);
  }
});

app.post("/getmessages", async (req, res) => {
  try {
    let { from, to } = req.body;
    let connection = await client.connect(process.env.MONGO_URL);
    const messages = await connection
      .db("ChatApp")
      .collection("messages")
      .find({ usersInvolved: { $all: [from, to] } })
      .toArray();
    const result = messages.map((msg) => {
      return {
        self: msg.sender.toString() === from,
        message: msg.message,
        time: msg.time,
      };
    });
    res.send(result);
    await connection.close();
  } catch (error) {
    res.send(error.message);
  }
});

app.post("/getmessagesbydate", async (req, res) => {
  try {
    let { from, to } = req.body;
    let connection = await client.connect(process.env.MONGO_URL);
    const messages = await connection
      .db("ChatApp")
      .collection("messages")
      .aggregate([
        { $match: { usersInvolved: { $all: [from, to] } } },
        { $group: { _id: "$date", messages: { $push: "$$ROOT" } } },
      ])
      .sort({ _id: 1 })
      .toArray();
    res.send(messages);
    await connection.close();
  } catch (error) {
    res.send(error.message);
  }
});

const server = app.listen(process.env.PORT, () =>
  console.log("Server started at PORT : " + process.env.PORT)
);

const io = socket(server, {
  cors: {
    origin: "*",
  },
});

global.onlineUsers = new Map();

const refresh = (id) => {
  io.emit("refresh", id);
};

io.on("connection", async (socket) => {
  let connection = await client.connect(process.env.MONGO_URL);
  global.chatSocket = socket;

  socket.on("join-user", (userId) => {
    onlineUsers.set(userId, socket.id);
    refresh(userId);
  });

  socket.on("send-msg", async (data) => {
    try {
      let doc = {
        message: data.message,
        sender: data.from,
        time: data.time,
        date: data.date,
        usersInvolved: [data.from, data.to],
      };
      const messages = await connection
        .db("ChatApp")
        .collection("messages")
        .insertOne(doc);
      const sendUserSocket = onlineUsers.get(data.to);

      if (sendUserSocket) {
        socket.to(sendUserSocket).emit("msg-recieve", data);
      }
    } catch (error) {
      console.log("533", error.msg);
    }
  });

  socket.on("log-off", async ({ currentUser, date }) => {
    try {
      await connection
        .db("ChatApp")
        .collection("users")
        .updateOne(
          { email: currentUser.email },
          { $set: { online: false, lastSeen: currentTime, lastSeenDate: date } }
        );

      refresh(currentUser._id);
    } catch (error) {
      console.log(error);
    }
  });
});
