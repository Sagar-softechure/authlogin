require('dotenv').config();
const mongoose = require('mongoose');
const uri = process.env.MONGO_URI;
console.log(uri);

mongoose.connect(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("MongoDB Atlas connected"))
.catch(err => console.error("MongoDB connection error:", err));
