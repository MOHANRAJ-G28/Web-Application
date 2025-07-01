const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// Define schema
const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    trim: true
  },
  lastName: {
    type: String,
    trim: true
  },
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true // optional but helps
  },
  password: {
    type: String,
    required: true
  }
}, { timestamps: true }); // optional: adds createdAt & updatedAt

// Middleware to hash password before saving
userSchema.pre("save", async function (next) {
  const user = this;
  if (!user.isModified('password')) return next(); // Only hash if modified
  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(user.password, salt);
  next();
});

// Custom method to compare passwords
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Export model
const User = mongoose.model("User", userSchema);
module.exports = User;
