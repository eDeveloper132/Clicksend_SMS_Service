import mongoose from "mongoose";
const { Schema, model } = mongoose;

const Sign = new Schema({
  id: { type: String, required: true },
  Name: { type: String, required: true },
  Email: { type: String, required: true, unique: true, match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ // Simple email validation
  },
  Password: { type: String, required: true },
}, { timestamps: true }); // Add timestamps

const Token = new Schema({
  Token: { type: String, required: true, unique: true }
}, { timestamps: true });

const SignModel = model("SignHandler", Sign);
const TokenModel = model("TokenHandler", Token);

export {
  SignModel,
  TokenModel
};
