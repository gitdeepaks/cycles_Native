import { connect } from "mongoose";

const uri = "mongodb://root:root@localhost:27017";

connect(uri)
  .then(() => {
    console.log("Connected to database");
  })
  .catch((err) => {
    console.log(err.message, "error connecting to database");
  });
