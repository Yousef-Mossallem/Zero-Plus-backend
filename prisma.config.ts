import "dotenv/config";
import process from "node:process";
import { defineConfig } from "prisma/config";

export default defineConfig({
  schema: "Prisma/schema.prisma",

  migrations: {
    path: "Prisma/migrations",
  },

  datasource: {
    url: process.env["DATABASE_URL"],
  },
});
