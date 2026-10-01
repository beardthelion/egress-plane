import * as net from "net";

export function connectDb(): net.Socket {
  return net.createConnection(5432, "db.example.com");
}
