import axios from "axios";

export class Http {
  send(path, body) {
    return axios.post(path, body);
  }
}
