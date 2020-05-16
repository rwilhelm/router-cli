#!/usr/bin/node

require("dotenv").config();

const axios = require("axios").default;
const axiosCookieJarSupport = require("axios-cookiejar-support").default;
axiosCookieJarSupport(axios);

const chalk = require("chalk");
const cheerio = require("cheerio");
const Hjson = require("hjson");
const sjcl = require("sjcl");
const tough = require("tough-cookie");

const { format } = require("date-fns");
const { de } = require("date-fns/locale");
const formatRelative = require("date-fns/formatRelative");

const transport = axios.create({
  baseURL: "http://192.168.1.1/",
  withCredentials: true,
  jar: new tough.CookieJar(),
  headers: {
    post: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
  },
});

function encrypt(challenge, pwd) {
  return sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(challenge + ":" + pwd));
}

const handshake = async (password) => {
  const res = await transport.get("/");

  const $ = cheerio.load(res.data);
  const scriptContent = $("script").html();

  const csrfToken = scriptContent.match(/var csrf_token = "(?<csrfToken>.*)"/)
    .groups.csrfToken;

  const challenge = scriptContent.match(/var challenge = "(?<challenge>.*)"/)
    .groups.challenge;

  // minlength:1,maxlength:12
  const passwordHash = encrypt(challenge, password);

  const params = new URLSearchParams();
  params.append("csrf_token", csrfToken);
  params.append("challengev", challenge);
  params.append("showpw", 0);
  params.append("password", passwordHash);

  return params;
};

const login = async (password) => {
  return handshake(password).then((params) => {
    return transport.post("data/Login.json", params);
  });
};

const get = async (s) => {
  return transport
    .get(`data/${s}.json`)
    .then(({ data }) => {
      switch (typeof data) {
        case "string":
          return Hjson.parse(data);
        case "object":
          return data;
      }
    })
    .then(handlers[s]);
};

const handlers = {
  PhoneCalls: (data) => {
    return data
      .map(({ vartype, varid, varvalue }) => {
        if (vartype === "template") {
          var vars = varvalue.map((v) => v.varvalue.trim());
          return {
            type: varid.replace(/(add|calls)/g, ""),
            number: vars[3],
            date: new Date([vars[1], vars[2]].join(" ")),
            duration: vars[4],
            id: vars[0],
          };
        }
      })
      .filter((x) => x)
      .sort((a, b) => {
        return a.date - b.date;
      });
  },
};

login(process.env.ROUTER_PASSWORD).then(() => {
  //console.log(Hjson.parse(loginResponse.data));

  get("PhoneCalls").then((calls) => {
    calls.forEach(({ type, number, date, duration, id }) => {
      const name = process.env.hasOwnProperty(number)
        ? process.env[number]
        : "XXX";

      // Pretty print
      console.log(
        id.padStart(2, 0),
        name,
        number.padEnd(13, " "),
        format(date, "yyyy-MM-dd HH:mm:SS"),
        (() => {
          switch (type) {
            case "missed":
              return chalk.grey("00:00:00");
            case "taken":
              return chalk.yellow(duration);
            case "dialed":
              return chalk.green(duration);
          }
        })(),
        type.padEnd(6, " "),
        formatRelative(date, new Date(), {
          locale: de,
        })
      );
    });
  });
});
