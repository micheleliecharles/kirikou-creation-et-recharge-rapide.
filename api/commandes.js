const crypto = require("crypto");

const {
  db
} = require("./firebase");


const COOKIE_NAME =
  "admin_session";

const SESSION_DURATION =
  8 * 60 * 60 * 1000;


function createSignature(
  timestamp,
  token
) {

  return crypto
    .createHmac(
      "sha256",
      token
    )
    .update(timestamp)
    .digest("hex");

}


function parseCookies(
  cookieHeader = ""
) {

  const cookies = {};

  cookieHeader
    .split(";")
    .forEach((cookie) => {

      const [
        name,
        ...rest
      ] = cookie
        .trim()
        .split("=");

      if (name) {
        cookies[name] =
          rest.join("=");
      }

    });

  return cookies;

}


function isAdmin(req) {

  const token =
    process.env.ADMIN_TOKEN;

  if (!token) {
    return false;
  }


  const cookies =
    parseCookies(
      req.headers.cookie || ""
    );


  const session =
    cookies[COOKIE_NAME];

  if (!session) {
    return false;
  }


  const parts =
    session.split(".");


  if (parts.length !== 2) {
    return false;
  }


  const [
    timestamp,
    signature
  ] = parts;


  const time =
    Number(timestamp);


  if (!Number.isFinite(time)) {
    return false;
  }


  if (
    Date.now() - time >
    SESSION_DURATION
  ) {

    return false;

  }


  const expected =
    createSignature(
      timestamp,
      token
    );


  try {

    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );

  } catch {

    return false;

  }

}


function clean(
  value,
  max = 500
) {

  if (
    typeof value !== "string"
  ) {

    return "";

  }

  return value
    .trim()
    .slice(0, max);

}


module.exports = async (
  req,
  res
) => {


  res.setHeader(
    "Cache-Control",
    "no-store"
  );


  // =====================================
  // CRÉER UNE COMMANDE
  // =====================================

  if (req.method === "POST") {

    try {

      const body =
        typeof req.body === "string"
          ? JSON.parse(req.body)
          : req.body || {};


      const name =
        clean(
          body.name,
          100
        );


      const phone =
        clean(
          body.phone,
          40
        );


      const service =
        clean(
          body.service,
          150
        );


      const amount =
        clean(
          body.amount,
          50
        );


      const details =
        clean(
          body.details,
          1000
        );


      if (
        !name ||
        !phone ||
        !service
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Nom, téléphone et service sont obligatoires."

        });

      }


      const order = {

        name,

        phone,

        service,

        amount,

        details,

        status:
          "pending",

        createdAt:
          new Date().toISOString(),

        source:
          "website"

      };


      const docRef =
        await db
          .collection("orders")
          .add(order);


      return res.status(201).json({

        success: true,

        orderId:
          docRef.id,

        message:
          "Commande enregistrée."

      });


    } catch (error) {

      console.error(
        "ORDER CREATE ERROR:",
        error
      );


      return res.status(500).json({

        success: false,

        message:
          "Impossible d'enregistrer la commande."

      });

    }

  }


  // =====================================
  // LIRE LES COMMANDES
  // =====================================

  if (req.method === "GET") {

    if (!isAdmin(req)) {

      return res.status(401).json({

        success: false,

        message:
          "Non autorisé."

      });

    }


    try {

      const snapshot =
        await db
          .collection("orders")
          .orderBy(
            "createdAt",
            "desc"
          )
          .limit(100)
          .get();


      const orders = [];


      snapshot.forEach(
        (doc) => {

          orders.push({

            id:
              doc.id,

            ...doc.data()

          });

        }
      );


      return res.status(200).json({

        success: true,

        orders

      });


    } catch (error) {

      console.error(
        "ORDER GET ERROR:",
        error
      );


      return res.status(500).json({

        success: false,

        message:
          "Impossible de charger les commandes."

      });

    }

  }


  // =====================================
  // MODIFIER LE STATUT
  // =====================================

  if (req.method === "PATCH") {

    if (!isAdmin(req)) {

      return res.status(401).json({

        success: false,

        message:
          "Non autorisé."

      });

    }


    try {

      const body =
        typeof req.body === "string"
          ? JSON.parse(req.body)
          : req.body || {};


      const id =
        clean(
          body.id,
          100
        );


      const status =
        clean(
          body.status,
          30
        );


      const allowedStatuses = [
        "pending",
        "completed",
        "cancelled"
      ];


      if (
        !id ||
        !allowedStatuses.includes(
          status
        )
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Données invalides."

        });

      }


      await db
        .collection("orders")
        .doc(id)
        .update({

          status,

          updatedAt:
            new Date().toISOString()

        });


      return res.status(200).json({

        success: true,

        message:
          "Statut mis à jour."

      });


    } catch (error) {

      console.error(
        "ORDER UPDATE ERROR:",
        error
      );


      return res.status(500).json({

        success: false,

        message:
          "Impossible de modifier la commande."

      });

    }

  }


  return res.status(405).json({

    success: false,

    message:
      "Méthode non autorisée."

  });

};
