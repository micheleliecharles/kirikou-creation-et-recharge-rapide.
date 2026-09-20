const {
  initializeApp,
  cert,
  getApps
} = require("firebase-admin/app");

const {
  getFirestore
} = require("firebase-admin/firestore");


function getFirebaseApp() {

  // Si Firebase deja initialisé
  if (getApps().length > 0) {
    return getApps()[0];
  }


  const projectId =
    process.env.FIREBASE_PROJECT_ID;

  const clientEmail =
    process.env.FIREBASE_CLIENT_EMAIL;

  const privateKey =
    process.env.FIREBASE_PRIVATE_KEY;


  if (
    !projectId ||
    !clientEmail ||
    !privateKey
  ) {

    throw new Error(
      "Firebase Environment Variables yo pa konfigire."
    );

  }


  return initializeApp({

    credential: cert({

      projectId: projectId,

      clientEmail: clientEmail,

      privateKey:
        privateKey.replace(
          /\\n/g,
          "\n"
        )

    })

  });

}


const app =
  getFirebaseApp();


const db =
  getFirestore(app);


module.exports = {
  db
};
