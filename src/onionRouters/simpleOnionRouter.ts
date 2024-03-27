import bodyParser from "body-parser";
import express from "express";
import {generateRsaKeyPair,exportPrvKey,exportPubKey,rsaDecrypt, symDecrypt, importPrvKey} from "../crypto";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { Node, RegisterNodeBody } from "../registry/registry";


export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  let lastReceivedEncryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;
  let lastReceivedDecryptedMessage: string | null = null;

  const { privateKey, publicKey } = await generateRsaKeyPair();
  const publicKeyStr = await exportPubKey(publicKey);

  const registerNode: RegisterNodeBody = {
    nodeId: nodeId,
    pubKey: publicKeyStr,
  };

  const registryUrl = `http://localhost:${REGISTRY_PORT}/registerNode`;
  try {
    await fetch(registryUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(registerNode),
    });
    console.log(`Node ${nodeId} successfully registered.`);
  } catch (error) {
    console.error(`Failed to register Node ${nodeId}: `);
  }

 

  onionRouter.get("/getLastReceivedEncryptedMessage", (reqst, resp) => {
    resp.json({ result: lastReceivedEncryptedMessage });
  });
   // destination of the last message 
  onionRouter.get("/getLastMessageDestination", (reqst, resp) => {
    resp.json({ result: lastMessageDestination });
  });

  
  // Implementing the last received decrypted message
  onionRouter.get("/getLastReceivedDecryptedMessage", (reqst, resp) => {
    resp.json({ result: lastReceivedDecryptedMessage });
  });


// status of the route
  onionRouter.get("/status", (reqst, resp) => {
    resp.send("live");
  });
  onionRouter.get("/getPrivateKey", async (reqst, resp) => {
    try {
      const privateKeyStr = await exportPrvKey(privateKey);
      resp.json({ result: privateKeyStr });
    } catch (error) {
      resp.status(500).json({ error: "Failed " });
    }
  });

  onionRouter.post("/message", async (reqst, resp) => {
    try {
      const { message } = reqst.body;
      // Decrypt the symmetric key (the first 344 characters) with our RSA private key.
      const encryptedSymKey = message.slice(0, 344);
      const symKey = await rsaDecrypt(encryptedSymKey, privateKey);

      // Decrypt the rest of the message with our symmetric key.

      const encryptedMessage = message.slice(344);
      const decryptedMessage = await symDecrypt(symKey, encryptedMessage);

      // The first 10 characters of the decrypted message represent the identifier of the next destination in the network
      const nextDestination = parseInt(decryptedMessage.slice(0, 10), 10);
      // Le reste du message est extrait après ces 10 premiers caractères
      const remainingMessage = decryptedMessage.slice(10);

      // Updating informations
      lastMessageDestination = nextDestination;
      lastReceivedEncryptedMessage = message;
      lastReceivedDecryptedMessage = remainingMessage;

      // Sending the information to the next node in the anonymous network via an HTTP POST request to the URL corresponding to the next destination
      await fetch(`http://localhost:${nextDestination}/message`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ message: remainingMessage }),
      });

      resp.status(200).send("Message traité avec succès.");
    } catch (error) {
      console.error("Erreur lors du traitement du message:", error);
      resp.status(500).send("Erreur lors du traitement du message.");
    }
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}