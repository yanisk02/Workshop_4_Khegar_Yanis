import express from "express";
import bodyParser from "body-parser";
import { Node,  GetNodeRegistryBody} from "../registry/registry";
import {
  BASE_USER_PORT,
  REGISTRY_PORT,
  BASE_ONION_ROUTER_PORT,
} from "../config";
import {
  createRandomSymmetricKey,
  exportSymKey,
  rsaEncrypt,
  symEncrypt,
} from "../crypto";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

interface RegistryResponse {
  nodes: Node[];
}

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: Node[] = [];

  

  // Creating a Route for the last received message retreiving
  _user.get("/getLastReceivedMessage", (reqst, resp) => {
    resp.json({ result: lastReceivedMessage });
  });

// Creating a Route for the messages reception
  _user.post("/message", (reqst, resp) => {
    const { message }: { message: string } = reqst.body;
    console.log(`User ${userId} received message: ${message}`);
    lastReceivedMessage = message;
    resp.send("success");
  });



  // Creating a Route for the last circuit obtention
  _user.get("/getLastCircuit", (reqst, resp) => {
    resp.json({ status: 200, result: lastCircuit.map((node) => node.nodeId) });
  });

  // Creating a Route for the last sent message retreiving
  _user.get("/getLastSentMessage", (reqst, resp) => {
    resp.json({ result: lastSentMessage });
  });

  _user.get("/status", (reqst, resp) => {
    resp.send("live");
  });


  _user.post("/message", (reqst, resp) => {
    const message = reqst.body.message;

    lastReceivedMessage = message;

    console.log(`Received message: ${message}`);

    // Send a response for the success
    resp.status(200).send("success");
  });

  _user.post("/sendMessage", async (reqst, resp) => {
    const { message, destinationUserId } = reqst.body;

    // Get the list of available nodes in the network.
    const response = await fetch(
      `http://localhost:${REGISTRY_PORT}/getNodeRegistry`
    );
    const nodes = await fetch(
      `http://localhost:${REGISTRY_PORT}/getNodeRegistry`
    )
      .then((resp) => resp.json())
      .then((body: any) => body.nodes);

    // Generate a 3-node circuit using the list of available nodes
    let circuit: Node[] = [];
    while (circuit.length < 3) {
      const randomNode = nodes[Math.floor(Math.random() * nodes.length)];
      if (!circuit.find((node) => node.nodeId === randomNode.nodeId)) {
        circuit.push(randomNode);
      }
    }

    // Compose the message that will be sent
    let finalMessage = message;
    let destination = `${BASE_USER_PORT + destinationUserId}`.padStart(10, "0");

    // Encrypt the message for each node in the circuit
    for (let i = circuit.length - 1; i >= 0; i--) {
      const node = circuit[i];
      const symmetricKey = await createRandomSymmetricKey();
      const symmetricKey64 = await exportSymKey(symmetricKey);
      finalMessage = await symEncrypt(symmetricKey, destination + finalMessage);
      const encryptedSymKey = await rsaEncrypt(symmetricKey64, node.pubKey);
      finalMessage = encryptedSymKey + finalMessage;
      destination = `${BASE_ONION_ROUTER_PORT + node.nodeId}`.padStart(10, "0");
    }

    lastSentMessage = message;
    lastCircuit = circuit.reverse();
    

    // Send the final message to the first node in the circuit
    await fetch(`http://localhost:${destination}/message`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: finalMessage }),
    });

    resp.status(200).send("Message envoyé avec succès.");
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}