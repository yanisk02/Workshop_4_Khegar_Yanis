import express from "express";
import bodyParser from "body-parser";
import { REGISTRY_PORT } from "../config";
import {
  generateRsaKeyPair,
  exportPubKey,
  exportPrvKey,
  importPrvKey,
} from "../crypto";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

const registeredNodes: Node[] = [];


async function generatePrivateKey() {
  const keyPair = await generateRsaKeyPair();
  const prvKey = await exportPrvKey(keyPair.privateKey);
  return prvKey;
}

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  _registry.get("/status", (reqst, resp) => {
    resp.send("live");
  });



  _registry.get("/getNodeRegistry", (reqst, resp) => {
    const nodeRegistry: GetNodeRegistryBody = { nodes: registeredNodes };
    resp.json(nodeRegistry);
  });


  
  _registry.post("/registerNode", (reqst, resp) => {
    const { nodeId, pubKey }: RegisterNodeBody = reqst.body;

    // Checking wether the node is already registered or not
    const existingNode = registeredNodes.find((node) => node.nodeId === nodeId);

    if (existingNode) {
      return resp
        .status(400)
        .json({ message: `Node ${nodeId} is already registered.` });
    }

    // Adding it to the registered nodes array
    registeredNodes.push({ nodeId, pubKey });
    const nodeRegistry: GetNodeRegistryBody = { nodes: registeredNodes };
    resp.json(nodeRegistry);

    return resp
      .status(201)
      .json({ message: `Node ${nodeId} successfully registered.` });
  });



  _registry.get("/getPrivateKey/:nodeId", async (reqst, resp) => {
    const nodeId = parseInt(reqst.params.nodeId);
    const node = registeredNodes.find((n) => n.nodeId === nodeId);
    if (!node) {
      return resp.status(404).json({ error: "Node not found" });
    }
    try {

  // Import a private key instead of using the generation of a new key
      const prvKey = await generatePrivateKey();
      return resp.json({ result: prvKey });
    } catch (error) {
      console.error("Error retrieving private key:", error);
      return resp.status(500).json({ error: "Internal server error" });
    }
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}